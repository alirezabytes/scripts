#!/bin/bash

set -e

APP_DIR="/opt/ocserv-session-api"
APP_FILE="$APP_DIR/app.py"
VENV_DIR="$APP_DIR/venv"
SERVICE_FILE="/etc/systemd/system/ocserv-session-api.service"
GROUP_LIMITS_FILE="$APP_DIR/group_limits.json"

NODE_CONF="/etc/ocserv-central-node.conf"
CONNECT_SCRIPT="/usr/local/bin/ocserv-central-connect.sh"
DISCONNECT_SCRIPT="/usr/local/bin/ocserv-central-disconnect.sh"
HEARTBEAT_SCRIPT="/usr/local/bin/ocserv-central-heartbeat.sh"
NODE_STATE_DIR="/var/lib/ocserv-central"
NODE_LOG_DIR="/var/log/ocserv-central"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_err() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

require_root() {
    if [ "$EUID" -ne 0 ]; then
        print_err "Please run this script as root."
        exit 1
    fi
}

pause() {
    echo
    read -rp "Press Enter to continue..."
}

generate_secret() {
    tr -dc 'A-Za-z0-9_@%+=:.-' </dev/urandom | head -c 48
    echo
}

install_central_packages() {
    print_info "Installing central server packages..."
    apt update
    apt install -y python3 python3-venv redis-server curl jq
    systemctl enable --now redis-server
    print_ok "Packages installed."
}

ask_group_limits() {
    echo
    print_info "Define group connection limits."
    echo "Example:"
    echo "  group1=1,group2=2,group3=3,group4=1,vip=5"
    echo
    read -rp "Enter group limits: " GROUP_LIMITS_INPUT

    if [ -z "$GROUP_LIMITS_INPUT" ]; then
        GROUP_LIMITS_INPUT="default=1"
    fi

    mkdir -p "$APP_DIR"

    python3 - "$GROUP_LIMITS_INPUT" "$GROUP_LIMITS_FILE" <<'PY'
import sys, json

raw = sys.argv[1]
path = sys.argv[2]

limits = {}

for item in raw.split(","):
    item = item.strip()
    if not item:
        continue
    if "=" not in item:
        continue
    name, value = item.split("=", 1)
    name = name.strip()
    value = value.strip()
    try:
        limits[name] = int(value)
    except ValueError:
        pass

if "default" not in limits:
    limits["default"] = 1

with open(path, "w") as f:
    json.dump(limits, f, indent=4)

print(json.dumps(limits, indent=4))
PY

    print_ok "Group limits saved to $GROUP_LIMITS_FILE"
}

create_central_app() {
    print_info "Creating Central Session API..."

    mkdir -p "$APP_DIR"

    if [ -f "$APP_FILE" ]; then
        cp "$APP_FILE" "$APP_FILE.backup.$(date +%F-%H%M%S)"
        print_warn "Existing app.py backed up."
    fi

    read -rp "Enter API secret, or press Enter to generate random secret: " API_SECRET
    if [ -z "$API_SECRET" ]; then
        API_SECRET="$(generate_secret)"
    fi

    cat > "$APP_FILE" <<PYAPP
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import redis
import time
import json
import os
from typing import Optional

SECRET = "$API_SECRET"
SESSION_TTL_SECONDS = 600
GROUP_LIMITS_FILE = "$GROUP_LIMITS_FILE"

r = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True)
app = FastAPI()


class AuthorizeRequest(BaseModel):
    username: str
    group: str = "default"
    server_id: str
    session_id: str
    ip_real: Optional[str] = None
    hostname: Optional[str] = None
    device: Optional[str] = None


class DisconnectRequest(BaseModel):
    username: str
    server_id: str
    session_id: str


class HeartbeatRequest(BaseModel):
    server_id: str
    sessions: list[AuthorizeRequest]


def load_group_limits():
    default_limits = {"default": 1}

    if not os.path.exists(GROUP_LIMITS_FILE):
        return default_limits

    try:
        with open(GROUP_LIMITS_FILE, "r") as f:
            data = json.load(f)

        limits = {}
        for key, value in data.items():
            try:
                limits[str(key)] = int(value)
            except Exception:
                pass

        if "default" not in limits:
            limits["default"] = 1

        return limits
    except Exception:
        return default_limits


def require_secret(request: Request):
    secret = request.headers.get("X-Secret", "")
    if secret != SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")


def user_sessions_key(username: str) -> str:
    return f"user:{username}:sessions"


def session_key(session_id: str) -> str:
    return f"session:{session_id}"


def server_sessions_key(server_id: str) -> str:
    return f"server:{server_id}:sessions"


def cleanup_user(username: str):
    key = user_sessions_key(username)
    sessions = list(r.smembers(key))

    for sid in sessions:
        if not r.exists(session_key(sid)):
            r.srem(key, sid)


def get_active_sessions(username: str):
    cleanup_user(username)

    result = []
    for sid in r.smembers(user_sessions_key(username)):
        raw = r.get(session_key(sid))
        if raw:
            try:
                result.append(json.loads(raw))
            except Exception:
                pass

    return result


def save_session(data: AuthorizeRequest):
    now = int(time.time())

    payload = {
        "username": data.username,
        "group": data.group,
        "server_id": data.server_id,
        "session_id": data.session_id,
        "ip_real": data.ip_real,
        "hostname": data.hostname,
        "device": data.device,
        "updated_at": now,
    }

    r.sadd(user_sessions_key(data.username), data.session_id)
    r.sadd(server_sessions_key(data.server_id), data.session_id)
    r.setex(session_key(data.session_id), SESSION_TTL_SECONDS, json.dumps(payload))


def remove_session(username: str, server_id: str, session_id: str):
    r.srem(user_sessions_key(username), session_id)
    r.srem(server_sessions_key(server_id), session_id)
    r.delete(session_key(session_id))


@app.post("/authorize")
async def authorize(data: AuthorizeRequest, request: Request):
    require_secret(request)

    group_limits = load_group_limits()

    username = data.username.strip()
    group = data.group.strip() or "default"

    if not username:
        return {"allow": False, "reason": "empty_username"}

    limit = group_limits.get(group, group_limits.get("default", 1))
    active_sessions = get_active_sessions(username)

    for session in active_sessions:
        if session.get("session_id") == data.session_id:
            save_session(data)
            return {
                "allow": True,
                "reason": "same_session_refreshed",
                "username": username,
                "group": group,
                "active": len(active_sessions),
                "limit": limit,
            }

    if len(active_sessions) >= limit:
        return {
            "allow": False,
            "reason": "global_connection_limit_reached",
            "username": username,
            "group": group,
            "active": len(active_sessions),
            "limit": limit,
            "sessions": active_sessions,
        }

    save_session(data)

    return {
        "allow": True,
        "reason": "allowed",
        "username": username,
        "group": group,
        "active": len(get_active_sessions(username)),
        "limit": limit,
    }


@app.post("/disconnect")
async def disconnect(data: DisconnectRequest, request: Request):
    require_secret(request)

    remove_session(data.username, data.server_id, data.session_id)

    return {
        "ok": True,
        "reason": "session_removed",
        "username": data.username,
        "server_id": data.server_id,
        "session_id": data.session_id,
    }


@app.post("/heartbeat")
async def heartbeat(data: HeartbeatRequest, request: Request):
    require_secret(request)

    reported_session_ids = set()

    for session in data.sessions:
        if session.username and session.session_id:
            save_session(session)
            reported_session_ids.add(session.session_id)

    old_sessions = list(r.smembers(server_sessions_key(data.server_id)))

    for sid in old_sessions:
        if sid not in reported_session_ids:
            raw = r.get(session_key(sid))
            if raw:
                try:
                    payload = json.loads(raw)
                    username = payload.get("username")
                    if username:
                        remove_session(username, data.server_id, sid)
                except Exception:
                    r.srem(server_sessions_key(data.server_id), sid)
                    r.delete(session_key(sid))
            else:
                r.srem(server_sessions_key(data.server_id), sid)

    r.setex(
        f"server:{data.server_id}:last_seen",
        SESSION_TTL_SECONDS,
        str(int(time.time()))
    )

    return {
        "ok": True,
        "server_id": data.server_id,
        "reported": len(reported_session_ids),
    }


@app.get("/status/{username}")
async def user_status(username: str, request: Request):
    require_secret(request)

    sessions = get_active_sessions(username)

    return {
        "username": username,
        "active": len(sessions),
        "sessions": sessions,
    }


@app.get("/all")
async def all_sessions(request: Request):
    require_secret(request)

    users = {}

    for key in r.scan_iter("user:*:sessions"):
        username = key.split(":")[1]
        sessions = get_active_sessions(username)
        if sessions:
            users[username] = {
                "active": len(sessions),
                "sessions": sessions,
            }

    return users


@app.get("/limits")
async def limits(request: Request):
    require_secret(request)
    return load_group_limits()


@app.get("/health")
async def health():
    return {"ok": True}
PYAPP

    print_ok "Central API created."
    echo
    print_info "Your API secret is:"
    echo "$API_SECRET"
    echo
    print_warn "Save this secret. You need it on all ocserv nodes."
}

install_central_api() {
    install_central_packages
    ask_group_limits
    create_central_app

    print_info "Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip
    "$VENV_DIR/bin/pip" install fastapi uvicorn redis pydantic

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=OCServ Central Session API
After=network.target redis-server.service
Wants=redis-server.service

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$VENV_DIR/bin/uvicorn app:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now ocserv-session-api

    print_ok "Central Session API installed and started."
    print_info "Test with:"
    echo "curl http://127.0.0.1:8080/health"
}

show_central_status() {
    echo
    systemctl status ocserv-session-api --no-pager || true
    echo
    systemctl status redis-server --no-pager || true
}

restart_central() {
    systemctl restart ocserv-session-api
    print_ok "Central API restarted."
}

edit_group_limits() {
    if [ ! -d "$APP_DIR" ]; then
        print_err "Central API directory not found."
        return
    fi

    ask_group_limits
    systemctl restart ocserv-session-api || true
    print_ok "Group limits updated."
}

show_group_limits() {
    if [ -f "$GROUP_LIMITS_FILE" ]; then
        cat "$GROUP_LIMITS_FILE" | jq .
    else
        print_err "Group limits file not found."
    fi
}

install_node_packages() {
    print_info "Installing node packages..."
    apt update
    apt install -y curl jq
    print_ok "Packages installed."
}

create_node_config() {
    echo
    read -rp "Central API URL [example: http://1.2.3.4:8080]: " CENTRAL_API
    read -rp "API secret: " API_SECRET
    read -rp "This node server ID [example: de1]: " SERVER_ID
    read -rp "ocpasswd path [/etc/ocserv/ocpasswd]: " OCPASSWD_PATH
    read -rp "Fail mode if Central API is down? [closed/open] default=closed: " FAIL_MODE

    if [ -z "$OCPASSWD_PATH" ]; then
        OCPASSWD_PATH="/etc/ocserv/ocpasswd"
    fi

    if [ -z "$FAIL_MODE" ]; then
        FAIL_MODE="closed"
    fi

    if [ -z "$CENTRAL_API" ] || [ -z "$API_SECRET" ] || [ -z "$SERVER_ID" ]; then
        print_err "Central API, secret and server ID are required."
        exit 1
    fi

    cat > "$NODE_CONF" <<EOF
CENTRAL_API="$CENTRAL_API"
SECRET="$API_SECRET"
SERVER_ID="$SERVER_ID"
OCPASSWD_FILE="$OCPASSWD_PATH"
FAIL_MODE="$FAIL_MODE"
STATE_DIR="$NODE_STATE_DIR"
LOG_DIR="$NODE_LOG_DIR"
EOF

    chmod 600 "$NODE_CONF"
    print_ok "Node config saved to $NODE_CONF"
}

create_node_scripts() {
    mkdir -p "$NODE_STATE_DIR" "$NODE_LOG_DIR"

    cat > "$CONNECT_SCRIPT" <<'EOF'
#!/bin/bash

CONF="/etc/ocserv-central-node.conf"

if [ ! -f "$CONF" ]; then
    logger -t ocserv-central "Config file not found: $CONF"
    exit 1
fi

source "$CONF"

mkdir -p "$STATE_DIR" "$LOG_DIR"

LOG_FILE="$LOG_DIR/connect.log"

log_msg() {
    echo "$(date '+%F %T') $*" >> "$LOG_FILE"
    logger -t ocserv-central "$*"
}

USERNAME="${USERNAME:-}"
GROUPNAME="${GROUPNAME:-}"
IP_REAL="${IP_REAL:-}"
HOSTNAME="${HOSTNAME:-}"
DEVICE="${DEVICE:-}"

if [ -z "$USERNAME" ]; then
    log_msg "DENY: missing USERNAME"
    exit 1
fi

if [ -z "$GROUPNAME" ]; then
    if [ -f "$OCPASSWD_FILE" ]; then
        GROUPNAME="$(awk -F: -v u="$USERNAME" '$1 == u {print $2; exit}' "$OCPASSWD_FILE")"
    fi
fi

GROUPNAME="$(echo "$GROUPNAME" | cut -d',' -f1)"

if [ -z "$GROUPNAME" ]; then
    GROUPNAME="default"
fi

if [ -z "$DEVICE" ]; then
    DEVICE="${IP_REAL}-${RANDOM}-$(date +%s)"
fi

SESSION_ID="${USERNAME}_${SERVER_ID}_${DEVICE}"

PAYLOAD=$(jq -n \
    --arg username "$USERNAME" \
    --arg group "$GROUPNAME" \
    --arg server_id "$SERVER_ID" \
    --arg session_id "$SESSION_ID" \
    --arg ip_real "$IP_REAL" \
    --arg hostname "$HOSTNAME" \
    --arg device "$DEVICE" \
    '{
        username: $username,
        group: $group,
        server_id: $server_id,
        session_id: $session_id,
        ip_real: $ip_real,
        hostname: $hostname,
        device: $device
    }'
)

RESPONSE=$(curl -s --max-time 5 \
    -X POST "$CENTRAL_API/authorize" \
    -H "Content-Type: application/json" \
    -H "X-Secret: $SECRET" \
    -d "$PAYLOAD")

CURL_EXIT=$?

if [ "$CURL_EXIT" -ne 0 ] || [ -z "$RESPONSE" ]; then
    if [ "$FAIL_MODE" = "open" ]; then
        log_msg "ALLOW_FAIL_OPEN: central unavailable user=$USERNAME group=$GROUPNAME server=$SERVER_ID"
        exit 0
    else
        log_msg "DENY: central unavailable user=$USERNAME group=$GROUPNAME server=$SERVER_ID"
        exit 1
    fi
fi

ALLOW=$(echo "$RESPONSE" | jq -r '.allow // false')
REASON_API=$(echo "$RESPONSE" | jq -r '.reason // "unknown"')
ACTIVE=$(echo "$RESPONSE" | jq -r '.active // 0')
LIMIT=$(echo "$RESPONSE" | jq -r '.limit // 0')

if [ "$ALLOW" = "true" ]; then
    echo "$SESSION_ID|$USERNAME|$GROUPNAME|$SERVER_ID|$IP_REAL|$HOSTNAME|$DEVICE" > "$STATE_DIR/$SESSION_ID.session"
    log_msg "ALLOW: user=$USERNAME group=$GROUPNAME active=$ACTIVE limit=$LIMIT session=$SESSION_ID"
    exit 0
else
    log_msg "DENY: user=$USERNAME group=$GROUPNAME active=$ACTIVE limit=$LIMIT reason=$REASON_API response=$RESPONSE"
    exit 1
fi
EOF

    cat > "$DISCONNECT_SCRIPT" <<'EOF'
#!/bin/bash

CONF="/etc/ocserv-central-node.conf"

if [ ! -f "$CONF" ]; then
    logger -t ocserv-central "Config file not found: $CONF"
    exit 0
fi

source "$CONF"

mkdir -p "$STATE_DIR" "$LOG_DIR"

LOG_FILE="$LOG_DIR/disconnect.log"

log_msg() {
    echo "$(date '+%F %T') $*" >> "$LOG_FILE"
    logger -t ocserv-central "$*"
}

USERNAME="${USERNAME:-}"
DEVICE="${DEVICE:-}"

if [ -z "$USERNAME" ]; then
    log_msg "SKIP: missing USERNAME on disconnect"
    exit 0
fi

if [ -z "$DEVICE" ]; then
    SESSION_FILE=$(ls "$STATE_DIR"/"${USERNAME}_${SERVER_ID}_"*.session 2>/dev/null | head -n 1)
    if [ -n "$SESSION_FILE" ]; then
        SESSION_ID="$(basename "$SESSION_FILE" .session)"
    else
        log_msg "SKIP: no DEVICE and no session file for user=$USERNAME"
        exit 0
    fi
else
    SESSION_ID="${USERNAME}_${SERVER_ID}_${DEVICE}"
fi

PAYLOAD=$(jq -n \
    --arg username "$USERNAME" \
    --arg server_id "$SERVER_ID" \
    --arg session_id "$SESSION_ID" \
    '{
        username: $username,
        server_id: $server_id,
        session_id: $session_id
    }'
)

curl -s --max-time 5 \
    -X POST "$CENTRAL_API/disconnect" \
    -H "Content-Type: application/json" \
    -H "X-Secret: $SECRET" \
    -d "$PAYLOAD" >/dev/null 2>&1

rm -f "$STATE_DIR/$SESSION_ID.session"

log_msg "DISCONNECT: user=$USERNAME session=$SESSION_ID server=$SERVER_ID"

exit 0
EOF

    cat > "$HEARTBEAT_SCRIPT" <<'EOF'
#!/bin/bash

CONF="/etc/ocserv-central-node.conf"

if [ ! -f "$CONF" ]; then
    exit 0
fi

source "$CONF"

mkdir -p "$STATE_DIR" "$LOG_DIR"

LOG_FILE="$LOG_DIR/heartbeat.log"

SESSIONS_JSON="[]"

for file in "$STATE_DIR"/*.session; do
    [ -e "$file" ] || continue

    IFS='|' read -r SESSION_ID USERNAME GROUPNAME SERVER_ID_FILE IP_REAL HOSTNAME DEVICE < "$file"

    if [ -z "$SESSION_ID" ] || [ -z "$USERNAME" ]; then
        continue
    fi

    ITEM=$(jq -n \
        --arg username "$USERNAME" \
        --arg group "$GROUPNAME" \
        --arg server_id "$SERVER_ID" \
        --arg session_id "$SESSION_ID" \
        --arg ip_real "$IP_REAL" \
        --arg hostname "$HOSTNAME" \
        --arg device "$DEVICE" \
        '{
            username: $username,
            group: $group,
            server_id: $server_id,
            session_id: $session_id,
            ip_real: $ip_real,
            hostname: $hostname,
            device: $device
        }'
    )

    SESSIONS_JSON=$(echo "$SESSIONS_JSON" | jq --argjson item "$ITEM" '. + [$item]')
done

PAYLOAD=$(jq -n \
    --arg server_id "$SERVER_ID" \
    --argjson sessions "$SESSIONS_JSON" \
    '{
        server_id: $server_id,
        sessions: $sessions
    }'
)

RESPONSE=$(curl -s --max-time 10 \
    -X POST "$CENTRAL_API/heartbeat" \
    -H "Content-Type: application/json" \
    -H "X-Secret: $SECRET" \
    -d "$PAYLOAD")

echo "$(date '+%F %T') heartbeat server=$SERVER_ID response=$RESPONSE" >> "$LOG_FILE"
EOF

    chmod +x "$CONNECT_SCRIPT" "$DISCONNECT_SCRIPT" "$HEARTBEAT_SCRIPT"

    print_ok "Node scripts created."
}

configure_ocserv_conf() {
    read -rp "Do you want to automatically configure /etc/ocserv/ocserv.conf? [y/N]: " AUTO_CONF

    if [[ ! "$AUTO_CONF" =~ ^[Yy]$ ]]; then
        print_warn "Skipping ocserv.conf auto configuration."
        echo
        print_info "Add these lines manually:"
        echo "use-occtl = true"
        echo "connect-script = $CONNECT_SCRIPT"
        echo "disconnect-script = $DISCONNECT_SCRIPT"
        return
    fi

    OCSERV_CONF="/etc/ocserv/ocserv.conf"

    if [ ! -f "$OCSERV_CONF" ]; then
        print_err "$OCSERV_CONF not found."
        return
    fi

    BACKUP="$OCSERV_CONF.backup.$(date +%F-%H%M%S)"
    cp "$OCSERV_CONF" "$BACKUP"
    print_ok "Backup created: $BACKUP"

    set_or_append() {
        local key="$1"
        local value="$2"
        local file="$3"

        if grep -Eq "^[[:space:]]*#?[[:space:]]*$key[[:space:]]*=" "$file"; then
            sed -i -E "s|^[[:space:]]*#?[[:space:]]*$key[[:space:]]*=.*|$key = $value|" "$file"
        else
            echo "$key = $value" >> "$file"
        fi
    }

    set_or_append "use-occtl" "true" "$OCSERV_CONF"
    set_or_append "connect-script" "$CONNECT_SCRIPT" "$OCSERV_CONF"
    set_or_append "disconnect-script" "$DISCONNECT_SCRIPT" "$OCSERV_CONF"

    print_ok "ocserv.conf updated."

    read -rp "Restart ocserv now? [y/N]: " RESTART_OCSERV
    if [[ "$RESTART_OCSERV" =~ ^[Yy]$ ]]; then
        systemctl restart ocserv
        print_ok "ocserv restarted."
    else
        print_warn "Restart ocserv later with: systemctl restart ocserv"
    fi
}

install_heartbeat_cron() {
    CRON_LINE="* * * * * $HEARTBEAT_SCRIPT >/dev/null 2>&1"

    TMP_CRON="$(mktemp)"
    crontab -l 2>/dev/null > "$TMP_CRON" || true

    if grep -Fq "$HEARTBEAT_SCRIPT" "$TMP_CRON"; then
        print_warn "Heartbeat cron already exists."
    else
        echo "$CRON_LINE" >> "$TMP_CRON"
        crontab "$TMP_CRON"
        print_ok "Heartbeat cron installed."
    fi

    rm -f "$TMP_CRON"
}

install_node() {
    install_node_packages
    create_node_config
    create_node_scripts
    configure_ocserv_conf
    install_heartbeat_cron
    print_ok "Node installation completed."
}

show_node_status() {
    echo
    print_info "Node config:"
    if [ -f "$NODE_CONF" ]; then
        cat "$NODE_CONF"
    else
        print_warn "$NODE_CONF not found."
    fi

    echo
    print_info "Recent connect log:"
    tail -n 30 "$NODE_LOG_DIR/connect.log" 2>/dev/null || true

    echo
    print_info "Recent disconnect log:"
    tail -n 30 "$NODE_LOG_DIR/disconnect.log" 2>/dev/null || true

    echo
    print_info "Recent heartbeat log:"
    tail -n 10 "$NODE_LOG_DIR/heartbeat.log" 2>/dev/null || true
}

test_node_api() {
    if [ ! -f "$NODE_CONF" ]; then
        print_err "$NODE_CONF not found."
        return
    fi

    source "$NODE_CONF"

    echo
    read -rp "Test username: " T_USER
    read -rp "Test group: " T_GROUP

    if [ -z "$T_USER" ]; then
        print_err "Username is required."
        return
    fi

    if [ -z "$T_GROUP" ]; then
        T_GROUP="default"
    fi

    TEST_SESSION="${T_USER}_${SERVER_ID}_manualtest_$(date +%s)"

    PAYLOAD=$(jq -n \
        --arg username "$T_USER" \
        --arg group "$T_GROUP" \
        --arg server_id "$SERVER_ID" \
        --arg session_id "$TEST_SESSION" \
        --arg ip_real "manual-test" \
        --arg hostname "$(hostname)" \
        --arg device "manualtest" \
        '{
            username: $username,
            group: $group,
            server_id: $server_id,
            session_id: $session_id,
            ip_real: $ip_real,
            hostname: $hostname,
            device: $device
        }'
    )

    curl -s -X POST "$CENTRAL_API/authorize" \
        -H "Content-Type: application/json" \
        -H "X-Secret: $SECRET" \
        -d "$PAYLOAD" | jq .

    echo
    read -rp "Remove this test session now? [Y/n]: " REMOVE_TEST
    if [[ ! "$REMOVE_TEST" =~ ^[Nn]$ ]]; then
        DPAYLOAD=$(jq -n \
            --arg username "$T_USER" \
            --arg server_id "$SERVER_ID" \
            --arg session_id "$TEST_SESSION" \
            '{
                username: $username,
                server_id: $server_id,
                session_id: $session_id
            }'
        )

        curl -s -X POST "$CENTRAL_API/disconnect" \
            -H "Content-Type: application/json" \
            -H "X-Secret: $SECRET" \
            -d "$DPAYLOAD" | jq .
    fi
}

query_central_from_node() {
    if [ ! -f "$NODE_CONF" ]; then
        print_err "$NODE_CONF not found."
        return
    fi

    source "$NODE_CONF"

    echo
    echo "1) Health"
    echo "2) Show all active sessions"
    echo "3) Show one user status"
    echo "4) Show group limits"
    read -rp "Choose: " Q

    case "$Q" in
        1)
            curl -s "$CENTRAL_API/health" | jq .
            ;;
        2)
            curl -s "$CENTRAL_API/all" -H "X-Secret: $SECRET" | jq .
            ;;
        3)
            read -rp "Username: " U
            curl -s "$CENTRAL_API/status/$U" -H "X-Secret: $SECRET" | jq .
            ;;
        4)
            curl -s "$CENTRAL_API/limits" -H "X-Secret: $SECRET" | jq .
            ;;
        *)
            print_err "Invalid option."
            ;;
    esac
}

uninstall_node() {
    print_warn "This will remove node scripts, config, cron entry, state files and logs."
    read -rp "Continue? [y/N]: " C

    if [[ ! "$C" =~ ^[Yy]$ ]]; then
        return
    fi

    TMP_CRON="$(mktemp)"
    crontab -l 2>/dev/null > "$TMP_CRON" || true
    grep -v "$HEARTBEAT_SCRIPT" "$TMP_CRON" > "$TMP_CRON.clean" || true
    crontab "$TMP_CRON.clean" || true
    rm -f "$TMP_CRON" "$TMP_CRON.clean"

    rm -f "$CONNECT_SCRIPT" "$DISCONNECT_SCRIPT" "$HEARTBEAT_SCRIPT" "$NODE_CONF"
    rm -rf "$NODE_STATE_DIR"

    read -rp "Remove logs too? [y/N]: " REMOVE_LOGS
    if [[ "$REMOVE_LOGS" =~ ^[Yy]$ ]]; then
        rm -rf "$NODE_LOG_DIR"
    fi

    print_ok "Node files removed."
    print_warn "ocserv.conf was not reverted automatically. Restore backup if needed."
}

uninstall_central() {
    print_warn "This will remove Central API service and app directory."
    read -rp "Continue? [y/N]: " C

    if [[ ! "$C" =~ ^[Yy]$ ]]; then
        return
    fi

    systemctl disable --now ocserv-session-api 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload

    read -rp "Remove $APP_DIR too? [y/N]: " REMOVE_APP
    if [[ "$REMOVE_APP" =~ ^[Yy]$ ]]; then
        rm -rf "$APP_DIR"
    fi

    print_ok "Central API removed."
    print_warn "Redis was not removed."
}

show_main_menu() {
    clear
    echo "=============================================="
    echo "        OCServ Central Session Manager"
    echo "=============================================="
    echo
    echo "1) Install / Setup Central Server"
    echo "2) Install / Setup ocserv Node"
    echo
    echo "3) Central: Show status"
    echo "4) Central: Restart API"
    echo "5) Central: Edit group limits"
    echo "6) Central: Show group limits"
    echo
    echo "7) Node: Show status/logs"
    echo "8) Node: Test Central API"
    echo "9) Node: Query Central API"
    echo
    echo "10) Uninstall Node files"
    echo "11) Uninstall Central API"
    echo
    echo "0) Exit"
    echo
}

main() {
    require_root

    while true; do
        show_main_menu
        read -rp "Choose an option: " CHOICE

        case "$CHOICE" in
            1)
                install_central_api
                pause
                ;;
            2)
                install_node
                pause
                ;;
            3)
                show_central_status
                pause
                ;;
            4)
                restart_central
                pause
                ;;
            5)
                edit_group_limits
                pause
                ;;
            6)
                show_group_limits
                pause
                ;;
            7)
                show_node_status
                pause
                ;;
            8)
                test_node_api
                pause
                ;;
            9)
                query_central_from_node
                pause
                ;;
            10)
                uninstall_node
                pause
                ;;
            11)
                uninstall_central
                pause
                ;;
            0)
                exit 0
                ;;
            *)
                print_err "Invalid option."
                pause
                ;;
        esac
    done
}

main