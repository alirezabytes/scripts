#!/usr/bin/env bash
# ocserv-central-manager.sh
# Central concurrent-session and quota controller for multiple ocserv nodes.
# Target OS: Ubuntu 24.x
# Author: generated for Alireza's ocserv + ocpasswd + rsync architecture.

set -Eeuo pipefail

APP_DIR="/opt/ocserv-central"
MASTER_ETC="/etc/ocserv-central"
DB_DIR="/var/lib/ocserv-central"
NODE_ETC="/etc/ocserv-central-node"
MANAGER_BIN="/usr/local/sbin/ocserv-central-manager"

MASTER_SERVICE="/etc/systemd/system/ocserv-central.service"
NODE_AGENT_SERVICE="/etc/systemd/system/ocserv-central-agent.service"

HOOK_SCRIPT="/usr/local/sbin/ocserv-central-hook.sh"
CONNECT_WRAPPER="/usr/local/sbin/ocserv-central-connect.sh"
DISCONNECT_WRAPPER="/usr/local/sbin/ocserv-central-disconnect.sh"
AGENT_SCRIPT="/usr/local/sbin/ocserv-central-agent.py"

C_RESET="\033[0m"
C_RED="\033[31m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_BLUE="\033[34m"
C_CYAN="\033[36m"

print_ok() { echo -e "${C_GREEN}[OK]${C_RESET} $*"; }
print_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
print_err() { echo -e "${C_RED}[ERR]${C_RESET} $*" >&2; }
print_info() { echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        print_err "Run this script as root."
        exit 1
    fi
}

pause() {
    echo
    read -rp "Press Enter to continue..."
}

ask_yes_no() {
    local prompt="$1"
    local default="${2:-y}"
    local ans
    while true; do
        if [[ "$default" == "y" ]]; then
            read -rp "$prompt [Y/n]: " ans
            ans="${ans:-y}"
        else
            read -rp "$prompt [y/N]: " ans
            ans="${ans:-n}"
        fi
        case "$ans" in
            y|Y|yes|YES) return 0 ;;
            n|N|no|NO) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

ask_value() {
    local prompt="$1"
    local default="${2:-}"
    local ans
    if [[ -n "$default" ]]; then
        read -rp "$prompt [$default]: " ans
        echo "${ans:-$default}"
    else
        read -rp "$prompt: " ans
        echo "$ans"
    fi
}

ask_number() {
    local prompt="$1"
    local default="${2:-0}"
    local ans
    while true; do
        ans="$(ask_value "$prompt" "$default")"
        if [[ "$ans" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            echo "$ans"
            return 0
        fi
        echo "Enter a number."
    done
}

install_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt update
    apt install -y curl jq sqlite3 python3 python3-venv python3-pip gawk openssl ca-certificates
}

gen_token() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        tr -dc 'a-f0-9' </dev/urandom | head -c 64
        echo
    fi
}

install_self_manager() {
    if [[ -f "$0" && "$0" != "$MANAGER_BIN" ]]; then
        cp -f "$0" "$MANAGER_BIN"
        chmod +x "$MANAGER_BIN"
        print_ok "Manager installed as: $MANAGER_BIN"
    fi
}

detect_ocserv_service() {
    if systemctl list-unit-files | grep -q '^ocserv\.service'; then
        echo "ocserv"
    elif systemctl list-unit-files | grep -q '^ocserv-server\.service'; then
        echo "ocserv-server"
    else
        if systemctl status ocserv >/dev/null 2>&1; then
            echo "ocserv"
        elif systemctl status ocserv-server >/dev/null 2>&1; then
            echo "ocserv-server"
        else
            echo ""
        fi
    fi
}

detect_ocserv_conf() {
    local svc
    svc="$(detect_ocserv_service)"
    local conf=""

    if [[ -n "$svc" ]]; then
        conf="$(systemctl cat "$svc" 2>/dev/null | grep -Eo -- '-c[[:space:]]+[^[:space:]]+' | awk '{print $2}' | tail -n1 || true)"
        if [[ -n "$conf" && -f "$conf" ]]; then
            echo "$conf"
            return 0
        fi
    fi

    if [[ -f /etc/ocserv/ocserv.conf ]]; then
        echo "/etc/ocserv/ocserv.conf"
    elif [[ -f /etc/ocserv/ocserv-server.conf ]]; then
        echo "/etc/ocserv/ocserv-server.conf"
    else
        echo ""
    fi
}

restart_ocserv_if_available() {
    local svc
    svc="$(detect_ocserv_service)"
    if [[ -n "$svc" ]]; then
        systemctl restart "$svc" || print_warn "Could not restart $svc. Check manually."
    else
        print_warn "Could not detect ocserv service name. Restart ocserv manually."
    fi
}

write_master_app() {
    mkdir -p "$APP_DIR" "$MASTER_ETC" "$DB_DIR"

    cat > "$APP_DIR/app.py" <<'PYAPP'
#!/usr/bin/env python3
import json
import os
import re
import sqlite3
import time
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

DB_PATH = os.getenv("DB_PATH", "/var/lib/ocserv-central/central.db")
LIMITS_PATH = os.getenv("LIMITS_PATH", "/etc/ocserv-central/limits.json")
OCPASSWD_PATH = os.getenv("OCPASSWD_PATH", "/etc/ocserv/ocpasswd")
API_TOKEN = os.getenv("API_TOKEN", "CHANGE_ME_NOW")
SESSION_TTL = int(os.getenv("SESSION_TTL", "120"))
DISABLE_MISSING_USERS = os.getenv("DISABLE_MISSING_USERS", "0") == "1"
EXHAUSTED_LOG_DEFAULT = os.getenv("EXHAUSTED_LOG_PATH", "/var/lib/ocserv-central/quota_exhausted_users.jsonl")
GIB = 1024 * 1024 * 1024

app = FastAPI(title="ocserv-central", version="1.1")

def now() -> int:
    return int(time.time())

def auth(x_api_token: str | None):
    if x_api_token != API_TOKEN:
        raise HTTPException(status_code=401, detail="unauthorized")

def db():
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    return con

def column_exists(con, table, column):
    rows = con.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with db() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            used_bytes INTEGER NOT NULL DEFAULT 0,
            disabled INTEGER NOT NULL DEFAULT 0
        )
        """)
        for col, ddl in [
            ("groupname", "ALTER TABLE users ADD COLUMN groupname TEXT"),
            ("updated_at", "ALTER TABLE users ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0"),
            ("quota_extra_bytes", "ALTER TABLE users ADD COLUMN quota_extra_bytes INTEGER NOT NULL DEFAULT 0"),
            ("expires_at", "ALTER TABLE users ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0"),
        ]:
            if not column_exists(con, "users", col):
                con.execute(ddl)

        con.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            node_id TEXT NOT NULL,
            ocserv_id TEXT NOT NULL,
            username TEXT NOT NULL,
            groupname TEXT,
            ip_real TEXT,
            ip_remote TEXT,
            started_at INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            last_total_bytes INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (node_id, ocserv_id)
        )
        """)

        con.execute("""
        CREATE TABLE IF NOT EXISTS usage_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            node_id TEXT NOT NULL,
            ocserv_id TEXT NOT NULL,
            bytes INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        )
        """)

        con.execute("""
        CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY,
            last_seen INTEGER NOT NULL,
            last_ip TEXT,
            sessions_count INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        )
        """)

def default_limits():
    return {
        "features": {
            "session_limit": True,
            "quota": True,
            "account_expiry": False,
            "exhausted_log_enabled": True
        },
        "default_quota_gb": 0,
        "exhausted_log_path": EXHAUSTED_LOG_DEFAULT,
        "groups": {},
        "users": {}
    }

def load_limits():
    try:
        with open(LIMITS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = default_limits()

    d = default_limits()
    data.setdefault("features", {})
    for k, v in d["features"].items():
        data["features"].setdefault(k, v)
    data.setdefault("default_quota_gb", 0)
    data.setdefault("exhausted_log_path", EXHAUSTED_LOG_DEFAULT)
    data.setdefault("groups", {})
    data.setdefault("users", {})
    return data

def save_limits(data):
    Path(LIMITS_PATH).parent.mkdir(parents=True, exist_ok=True)
    tmp = LIMITS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, LIMITS_PATH)

def pick_primary_group(group_field: str | None) -> str:
    if not group_field:
        return "group1"
    groups = [g.strip() for g in group_field.split(",") if g.strip()]
    if not groups:
        return "group1"
    for g in groups:
        if re.search(r"\d+", g):
            return g
    return groups[0]

def parse_ocpasswd():
    users = []
    if not os.path.exists(OCPASSWD_PATH):
        return users

    with open(OCPASSWD_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":", 2)
            if len(parts) < 2:
                continue
            username = parts[0].strip()
            groupname = pick_primary_group(parts[1].strip())
            if username:
                users.append({"username": username, "groupname": groupname})
    return users

def sync_ocpasswd_to_db():
    parsed_users = parse_ocpasswd()
    t = now()
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        for u in parsed_users:
            con.execute(
                """
                INSERT INTO users(username, groupname, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at)
                VALUES (?, ?, 0, 0, ?, 0, 0)
                ON CONFLICT(username) DO UPDATE SET
                    groupname=excluded.groupname,
                    updated_at=excluded.updated_at
                """,
                (u["username"], u["groupname"], t)
            )
        if DISABLE_MISSING_USERS:
            usernames = [u["username"] for u in parsed_users]
            if usernames:
                placeholders = ",".join("?" for _ in usernames)
                con.execute(
                    f"UPDATE users SET disabled=1, updated_at=? WHERE username NOT IN ({placeholders})",
                    [t] + usernames
                )
    return {"ok": True, "ocpasswd_path": OCPASSWD_PATH, "users_found": len(parsed_users), "disable_missing_users": DISABLE_MISSING_USERS}

def group_number(groupname: str | None) -> int:
    if not groupname:
        return 1
    m = re.search(r"(\d+)", groupname)
    return int(m.group(1)) if m else 1

def get_user_from_db(username: str):
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return row

def get_user_group_from_db(username: str) -> str | None:
    row = get_user_from_db(username)
    return row["groupname"] if row else None

def effective_limits(username: str, groupname: str | None):
    if not groupname:
        groupname = get_user_group_from_db(username)

    limits = load_limits()
    features = limits.get("features", {})
    session_feature = bool(features.get("session_limit", True))
    quota_feature = bool(features.get("quota", True))

    max_sessions = group_number(groupname) if session_feature else 999999
    quota_gb = float(limits.get("default_quota_gb", 0) or 0)

    group_cfg = limits.get("groups", {}).get(groupname or "", {})
    if session_feature and "max_sessions" in group_cfg:
        max_sessions = int(group_cfg["max_sessions"])
    if quota_feature and "quota_gb" in group_cfg:
        quota_gb = float(group_cfg["quota_gb"])

    user_cfg = limits.get("users", {}).get(username, {})
    if session_feature and "max_sessions" in user_cfg:
        max_sessions = int(user_cfg["max_sessions"])
    if quota_feature and "quota_gb" in user_cfg:
        quota_gb = float(user_cfg["quota_gb"])

    if not quota_feature:
        quota_bytes = 0
    else:
        quota_bytes = int(quota_gb * GIB) if quota_gb and quota_gb > 0 else 0
        # Extra traffic is only meaningful when the account/group already has a finite quota.
        if quota_bytes > 0:
            row = get_user_from_db(username)
            if row:
                quota_bytes += int(row["quota_extra_bytes"] or 0)

    return max_sessions, quota_bytes

def account_is_expired(username: str) -> bool:
    limits = load_limits()
    if not bool(limits.get("features", {}).get("account_expiry", False)):
        return False
    row = get_user_from_db(username)
    if not row:
        return False
    exp = int(row["expires_at"] or 0)
    return exp > 0 and exp <= now()

def exhausted_log_path():
    return load_limits().get("exhausted_log_path") or EXHAUSTED_LOG_DEFAULT

def log_quota_exhausted(username: str, groupname: str | None, used_bytes: int, quota_bytes: int, reason: str):
    limits = load_limits()
    if not bool(limits.get("features", {}).get("exhausted_log_enabled", True)):
        return
    path = exhausted_log_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)

    # Avoid endless duplicate spam. If username already exists in the file, do not add again.
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                        if obj.get("username") == username:
                            return
                    except Exception:
                        continue
        except Exception:
            pass

    item = {
        "time": now(),
        "username": username,
        "groupname": groupname,
        "used_bytes": int(used_bytes or 0),
        "quota_bytes": int(quota_bytes or 0),
        "reason": reason,
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")

def remove_from_exhausted_log(username: str):
    path = exhausted_log_path()
    if not os.path.exists(path):
        return
    kept = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if obj.get("username") == username:
                        continue
                except Exception:
                    pass
                kept.append(line)
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(kept)
    except Exception:
        return

def update_node(node_id: str, request: Request | None = None, sessions_count: int = 0):
    ip = None
    if request is not None and request.client:
        ip = request.client.host
    t = now()
    with db() as con:
        con.execute(
            """
            INSERT INTO nodes(node_id, last_seen, last_ip, sessions_count, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET
                last_seen=excluded.last_seen,
                last_ip=excluded.last_ip,
                sessions_count=excluded.sessions_count,
                updated_at=excluded.updated_at
            """,
            (node_id, t, ip, sessions_count, t)
        )

def cleanup_expired(con, t):
    cutoff = t - SESSION_TTL
    con.execute("UPDATE sessions SET active=0 WHERE last_seen < ?", (cutoff,))

class ConnectReq(BaseModel):
    node_id: str
    ocserv_id: str
    username: str
    groupname: str | None = None
    ip_real: str | None = None
    ip_remote: str | None = None

class DisconnectReq(BaseModel):
    node_id: str
    ocserv_id: str
    username: str
    bytes_in: int = 0
    bytes_out: int = 0

class HeartbeatSession(BaseModel):
    ocserv_id: str
    username: str
    groupname: str | None = None
    total_bytes: int = 0

class HeartbeatReq(BaseModel):
    node_id: str
    sessions: list[HeartbeatSession]

class UsageResetReq(BaseModel):
    username: str

class UserToggleReq(BaseModel):
    username: str
    disabled: bool

class AddTrafficReq(BaseModel):
    username: str
    gb: float

class SetExpiryReq(BaseModel):
    username: str
    expires_at: int

class AddTimeReq(BaseModel):
    username: str
    days: int = 0
    hours: int = 0
    minutes: int = 0

@app.on_event("startup")
def startup():
    init_db()
    sync_ocpasswd_to_db()

@app.get("/health")
def health():
    return {"ok": True, "time": now()}

@app.get("/config")
def get_config(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    return load_limits()

@app.post("/sync-ocpasswd")
def sync_ocpasswd(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    return sync_ocpasswd_to_db()

@app.post("/connect")
def connect(req: ConnectReq, request: Request, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    t = now()
    sync_ocpasswd_to_db()
    update_node(req.node_id, request, 0)

    if not req.groupname:
        req.groupname = get_user_group_from_db(req.username)

    max_sessions, quota_bytes = effective_limits(req.username, req.groupname)

    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        con.execute(
            """
            INSERT OR IGNORE INTO users(username, groupname, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at)
            VALUES (?, ?, 0, 0, ?, 0, 0)
            """,
            (req.username, req.groupname, t)
        )

        user = con.execute("SELECT * FROM users WHERE username=?", (req.username,)).fetchone()

        if user["disabled"]:
            return {"allow": False, "reason": "user disabled"}

        if account_is_expired(req.username):
            return {"allow": False, "reason": "account expired"}

        if quota_bytes > 0 and user["used_bytes"] >= quota_bytes:
            log_quota_exhausted(req.username, req.groupname, user["used_bytes"], quota_bytes, "connect quota exceeded")
            return {"allow": False, "reason": "quota exceeded"}

        cleanup_expired(con, t)

        active_count = con.execute(
            "SELECT COUNT(*) AS c FROM sessions WHERE username=? AND active=1",
            (req.username,)
        ).fetchone()["c"]

        if active_count >= max_sessions:
            return {"allow": False, "reason": f"session limit exceeded: {active_count}/{max_sessions}", "active_count": active_count, "max_sessions": max_sessions}

        con.execute(
            """
            INSERT OR REPLACE INTO sessions
            (node_id, ocserv_id, username, groupname, ip_real, ip_remote,
             started_at, last_seen, last_total_bytes, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 1)
            """,
            (req.node_id, req.ocserv_id, req.username, req.groupname, req.ip_real, req.ip_remote, t, t)
        )

        return {
            "allow": True,
            "reason": "ok",
            "username": req.username,
            "groupname": req.groupname,
            "max_sessions": max_sessions,
            "quota_bytes": quota_bytes,
            "used_bytes": user["used_bytes"],
            "quota_extra_bytes": user["quota_extra_bytes"],
            "expires_at": user["expires_at"],
        }

@app.post("/disconnect")
def disconnect(req: DisconnectReq, request: Request, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    t = now()
    total = max(0, int(req.bytes_in) + int(req.bytes_out))
    update_node(req.node_id, request, 0)

    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        con.execute("INSERT OR IGNORE INTO users(username, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at) VALUES (?, 0, 0, ?, 0, 0)", (req.username, t))

        old = con.execute("SELECT last_total_bytes FROM sessions WHERE node_id=? AND ocserv_id=?", (req.node_id, req.ocserv_id)).fetchone()
        old_total = old["last_total_bytes"] if old else 0
        delta = max(0, total - old_total)

        if delta > 0:
            con.execute("UPDATE users SET used_bytes = used_bytes + ?, updated_at=? WHERE username=?", (delta, t, req.username))
            con.execute("INSERT INTO usage_log(username, node_id, ocserv_id, bytes, created_at) VALUES (?, ?, ?, ?, ?)", (req.username, req.node_id, req.ocserv_id, delta, t))

        con.execute("UPDATE sessions SET active=0, last_seen=?, last_total_bytes=? WHERE node_id=? AND ocserv_id=?", (t, total, req.node_id, req.ocserv_id))

    row = get_user_from_db(req.username)
    if row:
        _, quota_bytes = effective_limits(req.username, row["groupname"])
        if quota_bytes > 0 and row["used_bytes"] >= quota_bytes:
            log_quota_exhausted(req.username, row["groupname"], row["used_bytes"], quota_bytes, "disconnect quota exceeded")

    return {"ok": True, "added_bytes": delta}

@app.post("/heartbeat")
def heartbeat(req: HeartbeatReq, request: Request, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    t = now()
    disconnect_ids = []
    sync_ocpasswd_to_db()
    update_node(req.node_id, request, len(req.sessions))

    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        seen_ids = set()

        for s in req.sessions:
            seen_ids.add(s.ocserv_id)
            if not s.groupname:
                s.groupname = get_user_group_from_db(s.username)

            con.execute(
                """
                INSERT OR IGNORE INTO users(username, groupname, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at)
                VALUES (?, ?, 0, 0, ?, 0, 0)
                """,
                (s.username, s.groupname, t)
            )

            old = con.execute("SELECT last_total_bytes FROM sessions WHERE node_id=? AND ocserv_id=?", (req.node_id, s.ocserv_id)).fetchone()
            old_total = old["last_total_bytes"] if old else 0
            new_total = max(0, int(s.total_bytes))
            delta = max(0, new_total - old_total)

            if old:
                con.execute(
                    """
                    UPDATE sessions
                    SET last_seen=?, last_total_bytes=?, active=1, username=?, groupname=?
                    WHERE node_id=? AND ocserv_id=?
                    """,
                    (t, new_total, s.username, s.groupname, req.node_id, s.ocserv_id)
                )
            else:
                con.execute(
                    """
                    INSERT INTO sessions
                    (node_id, ocserv_id, username, groupname, started_at, last_seen, last_total_bytes, active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (req.node_id, s.ocserv_id, s.username, s.groupname, t, t, new_total)
                )

            if delta > 0:
                con.execute("UPDATE users SET used_bytes = used_bytes + ?, updated_at=? WHERE username=?", (delta, t, s.username))
                con.execute("INSERT INTO usage_log(username, node_id, ocserv_id, bytes, created_at) VALUES (?, ?, ?, ?, ?)", (s.username, req.node_id, s.ocserv_id, delta, t))

            user = con.execute("SELECT * FROM users WHERE username=?", (s.username,)).fetchone()
            _, quota_bytes = effective_limits(s.username, s.groupname)

            if user["disabled"]:
                disconnect_ids.append(s.ocserv_id)
            elif account_is_expired(s.username):
                disconnect_ids.append(s.ocserv_id)
            elif quota_bytes > 0 and user["used_bytes"] >= quota_bytes:
                log_quota_exhausted(s.username, s.groupname, user["used_bytes"], quota_bytes, "heartbeat quota exceeded")
                disconnect_ids.append(s.ocserv_id)

        rows = con.execute("SELECT ocserv_id FROM sessions WHERE node_id=? AND active=1", (req.node_id,)).fetchall()
        for row in rows:
            if row["ocserv_id"] not in seen_ids:
                con.execute("UPDATE sessions SET active=0, last_seen=? WHERE node_id=? AND ocserv_id=?", (t, req.node_id, row["ocserv_id"]))

        cleanup_expired(con, t)

    return {"ok": True, "disconnect_ids": disconnect_ids}

@app.get("/user/{username}")
def user_status(username: str, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    sync_ocpasswd_to_db()

    with db() as con:
        user = con.execute("SELECT username, groupname, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at FROM users WHERE username=?", (username,)).fetchone()
        sessions = con.execute("SELECT node_id, ocserv_id, groupname, ip_real, ip_remote, started_at, last_seen, active FROM sessions WHERE username=? AND active=1", (username,)).fetchall()

    max_sessions, quota_bytes = effective_limits(username, user["groupname"] if user else None)
    used = int(user["used_bytes"] or 0) if user else 0
    return {
        "user": dict(user) if user else None,
        "limits": {"max_sessions": max_sessions, "quota_bytes": quota_bytes, "remaining_bytes": (quota_bytes - used if quota_bytes > 0 else 0)},
        "expired": account_is_expired(username),
        "active_sessions": [dict(x) for x in sessions]
    }

@app.get("/users")
def list_users(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    sync_ocpasswd_to_db()
    with db() as con:
        rows = con.execute("SELECT username, groupname, used_bytes, disabled, quota_extra_bytes, expires_at, updated_at FROM users ORDER BY username").fetchall()
    return {"count": len(rows), "users": [dict(x) for x in rows]}

@app.get("/sessions")
def list_sessions(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    t = now()
    with db() as con:
        cleanup_expired(con, t)
        rows = con.execute("SELECT node_id, ocserv_id, username, groupname, ip_real, ip_remote, started_at, last_seen, last_total_bytes, active FROM sessions WHERE active=1 ORDER BY username, node_id").fetchall()
    return {"count": len(rows), "sessions": [dict(x) for x in rows]}

@app.get("/nodes")
def list_nodes(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    with db() as con:
        rows = con.execute("SELECT node_id, last_seen, last_ip, sessions_count, updated_at FROM nodes ORDER BY node_id").fetchall()
    t = now()
    items = []
    for r in rows:
        d = dict(r)
        d["online"] = (t - int(d["last_seen"])) <= SESSION_TTL
        d["seconds_since_seen"] = t - int(d["last_seen"])
        items.append(d)
    return {"count": len(items), "nodes": items}

@app.post("/reset-usage")
def reset_usage(req: UsageResetReq, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    with db() as con:
        con.execute("UPDATE users SET used_bytes=0, updated_at=? WHERE username=?", (now(), req.username))
    remove_from_exhausted_log(req.username)
    return {"ok": True, "username": req.username, "used_bytes": 0}

@app.post("/toggle-user")
def toggle_user(req: UserToggleReq, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    with db() as con:
        con.execute("""
            INSERT INTO users(username, disabled, updated_at, quota_extra_bytes, expires_at)
            VALUES (?, ?, ?, 0, 0)
            ON CONFLICT(username) DO UPDATE SET disabled=excluded.disabled, updated_at=excluded.updated_at
        """, (req.username, 1 if req.disabled else 0, now()))
    return {"ok": True, "username": req.username, "disabled": req.disabled}

@app.post("/add-traffic")
def add_traffic(req: AddTrafficReq, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    add_bytes = int(float(req.gb) * GIB)
    with db() as con:
        con.execute("""
            INSERT INTO users(username, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at)
            VALUES (?, 0, 0, ?, ?, 0)
            ON CONFLICT(username) DO UPDATE SET
                quota_extra_bytes = quota_extra_bytes + excluded.quota_extra_bytes,
                updated_at = excluded.updated_at
        """, (req.username, now(), add_bytes))
        row = con.execute("SELECT username, quota_extra_bytes FROM users WHERE username=?", (req.username,)).fetchone()
    remove_from_exhausted_log(req.username)
    return {"ok": True, "username": req.username, "added_gb": req.gb, "quota_extra_bytes": row["quota_extra_bytes"]}

@app.post("/set-expiry")
def set_expiry(req: SetExpiryReq, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    with db() as con:
        con.execute("""
            INSERT INTO users(username, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at)
            VALUES (?, 0, 0, ?, 0, ?)
            ON CONFLICT(username) DO UPDATE SET expires_at=excluded.expires_at, updated_at=excluded.updated_at
        """, (req.username, now(), int(req.expires_at)))
    return {"ok": True, "username": req.username, "expires_at": int(req.expires_at)}

@app.post("/add-time")
def add_time(req: AddTimeReq, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    seconds = int(req.days) * 86400 + int(req.hours) * 3600 + int(req.minutes) * 60
    if seconds <= 0:
        return {"ok": False, "reason": "no time added"}
    t = now()
    with db() as con:
        row = con.execute("SELECT expires_at FROM users WHERE username=?", (req.username,)).fetchone()
        base = t
        if row and int(row["expires_at"] or 0) > t:
            base = int(row["expires_at"])
        new_exp = base + seconds
        con.execute("""
            INSERT INTO users(username, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at)
            VALUES (?, 0, 0, ?, 0, ?)
            ON CONFLICT(username) DO UPDATE SET expires_at=excluded.expires_at, updated_at=excluded.updated_at
        """, (req.username, t, new_exp))
    return {"ok": True, "username": req.username, "added_seconds": seconds, "expires_at": new_exp}

@app.post("/clear-expiry")
def clear_expiry(req: UsageResetReq, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    with db() as con:
        con.execute("UPDATE users SET expires_at=0, updated_at=? WHERE username=?", (now(), req.username))
    return {"ok": True, "username": req.username, "expires_at": 0}

@app.get("/quota-exhausted")
def quota_exhausted(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    path = exhausted_log_path()
    items = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except Exception:
                    items.append({"raw": line})
    return {"path": path, "count": len(items), "items": items}

@app.post("/quota-exhausted/reset")
def quota_exhausted_reset(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    path = exhausted_log_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    open(path, "w", encoding="utf-8").close()
    return {"ok": True, "path": path, "action": "reset"}

@app.post("/quota-exhausted/delete")
def quota_exhausted_delete(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    path = exhausted_log_path()
    if os.path.exists(path):
        os.remove(path)
    return {"ok": True, "path": path, "action": "delete"}
PYAPP

    chmod +x "$APP_DIR/app.py"
}

ensure_limits_file() {
    mkdir -p "$MASTER_ETC"
    if [[ ! -f "$MASTER_ETC/limits.json" ]]; then
        cat > "$MASTER_ETC/limits.json" <<'JSON'
{
  "features": {
    "session_limit": true,
    "quota": true,
    "account_expiry": false,
    "exhausted_log_enabled": true
  },
  "default_quota_gb": 0,
  "exhausted_log_path": "/var/lib/ocserv-central/quota_exhausted_users.jsonl",
  "groups": {},
  "users": {}
}
JSON
    else
        tmp="$(mktemp)"
        jq '.features = (.features // {}) |
            .features.session_limit = (.features.session_limit // true) |
            .features.quota = (.features.quota // true) |
            .features.account_expiry = (.features.account_expiry // false) |
            .features.exhausted_log_enabled = (.features.exhausted_log_enabled // true) |
            .default_quota_gb = (.default_quota_gb // 0) |
            .exhausted_log_path = (.exhausted_log_path // "/var/lib/ocserv-central/quota_exhausted_users.jsonl") |
            .groups = (.groups // {}) |
            .users = (.users // {})' "$MASTER_ETC/limits.json" > "$tmp" && mv "$tmp" "$MASTER_ETC/limits.json"
    fi
}

configure_features() {
    ensure_limits_file

    local enable_sessions enable_quota enable_expiry enable_exhausted
    if ask_yes_no "Enable central concurrent-session limit?" "y"; then
        enable_sessions="true"
    else
        enable_sessions="false"
    fi

    if ask_yes_no "Enable quota / traffic limit?" "y"; then
        enable_quota="true"
    else
        enable_quota="false"
    fi

    if ask_yes_no "Enable account expiry by days/date/time?" "n"; then
        enable_expiry="true"
    else
        enable_expiry="false"
    fi

    if ask_yes_no "Enable exhausted-quota users file?" "y"; then
        enable_exhausted="true"
    else
        enable_exhausted="false"
    fi

    local path
    path="$(jq -r '.exhausted_log_path // "/var/lib/ocserv-central/quota_exhausted_users.jsonl"' "$MASTER_ETC/limits.json")"
    path="$(ask_value "Exhausted users file path" "$path")"

    tmp="$(mktemp)"
    jq --argjson s "$enable_sessions" --argjson q "$enable_quota" --argjson e "$enable_expiry" --argjson ex "$enable_exhausted" --arg path "$path" \
       '.features.session_limit=$s | .features.quota=$q | .features.account_expiry=$e | .features.exhausted_log_enabled=$ex | .exhausted_log_path=$path' \
       "$MASTER_ETC/limits.json" > "$tmp"
    mv "$tmp" "$MASTER_ETC/limits.json"

    print_ok "Features updated."
}

extract_groups_from_ocpasswd() {
    local ocpasswd="$1"
    if [[ ! -f "$ocpasswd" ]]; then
        return 0
    fi

    awk -F: '
        NF >= 2 && $1 !~ /^#/ {
            n=split($2, a, ",")
            for (i=1; i<=n; i++) {
                g=a[i]
                gsub(/^[ \t]+|[ \t]+$/, "", g)
                if (g != "") print g
            }
        }
    ' "$ocpasswd" | sort -u
}

group_default_sessions() {
    local group="$1"
    local num
    num="$(echo "$group" | grep -Eo '[0-9]+' | head -n1 || true)"
    if [[ -n "$num" ]]; then
        echo "$num"
    else
        echo "1"
    fi
}

configure_groups_from_ocpasswd() {
    ensure_limits_file

    local ocpasswd="${1:-}"
    if [[ -z "$ocpasswd" ]]; then
        ocpasswd="$(systemctl show ocserv-central -p Environment --value 2>/dev/null | tr ' ' '\n' | sed -n 's/^OCPASSWD_PATH=//p' | tail -n1 || true)"
        ocpasswd="${ocpasswd:-/etc/ocserv/ocpasswd}"
    fi

    if [[ ! -f "$ocpasswd" ]]; then
        print_warn "ocpasswd not found: $ocpasswd"
        return 0
    fi

    mapfile -t groups < <(extract_groups_from_ocpasswd "$ocpasswd")

    if [[ "${#groups[@]}" -eq 0 ]]; then
        print_warn "No groups found in $ocpasswd"
        return 0
    fi

    print_info "Groups found:"
    printf ' - %s\n' "${groups[@]}"

    for g in "${groups[@]}"; do
        echo
        print_info "Configure group: $g"
        local def_sessions max_sessions quota_gb tmp current_quota
        def_sessions="$(group_default_sessions "$g")"
        max_sessions="$(ask_number "Max concurrent sessions for $g" "$def_sessions")"

        current_quota="$(jq -r --arg g "$g" '.groups[$g].quota_gb // 0' "$MASTER_ETC/limits.json")"
        quota_gb="$(ask_number "Quota for $g in GB, 0 = unlimited" "$current_quota")"

        tmp="$(mktemp)"
        jq --arg g "$g" --argjson ms "$max_sessions" --argjson q "$quota_gb" \
           '.groups[$g] = {"max_sessions": $ms, "quota_gb": $q}' \
           "$MASTER_ETC/limits.json" > "$tmp"
        mv "$tmp" "$MASTER_ETC/limits.json"
    done

    print_ok "Group limits updated."
}

write_master_service() {
    local token="$1"
    local ocpasswd_path="$2"
    local ttl="$3"
    local disable_missing="$4"

    cat > "$MASTER_SERVICE" <<EOF
[Unit]
Description=Ocserv Central Limit API
After=network.target

[Service]
Type=simple
Environment=API_TOKEN=$token
Environment=DB_PATH=$DB_DIR/central.db
Environment=LIMITS_PATH=$MASTER_ETC/limits.json
Environment=OCPASSWD_PATH=$ocpasswd_path
Environment=SESSION_TTL=$ttl
Environment=DISABLE_MISSING_USERS=$disable_missing
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/venv/bin/uvicorn app:app --host 0.0.0.0 --port 8088 --workers 1
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

install_master() {
    need_root
    install_self_manager
    install_packages

    mkdir -p "$APP_DIR" "$MASTER_ETC" "$DB_DIR"

    local existing_token=""
    if systemctl cat ocserv-central >/dev/null 2>&1; then
        existing_token="$(systemctl show ocserv-central -p Environment --value 2>/dev/null | tr ' ' '\n' | sed -n 's/^API_TOKEN=//p' | tail -n1 || true)"
    fi

    local token
    token="$(ask_value "API token for nodes" "${existing_token:-$(gen_token)}")"

    local ocpasswd_default="/etc/ocserv/ocpasswd"
    local detected_conf
    detected_conf="$(detect_ocserv_conf || true)"
    if [[ -n "$detected_conf" ]]; then
        ocpasswd_from_conf="$(grep -E '^[[:space:]]*auth[[:space:]]*=' "$detected_conf" | grep -Eo 'passwd=[^],]+' | sed 's/passwd=//' | tail -n1 || true)"
        if [[ -n "${ocpasswd_from_conf:-}" ]]; then
            ocpasswd_default="$ocpasswd_from_conf"
        fi
    fi

    local ocpasswd_path
    ocpasswd_path="$(ask_value "Master ocpasswd path" "$ocpasswd_default")"

    local ttl
    ttl="$(ask_number "Session TTL in seconds, used to expire dead sessions" "120")"

    local disable_missing="0"
    if ask_yes_no "Disable users in central DB when they are removed from ocpasswd? Safer answer: no" "n"; then
        disable_missing="1"
    fi

    ensure_limits_file
    configure_features
    configure_groups_from_ocpasswd "$ocpasswd_path"

    write_master_app

    if [[ ! -d "$APP_DIR/venv" ]]; then
        python3 -m venv "$APP_DIR/venv"
    fi

    "$APP_DIR/venv/bin/pip" install --upgrade pip
    "$APP_DIR/venv/bin/pip" install fastapi uvicorn pydantic

    write_master_service "$token" "$ocpasswd_path" "$ttl" "$disable_missing"

    systemctl daemon-reload
    systemctl enable --now ocserv-central

    sleep 1
    systemctl status ocserv-central --no-pager || true

    echo
    print_ok "Master installed."
    print_info "API URL for nodes: http://MASTER_SERVER_IP:8088"
    print_info "API token: $token"
    print_warn "Keep this token safe. Use it on all nodes."
}

write_node_files() {
    mkdir -p "$NODE_ETC"

    cat > "$HOOK_SCRIPT" <<'HOOK'
#!/usr/bin/env bash
set -u

ENV_FILE="/etc/ocserv-central-node/node.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    . "$ENV_FILE"
fi

API_URL="${API_URL:-}"
API_TOKEN="${API_TOKEN:-}"
NODE_ID="${NODE_ID:-$(hostname -s)}"
API_TIMEOUT="${API_TIMEOUT:-5}"
FAIL_MODE="${FAIL_MODE:-closed}"

log() {
    logger -t ocserv-central-hook "$*"
}

if [[ -z "$API_URL" || -z "$API_TOKEN" ]]; then
    log "missing API_URL or API_TOKEN"
    [[ "$FAIL_MODE" == "open" ]] && exit 0 || exit 1
fi

log "START reason=${REASON:-empty} user=${USERNAME:-empty} group=${GROUPNAME:-empty} id=${ID:-empty}"

if [[ "${REASON:-}" == "connect" ]]; then
    payload="$(jq -n \
        --arg node_id "$NODE_ID" \
        --arg ocserv_id "${ID:-}" \
        --arg username "${USERNAME:-}" \
        --arg groupname "${GROUPNAME:-}" \
        --arg ip_real "${IP_REAL:-}" \
        --arg ip_remote "${IP_REMOTE:-}" \
        '{
          node_id: $node_id,
          ocserv_id: $ocserv_id,
          username: $username,
          groupname: $groupname,
          ip_real: $ip_real,
          ip_remote: $ip_remote
        }'
    )"

    response="$(curl -sS -m "$API_TIMEOUT" \
        -H "Content-Type: application/json" \
        -H "X-API-Token: $API_TOKEN" \
        -d "$payload" \
        "$API_URL/connect" 2>&1)"
    rc=$?

    if [[ "$rc" -ne 0 ]]; then
        log "CONNECT_API_ERROR user=${USERNAME:-empty} rc=$rc response=$response"
        [[ "$FAIL_MODE" == "open" ]] && exit 0 || exit 1
    fi

    log "CONNECT_RESPONSE user=${USERNAME:-empty} response=$response"

    allow="$(echo "$response" | jq -r '.allow // false' 2>/dev/null || echo false)"
    reason="$(echo "$response" | jq -r '.reason // "api error"' 2>/dev/null || echo "api error")"

    if [[ "$allow" == "true" ]]; then
        log "ALLOW user=${USERNAME:-unknown} group=${GROUPNAME:-unknown} id=${ID:-unknown}"
        exit 0
    else
        log "DENY user=${USERNAME:-unknown} group=${GROUPNAME:-unknown} id=${ID:-unknown} reason=$reason"
        exit 1
    fi
fi

if [[ "${REASON:-}" == "disconnect" ]]; then
    payload="$(jq -n \
        --arg node_id "$NODE_ID" \
        --arg ocserv_id "${ID:-}" \
        --arg username "${USERNAME:-}" \
        --argjson bytes_in "${STATS_BYTES_IN:-0}" \
        --argjson bytes_out "${STATS_BYTES_OUT:-0}" \
        '{
          node_id: $node_id,
          ocserv_id: $ocserv_id,
          username: $username,
          bytes_in: $bytes_in,
          bytes_out: $bytes_out
        }'
    )"

    response="$(curl -sS -m "$API_TIMEOUT" \
        -H "Content-Type: application/json" \
        -H "X-API-Token: $API_TOKEN" \
        -d "$payload" \
        "$API_URL/disconnect" 2>&1 || true)"

    log "DISCONNECT_RESPONSE user=${USERNAME:-empty} response=$response"
    exit 0
fi

log "UNKNOWN_REASON reason=${REASON:-empty}"
exit 0
HOOK

    cat > "$CONNECT_WRAPPER" <<'EOF'
#!/usr/bin/env bash
export REASON=connect
exec /usr/local/sbin/ocserv-central-hook.sh
EOF

    cat > "$DISCONNECT_WRAPPER" <<'EOF'
#!/usr/bin/env bash
export REASON=disconnect
exec /usr/local/sbin/ocserv-central-hook.sh
EOF

    chmod +x "$HOOK_SCRIPT" "$CONNECT_WRAPPER" "$DISCONNECT_WRAPPER"

    cat > "$AGENT_SCRIPT" <<'PYAGENT'
#!/usr/bin/env python3
import json
import os
import subprocess
import time
import urllib.request

ENV_FILE = "/etc/ocserv-central-node/node.env"

def load_env(path):
    env = {}
    if not os.path.exists(path):
        return env
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env

ENV = load_env(ENV_FILE)
API_URL = ENV.get("API_URL", "")
API_TOKEN = ENV.get("API_TOKEN", "")
NODE_ID = ENV.get("NODE_ID") or subprocess.getoutput("hostname -s").strip()
INTERVAL = int(ENV.get("INTERVAL", "30"))
API_TIMEOUT = int(ENV.get("API_TIMEOUT", "5"))

def logger(msg):
    subprocess.run(["logger", "-t", "ocserv-central-agent", msg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def post(path, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        API_URL + path,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-API-Token": API_TOKEN,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=API_TIMEOUT) as r:
        return json.loads(r.read().decode())

def run(cmd):
    return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)

def get_json_users():
    raw = run(["occtl", "--json", "show", "users"])
    return json.loads(raw)

def find_user_objects(obj):
    result = []

    if isinstance(obj, dict):
        lower = {str(k).lower(): k for k in obj.keys()}
        username_key = None
        id_key = None

        for lk, real_key in lower.items():
            if lk in ("username", "user", "name"):
                username_key = real_key
            if lk in ("id", "session_id", "session-id", "sid"):
                id_key = real_key

        if username_key and id_key:
            result.append(obj)

        for v in obj.values():
            result.extend(find_user_objects(v))

    elif isinstance(obj, list):
        for x in obj:
            result.extend(find_user_objects(x))

    return result

def pick(obj, names, default=""):
    lower = {str(k).lower(): k for k in obj.keys()}
    for name in names:
        if name in lower:
            return obj[lower[name]]
    return default

def to_int(v):
    try:
        if isinstance(v, int):
            return v
        if isinstance(v, float):
            return int(v)
        s = str(v)
        # Handles values like "12345", "12.3 MB" badly but safely.
        # For human-formatted values, this becomes approximate. Prefer JSON numeric keys when available.
        digits = "".join(ch for ch in s if ch.isdigit())
        return int(digits) if digits else 0
    except Exception:
        return 0

def extract_sessions():
    data = get_json_users()
    objs = find_user_objects(data)
    sessions = []

    for o in objs:
        ocserv_id = str(pick(o, ["id", "session_id", "session-id", "sid"], ""))
        username = str(pick(o, ["username", "user", "name"], ""))
        groupname = str(pick(o, ["groupname", "group", "authgroup", "auth_group"], ""))

        rx = to_int(pick(o, ["rx", "bytes_in", "bytes-in", "in", "input", "received"], 0))
        tx = to_int(pick(o, ["tx", "bytes_out", "bytes-out", "out", "output", "sent"], 0))

        total = to_int(pick(o, ["total_bytes", "total-bytes", "bytes", "traffic"], 0))
        if total <= 0:
            total = rx + tx

        if ocserv_id and username:
            sessions.append({
                "ocserv_id": ocserv_id,
                "username": username,
                "groupname": groupname,
                "total_bytes": total,
            })

    return sessions

def disconnect_id(ocserv_id):
    subprocess.run(
        ["occtl", "disconnect", "id", str(ocserv_id)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

def main():
    if not API_URL or not API_TOKEN:
        logger("missing API_URL or API_TOKEN")
        return

    logger(f"started node_id={NODE_ID} interval={INTERVAL}")

    while True:
        try:
            sessions = extract_sessions()
            response = post("/heartbeat", {
                "node_id": NODE_ID,
                "sessions": sessions,
            })

            for ocserv_id in response.get("disconnect_ids", []):
                logger(f"disconnecting session id={ocserv_id} because quota/user status")
                disconnect_id(ocserv_id)

        except Exception as e:
            logger(f"error: {e}")

        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
PYAGENT

    chmod +x "$AGENT_SCRIPT"

    cat > "$NODE_AGENT_SERVICE" <<EOF
[Unit]
Description=Ocserv Central Live Quota Agent
After=network.target

[Service]
Type=simple
ExecStart=$AGENT_SCRIPT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

configure_ocserv_conf_for_node() {
    local conf="$1"
    mkdir -p "$NODE_ETC/backup"

    if [[ ! -f "$conf" ]]; then
        print_err "ocserv config not found: $conf"
        return 1
    fi

    if [[ ! -f "$NODE_ETC/original_ocserv.conf" ]]; then
        cp -a "$conf" "$NODE_ETC/original_ocserv.conf"
        echo "$conf" > "$NODE_ETC/ocserv_conf_path"
        print_ok "Original ocserv.conf backup saved: $NODE_ETC/original_ocserv.conf"
    fi

    cp -a "$conf" "$NODE_ETC/backup/ocserv.conf.$(date +%Y%m%d-%H%M%S)"

    python3 - "$conf" <<'PYMOD'
import re
import sys
from pathlib import Path

p = Path(sys.argv[1])
text = p.read_text(encoding="utf-8", errors="ignore")

text = re.sub(
    r"\n?# BEGIN OCSERV-CENTRAL\n.*?\n# END OCSERV-CENTRAL\n?",
    "\n",
    text,
    flags=re.S,
)

new_lines = []
for line in text.splitlines():
    if re.match(r"^\s*connect-script\s*=", line):
        new_lines.append("# disabled by ocserv-central-manager: " + line)
    elif re.match(r"^\s*disconnect-script\s*=", line):
        new_lines.append("# disabled by ocserv-central-manager: " + line)
    elif re.match(r"^\s*use-occtl\s*=", line):
        new_lines.append("# disabled by ocserv-central-manager: " + line)
    else:
        new_lines.append(line)

block = """
# BEGIN OCSERV-CENTRAL
use-occtl = true
connect-script = /usr/local/sbin/ocserv-central-connect.sh
disconnect-script = /usr/local/sbin/ocserv-central-disconnect.sh
# END OCSERV-CENTRAL
""".strip()

new_text = "\n".join(new_lines).rstrip() + "\n\n" + block + "\n"
p.write_text(new_text, encoding="utf-8")
PYMOD

    print_ok "ocserv.conf updated: $conf"
}

install_node() {
    need_root
    install_self_manager
    install_packages

    mkdir -p "$NODE_ETC"

    local api_url token node_id interval timeout fail_mode conf default_conf
    api_url="$(ask_value "Central API URL, example http://1.2.3.4:8088" "http://MASTER_SERVER_IP:8088")"
    token="$(ask_value "Central API token" "")"
    node_id="$(ask_value "Node ID" "$(hostname -s)")"
    interval="$(ask_number "Live quota check interval in seconds" "30")"
    timeout="$(ask_number "API timeout in seconds" "5")"

    if ask_yes_no "If central API is unreachable, allow users temporarily? This weakens enforcement." "n"; then
        fail_mode="open"
    else
        fail_mode="closed"
    fi

    default_conf="$(detect_ocserv_conf || true)"
    if [[ -z "$default_conf" ]]; then
        default_conf="/etc/ocserv/ocserv.conf"
    fi
    conf="$(ask_value "ocserv config path" "$default_conf")"

    cat > "$NODE_ETC/node.env" <<EOF
API_URL="$api_url"
API_TOKEN="$token"
NODE_ID="$node_id"
INTERVAL="$interval"
API_TIMEOUT="$timeout"
FAIL_MODE="$fail_mode"
EOF
    chmod 600 "$NODE_ETC/node.env"

    write_node_files
    configure_ocserv_conf_for_node "$conf"

    systemctl daemon-reload

    if ask_yes_no "Enable live quota agent now?" "y"; then
        systemctl enable --now ocserv-central-agent
    else
        systemctl disable --now ocserv-central-agent >/dev/null 2>&1 || true
    fi

    restart_ocserv_if_available

    print_ok "Node installed/configured."
    print_info "Check hook logs with:"
    echo "journalctl -t ocserv-central-hook -n 100 --no-pager"
    print_info "Check agent logs with:"
    echo "journalctl -t ocserv-central-agent -n 100 --no-pager"
}

master_token_from_systemd() {
    systemctl show ocserv-central -p Environment --value 2>/dev/null | tr ' ' '\n' | sed -n 's/^API_TOKEN=//p' | tail -n1 || true
}

master_curl() {
    local method="$1"
    local path="$2"
    local data="${3:-}"
    local token="${4:-$(master_token_from_systemd)}"
    if [[ -z "$token" ]]; then
        token="$(ask_value "API token" "")"
    fi

    if [[ "$method" == "GET" ]]; then
        curl -sS -H "X-API-Token: $token" "http://127.0.0.1:8088$path" | jq .
    else
        curl -sS -X "$method" \
            -H "Content-Type: application/json" \
            -H "X-API-Token: $token" \
            -d "$data" \
            "http://127.0.0.1:8088$path" | jq .
    fi
}

master_status() {
    echo
    print_info "Master service:"
    systemctl status ocserv-central --no-pager || true
    echo
    print_info "Health:"
    curl -sS http://127.0.0.1:8088/health 2>/dev/null | jq . || print_warn "API not responding."
}

node_status() {
    echo
    print_info "Node config:"
    if [[ -f "$NODE_ETC/node.env" ]]; then
        sed 's/API_TOKEN=.*/API_TOKEN="***hidden***"/' "$NODE_ETC/node.env"
    else
        print_warn "Node config not found."
    fi

    echo
    print_info "Agent service:"
    systemctl status ocserv-central-agent --no-pager || true

    echo
    print_info "Recent hook logs:"
    journalctl -t ocserv-central-hook -n 30 --no-pager || true

    echo
    print_info "Recent agent logs:"
    journalctl -t ocserv-central-agent -n 30 --no-pager || true
}

sync_ocpasswd_now() {
    master_curl "POST" "/sync-ocpasswd" "{}"
}

list_users() {
    master_curl "GET" "/users"
}

list_sessions() {
    master_curl "GET" "/sessions"
}

show_user() {
    local u
    u="$(ask_value "Username" "")"
    [[ -z "$u" ]] && return 0
    master_curl "GET" "/user/$u"
}

edit_user_override() {
    ensure_limits_file
    local u max_sessions quota tmp
    u="$(ask_value "Username" "")"
    [[ -z "$u" ]] && return 0

    local current_ms current_q
    current_ms="$(jq -r --arg u "$u" '.users[$u].max_sessions // 0' "$MASTER_ETC/limits.json")"
    current_q="$(jq -r --arg u "$u" '.users[$u].quota_gb // 0' "$MASTER_ETC/limits.json")"

    max_sessions="$(ask_number "User max sessions, 0 = use group default" "$current_ms")"
    quota="$(ask_number "User quota GB, 0 = unlimited or group default depending your policy" "$current_q")"

    tmp="$(mktemp)"
    if [[ "$max_sessions" == "0" ]]; then
        jq --arg u "$u" --argjson q "$quota" \
           '.users[$u] = {"quota_gb": $q}' \
           "$MASTER_ETC/limits.json" > "$tmp"
    else
        jq --arg u "$u" --argjson ms "$max_sessions" --argjson q "$quota" \
           '.users[$u] = {"max_sessions": $ms, "quota_gb": $q}' \
           "$MASTER_ETC/limits.json" > "$tmp"
    fi
    mv "$tmp" "$MASTER_ETC/limits.json"
    print_ok "User override saved."
    systemctl restart ocserv-central || true
}

remove_user_override() {
    ensure_limits_file
    local u tmp
    u="$(ask_value "Username" "")"
    [[ -z "$u" ]] && return 0
    tmp="$(mktemp)"
    jq --arg u "$u" 'del(.users[$u])' "$MASTER_ETC/limits.json" > "$tmp"
    mv "$tmp" "$MASTER_ETC/limits.json"
    print_ok "User override removed."
    systemctl restart ocserv-central || true
}

reset_user_usage() {
    local u
    u="$(ask_value "Username" "")"
    [[ -z "$u" ]] && return 0
    master_curl "POST" "/reset-usage" "{\"username\":\"$u\"}"
}

toggle_user_disabled() {
    local u disabled
    u="$(ask_value "Username" "")"
    [[ -z "$u" ]] && return 0
    if ask_yes_no "Disable this user?" "y"; then
        disabled="true"
    else
        disabled="false"
    fi
    master_curl "POST" "/toggle-user" "{\"username\":\"$u\",\"disabled\":$disabled}"
}

add_user_traffic() {
    local u gb
    u="$(ask_value "Username" "")"
    [[ -z "$u" ]] && return 0
    gb="$(ask_number "Traffic to add in GB" "10")"
    master_curl "POST" "/add-traffic" "{\"username\":\"$u\",\"gb\":$gb}"
}

add_user_time() {
    local u days hours minutes
    u="$(ask_value "Username" "")"
    [[ -z "$u" ]] && return 0
    days="$(ask_number "Days to add" "30")"
    hours="$(ask_number "Hours to add" "0")"
    minutes="$(ask_number "Minutes to add" "0")"
    master_curl "POST" "/add-time" "{\"username\":\"$u\",\"days\":$days,\"hours\":$hours,\"minutes\":$minutes}"
}

set_user_expiry_exact() {
    local u dt epoch
    u="$(ask_value "Username" "")"
    [[ -z "$u" ]] && return 0
    dt="$(ask_value "Expiry date/time, example 2026-07-14 23:59:00" "")"
    [[ -z "$dt" ]] && return 0
    epoch="$(date -d "$dt" +%s 2>/dev/null || true)"
    if [[ -z "$epoch" ]]; then
        print_err "Invalid date/time. Example: 2026-07-14 23:59:00"
        return 1
    fi
    master_curl "POST" "/set-expiry" "{\"username\":\"$u\",\"expires_at\":$epoch}"
}

clear_user_expiry() {
    local u
    u="$(ask_value "Username" "")"
    [[ -z "$u" ]] && return 0
    master_curl "POST" "/clear-expiry" "{\"username\":\"$u\"}"
}

list_nodes() {
    master_curl "GET" "/nodes"
}

list_quota_exhausted() {
    master_curl "GET" "/quota-exhausted"
}

reset_quota_exhausted_file() {
    master_curl "POST" "/quota-exhausted/reset" "{}"
}

delete_quota_exhausted_file() {
    master_curl "POST" "/quota-exhausted/delete" "{}"
}

backup_master_data() {
    need_root
    local out
    out="$(ask_value "Backup output file" "/root/ocserv-central-backup-$(date +%Y%m%d-%H%M%S).tar.gz")"
    tar -czf "$out" \
        --ignore-failed-read \
        "$APP_DIR" "$MASTER_ETC" "$DB_DIR" "$MASTER_SERVICE" 2>/dev/null
    print_ok "Backup saved: $out"
}

restore_master_data() {
    need_root
    local in
    in="$(ask_value "Backup tar.gz path to restore" "")"
    [[ -z "$in" ]] && return 0
    if [[ ! -f "$in" ]]; then
        print_err "Backup file not found: $in"
        return 1
    fi
    print_warn "This will overwrite ocserv-central app/config/database files from backup."
    if ! ask_yes_no "Continue restore?" "n"; then
        return 0
    fi
    systemctl stop ocserv-central >/dev/null 2>&1 || true
    tar -xzf "$in" -C /
    systemctl daemon-reload
    systemctl enable --now ocserv-central >/dev/null 2>&1 || true
    print_ok "Restore completed."
}

remove_helper_packages() {
    print_warn "The script installed helper packages such as jq, sqlite3, python3-venv, python3-pip, gawk, openssl, ca-certificates."
    print_warn "Some of these packages may be used by other services. Removing them can break unrelated scripts."
    if ask_yes_no "Remove only safer helper packages: jq sqlite3 gawk python3-venv python3-pip?" "n"; then
        apt purge -y jq sqlite3 gawk python3-venv python3-pip || true
        apt autoremove -y || true
    fi
}

edit_node_settings() {
    mkdir -p "$NODE_ETC"
    local current_url current_token current_node current_interval current_timeout current_fail
    if [[ -f "$NODE_ETC/node.env" ]]; then
        # shellcheck disable=SC1090
        . "$NODE_ETC/node.env"
    fi
    current_url="${API_URL:-http://MASTER_SERVER_IP:8088}"
    current_token="${API_TOKEN:-}"
    current_node="${NODE_ID:-$(hostname -s)}"
    current_interval="${INTERVAL:-30}"
    current_timeout="${API_TIMEOUT:-5}"
    current_fail="${FAIL_MODE:-closed}"

    local api_url token node_id interval timeout fail_mode
    api_url="$(ask_value "Central API URL" "$current_url")"
    token="$(ask_value "Central API token" "$current_token")"
    node_id="$(ask_value "Node ID" "$current_node")"
    interval="$(ask_number "Live quota check interval in seconds" "$current_interval")"
    timeout="$(ask_number "API timeout in seconds" "$current_timeout")"

    if [[ "$current_fail" == "open" ]]; then
        if ask_yes_no "Fail mode is open. Keep fail-open?" "y"; then fail_mode="open"; else fail_mode="closed"; fi
    else
        if ask_yes_no "Use fail-open when API is unreachable?" "n"; then fail_mode="open"; else fail_mode="closed"; fi
    fi

    cat > "$NODE_ETC/node.env" <<EOF
API_URL="$api_url"
API_TOKEN="$token"
NODE_ID="$node_id"
INTERVAL="$interval"
API_TIMEOUT="$timeout"
FAIL_MODE="$fail_mode"
EOF
    chmod 600 "$NODE_ETC/node.env"

    systemctl restart ocserv-central-agent 2>/dev/null || true
    print_ok "Node settings updated."
}

uninstall_node() {
    need_root

    print_warn "This will remove node hooks/agent and restore the original ocserv.conf backup if available."

    if ! ask_yes_no "Continue node uninstall?" "n"; then
        return 0
    fi

    systemctl disable --now ocserv-central-agent >/dev/null 2>&1 || true
    rm -f "$NODE_AGENT_SERVICE"
    rm -f "$HOOK_SCRIPT" "$CONNECT_WRAPPER" "$DISCONNECT_WRAPPER" "$AGENT_SCRIPT"

    if [[ -f "$NODE_ETC/original_ocserv.conf" && -f "$NODE_ETC/ocserv_conf_path" ]]; then
        local conf
        conf="$(cat "$NODE_ETC/ocserv_conf_path")"
        if [[ -n "$conf" ]]; then
            cp -a "$conf" "$NODE_ETC/backup/ocserv.conf.before-restore.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
            cp -a "$NODE_ETC/original_ocserv.conf" "$conf"
            print_ok "Restored original ocserv config: $conf"
        fi
    else
        print_warn "Original ocserv.conf backup not found. Removing central block only if config is detected."
        local conf
        conf="$(detect_ocserv_conf || true)"
        if [[ -n "$conf" && -f "$conf" ]]; then
            python3 - "$conf" <<'PYRM'
import re, sys
from pathlib import Path
p=Path(sys.argv[1])
text=p.read_text(encoding="utf-8", errors="ignore")
text=re.sub(r"\n?# BEGIN OCSERV-CENTRAL\n.*?\n# END OCSERV-CENTRAL\n?", "\n", text, flags=re.S)
p.write_text(text, encoding="utf-8")
PYRM
        fi
    fi

    rm -rf "$NODE_ETC"

    systemctl daemon-reload
    restart_ocserv_if_available

    print_ok "Node uninstalled."
    remove_helper_packages
}

uninstall_master() {
    need_root

    print_warn "This will remove the central API service."
    print_warn "If you also delete database/config, usage history and quotas will be lost."

    if ! ask_yes_no "Continue master uninstall?" "n"; then
        return 0
    fi

    systemctl disable --now ocserv-central >/dev/null 2>&1 || true
    rm -f "$MASTER_SERVICE"
    systemctl daemon-reload

    if ask_yes_no "Delete app directory $APP_DIR ?" "y"; then
        rm -rf "$APP_DIR"
    fi

    if ask_yes_no "Delete config directory $MASTER_ETC, including limits.json ?" "n"; then
        rm -rf "$MASTER_ETC"
    fi

    if ask_yes_no "Delete database directory $DB_DIR, including traffic usage DB ?" "n"; then
        rm -rf "$DB_DIR"
    fi

    print_ok "Master uninstalled."
    remove_helper_packages
}

master_menu() {
    while true; do
        clear
        echo "==== Ocserv Central - Master Menu ===="
        echo "1) Install / reconfigure master"
        echo "2) Configure features: session limit / quota"
        echo "3) Configure group limits from ocpasswd"
        echo "4) Sync ocpasswd now"
        echo "5) List users"
        echo "6) Show one user"
        echo "7) List active sessions"
        echo "8) Add/edit user override"
        echo "9) Remove user override"
        echo "10) Reset user usage"
        echo "11) Add traffic to user"
        echo "12) Add time to user account"
        echo "13) Set exact account expiry"
        echo "14) Clear account expiry"
        echo "15) Enable/disable user"
        echo "16) List connected nodes / API servers"
        echo "17) List exhausted-quota users"
        echo "18) Reset exhausted-quota file"
        echo "19) Delete exhausted-quota file"
        echo "20) Status"
        echo "21) Show current limits.json"
        echo "22) Backup program data"
        echo "23) Restore program data"
        echo "24) Uninstall master"
        echo "0) Back"
        echo
        read -rp "Select: " choice
        case "$choice" in
            1) install_master; pause ;;
            2) configure_features; systemctl restart ocserv-central 2>/dev/null || true; pause ;;
            3)
                ocp="$(ask_value "ocpasswd path" "/etc/ocserv/ocpasswd")"
                configure_groups_from_ocpasswd "$ocp"
                systemctl restart ocserv-central 2>/dev/null || true
                pause
                ;;
            4) sync_ocpasswd_now; pause ;;
            5) list_users; pause ;;
            6) show_user; pause ;;
            7) list_sessions; pause ;;
            8) edit_user_override; pause ;;
            9) remove_user_override; pause ;;
            10) reset_user_usage; pause ;;
            11) add_user_traffic; pause ;;
            12) add_user_time; pause ;;
            13) set_user_expiry_exact; pause ;;
            14) clear_user_expiry; pause ;;
            15) toggle_user_disabled; pause ;;
            16) list_nodes; pause ;;
            17) list_quota_exhausted; pause ;;
            18) reset_quota_exhausted_file; pause ;;
            19) delete_quota_exhausted_file; pause ;;
            20) master_status; pause ;;
            21) ensure_limits_file; jq . "$MASTER_ETC/limits.json"; pause ;;
            22) backup_master_data; pause ;;
            23) restore_master_data; pause ;;
            24) uninstall_master; pause ;;
            0) return 0 ;;
            *) echo "Invalid choice"; sleep 1 ;;
        esac
    done
}

node_menu() {
    while true; do
        clear
        echo "==== Ocserv Central - Node Menu ===="
        echo "1) Install / reconfigure node"
        echo "2) Edit node API settings"
        echo "3) Enable live quota agent"
        echo "4) Disable live quota agent"
        echo "5) Status / logs"
        echo "6) Test API connection"
        echo "7) Re-apply ocserv.conf hook"
        echo "8) Uninstall node and restore ocserv.conf"
        echo "0) Back"
        echo
        read -rp "Select: " choice
        case "$choice" in
            1) install_node; pause ;;
            2) edit_node_settings; pause ;;
            3) systemctl enable --now ocserv-central-agent; pause ;;
            4) systemctl disable --now ocserv-central-agent; pause ;;
            5) node_status; pause ;;
            6)
                if [[ -f "$NODE_ETC/node.env" ]]; then
                    # shellcheck disable=SC1090
                    . "$NODE_ETC/node.env"
                    curl -sS -m "${API_TIMEOUT:-5}" -H "X-API-Token: $API_TOKEN" "$API_URL/health" | jq . || true
                else
                    print_warn "Node env not found."
                fi
                pause
                ;;
            7)
                conf="$(ask_value "ocserv config path" "$(detect_ocserv_conf || true)")"
                configure_ocserv_conf_for_node "$conf"
                restart_ocserv_if_available
                pause
                ;;
            8) uninstall_node; pause ;;
            0) return 0 ;;
            *) echo "Invalid choice"; sleep 1 ;;
        esac
    done
}

full_status() {
    echo "==== Master ===="
    systemctl is-active ocserv-central 2>/dev/null || true
    echo
    echo "==== Node Agent ===="
    systemctl is-active ocserv-central-agent 2>/dev/null || true
    echo
    echo "==== ocserv ===="
    local svc
    svc="$(detect_ocserv_service)"
    if [[ -n "$svc" ]]; then
        systemctl status "$svc" --no-pager || true
    else
        print_warn "ocserv service not detected."
    fi
}

main_menu() {
    need_root
    while true; do
        clear
        echo "=============================================="
        echo "       Ocserv Central Manager"
        echo "=============================================="
        echo "1) Master server menu"
        echo "2) Node server menu"
        echo "3) Install both master and node on this server"
        echo "4) Full status"
        echo "5) Uninstall node part"
        echo "6) Uninstall master part"
        echo "0) Exit"
        echo
        read -rp "Select: " choice
        case "$choice" in
            1) master_menu ;;
            2) node_menu ;;
            3) install_master; install_node; pause ;;
            4) full_status; pause ;;
            5) uninstall_node; pause ;;
            6) uninstall_master; pause ;;
            0) exit 0 ;;
            *) echo "Invalid choice"; sleep 1 ;;
        esac
    done
}

main_menu
