#!/usr/bin/env bash
# ocserv-central-manager v15
# Adds exact pre-reset usage snapshots, usage_log recovery tools, and group-aware user quota override handling.
# Keeps v13 authoritative group refresh, v12 cleanup+VACUUM, v10 exhausted tools, v9 DB prune, and v8 unlimited groups.
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

CLEANUP_SCRIPT="/usr/local/sbin/ocserv-central-cleanup-usage.sh"
CLEANUP_ENV="/etc/ocserv-central/cleanup.env"
CLEANUP_SERVICE="/etc/systemd/system/ocserv-central-cleanup.service"
CLEANUP_TIMER="/etc/systemd/system/ocserv-central-cleanup.timer"

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
        echo "Enter a number." >&2
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
import uuid
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

app = FastAPI(title="ocserv-central", version="1.5")

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

        con.execute("""
        CREATE TABLE IF NOT EXISTS usage_reset_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            target TEXT,
            username TEXT NOT NULL,
            old_used_bytes INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            note TEXT
        )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_usage_reset_snapshots_batch ON usage_reset_snapshots(batch_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_usage_reset_snapshots_created ON usage_reset_snapshots(created_at)")

        con.execute("""
        CREATE TABLE IF NOT EXISTS extra_traffic_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            target TEXT,
            username TEXT NOT NULL,
            old_extra_bytes INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            operation TEXT NOT NULL,
            note TEXT
        )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_extra_traffic_snapshots_batch ON extra_traffic_snapshots(batch_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_extra_traffic_snapshots_created ON extra_traffic_snapshots(created_at)")


def create_usage_reset_snapshot(con, scope: str, target: str | None = None, usernames: list[str] | None = None, note: str = ""):
    """Save exact used_bytes values before a destructive reset."""
    con.execute("""
        CREATE TABLE IF NOT EXISTS usage_reset_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            target TEXT,
            username TEXT NOT NULL,
            old_used_bytes INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            note TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_usage_reset_snapshots_batch ON usage_reset_snapshots(batch_id)")
    t = now()
    batch_id = f"reset-{t}-{uuid.uuid4().hex[:10]}"

    if usernames is None:
        rows = con.execute("SELECT username, used_bytes FROM users ORDER BY username").fetchall()
    elif not usernames:
        rows = []
    else:
        placeholders = ",".join("?" for _ in usernames)
        rows = con.execute(
            f"SELECT username, used_bytes FROM users WHERE username IN ({placeholders}) ORDER BY username",
            usernames,
        ).fetchall()

    con.executemany(
        """
        INSERT INTO usage_reset_snapshots(batch_id, scope, target, username, old_used_bytes, created_at, note)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (batch_id, scope, target, row["username"], int(row["used_bytes"] or 0), t, note)
            for row in rows
        ],
    )
    return batch_id, len(rows)


def create_extra_traffic_snapshot(
    con,
    scope: str,
    target: str | None = None,
    usernames: list[str] | None = None,
    operation: str = "change",
    note: str = "",
):
    """Save exact quota_extra_bytes values before add/decrease/set/clear operations."""
    con.execute("""
        CREATE TABLE IF NOT EXISTS extra_traffic_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            target TEXT,
            username TEXT NOT NULL,
            old_extra_bytes INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            operation TEXT NOT NULL,
            note TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_extra_traffic_snapshots_batch ON extra_traffic_snapshots(batch_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_extra_traffic_snapshots_created ON extra_traffic_snapshots(created_at)")

    t = now()
    batch_id = f"extra-{t}-{uuid.uuid4().hex[:10]}"

    if usernames is None:
        rows = con.execute(
            "SELECT username, quota_extra_bytes FROM users ORDER BY username"
        ).fetchall()
    elif not usernames:
        rows = []
    else:
        placeholders = ",".join("?" for _ in usernames)
        rows = con.execute(
            f"SELECT username, quota_extra_bytes FROM users WHERE username IN ({placeholders}) ORDER BY username",
            usernames,
        ).fetchall()

    con.executemany(
        """
        INSERT INTO extra_traffic_snapshots(
            batch_id, scope, target, username, old_extra_bytes, created_at, operation, note
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                batch_id,
                scope,
                target,
                row["username"],
                int(row["quota_extra_bytes"] or 0),
                t,
                operation,
                note,
            )
            for row in rows
        ],
    )
    return batch_id, len(rows)


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

def known_groups_from_db_and_limits():
    groups = set()
    limits = load_limits()
    for g in limits.get("groups", {}).keys():
        if g:
            groups.add(g)
    try:
        with db() as con:
            rows = con.execute("SELECT DISTINCT groupname FROM users WHERE groupname IS NOT NULL AND groupname != ''").fetchall()
            for r in rows:
                if r["groupname"]:
                    groups.add(r["groupname"])
    except Exception:
        pass
    if not groups:
        groups.add("group1")
    return sorted(groups)

def set_quota_for_all_known_groups(gb: float):
    sync_ocpasswd_to_db()
    quota = float(gb)
    limits = load_limits()
    limits.setdefault("features", {})["quota"] = True
    limits["default_quota_gb"] = quota
    limits.setdefault("groups", {})
    groups = known_groups_from_db_and_limits()
    for g in groups:
        old = limits["groups"].get(g, {}) or {}
        old.setdefault("max_sessions", group_number(g))
        old["quota_gb"] = quota
        limits["groups"][g] = old
    save_limits(limits)
    return groups

def clear_quota_for_all_known_groups():
    sync_ocpasswd_to_db()
    limits = load_limits()
    limits.setdefault("features", {})["quota"] = True
    limits["default_quota_gb"] = 0
    limits.setdefault("groups", {})
    groups = known_groups_from_db_and_limits()
    for g in groups:
        old = limits["groups"].get(g, {}) or {}
        old.setdefault("max_sessions", group_number(g))
        old["quota_gb"] = 0
        limits["groups"][g] = old
    save_limits(limits)
    return groups

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
    g = str(groupname).strip().lower()
    if g in ("*", "unlimited", "unlimit", "nolimit", "no-limit", "no_limit", "all"):
        return 999999
    m = re.search(r"(\d+)", str(groupname))
    return int(m.group(1)) if m else 1

def get_user_from_db(username: str):
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return row

def get_user_group_from_db(username: str) -> str | None:
    row = get_user_from_db(username)
    return row["groupname"] if row else None

def authoritative_group_for_user(username: str, fallback_group: str | None = None) -> str | None:
    """
    Always prefer the group stored in central DB after sync_ocpasswd_to_db().

    Why: ocserv/occtl can keep reporting the group that existed when a session started.
    If the admin changes a user from group1 to group2 in ocpasswd, quota/session
    checks must use the new ocpasswd-backed group immediately, not the stale session group.
    """
    db_group = get_user_group_from_db(username)
    if db_group:
        return db_group
    if fallback_group:
        return pick_primary_group(fallback_group)
    return None

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
        group_ms = int(group_cfg["max_sessions"])
        max_sessions = 999999 if group_ms <= 0 else group_ms
    if quota_feature and "quota_gb" in group_cfg:
        quota_gb = float(group_cfg["quota_gb"])

    user_cfg = limits.get("users", {}).get(username, {})
    if session_feature and "max_sessions" in user_cfg:
        user_ms = int(user_cfg["max_sessions"])
        # User override convention:
        #   max_sessions = 0  => use group default; this value is normally omitted by the menu.
        #   max_sessions < 0  => unlimited for this user.
        #   max_sessions > 0  => exact user limit.
        if user_ms < 0:
            max_sessions = 999999
        elif user_ms > 0:
            max_sessions = user_ms
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

def make_exhausted_item(username: str, groupname: str | None, used_bytes: int, quota_bytes: int, reason: str):
    return {
        "time": now(),
        "username": username,
        "groupname": groupname,
        "used_bytes": int(used_bytes or 0),
        "quota_bytes": int(quota_bytes or 0),
        "reason": reason,
    }

def read_exhausted_items_dedup(path: str):
    """
    Read exhausted log and return one item per username.
    If a username appears multiple times, keep the newest record by time.
    Invalid/raw lines are preserved only if they do not look like JSON user rows.
    """
    by_user: dict[str, dict] = {}
    raw_items: list[dict] = []

    if not os.path.exists(path):
        return [], {"read": 0, "valid": 0, "raw": 0, "duplicates_removed": 0}

    read_count = 0
    valid_count = 0
    raw_count = 0

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                read_count += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    username = obj.get("username")
                    if username:
                        valid_count += 1
                        prev = by_user.get(username)
                        if not prev or int(obj.get("time") or 0) >= int(prev.get("time") or 0):
                            by_user[username] = obj
                    else:
                        raw_count += 1
                        raw_items.append({"raw": line})
                except Exception:
                    raw_count += 1
                    raw_items.append({"raw": line})
    except Exception:
        return [], {"read": read_count, "valid": valid_count, "raw": raw_count, "duplicates_removed": 0}

    items = list(by_user.values()) + raw_items
    items.sort(key=lambda x: (str(x.get("username") or x.get("raw") or ""), int(x.get("time") or 0)))
    duplicates_removed = max(0, valid_count - len(by_user))
    return items, {"read": read_count, "valid": valid_count, "raw": raw_count, "duplicates_removed": duplicates_removed}

def write_exhausted_items(path: str, items: list[dict]):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

def user_is_quota_exhausted(username: str, groupname: str | None = None):
    row = get_user_from_db(username)
    if not row:
        return False, None
    g = groupname or row["groupname"]
    _, quota_bytes = effective_limits(username, g)
    used = int(row["used_bytes"] or 0)
    exhausted = quota_bytes > 0 and used >= quota_bytes
    return exhausted, make_exhausted_item(username, g, used, quota_bytes, "rebuild quota exceeded")

def log_quota_exhausted(username: str, groupname: str | None, used_bytes: int, quota_bytes: int, reason: str):
    limits = load_limits()
    if not bool(limits.get("features", {}).get("exhausted_log_enabled", True)):
        return

    path = exhausted_log_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)

    item = make_exhausted_item(username, groupname, used_bytes, quota_bytes, reason)

    # Upsert, not append-spam:
    # - If username already exists, update the existing record.
    # - If the file has duplicates, dedupe it automatically.
    items, _stats = read_exhausted_items_dedup(path)
    by_user = {}
    raw_items = []
    for old in items:
        if old.get("username"):
            by_user[old["username"]] = old
        else:
            raw_items.append(old)

    by_user[username] = item

    final_items = list(by_user.values()) + raw_items
    final_items.sort(key=lambda x: (str(x.get("username") or x.get("raw") or ""), int(x.get("time") or 0)))
    write_exhausted_items(path, final_items)

def remove_from_exhausted_log(username: str):
    path = exhausted_log_path()
    if not os.path.exists(path):
        return

    try:
        items, _stats = read_exhausted_items_dedup(path)
        kept = [item for item in items if item.get("username") != username]
        write_exhausted_items(path, kept)
    except Exception:
        return

def rebuild_exhausted_log_from_db():
    path = exhausted_log_path()
    items = []
    with db() as con:
        rows = con.execute("SELECT username, groupname, used_bytes FROM users ORDER BY username").fetchall()

    for row in rows:
        username = row["username"]
        exhausted, item = user_is_quota_exhausted(username, row["groupname"])
        if exhausted and item:
            item["reason"] = "rebuild current quota exceeded"
            items.append(item)

    write_exhausted_items(path, items)
    return {"ok": True, "path": path, "count": len(items), "action": "rebuild_from_db"}

def prune_resolved_exhausted_log():
    path = exhausted_log_path()
    items, stats = read_exhausted_items_dedup(path)
    kept = []
    removed = 0

    for item in items:
        username = item.get("username")
        if not username:
            kept.append(item)
            continue
        exhausted, new_item = user_is_quota_exhausted(username, item.get("groupname"))
        if exhausted and new_item:
            # Keep fresh used/quota values.
            new_item["reason"] = item.get("reason") or "quota exceeded"
            kept.append(new_item)
        else:
            removed += 1

    write_exhausted_items(path, kept)
    return {"ok": True, "path": path, "kept": len(kept), "removed_resolved": removed, "dedupe_stats": stats, "action": "prune_resolved"}

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

class BulkQuotaReq(BaseModel):
    gb: float

class BulkTrafficReq(BaseModel):
    gb: float = 0
    clear_exhausted: bool = True

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

@app.post("/refresh-now")
def refresh_now(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    result = sync_ocpasswd_to_db()
    return {"ok": True, "action": "sync_ocpasswd_and_reload_limits", "sync": result, "note": "limits.json is read on every quota/session check; API restart is not required for group/quota edits."}

@app.post("/connect")
def connect(req: ConnectReq, request: Request, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    t = now()
    sync_ocpasswd_to_db()
    update_node(req.node_id, request, 0)

    # v13: ocpasswd/central DB is authoritative for group changes.
    # Do not trust a stale GROUPNAME coming from ocserv/session state.
    req.groupname = authoritative_group_for_user(req.username, req.groupname)

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
    # v13: refresh ocpasswd-backed group before final quota/exhausted checks.
    sync_ocpasswd_to_db()
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
            # v13: always use ocpasswd-backed DB group if available.
            # This makes group changes apply on the next heartbeat without deleting/re-adding user.
            s.groupname = authoritative_group_for_user(s.username, s.groupname)

            con.execute(
                """
                INSERT OR IGNORE INTO users(username, groupname, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at)
                VALUES (?, ?, 0, 0, ?, 0, 0)
                """,
                (s.username, s.groupname, t)
            )
            if s.groupname:
                con.execute("UPDATE users SET groupname=?, updated_at=? WHERE username=?", (s.groupname, t, s.username))

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
    used = max(0, int(user["used_bytes"] or 0)) if user else 0
    quota_unlimited = quota_bytes <= 0
    remaining_bytes = None if quota_unlimited else max(0, int(quota_bytes) - used)
    exhausted = False if quota_unlimited else used >= int(quota_bytes)

    # Backward compatibility:
    # - remaining_bytes used to be 0 for unlimited quota. That was ambiguous.
    # - v11 returns null for unlimited and also adds remaining_bytes_compat=0.
    return {
        "user": dict(user) if user else None,
        "limits": {
            "max_sessions": max_sessions,
            "quota_bytes": int(quota_bytes),
            "used_bytes": used,
            "remaining_bytes": remaining_bytes,
            "remaining_bytes_compat": 0 if remaining_bytes is None else remaining_bytes,
            "quota_unlimited": quota_unlimited,
            "exhausted": exhausted,
            "quota_gib": (round(int(quota_bytes) / GIB, 6) if quota_bytes > 0 else None),
            "used_gib": round(used / GIB, 6),
            "remaining_gib": (round(remaining_bytes / GIB, 6) if remaining_bytes is not None else None),
        },
        "expired": account_is_expired(username),
        "current_group_authoritative": user["groupname"] if user else None,
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
        batch_id, snap_count = create_usage_reset_snapshot(
            con, "user", req.username, [req.username], "API single-user usage reset"
        )
        con.execute("UPDATE users SET used_bytes=0, updated_at=? WHERE username=?", (now(), req.username))
    remove_from_exhausted_log(req.username)
    return {
        "ok": True,
        "username": req.username,
        "used_bytes": 0,
        "snapshot_batch_id": batch_id,
        "snapshot_users": snap_count,
    }

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
    if float(req.gb) <= 0:
        raise HTTPException(status_code=400, detail="gb must be greater than zero")

    sync_ocpasswd_to_db()
    add_bytes = int(float(req.gb) * GIB)
    t = now()

    with db() as con:
        con.execute("""
            INSERT OR IGNORE INTO users(
                username, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at
            )
            VALUES (?, 0, 0, ?, 0, 0)
        """, (req.username, t))

        before = con.execute(
            "SELECT quota_extra_bytes FROM users WHERE username=?",
            (req.username,),
        ).fetchone()
        old_extra = int(before["quota_extra_bytes"] or 0)

        batch_id, snap_count = create_extra_traffic_snapshot(
            con,
            "user",
            req.username,
            [req.username],
            "add",
            f"Add {req.gb} GiB extra traffic",
        )

        new_extra = old_extra + add_bytes
        con.execute(
            "UPDATE users SET quota_extra_bytes=?, updated_at=? WHERE username=?",
            (new_extra, t, req.username),
        )

    exhausted, item = user_is_quota_exhausted(req.username)
    if exhausted and item:
        log_quota_exhausted(
            req.username,
            item.get("groupname"),
            item.get("used_bytes", 0),
            item.get("quota_bytes", 0),
            "quota still exceeded after adding extra traffic",
        )
    else:
        remove_from_exhausted_log(req.username)

    return {
        "ok": True,
        "username": req.username,
        "requested_add_gb": float(req.gb),
        "actual_added_bytes": add_bytes,
        "old_extra_bytes": old_extra,
        "new_extra_bytes": new_extra,
        "old_extra_gib": round(old_extra / GIB, 6),
        "new_extra_gib": round(new_extra / GIB, 6),
        "snapshot_batch_id": batch_id,
        "snapshot_users": snap_count,
    }

@app.post("/decrease-traffic")
def decrease_traffic(req: AddTrafficReq, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    if float(req.gb) <= 0:
        raise HTTPException(status_code=400, detail="gb must be greater than zero")

    sync_ocpasswd_to_db()
    requested_bytes = int(float(req.gb) * GIB)
    t = now()

    with db() as con:
        con.execute("""
            INSERT OR IGNORE INTO users(
                username, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at
            )
            VALUES (?, 0, 0, ?, 0, 0)
        """, (req.username, t))

        before = con.execute(
            "SELECT quota_extra_bytes FROM users WHERE username=?",
            (req.username,),
        ).fetchone()
        old_extra = int(before["quota_extra_bytes"] or 0)

        batch_id, snap_count = create_extra_traffic_snapshot(
            con,
            "user",
            req.username,
            [req.username],
            "decrease",
            f"Decrease {req.gb} GiB extra traffic",
        )

        actual_decreased = min(old_extra, requested_bytes)
        new_extra = max(0, old_extra - requested_bytes)
        con.execute(
            "UPDATE users SET quota_extra_bytes=?, updated_at=? WHERE username=?",
            (new_extra, t, req.username),
        )

    exhausted, item = user_is_quota_exhausted(req.username)
    if exhausted and item:
        log_quota_exhausted(
            req.username,
            item.get("groupname"),
            item.get("used_bytes", 0),
            item.get("quota_bytes", 0),
            "quota exceeded after decreasing extra traffic",
        )
    else:
        remove_from_exhausted_log(req.username)

    return {
        "ok": True,
        "username": req.username,
        "requested_decrease_gb": float(req.gb),
        "requested_decrease_bytes": requested_bytes,
        "actual_decreased_bytes": actual_decreased,
        "actual_decreased_gib": round(actual_decreased / GIB, 6),
        "old_extra_bytes": old_extra,
        "new_extra_bytes": new_extra,
        "old_extra_gib": round(old_extra / GIB, 6),
        "new_extra_gib": round(new_extra / GIB, 6),
        "clamped_at_zero": requested_bytes > old_extra,
        "snapshot_batch_id": batch_id,
        "snapshot_users": snap_count,
    }

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

@app.post("/bulk/set-all-group-quota")
def bulk_set_all_group_quota(req: BulkQuotaReq, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    groups = set_quota_for_all_known_groups(req.gb)
    return {"ok": True, "quota_gb": req.gb, "groups_updated": groups, "count": len(groups)}

@app.post("/bulk/remove-all-group-quota")
def bulk_remove_all_group_quota(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    groups = clear_quota_for_all_known_groups()
    return {"ok": True, "quota_gb": 0, "groups_updated": groups, "count": len(groups), "meaning": "unlimited"}

@app.post("/bulk/add-traffic-all-users")
def bulk_add_traffic_all_users(req: BulkTrafficReq, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    if float(req.gb) <= 0:
        raise HTTPException(status_code=400, detail="gb must be greater than zero")

    sync_ocpasswd_to_db()
    add_bytes = int(float(req.gb) * GIB)
    t = now()
    with db() as con:
        batch_id, snap_count = create_extra_traffic_snapshot(
            con, "all", "all-users", None, "bulk-add", f"Add {req.gb} GiB to all users"
        )
        before_total = int(con.execute(
            "SELECT COALESCE(SUM(quota_extra_bytes),0) AS total FROM users"
        ).fetchone()["total"] or 0)
        con.execute(
            "UPDATE users SET quota_extra_bytes = quota_extra_bytes + ?, updated_at=?",
            (add_bytes, t),
        )
        count = int(con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"])
        after_total = int(con.execute(
            "SELECT COALESCE(SUM(quota_extra_bytes),0) AS total FROM users"
        ).fetchone()["total"] or 0)

    rebuild_result = rebuild_exhausted_log_from_db() if req.clear_exhausted else None
    return {
        "ok": True,
        "users_updated": count,
        "requested_add_gb": float(req.gb),
        "added_bytes_per_user": add_bytes,
        "before_total_extra_bytes": before_total,
        "after_total_extra_bytes": after_total,
        "snapshot_batch_id": batch_id,
        "snapshot_users": snap_count,
        "exhausted_rebuild": rebuild_result,
    }

@app.post("/bulk/decrease-traffic-all-users")
def bulk_decrease_traffic_all_users(req: BulkTrafficReq, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    if float(req.gb) <= 0:
        raise HTTPException(status_code=400, detail="gb must be greater than zero")

    sync_ocpasswd_to_db()
    requested_bytes = int(float(req.gb) * GIB)
    t = now()
    with db() as con:
        batch_id, snap_count = create_extra_traffic_snapshot(
            con,
            "all",
            "all-users",
            None,
            "bulk-decrease",
            f"Decrease {req.gb} GiB from all users",
        )
        before_total = int(con.execute(
            "SELECT COALESCE(SUM(quota_extra_bytes),0) AS total FROM users"
        ).fetchone()["total"] or 0)
        affected = int(con.execute(
            "SELECT COUNT(*) AS c FROM users WHERE quota_extra_bytes > 0"
        ).fetchone()["c"])
        con.execute(
            """
            UPDATE users
            SET quota_extra_bytes =
                CASE
                    WHEN quota_extra_bytes > ? THEN quota_extra_bytes - ?
                    ELSE 0
                END,
                updated_at=?
            """,
            (requested_bytes, requested_bytes, t),
        )
        count = int(con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"])
        after_total = int(con.execute(
            "SELECT COALESCE(SUM(quota_extra_bytes),0) AS total FROM users"
        ).fetchone()["total"] or 0)

    rebuild_result = rebuild_exhausted_log_from_db()
    return {
        "ok": True,
        "users_checked": count,
        "users_with_extra_before_change": affected,
        "requested_decrease_gb_per_user": float(req.gb),
        "requested_decrease_bytes_per_user": requested_bytes,
        "actual_total_decreased_bytes": max(0, before_total - after_total),
        "actual_total_decreased_gib": round(max(0, before_total - after_total) / GIB, 6),
        "before_total_extra_bytes": before_total,
        "after_total_extra_bytes": after_total,
        "snapshot_batch_id": batch_id,
        "snapshot_users": snap_count,
        "exhausted_rebuild": rebuild_result,
    }

@app.post("/bulk/set-extra-traffic-all-users")
def bulk_set_extra_traffic_all_users(req: BulkTrafficReq, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    if float(req.gb) < 0:
        raise HTTPException(status_code=400, detail="gb cannot be negative")

    sync_ocpasswd_to_db()
    set_bytes = int(float(req.gb) * GIB)
    t = now()
    with db() as con:
        batch_id, snap_count = create_extra_traffic_snapshot(
            con, "all", "all-users", None, "bulk-set", f"Set all users extra traffic to {req.gb} GiB"
        )
        con.execute("UPDATE users SET quota_extra_bytes = ?, updated_at=?", (set_bytes, t))
        count = int(con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"])

    rebuild_result = rebuild_exhausted_log_from_db() if req.clear_exhausted else None
    return {
        "ok": True,
        "users_updated": count,
        "extra_traffic_gb": float(req.gb),
        "extra_traffic_bytes": set_bytes,
        "snapshot_batch_id": batch_id,
        "snapshot_users": snap_count,
        "exhausted_rebuild": rebuild_result,
    }

@app.post("/bulk/clear-extra-traffic-all-users")
def bulk_clear_extra_traffic_all_users(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    sync_ocpasswd_to_db()
    with db() as con:
        batch_id, snap_count = create_extra_traffic_snapshot(
            con, "all", "all-users", None, "bulk-clear", "Clear all users extra traffic"
        )
        con.execute("UPDATE users SET quota_extra_bytes = 0, updated_at=?", (now(),))
        count = int(con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"])

    rebuild_result = rebuild_exhausted_log_from_db()
    return {
        "ok": True,
        "users_updated": count,
        "quota_extra_bytes": 0,
        "snapshot_batch_id": batch_id,
        "snapshot_users": snap_count,
        "exhausted_rebuild": rebuild_result,
    }

@app.post("/bulk/reset-usage-all-users")
def bulk_reset_usage_all_users(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    sync_ocpasswd_to_db()
    with db() as con:
        batch_id, snap_count = create_usage_reset_snapshot(
            con, "all", "all-users", None, "API bulk reset of all users"
        )
        con.execute("UPDATE users SET used_bytes = 0, updated_at=?", (now(),))
        count = con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    path = exhausted_log_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    open(path, "w", encoding="utf-8").close()
    return {
        "ok": True,
        "users_updated": count,
        "used_bytes": 0,
        "exhausted_file_reset": True,
        "snapshot_batch_id": batch_id,
        "snapshot_users": snap_count,
    }

@app.get("/quota-exhausted")
def quota_exhausted(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    path = exhausted_log_path()
    items, stats = read_exhausted_items_dedup(path)

    # If duplicates exist, clean them immediately so list output and file match.
    if stats.get("duplicates_removed", 0) > 0:
        write_exhausted_items(path, items)

    return {"path": path, "count": len(items), "dedupe_stats": stats, "items": items}

@app.post("/quota-exhausted/reset")
def quota_exhausted_reset(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    path = exhausted_log_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    open(path, "w", encoding="utf-8").close()
    return {
        "ok": True,
        "path": path,
        "action": "reset_empty",
        "note": "This only clears the file. Users that are still over quota can be logged again on the next connect/heartbeat."
    }

@app.post("/quota-exhausted/dedupe")
def quota_exhausted_dedupe(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    path = exhausted_log_path()
    items, stats = read_exhausted_items_dedup(path)
    write_exhausted_items(path, items)
    return {"ok": True, "path": path, "count": len(items), "dedupe_stats": stats, "action": "dedupe"}

@app.post("/quota-exhausted/rebuild")
def quota_exhausted_rebuild(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    return rebuild_exhausted_log_from_db()

@app.post("/quota-exhausted/prune-resolved")
def quota_exhausted_prune_resolved(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    return prune_resolved_exhausted_log()

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
    local lower num
    lower="$(echo "$group" | tr '[:upper:]' '[:lower:]' | xargs)"
    case "$lower" in
        "*"|"unlimited"|"unlimit"|"nolimit"|"no-limit"|"no_limit"|"all")
            echo "0"
            return 0
            ;;
    esac

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
        ocpasswd="$(systemctl show ocserv-central -p Environment --value 2>/dev/null | tr ' ' '
' | sed -n 's/^OCPASSWD_PATH=//p' | tail -n1 || true)"
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
    printf ' - %s
' "${groups[@]}"

    local use_same_quota="no" same_quota="" tmp
    if ask_yes_no "Apply ONE traffic quota to ALL found groups now?" "y"; then
        use_same_quota="yes"
        same_quota="$(ask_number "Traffic quota for ALL groups in GB, 0 = unlimited" "100")"
        tmp="$(mktemp)"
        jq --argjson q "$same_quota" '.features.quota=true | .default_quota_gb=$q' "$MASTER_ETC/limits.json" > "$tmp"
        mv "$tmp" "$MASTER_ETC/limits.json"
    fi

    for g in "${groups[@]}"; do
        echo
        print_info "Configure group: $g"
        local def_sessions max_sessions quota_gb current_quota
        def_sessions="$(group_default_sessions "$g")"
        max_sessions="$(ask_number "Max concurrent sessions for $g" "$def_sessions")"

        if [[ "$use_same_quota" == "yes" ]]; then
            quota_gb="$same_quota"
            print_info "Quota for $g will be set to ${quota_gb} GB because global group quota was selected."
        else
            current_quota="$(jq -r --arg g "$g" '.groups[$g].quota_gb // .default_quota_gb // 0' "$MASTER_ETC/limits.json")"
            quota_gb="$(ask_number "Quota for $g in GB, 0 = unlimited" "$current_quota")"
        fi

        tmp="$(mktemp)"
        jq --arg g "$g" --argjson ms "$max_sessions" --argjson q "$quota_gb"            '.groups[$g] = {"max_sessions": $ms, "quota_gb": $q}'            "$MASTER_ETC/limits.json" > "$tmp"
        mv "$tmp" "$MASTER_ETC/limits.json"
        handle_group_manual_quota_overrides "$g" "$quota_gb"
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

restart_master_api() {
    need_root
    print_info "Restarting ocserv-central API..."
    systemctl restart ocserv-central
    sleep 1
    systemctl status ocserv-central --no-pager || true
    echo
    print_info "Health:"
    curl -sS http://127.0.0.1:8088/health 2>/dev/null | jq . || print_warn "API not responding after restart. Check: journalctl -u ocserv-central -n 100 --no-pager"
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

refresh_now_menu() {
    master_curl "POST" "/refresh-now" "{}"
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

    max_sessions="$(ask_number "User max sessions, 0 = use group default, -1 = unlimited" "$current_ms")"
    quota="$(ask_number "User quota GB, 0 = unlimited or group default depending your policy" "$current_q")"

    tmp="$(mktemp)"
    if [[ "$max_sessions" == "0" || "$max_sessions" == "0.0" ]]; then
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

decrease_user_traffic() {
    local u gb
    u="$(ask_value "Username" "")"
    [[ -z "$u" ]] && return 0
    gb="$(ask_number "EXTRA traffic to decrease in GB" "10")"
    print_info "Only quota_extra_bytes is reduced. Group quota and manual limits.json quota are not changed."
    print_info "The result cannot go below zero."
    if ! ask_yes_no "Decrease this user's added traffic now?" "n"; then
        return 0
    fi
    master_curl "POST" "/decrease-traffic" "{\"username\":\"$u\",\"gb\":$gb}"
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

dedupe_quota_exhausted_file() {
    master_curl "POST" "/quota-exhausted/dedupe" "{}"
}

rebuild_quota_exhausted_file() {
    master_curl "POST" "/quota-exhausted/rebuild" "{}"
}

prune_resolved_quota_exhausted_file() {
    master_curl "POST" "/quota-exhausted/prune-resolved" "{}"
}

delete_quota_exhausted_file() {
    master_curl "POST" "/quota-exhausted/delete" "{}"
}

exhausted_quota_file_menu() {
    while true; do
        clear
        echo "==== Ocserv Central - Exhausted Quota File Tools ===="
        echo "1) List exhausted-quota users, auto-dedupe if duplicates exist"
        echo "2) Reset file only, empty it"
        echo "3) Dedupe file only, keep one row per username"
        echo "4) Rebuild file from current DB state, only users still really over quota"
        echo "5) Prune resolved users, remove users that are no longer over quota"
        echo "6) Delete exhausted-quota file"
        echo "0) Back"
        echo
        echo "Important:"
        echo "- Reset only clears the report file."
        echo "- If a user is still over quota, they can be logged again on next connect/heartbeat."
        echo "- Rebuild is usually the cleanest option after changing quotas or adding traffic."
        echo
        read -rp "Select: " choice
        case "$choice" in
            1) list_quota_exhausted; pause ;;
            2)
                print_warn "This only empties the file. It does not reset user usage or add traffic."
                if ask_yes_no "Continue reset-empty?" "n"; then
                    reset_quota_exhausted_file
                fi
                pause
                ;;
            3) dedupe_quota_exhausted_file; pause ;;
            4) rebuild_quota_exhausted_file; pause ;;
            5) prune_resolved_quota_exhausted_file; pause ;;
            6)
                if ask_yes_no "Delete exhausted-quota file?" "n"; then
                    delete_quota_exhausted_file
                fi
                pause
                ;;
            0) return 0 ;;
            *) echo "Invalid choice"; sleep 1 ;;
        esac
    done
}

human_size() {
    local target="$1"
    if [[ -e "$target" ]]; then
        du -sh "$target" 2>/dev/null | awk '{print $1}'
    else
        echo "0"
    fi
}

db_path() {
    echo "$DB_DIR/central.db"
}

usage_log_stats() {
    local db
    db="$(db_path)"

    if [[ ! -f "$db" ]]; then
        print_warn "Database not found: $db"
        return 0
    fi

    echo
    print_info "Database file:"
    ls -lh "$db" 2>/dev/null || true
    echo

    print_info "Tables overview:"
    sqlite3 "$db" <<'SQL' || true
.headers on
.mode column
SELECT 'users' AS table_name, COUNT(*) AS rows FROM users
UNION ALL
SELECT 'sessions', COUNT(*) FROM sessions
UNION ALL
SELECT 'usage_log', COUNT(*) FROM usage_log
UNION ALL
SELECT 'nodes', COUNT(*) FROM nodes;
SQL

    echo
    print_info "usage_log date range:"
    sqlite3 "$db" <<'SQL' || true
.headers on
.mode column
SELECT
  COUNT(*) AS usage_rows,
  datetime(MIN(created_at), 'unixepoch', 'localtime') AS oldest,
  datetime(MAX(created_at), 'unixepoch', 'localtime') AS newest
FROM usage_log;
SQL

    echo
    print_info "Approx directory sizes:"
    echo "APP_DIR=$APP_DIR -> $(human_size "$APP_DIR")"
    echo "MASTER_ETC=$MASTER_ETC -> $(human_size "$MASTER_ETC")"
    echo "DB_DIR=$DB_DIR -> $(human_size "$DB_DIR")"
}

backup_paths_tar() {
    local out="$1"
    shift
    mkdir -p "$(dirname "$out")"

    tar -czf "$out" --ignore-failed-read -C / "$@" 2>/dev/null
    print_ok "Backup saved: $out"
    ls -lh "$out" 2>/dev/null || true
}

backup_master_full() {
    need_root
    local out
    out="$(ask_value "Full backup output file" "/root/ocserv-central-full-$(date +%Y%m%d-%H%M%S).tar.gz")"

    backup_paths_tar "$out" \
        "opt/ocserv-central" \
        "etc/ocserv-central" \
        "var/lib/ocserv-central" \
        "etc/systemd/system/ocserv-central.service"
}

make_temp_backup_root() {
    mktemp -d /tmp/ocserv-central-backup.XXXXXX
}

copy_master_common_to_tmp() {
    local tmp="$1"

    mkdir -p "$tmp/opt" "$tmp/etc/systemd/system" "$tmp/var/lib/ocserv-central"

    if [[ -d "$APP_DIR" ]]; then
        cp -a "$APP_DIR" "$tmp/opt/"
    fi

    if [[ -d "$MASTER_ETC" ]]; then
        mkdir -p "$tmp/etc"
        cp -a "$MASTER_ETC" "$tmp/etc/"
    fi

    if [[ -f "$MASTER_SERVICE" ]]; then
        cp -a "$MASTER_SERVICE" "$tmp/etc/systemd/system/"
    fi

    if [[ -d "$DB_DIR" ]]; then
        find "$DB_DIR" -maxdepth 1 -type f ! -name 'central.db' ! -name 'central.db-wal' ! -name 'central.db-shm' -exec cp -a {} "$tmp/var/lib/ocserv-central/" \; 2>/dev/null || true
        find "$DB_DIR" -maxdepth 1 -type d ! -path "$DB_DIR" -exec cp -a {} "$tmp/var/lib/ocserv-central/" \; 2>/dev/null || true
    fi
}

sqlite_backup_to_tmp() {
    local tmp="$1"
    local mode="${2:-full}"
    local include_sessions="${3:-yes}"
    local db
    db="$(db_path)"

    mkdir -p "$tmp/var/lib/ocserv-central"

    if [[ ! -f "$db" ]]; then
        print_warn "Database not found, skipping DB backup: $db"
        return 0
    fi

    sqlite3 "$db" ".backup '$tmp/var/lib/ocserv-central/central.db'"

    if [[ "$mode" == "light" ]]; then
        sqlite3 "$tmp/var/lib/ocserv-central/central.db" "DELETE FROM usage_log; VACUUM;" || true
    fi

    if [[ "$include_sessions" == "no" ]]; then
        sqlite3 "$tmp/var/lib/ocserv-central/central.db" "DELETE FROM sessions; VACUUM;" || true
    fi
}

write_backup_metadata() {
    local tmp="$1"
    local btype="$2"

    cat > "$tmp/OCSERV_CENTRAL_BACKUP_INFO.txt" <<EOF
Backup type: $btype
Created at: $(date -Is)
Hostname: $(hostname -f 2>/dev/null || hostname)
Includes:
- /opt/ocserv-central
- /etc/ocserv-central
- /var/lib/ocserv-central
- /etc/systemd/system/ocserv-central.service

Notes:
- Full backup includes usage_log history.
- Lightweight backup keeps users, quotas, extra traffic, expiry dates, disabled status, limits, nodes and settings, but removes usage_log history to reduce size.
- Active sessions can be included or excluded depending on the selected backup option.
EOF
}

backup_master_lightweight() {
    need_root
    local out tmp include_sessions
    out="$(ask_value "Lightweight backup output file" "/root/ocserv-central-light-$(date +%Y%m%d-%H%M%S).tar.gz")"

    if ask_yes_no "Include current active sessions in backup?" "n"; then
        include_sessions="yes"
    else
        include_sessions="no"
    fi

    tmp="$(make_temp_backup_root)"
    copy_master_common_to_tmp "$tmp"
    sqlite_backup_to_tmp "$tmp" "light" "$include_sessions"
    write_backup_metadata "$tmp" "lightweight"

    mkdir -p "$(dirname "$out")"
    tar -czf "$out" -C "$tmp" .
    rm -rf "$tmp"

    print_ok "Lightweight backup saved: $out"
    print_info "This backup does NOT include usage_log history."
    print_info "It DOES include used_bytes, extra traffic, account expiry, disabled status, limits and node info."
    ls -lh "$out" 2>/dev/null || true
}

backup_master_recommended_default() {
    need_root
    local out tmp
    out="/root/ocserv-central-recommended-light-$(date +%Y%m%d-%H%M%S).tar.gz"

    print_info "Recommended default backup selected."
    print_info "This is a lightweight backup with NO usage_log history and NO active sessions."
    print_info "It DOES keep users.used_bytes, quota_extra_bytes, expires_at, disabled, limits.json, groups and user overrides."
    print_info "So if a user had 100GB quota and used 40GB, the restored DB still knows used_bytes=40GB."

    tmp="$(make_temp_backup_root)"
    copy_master_common_to_tmp "$tmp"
    sqlite_backup_to_tmp "$tmp" "light" "no"
    write_backup_metadata "$tmp" "recommended-lightweight-no-usage-log-no-sessions"

    mkdir -p "$(dirname "$out")"
    tar -czf "$out" -C "$tmp" .
    rm -rf "$tmp"

    print_ok "Recommended backup saved: $out"
    ls -lh "$out" 2>/dev/null || true
}

backup_master_config_only() {
    need_root
    local out
    out="$(ask_value "Config-only backup output file" "/root/ocserv-central-config-$(date +%Y%m%d-%H%M%S).tar.gz")"

    backup_paths_tar "$out" \
        "etc/ocserv-central" \
        "etc/systemd/system/ocserv-central.service"
}

backup_master_db_only() {
    need_root
    local out tmp mode include_sessions
    out="$(ask_value "DB-only backup output file" "/root/ocserv-central-db-$(date +%Y%m%d-%H%M%S).tar.gz")"

    if ask_yes_no "Make DB backup lightweight by excluding usage_log history?" "y"; then
        mode="light"
    else
        mode="full"
    fi

    if ask_yes_no "Include current active sessions in DB backup?" "n"; then
        include_sessions="yes"
    else
        include_sessions="no"
    fi

    tmp="$(make_temp_backup_root)"
    mkdir -p "$tmp/var/lib/ocserv-central"
    sqlite_backup_to_tmp "$tmp" "$mode" "$include_sessions"
    write_backup_metadata "$tmp" "db-only-$mode"

    mkdir -p "$(dirname "$out")"
    tar -czf "$out" -C "$tmp" .
    rm -rf "$tmp"

    print_ok "DB-only backup saved: $out"
    ls -lh "$out" 2>/dev/null || true
}

backup_master_custom() {
    need_root
    local out tmp db_mode include_sessions include_app include_config include_service include_exhausted
    out="$(ask_value "Custom backup output file" "/root/ocserv-central-custom-$(date +%Y%m%d-%H%M%S).tar.gz")"

    if ask_yes_no "Include app files /opt/ocserv-central ?" "y"; then include_app="yes"; else include_app="no"; fi
    if ask_yes_no "Include config /etc/ocserv-central ?" "y"; then include_config="yes"; else include_config="no"; fi
    if ask_yes_no "Include systemd service file ?" "y"; then include_service="yes"; else include_service="no"; fi
    if ask_yes_no "Include usage_log history? This can make backup very large." "n"; then db_mode="full"; else db_mode="light"; fi
    if ask_yes_no "Include active sessions?" "n"; then include_sessions="yes"; else include_sessions="no"; fi
    if ask_yes_no "Include exhausted-quota file if present?" "y"; then include_exhausted="yes"; else include_exhausted="no"; fi

    tmp="$(make_temp_backup_root)"
    mkdir -p "$tmp/opt" "$tmp/etc/systemd/system" "$tmp/var/lib/ocserv-central"

    if [[ "$include_app" == "yes" && -d "$APP_DIR" ]]; then
        cp -a "$APP_DIR" "$tmp/opt/"
    fi

    if [[ "$include_config" == "yes" && -d "$MASTER_ETC" ]]; then
        mkdir -p "$tmp/etc"
        cp -a "$MASTER_ETC" "$tmp/etc/"
    fi

    if [[ "$include_service" == "yes" && -f "$MASTER_SERVICE" ]]; then
        cp -a "$MASTER_SERVICE" "$tmp/etc/systemd/system/"
    fi

    sqlite_backup_to_tmp "$tmp" "$db_mode" "$include_sessions"

    if [[ "$include_exhausted" == "yes" && -f "$DB_DIR/quota_exhausted_users.jsonl" ]]; then
        cp -a "$DB_DIR/quota_exhausted_users.jsonl" "$tmp/var/lib/ocserv-central/"
    elif [[ "$include_exhausted" == "no" ]]; then
        rm -f "$tmp/var/lib/ocserv-central/quota_exhausted_users.jsonl"
    fi

    write_backup_metadata "$tmp" "custom-db-$db_mode"

    mkdir -p "$(dirname "$out")"
    tar -czf "$out" -C "$tmp" .
    rm -rf "$tmp"

    print_ok "Custom backup saved: $out"
    ls -lh "$out" 2>/dev/null || true
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
    print_warn "Recommended: take a full backup before restore."

    if ask_yes_no "Take a safety full backup before restore?" "y"; then
        local safety
        safety="/root/ocserv-central-before-restore-$(date +%Y%m%d-%H%M%S).tar.gz"
        backup_paths_tar "$safety" \
            "opt/ocserv-central" \
            "etc/ocserv-central" \
            "var/lib/ocserv-central" \
            "etc/systemd/system/ocserv-central.service"
    fi

    if ! ask_yes_no "Continue restore?" "n"; then
        return 0
    fi

    systemctl stop ocserv-central >/dev/null 2>&1 || true
    tar -xzf "$in" -C /
    systemctl daemon-reload
    systemctl enable --now ocserv-central >/dev/null 2>&1 || true

    print_ok "Restore completed."
    print_info "Check status with: systemctl status ocserv-central --no-pager"
}

cleanup_usage_logs() {
    need_root
    local db days cutoff before after stop_api do_vacuum
    db="$(db_path)"

    if [[ ! -f "$db" ]]; then
        print_err "Database not found: $db"
        return 1
    fi

    usage_log_stats
    echo

    days="$(ask_number "Delete usage_log records older than how many days? Use 0 to delete ALL usage_log history" "30")"

    if ask_yes_no "Take lightweight backup before cleanup?" "y"; then
        backup_master_lightweight
    fi

    if ask_yes_no "Stop ocserv-central API during cleanup? Safer for large DB." "y"; then
        stop_api="yes"
    else
        stop_api="no"
    fi

    if ask_yes_no "Run VACUUM after cleanup to shrink database file? Can take time on large DB." "y"; then
        do_vacuum="yes"
    else
        do_vacuum="no"
    fi

    if ! ask_yes_no "Continue cleanup?" "n"; then
        return 0
    fi

    before="$(sqlite3 "$db" "SELECT COUNT(*) FROM usage_log;" 2>/dev/null || echo 0)"

    if [[ "$stop_api" == "yes" ]]; then
        systemctl stop ocserv-central >/dev/null 2>&1 || true
    fi

    if [[ "$days" == "0" || "$days" == "0.0" ]]; then
        sqlite3 "$db" "DELETE FROM usage_log;"
    else
        cutoff="$(date -d "$days days ago" +%s)"
        sqlite3 "$db" "DELETE FROM usage_log WHERE created_at < $cutoff;"
    fi

    if [[ "$do_vacuum" == "yes" ]]; then
        sqlite3 "$db" "VACUUM;"
    fi

    if [[ "$stop_api" == "yes" ]]; then
        systemctl start ocserv-central >/dev/null 2>&1 || true
    fi

    after="$(sqlite3 "$db" "SELECT COUNT(*) FROM usage_log;" 2>/dev/null || echo 0)"

    print_ok "Cleanup done. usage_log rows: before=$before after=$after"
    usage_log_stats
}

cleanup_usage_log_default_now() {
    need_root
    local db before after cutoff
    db="$(db_path)"

    if [[ ! -f "$db" ]]; then
        print_err "Database not found: $db"
        return 1
    fi

    usage_log_stats
    echo
    print_warn "Default immediate cleanup + VACUUM will delete ALL usage_log rows from now and before."
    print_warn "It will NOT reset users.used_bytes, quota_extra_bytes, expires_at, disabled, limits.json or group/user quotas."
    print_info "This is useful when you only need current total usage, not detailed history."

    if ! ask_yes_no "Continue with default immediate usage_log cleanup?" "n"; then
        return 0
    fi

    if ask_yes_no "Take recommended lightweight backup first?" "y"; then
        backup_master_recommended_default
    fi

    before="$(sqlite3 "$db" "SELECT COUNT(*) FROM usage_log;" 2>/dev/null || echo 0)"
    cutoff="$(date +%s)"
    sqlite3 "$db" "DELETE FROM usage_log WHERE created_at <= $cutoff;"
    after="$(sqlite3 "$db" "SELECT COUNT(*) FROM usage_log;" 2>/dev/null || echo 0)"

    print_ok "Default cleanup done. usage_log rows: before=$before after=$after"
    print_info "Database file size may not shrink until you run VACUUM. For large cleanup, run option 9 later."
    print_info "Current user usage remains stored in users.used_bytes."
}

vacuum_database() {
    need_root
    local db
    db="$(db_path)"

    if [[ ! -f "$db" ]]; then
        print_err "Database not found: $db"
        return 1
    fi

    print_warn "VACUUM compacts the SQLite DB file. It may take time and lock the database."
    if ask_yes_no "Stop ocserv-central during VACUUM?" "y"; then
        systemctl stop ocserv-central >/dev/null 2>&1 || true
        sqlite3 "$db" "VACUUM;"
        systemctl start ocserv-central >/dev/null 2>&1 || true
    else
        sqlite3 "$db" "VACUUM;"
    fi

    print_ok "VACUUM completed."
    ls -lh "$db" 2>/dev/null || true
}

write_cleanup_script() {
    mkdir -p "$MASTER_ETC"

    cat > "$CLEANUP_SCRIPT" <<'CLEAN'
#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="/etc/ocserv-central/cleanup.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    . "$ENV_FILE"
fi

DB_PATH="${DB_PATH:-/var/lib/ocserv-central/central.db}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
VACUUM_AFTER="${VACUUM_AFTER:-0}"
STOP_API="${STOP_API:-0}"
BACKUP_BEFORE="${BACKUP_BEFORE:-0}"
BACKUP_DIR="${BACKUP_DIR:-/root}"

log() {
    logger -t ocserv-central-cleanup "$*"
    echo "$*"
}

if [[ ! -f "$DB_PATH" ]]; then
    log "Database not found: $DB_PATH"
    exit 0
fi

if [[ "$BACKUP_BEFORE" == "1" ]]; then
    out="$BACKUP_DIR/ocserv-central-auto-before-cleanup-$(date +%Y%m%d-%H%M%S).db"
    mkdir -p "$BACKUP_DIR"
    sqlite3 "$DB_PATH" ".backup '$out'"
    log "DB safety backup saved: $out"
fi

if [[ "$STOP_API" == "1" ]]; then
    systemctl stop ocserv-central >/dev/null 2>&1 || true
fi

before="$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM usage_log;" 2>/dev/null || echo 0)"

if [[ "$RETENTION_DAYS" == "0" || "$RETENTION_DAYS" == "0.0" ]]; then
    sqlite3 "$DB_PATH" "DELETE FROM usage_log;"
else
    cutoff="$(date -d "$RETENTION_DAYS days ago" +%s)"
    sqlite3 "$DB_PATH" "DELETE FROM usage_log WHERE created_at < $cutoff;"
fi

if [[ "$VACUUM_AFTER" == "1" ]]; then
    sqlite3 "$DB_PATH" "VACUUM;"
fi

after="$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM usage_log;" 2>/dev/null || echo 0)"

if [[ "$STOP_API" == "1" ]]; then
    systemctl start ocserv-central >/dev/null 2>&1 || true
fi

log "usage_log cleanup complete. retention_days=$RETENTION_DAYS before=$before after=$after vacuum=$VACUUM_AFTER"
CLEAN

    chmod +x "$CLEANUP_SCRIPT"
}

configure_auto_cleanup_timer() {
    need_root
    local days hour minute vacuum stop_api backup_before backup_dir

    days="$(ask_number "Keep usage_log history for how many days? 0 = delete all history each run" "30")"
    hour="$(ask_number "Run cleanup daily at hour 0-23" "3")"
    minute="$(ask_number "Run cleanup daily at minute 0-59" "15")"

    if ask_yes_no "Run VACUUM after automatic cleanup? This can take time." "n"; then vacuum="1"; else vacuum="0"; fi
    if ask_yes_no "Stop ocserv-central API during automatic cleanup? Safer, but brief downtime." "n"; then stop_api="1"; else stop_api="0"; fi
    if ask_yes_no "Take DB safety backup before automatic cleanup?" "n"; then backup_before="1"; else backup_before="0"; fi

    backup_dir="$(ask_value "Directory for automatic safety DB backups" "/root")"

    mkdir -p "$MASTER_ETC"

    cat > "$CLEANUP_ENV" <<EOF
DB_PATH="$DB_DIR/central.db"
RETENTION_DAYS="$days"
VACUUM_AFTER="$vacuum"
STOP_API="$stop_api"
BACKUP_BEFORE="$backup_before"
BACKUP_DIR="$backup_dir"
EOF
    chmod 600 "$CLEANUP_ENV"

    write_cleanup_script

    cat > "$CLEANUP_SERVICE" <<EOF
[Unit]
Description=Ocserv Central usage_log cleanup

[Service]
Type=oneshot
ExecStart=$CLEANUP_SCRIPT
EOF

    cat > "$CLEANUP_TIMER" <<EOF
[Unit]
Description=Run Ocserv Central usage_log cleanup daily

[Timer]
OnCalendar=*-*-* $(printf "%02d" "$hour"):$(printf "%02d" "$minute"):00
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now ocserv-central-cleanup.timer

    print_ok "Automatic cleanup timer configured."
    systemctl list-timers ocserv-central-cleanup.timer --no-pager || true
}

disable_auto_cleanup_timer() {
    systemctl disable --now ocserv-central-cleanup.timer >/dev/null 2>&1 || true
    rm -f "$CLEANUP_TIMER" "$CLEANUP_SERVICE"
    systemctl daemon-reload
    print_ok "Automatic cleanup timer disabled and removed."
}

show_cleanup_timer_status() {
    echo
    print_info "Cleanup env:"
    if [[ -f "$CLEANUP_ENV" ]]; then
        cat "$CLEANUP_ENV"
    else
        print_warn "No cleanup env found: $CLEANUP_ENV"
    fi

    echo
    print_info "Timer status:"
    systemctl status ocserv-central-cleanup.timer --no-pager || true

    echo
    print_info "Recent cleanup logs:"
    journalctl -t ocserv-central-cleanup -n 80 --no-pager || true
}


default_cleanup_usage_log_with_vacuum() {
    need_root
    local db="$DB_DIR/central.db"
    if [[ ! -f "$db" ]]; then
        print_err "Database not found: $db"
        return 1
    fi

    print_warn "This default cleanup will delete ALL usage_log history and then run VACUUM."
    print_info "It does NOT reset users.used_bytes."
    print_info "It does NOT delete account expiry, extra traffic, disabled status, users, groups, or limits."
    print_info "Only detailed usage_log history is removed. Final user usage remains in users.used_bytes."
    echo

    if ! ask_yes_no "Take lightweight backup before default cleanup + VACUUM?" "y"; then
        print_warn "Continuing without backup."
    else
        backup_master_lightweight
    fi

    if ! ask_yes_no "Continue default cleanup now?" "n"; then
        return 0
    fi

    print_info "Stopping ocserv-central API for safer cleanup and VACUUM..."
    systemctl stop ocserv-central >/dev/null 2>&1 || true

    local before after
    before="$(sqlite3 "$db" "SELECT COUNT(*) FROM usage_log;" 2>/dev/null || echo 0)"

    print_info "Deleting usage_log rows..."
    sqlite3 "$db" "DELETE FROM usage_log;" || true

    after="$(sqlite3 "$db" "SELECT COUNT(*) FROM usage_log;" 2>/dev/null || echo 0)"

    print_info "Running VACUUM to compact database file..."
    sqlite3 "$db" "VACUUM;" || true

    print_info "Starting ocserv-central API..."
    systemctl start ocserv-central >/dev/null 2>&1 || true

    print_ok "Default cleanup + VACUUM completed. usage_log rows: before=$before after=$after"
    ls -lh "$db" 2>/dev/null || true
}

backup_cleanup_menu() {
    while true; do
        clear
        echo "==== Ocserv Central - Backup / Restore / Cleanup Menu ===="
        echo "1) Show database and usage_log statistics"
        echo "2) Full backup: app + config + full database + full usage history"
        echo "3) Lightweight backup: app + config + database without usage_log history"
        echo "4) Config-only backup"
        echo "5) DB-only backup"
        echo "6) Custom backup"
        echo "7) Restore backup"
        echo "8) Cleanup old usage_log records manually"
        echo "9) VACUUM / compact database"
        echo "10) Configure automatic usage_log cleanup timer"
        echo "11) Disable automatic cleanup timer"
        echo "12) Show automatic cleanup timer status/logs"
        echo "13) RECOMMENDED default backup: lightweight, keeps current usage, removes usage_log history"
        echo "14) DEFAULT cleanup now: delete all usage_log history + VACUUM"
        echo "0) Back"
        echo
        read -rp "Select: " choice
        case "$choice" in
            1) usage_log_stats; pause ;;
            2) backup_master_full; pause ;;
            3) backup_master_lightweight; pause ;;
            4) backup_master_config_only; pause ;;
            5) backup_master_db_only; pause ;;
            6) backup_master_custom; pause ;;
            7) restore_master_data; pause ;;
            8) cleanup_usage_logs; pause ;;
            9) vacuum_database; pause ;;
            10) configure_auto_cleanup_timer; pause ;;
            11) disable_auto_cleanup_timer; pause ;;
            12) show_cleanup_timer_status; pause ;;
            13) backup_master_recommended_default; pause ;;
            14) default_cleanup_usage_log_with_vacuum; pause ;;
            0) return 0 ;;
            *) echo "Invalid choice"; sleep 1 ;;
        esac
    done
}

# Backward-compatible wrappers used by older menu/readme wording.
backup_master_data() {
    backup_cleanup_menu
}

remove_helper_packages() {
    print_warn "The script installed helper packages such as jq, sqlite3, python3-venv, python3-pip, gawk, openssl, ca-certificates."
    print_warn "Some of these packages may be used by other services. Removing them can break unrelated scripts."
    if ask_yes_no "Remove only safer helper packages: jq sqlite3 gawk python3-venv python3-pip?" "n"; then
        apt purge -y jq sqlite3 gawk python3-venv python3-pip || true
        apt autoremove -y || true
    fi
}

bulk_set_all_group_quota() {
    local gb
    gb="$(ask_number "Set traffic quota for ALL groups in GB, 0 = unlimited" "100")"
    master_curl "POST" "/bulk/set-all-group-quota" "{\"gb\":$gb}"
}

bulk_remove_all_group_quota() {
    print_warn "This makes all group quotas unlimited by setting quota_gb=0 for all known groups and default_quota_gb=0."
    if ! ask_yes_no "Continue?" "n"; then
        return 0
    fi
    master_curl "POST" "/bulk/remove-all-group-quota" "{}"
}

bulk_add_traffic_all_users() {
    local gb clear
    gb="$(ask_number "Traffic to ADD to ALL users in GB" "10")"
    if ask_yes_no "Reset exhausted-quota file after adding traffic to all users?" "y"; then clear="true"; else clear="false"; fi
    master_curl "POST" "/bulk/add-traffic-all-users" "{\"gb\":$gb,\"clear_exhausted\":$clear}"
}

bulk_decrease_traffic_all_users() {
    local gb
    gb="$(ask_number "EXTRA traffic to DECREASE from ALL users in GB" "10")"
    print_warn "This decreases only quota_extra_bytes for all users and clamps every result at zero."
    print_warn "Group quotas and manual user quota overrides are not changed."
    if ! ask_yes_no "Continue bulk decrease?" "n"; then
        return 0
    fi
    master_curl "POST" "/bulk/decrease-traffic-all-users" "{\"gb\":$gb,\"clear_exhausted\":true}"
}

bulk_set_extra_traffic_all_users() {
    local gb clear
    gb="$(ask_number "Set exact EXTRA traffic for ALL users in GB" "0")"
    if ask_yes_no "Reset exhausted-quota file after changing extra traffic?" "y"; then clear="true"; else clear="false"; fi
    master_curl "POST" "/bulk/set-extra-traffic-all-users" "{\"gb\":$gb,\"clear_exhausted\":$clear}"
}

bulk_clear_extra_traffic_all_users() {
    print_warn "This removes all previously added EXTRA traffic from every user. Base group quota remains unchanged."
    if ! ask_yes_no "Continue?" "n"; then
        return 0
    fi
    master_curl "POST" "/bulk/clear-extra-traffic-all-users" "{}"
}

bulk_reset_usage_all_users() {
    print_warn "This resets used traffic for ALL users to zero and resets the exhausted-quota file."
    if ! ask_yes_no "Continue?" "n"; then
        return 0
    fi
    master_curl "POST" "/bulk/reset-usage-all-users" "{}"
}

bulk_traffic_menu() {
    while true; do
        clear
        echo "==== Ocserv Central - Bulk Traffic / Quota Menu ===="
        echo "1) Set one traffic quota for ALL groups"
        echo "2) Remove traffic quota from ALL groups, make unlimited"
        echo "3) Add extra traffic to ALL users"
        echo "4) Set exact extra traffic for ALL users"
        echo "5) Clear extra traffic from ALL users"
        echo "6) Reset used traffic for ALL users"
        echo "7) Show users"
        echo "8) Show current limits.json"
        echo "9) Decrease extra traffic from ALL users"
        echo "0) Back"
        echo
        read -rp "Select: " choice
        case "$choice" in
            1) bulk_set_all_group_quota; pause ;;
            2) bulk_remove_all_group_quota; pause ;;
            3) bulk_add_traffic_all_users; pause ;;
            4) bulk_set_extra_traffic_all_users; pause ;;
            5) bulk_clear_extra_traffic_all_users; pause ;;
            6) bulk_reset_usage_all_users; pause ;;
            7) list_users; pause ;;
            8) ensure_limits_file; jq . "$MASTER_ETC/limits.json"; pause ;;
            9) bulk_decrease_traffic_all_users; pause ;;
            0) return 0 ;;
            *) echo "Invalid choice"; sleep 1 ;;
        esac
    done
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


# =========================
# v6: group/user quota editing helpers
# =========================

get_master_ocpasswd_path() {
    local ocp
    ocp="$(systemctl show ocserv-central -p Environment --value 2>/dev/null | tr ' ' '\n' | sed -n 's/^OCPASSWD_PATH=//p' | tail -n1 || true)"
    echo "${ocp:-/etc/ocserv/ocpasswd}"
}

reset_exhausted_file_optional() {
    if ask_yes_no "Reset exhausted-quota file after this change?" "y"; then
        mkdir -p "$DB_DIR"
        : > "$DB_DIR/quota_exhausted_users.jsonl"
        print_ok "Exhausted-quota file reset."
    fi
}

reset_usage_for_group_sqlite() {
    local group="$1"
    local db="$DB_DIR/central.db"

    if [[ ! -f "$db" ]]; then
        print_warn "Database not found: $db"
        return 0
    fi

    python3 - "$db" "$group" <<'PYRESETGROUP'
import sqlite3
import sys
import time
import uuid

db_path = sys.argv[1]
groupname = sys.argv[2]
t = int(time.time())
batch_id = f"reset-{t}-{uuid.uuid4().hex[:10]}"

con = sqlite3.connect(db_path, timeout=30)
try:
    con.execute("BEGIN IMMEDIATE")
    con.execute("""
        CREATE TABLE IF NOT EXISTS usage_reset_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            target TEXT,
            username TEXT NOT NULL,
            old_used_bytes INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            note TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_usage_reset_snapshots_batch ON usage_reset_snapshots(batch_id)")
    rows = con.execute(
        "SELECT username, used_bytes FROM users WHERE groupname=? ORDER BY username",
        (groupname,),
    ).fetchall()
    con.executemany(
        """
        INSERT INTO usage_reset_snapshots(batch_id, scope, target, username, old_used_bytes, created_at, note)
        VALUES (?, 'group', ?, ?, ?, ?, 'Group usage reset from manager')
        """,
        [(batch_id, groupname, r[0], int(r[1] or 0), t) for r in rows],
    )
    cur = con.execute(
        "UPDATE users SET used_bytes=0, updated_at=? WHERE groupname=?",
        (t, groupname),
    )
    con.commit()
    print(f"Recovery snapshot created: batch_id={batch_id} users={len(rows)}", file=sys.stderr)
    print(cur.rowcount)
except Exception:
    con.rollback()
    raise
finally:
    con.close()
PYRESETGROUP
}

reset_usage_for_user_sqlite() {
    local username="$1"
    local db="$DB_DIR/central.db"

    if [[ ! -f "$db" ]]; then
        print_warn "Database not found: $db"
        return 0
    fi

    python3 - "$db" "$username" <<'PYRESETUSER'
import sqlite3
import sys
import time
import uuid

db_path = sys.argv[1]
username = sys.argv[2]
t = int(time.time())
batch_id = f"reset-{t}-{uuid.uuid4().hex[:10]}"

con = sqlite3.connect(db_path, timeout=30)
try:
    con.execute("BEGIN IMMEDIATE")
    con.execute("""
        CREATE TABLE IF NOT EXISTS usage_reset_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            target TEXT,
            username TEXT NOT NULL,
            old_used_bytes INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            note TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_usage_reset_snapshots_batch ON usage_reset_snapshots(batch_id)")
    row = con.execute(
        "SELECT username, used_bytes FROM users WHERE username=?",
        (username,),
    ).fetchone()
    if row:
        con.execute(
            """
            INSERT INTO usage_reset_snapshots(batch_id, scope, target, username, old_used_bytes, created_at, note)
            VALUES (?, 'user', ?, ?, ?, ?, 'Single-user usage reset from manager')
            """,
            (batch_id, username, row[0], int(row[1] or 0), t),
        )
    cur = con.execute(
        "UPDATE users SET used_bytes=0, updated_at=? WHERE username=?",
        (t, username),
    )
    con.commit()
    print(f"Recovery snapshot created: batch_id={batch_id} users={1 if row else 0}", file=sys.stderr)
    print(cur.rowcount)
except Exception:
    con.rollback()
    raise
finally:
    con.close()
PYRESETUSER
}

count_users_in_group() {
    local group="$1"
    local db="$DB_DIR/central.db"
    if [[ ! -f "$db" ]]; then
        echo "0"
        return 0
    fi

    python3 - "$db" "$group" <<'PYCOUNTGROUP'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
try:
    row = con.execute("SELECT COUNT(*) FROM users WHERE groupname=?", (sys.argv[2],)).fetchone()
    print(row[0] if row else 0)
finally:
    con.close()
PYCOUNTGROUP
}

list_group_limits() {
    ensure_limits_file

    local ocp
    ocp="$(get_master_ocpasswd_path)"

    echo
    print_info "Groups found in ocpasswd and limits.json:"
    python3 - "$MASTER_ETC/limits.json" "$ocp" "$DB_DIR/central.db" <<'PYLISTGROUPS'
import json
import os
import re
import sqlite3
import sys

limits_path, ocp_path, db_path = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    with open(limits_path, "r", encoding="utf-8") as f:
        limits = json.load(f)
except Exception:
    limits = {"default_quota_gb": 0, "groups": {}}

groups = set(limits.get("groups", {}).keys())

if os.path.exists(ocp_path):
    with open(ocp_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":", 2)
            if len(parts) >= 2:
                for g in parts[1].split(","):
                    g = g.strip()
                    if g:
                        groups.add(g)

counts = {}
if os.path.exists(db_path):
    con = sqlite3.connect(db_path)
    try:
        for g, c in con.execute("SELECT groupname, COUNT(*) FROM users GROUP BY groupname"):
            counts[g or ""] = c
    except Exception:
        pass
    finally:
        con.close()

def group_num(g):
    s = (g or "").strip().lower()
    if s in ("*", "unlimited", "unlimit", "nolimit", "no-limit", "no_limit", "all"):
        return 0
    m = re.search(r"(\d+)", g or "")
    return int(m.group(1)) if m else 1

print(f"{'GROUP':<24} {'MAX_SESS':<10} {'QUOTA_GB':<12} {'USERS':<8} SOURCE")
print("-" * 72)

for g in sorted(groups):
    cfg = limits.get("groups", {}).get(g, {})
    max_sess = cfg.get("max_sessions", group_num(g))
    quota = cfg.get("quota_gb", limits.get("default_quota_gb", 0))
    source = "limits.json" if g in limits.get("groups", {}) else "ocpasswd/default"
    print(f"{g:<24} {str(max_sess):<10} {str(quota):<12} {str(counts.get(g, 0)):<8} {source}")
PYLISTGROUPS
}

sync_new_groups_from_ocpasswd_only() {
    ensure_limits_file

    local ocp
    ocp="$(ask_value "ocpasswd path" "$(get_master_ocpasswd_path)")"

    if [[ ! -f "$ocp" ]]; then
        print_err "ocpasswd not found: $ocp"
        return 1
    fi

    mapfile -t groups < <(extract_groups_from_ocpasswd "$ocp")

    if [[ "${#groups[@]}" -eq 0 ]]; then
        print_warn "No groups found in $ocp"
        return 0
    fi

    local added=0 skipped=0 g exists def_sessions max_sessions quota_gb current_default tmp

    current_default="$(jq -r '.default_quota_gb // 0' "$MASTER_ETC/limits.json")"

    for g in "${groups[@]}"; do
        if jq -e --arg g "$g" '.groups | has($g)' "$MASTER_ETC/limits.json" >/dev/null; then
            print_info "Skipping existing group without changing settings: $g"
            skipped=$((skipped + 1))
            continue
        fi

        echo
        print_info "New group found: $g"
        def_sessions="$(group_default_sessions "$g")"
        max_sessions="$(ask_number "Max concurrent sessions for NEW group $g, 0 = unlimited" "$def_sessions")"
        quota_gb="$(ask_number "Quota for NEW group $g in GB, 0 = unlimited" "$current_default")"

        tmp="$(mktemp)"
        jq --arg g "$g" --argjson ms "$max_sessions" --argjson q "$quota_gb" \
            '.groups[$g] = {"max_sessions": $ms, "quota_gb": $q}' \
            "$MASTER_ETC/limits.json" > "$tmp"
        mv "$tmp" "$MASTER_ETC/limits.json"

        added=$((added + 1))
        print_ok "Added new group: $g"
    done

    print_ok "New group sync completed. added=$added skipped_existing=$skipped"
    print_info "Existing group settings were not changed."
}


group_manual_quota_overrides_json() {
    local group="$1"
    local action="${2:-list}"
    local db="$DB_DIR/central.db"
    local limits="$MASTER_ETC/limits.json"

    python3 - "$db" "$limits" "$group" "$action" <<'PYGROUPOVERRIDE'
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time

DB, LIMITS, GROUP, ACTION = sys.argv[1:5]
result = {"group": GROUP, "count": 0, "users": [], "action": ACTION}

if not os.path.exists(DB) or not os.path.exists(LIMITS):
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0)

with open(LIMITS, "r", encoding="utf-8") as f:
    limits = json.load(f)

with sqlite3.connect(DB, timeout=20) as con:
    members = {r[0] for r in con.execute("SELECT username FROM users WHERE groupname=?", (GROUP,))}

users_cfg = limits.setdefault("users", {})
affected = []
for username in sorted(members):
    cfg = users_cfg.get(username)
    if isinstance(cfg, dict) and "quota_gb" in cfg:
        affected.append({
            "username": username,
            "quota_gb": cfg.get("quota_gb"),
            "max_sessions": cfg.get("max_sessions"),
        })

result["count"] = len(affected)
result["users"] = affected

if ACTION == "remove-quota" and affected:
    backup = LIMITS + ".before-group-override-change-" + time.strftime("%Y%m%d-%H%M%S")
    shutil.copy2(LIMITS, backup)
    for item in affected:
        username = item["username"]
        cfg = users_cfg.get(username, {})
        cfg.pop("quota_gb", None)
        if cfg:
            users_cfg[username] = cfg
        else:
            users_cfg.pop(username, None)

    parent = os.path.dirname(LIMITS) or "."
    fd, tmp = tempfile.mkstemp(prefix="limits.", suffix=".json", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(limits, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, LIMITS)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    result["backup"] = backup
    result["removed_quota_overrides"] = len(affected)

print(json.dumps(result, ensure_ascii=False))
PYGROUPOVERRIDE
}

handle_group_manual_quota_overrides() {
    local group="$1"
    local new_quota="$2"
    local info count choice result

    info="$(group_manual_quota_overrides_json "$group" "list")"
    count="$(jq -r '.count // 0' <<<"$info")"
    [[ "$count" =~ ^[0-9]+$ ]] || count=0
    if (( count == 0 )); then
        return 0
    fi

    echo
    print_warn "$count user(s) in group $group have a manually configured quota override."
    print_info "The new group quota is ${new_quota} GB, but manual user quotas take priority."
    jq -r '.users[] | " - \(.username): manual_quota_gb=\(.quota_gb), max_sessions_override=\(.max_sessions // "none")"' <<<"$info"
    echo
    echo "How should these manually configured users be handled?"
    echo "1) Keep their manual quota overrides; the group quota will NOT replace their manual volume"
    echo "2) Apply the new group quota to them; remove only quota_gb override"
    echo "   Any manual max_sessions override will be preserved"
    read -rp "Select [1]: " choice
    choice="${choice:-1}"

    case "$choice" in
        2)
            result="$(group_manual_quota_overrides_json "$group" "remove-quota")"
            print_ok "Removed manual quota override from $(jq -r '.removed_quota_overrides // 0' <<<"$result") user(s)."
            print_info "New group quota now applies to those users immediately."
            print_info "limits.json safety backup: $(jq -r '.backup // "not-created"' <<<"$result")"
            ;;
        *)
            print_ok "Manual user quota overrides kept. Group quota applies only to users without manual quota override."
            ;;
    esac
}

edit_one_group_quota() {
    ensure_limits_file

    local group max_sessions quota_gb current_ms current_q def_ms tmp reset_choice users_count

    list_group_limits
    echo
    group="$(ask_value "Group name to edit, example group2" "")"
    [[ -z "$group" ]] && return 0

    def_ms="$(group_default_sessions "$group")"
    current_ms="$(jq -r --arg g "$group" '.groups[$g].max_sessions // empty' "$MASTER_ETC/limits.json")"
    current_q="$(jq -r --arg g "$group" '.groups[$g].quota_gb // .default_quota_gb // 0' "$MASTER_ETC/limits.json")"
    current_ms="${current_ms:-$def_ms}"

    echo
    print_info "Editing group: $group"
    print_info "Current max_sessions: $current_ms"
    print_info "Current quota_gb: $current_q"

    max_sessions="$(ask_number "New max concurrent sessions for $group, 0 = unlimited" "$current_ms")"
    quota_gb="$(ask_number "New quota for $group in GB, 0 = unlimited" "$current_q")"

    tmp="$(mktemp)"
    jq --arg g "$group" --argjson ms "$max_sessions" --argjson q "$quota_gb" \
        '.groups[$g] = {"max_sessions": $ms, "quota_gb": $q}' \
        "$MASTER_ETC/limits.json" > "$tmp"
    mv "$tmp" "$MASTER_ETC/limits.json"

    handle_group_manual_quota_overrides "$group" "$quota_gb"

    users_count="$(count_users_in_group "$group")"

    echo
    print_warn "This group has $users_count synced users in central DB."
    echo "How should existing used traffic be handled?"
    echo "1) Keep used traffic and apply the new quota immediately"
    echo "   Example: user used 80GB, new quota 100GB => remaining 20GB"
    echo "2) Reset used traffic for users in this group to 0"
    echo "   Example: user used 80GB, new quota 100GB => remaining 100GB"
    read -rp "Select [1]: " reset_choice
    reset_choice="${reset_choice:-1}"

    case "$reset_choice" in
        2)
            local changed
            changed="$(reset_usage_for_group_sqlite "$group" | tail -n1)"
            print_ok "Used traffic reset to 0 for users in $group. rows_changed=${changed:-0}"
            reset_exhausted_file_optional
            ;;
        *)
            print_ok "Existing used traffic kept. New quota applies against already-used traffic."
            print_warn "If a user already used more than the new quota, they may be denied or disconnected on next check."
            reset_exhausted_file_optional
            ;;
    esac

    print_ok "Group quota/settings updated for $group."
    print_info "No restart is usually required because the API reads limits.json on each check."
}

remove_one_group_quota() {
    ensure_limits_file

    local group current_ms tmp choice
    list_group_limits
    echo
    group="$(ask_value "Group name to make unlimited, example group2" "")"
    [[ -z "$group" ]] && return 0

    current_ms="$(jq -r --arg g "$group" '.groups[$g].max_sessions // empty' "$MASTER_ETC/limits.json")"
    current_ms="${current_ms:-$(group_default_sessions "$group")}"

    print_warn "This will set quota_gb=0 for $group, meaning unlimited traffic for this group."
    if ! ask_yes_no "Continue?" "n"; then
        return 0
    fi

    tmp="$(mktemp)"
    jq --arg g "$group" --argjson ms "$current_ms" \
        '.groups[$g] = {"max_sessions": $ms, "quota_gb": 0}' \
        "$MASTER_ETC/limits.json" > "$tmp"
    mv "$tmp" "$MASTER_ETC/limits.json"

    handle_group_manual_quota_overrides "$group" "0 (unlimited)"

    if ask_yes_no "Reset used traffic for users in this group too?" "n"; then
        reset_usage_for_group_sqlite "$group" >/dev/null
        print_ok "Used traffic reset for users in $group."
    fi

    reset_exhausted_file_optional
    print_ok "Group $group is now unlimited."
}

reset_usage_for_one_group_menu() {
    local group changed
    list_group_limits
    echo
    group="$(ask_value "Group name to reset used traffic for, example group2" "")"
    [[ -z "$group" ]] && return 0

    print_warn "This will reset used traffic to 0 for all synced users in group: $group"
    if ! ask_yes_no "Continue?" "n"; then
        return 0
    fi

    changed="$(reset_usage_for_group_sqlite "$group" | tail -n1)"
    print_ok "Used traffic reset for group $group. rows_changed=${changed:-0}"
    reset_exhausted_file_optional
}

group_quota_menu() {
    while true; do
        clear
        echo "==== Ocserv Central - Group Quota / New Group Menu ===="
        echo "1) List group limits and user counts"
        echo "2) Add/sync NEW groups from ocpasswd only, keep old group settings"
        echo "3) Edit ONE group quota/sessions and choose used-traffic handling"
        echo "4) Make ONE group unlimited, keep sessions"
        echo "5) Reset used traffic for ONE group"
        echo "6) Configure ALL groups from ocpasswd, may edit existing groups too"
        echo "7) Show current limits.json"
        echo "0) Back"
        echo
        read -rp "Select: " choice
        case "$choice" in
            1) list_group_limits; pause ;;
            2) sync_new_groups_from_ocpasswd_only; pause ;;
            3) edit_one_group_quota; pause ;;
            4) remove_one_group_quota; pause ;;
            5) reset_usage_for_one_group_menu; pause ;;
            6)
                local ocp
                ocp="$(ask_value "ocpasswd path" "$(get_master_ocpasswd_path)")"
                configure_groups_from_ocpasswd "$ocp"
                pause
                ;;
            7) ensure_limits_file; jq . "$MASTER_ETC/limits.json"; pause ;;
            0) return 0 ;;
            *) echo "Invalid choice"; sleep 1 ;;
        esac
    done
}

# v6 override: adds used-traffic handling after editing a user's quota.
edit_user_override() {
    ensure_limits_file
    local u max_sessions quota tmp
    u="$(ask_value "Username" "")"
    [[ -z "$u" ]] && return 0

    local current_ms current_q
    current_ms="$(jq -r --arg u "$u" '.users[$u].max_sessions // 0' "$MASTER_ETC/limits.json")"
    current_q="$(jq -r --arg u "$u" '.users[$u].quota_gb // 0' "$MASTER_ETC/limits.json")"

    echo
    print_info "Editing user override: $u"
    echo "If max sessions is 0, the user uses group default. Use -1 for unlimited sessions."
    echo "If quota is 0 in user override, it means unlimited for this user override."
    echo

    max_sessions="$(ask_number "User max sessions, 0 = use group default, -1 = unlimited" "$current_ms")"
    quota="$(ask_number "User quota GB, 0 = unlimited for this user override" "$current_q")"

    tmp="$(mktemp)"
    if [[ "$max_sessions" == "0" || "$max_sessions" == "0.0" ]]; then
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

    echo
    echo "How should this user's already-used traffic be handled?"
    echo "1) Keep used traffic and apply the new user quota immediately"
    echo "   Example: user used 80GB, new quota 100GB => remaining 20GB"
    echo "2) Reset used traffic for this user to 0"
    echo "   Example: user used 80GB, new quota 100GB => remaining 100GB"
    read -rp "Select [1]: " reset_choice
    reset_choice="${reset_choice:-1}"

    case "$reset_choice" in
        2)
            reset_usage_for_user_sqlite "$u" >/dev/null
            print_ok "Used traffic reset to 0 for user: $u"
            reset_exhausted_file_optional
            ;;
        *)
            print_ok "Existing used traffic kept. New user quota applies against already-used traffic."
            print_warn "If this user already used more than the new quota, they may be denied or disconnected on next check."
            reset_exhausted_file_optional
            ;;
    esac

    print_info "No restart is usually required because the API reads limits.json on each check."
}



# =========================
# v9: database user cleanup / ocpasswd prune
# =========================

db_user_cleanup_python() {
    local mode="$1"
    local days="${2:-90}"
    local include_ocpasswd="${3:-0}"
    local apply="${4:-0}"
    local ocp="${5:-}"
    local db="$DB_DIR/central.db"

    if [[ -z "$ocp" ]]; then
        ocp="$(get_master_ocpasswd_path)"
    fi

    if [[ ! -f "$db" ]]; then
        print_err "Database not found: $db"
        return 1
    fi

    python3 - "$db" "$ocp" "$mode" "$days" "$include_ocpasswd" "$apply" <<'PYCLEANDB'
import os
import sqlite3
import sys
import time
from pathlib import Path

db_path, ocp_path, mode, days_s, include_ocpasswd_s, apply_s = sys.argv[1:7]
days = int(float(days_s))
include_ocpasswd = include_ocpasswd_s == "1"
apply = apply_s == "1"
now = int(time.time())
cutoff = now - days * 86400

def read_ocpasswd_users(path):
    users = set()
    if not path or not os.path.exists(path):
        return users
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":", 2)
            if len(parts) >= 1 and parts[0].strip():
                users.add(parts[0].strip())
    return users

def table_exists(con, table):
    return con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone() is not None

def columns(con, table):
    try:
        return [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]
    except Exception:
        return []

def max_col(con, table, username, col):
    try:
        r = con.execute(
            f'SELECT MAX("{col}") FROM "{table}" WHERE username=?',
            (username,),
        ).fetchone()
        if r and r[0] is not None:
            try:
                return int(float(r[0]))
            except Exception:
                return None
    except Exception:
        return None
    return None

def last_activity(con, username):
    candidates = []

    if table_exists(con, "sessions"):
        cols = columns(con, "sessions")
        if "username" in cols:
            for col in ("last_seen", "ended_at", "disconnected_at", "updated_at", "started_at", "created_at"):
                if col in cols:
                    v = max_col(con, "sessions", username, col)
                    if v:
                        candidates.append(v)

    if table_exists(con, "usage_log"):
        cols = columns(con, "usage_log")
        if "username" in cols:
            for col in ("created_at", "updated_at", "ts", "time"):
                if col in cols:
                    v = max_col(con, "usage_log", username, col)
                    if v:
                        candidates.append(v)

    # users.updated_at is intentionally NOT used as primary activity because sync_ocpasswd may update it.
    # It is only useful for display if the user never had sessions/usage.
    return max(candidates) if candidates else 0

def fmt_ts(ts):
    if not ts:
        return "never"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return str(ts)

def get_db_users(con):
    if not table_exists(con, "users"):
        return []
    cols = columns(con, "users")
    extra = []
    for col in ("groupname", "used_bytes", "quota_extra_bytes", "expires_at", "disabled", "updated_at"):
        if col in cols:
            extra.append(col)
    select_cols = ["username"] + extra
    q = 'SELECT ' + ', '.join(f'"{c}"' for c in select_cols) + ' FROM users ORDER BY username'
    rows = con.execute(q).fetchall()
    return select_cols, rows

def delete_username_everywhere(con, username):
    deleted = {}
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for table in tables:
        cols = columns(con, table)
        col = None
        if "username" in cols:
            col = "username"
        elif "user" in cols:
            col = "user"
        if not col:
            continue
        cur = con.execute(f'DELETE FROM "{table}" WHERE "{col}"=?', (username,))
        deleted[table] = cur.rowcount
    return deleted

ocp_users = read_ocpasswd_users(ocp_path)
con = sqlite3.connect(db_path, timeout=30)
con.row_factory = sqlite3.Row

try:
    if not table_exists(con, "users"):
        print("ERROR: users table not found.")
        sys.exit(1)

    select_cols, rows = get_db_users(con)
    db_usernames = [r["username"] for r in rows]
    missing = sorted([u for u in db_usernames if u not in ocp_users])

    if mode == "stats":
        print("Database user cleanup statistics")
        print("--------------------------------")
        print(f"DB users: {len(db_usernames)}")
        print(f"ocpasswd users: {len(ocp_users)}")
        print(f"DB users missing from ocpasswd: {len(missing)}")
        print(f"ocpasswd path: {ocp_path}")
        print()
        print("Important:")
        print("- Users missing from ocpasswd are stale/orphan DB users.")
        print("- If a user still exists in ocpasswd and you delete them only from DB, next sync can recreate them.")
        sys.exit(0)

    if mode in ("list_missing", "delete_missing"):
        target = missing
        title = "DB users missing from ocpasswd"
    elif mode in ("list_inactive", "delete_inactive_missing", "delete_inactive_all"):
        inactive = []
        ocp_set = ocp_users
        for u in db_usernames:
            la = last_activity(con, u)
            is_inactive = (la == 0) or (la < cutoff)
            if not is_inactive:
                continue
            in_ocp = u in ocp_set
            if mode == "delete_inactive_missing" and in_ocp:
                continue
            if mode == "delete_inactive_all":
                # include_ocpasswd controls whether users still in ocpasswd can be deleted.
                if in_ocp and not include_ocpasswd:
                    continue
            inactive.append((u, la, in_ocp))
        target = [x[0] for x in inactive]
        title = f"Inactive DB users older than {days} days"
    else:
        print(f"ERROR: unknown mode: {mode}")
        sys.exit(1)

    if mode.startswith("list"):
        print(title)
        print("-" * 90)
        if not target:
            print("No matching users found.")
            sys.exit(0)

        print(f"{'USERNAME':<28} {'IN_OCPASSWD':<12} {'LAST_ACTIVITY':<20} {'AGE_DAYS':<10}")
        print("-" * 90)
        for u in target[:500]:
            la = last_activity(con, u)
            age = "never" if not la else str(int((now - la) / 86400))
            print(f"{u:<28} {str(u in ocp_users):<12} {fmt_ts(la):<20} {age:<10}")
        if len(target) > 500:
            print(f"... truncated. total={len(target)}")
        sys.exit(0)

    if mode.startswith("delete"):
        if not target:
            print("No matching users to delete.")
            sys.exit(0)

        print(f"Users selected for deletion: {len(target)}")
        for u in target[:100]:
            la = last_activity(con, u)
            print(f"- {u} | in_ocpasswd={u in ocp_users} | last_activity={fmt_ts(la)}")
        if len(target) > 100:
            print(f"... and {len(target) - 100} more")

        if not apply:
            print()
            print("DRY-RUN only. Nothing was deleted.")
            sys.exit(0)

        totals = {}
        for u in target:
            deleted = delete_username_everywhere(con, u)
            for table, count in deleted.items():
                totals[table] = totals.get(table, 0) + count
        con.commit()

        print()
        print("Deletion completed.")
        for table, count in sorted(totals.items()):
            print(f"{table}: {count}")
finally:
    con.close()
PYCLEANDB
}

safety_backup_db_before_cleanup() {
    local db="$DB_DIR/central.db"
    local out="/root/ocserv-central-before-user-cleanup-$(date +%Y%m%d-%H%M%S).db"

    if [[ ! -f "$db" ]]; then
        print_warn "Database not found, skipping safety backup: $db"
        return 0
    fi

    sqlite3 "$db" ".backup '$out'"
    print_ok "Safety DB backup saved: $out"
    ls -lh "$out" 2>/dev/null || true
}

db_user_cleanup_menu() {
    local ocp days include apply

    while true; do
        clear
        echo "==== Ocserv Central - Database User Cleanup / ocpasswd Prune Menu ===="
        echo "1) Show DB vs ocpasswd user statistics"
        echo "2) List DB users missing from ocpasswd"
        echo "3) Delete DB users missing from ocpasswd"
        echo "4) List inactive DB users older than N days"
        echo "5) Delete inactive users older than N days ONLY if missing from ocpasswd"
        echo "6) DANGER: Delete inactive users older than N days even if still in ocpasswd"
        echo "7) VACUUM / compact database"
        echo "0) Back"
        echo
        read -rp "Select: " choice

        case "$choice" in
            1)
                ocp="$(ask_value "ocpasswd path" "$(get_master_ocpasswd_path)")"
                db_user_cleanup_python "stats" 90 0 0 "$ocp"
                pause
                ;;
            2)
                ocp="$(ask_value "ocpasswd path" "$(get_master_ocpasswd_path)")"
                db_user_cleanup_python "list_missing" 90 0 0 "$ocp"
                pause
                ;;
            3)
                ocp="$(ask_value "ocpasswd path" "$(get_master_ocpasswd_path)")"
                print_warn "This deletes users from central DB if they are NOT present in ocpasswd."
                print_info "It will also delete their rows from sessions/usage_log and similar DB tables."
                print_info "It does NOT edit ocpasswd itself."
                print_info "If a deleted user still exists in ocpasswd later, sync can recreate them."
                if ask_yes_no "Take safety DB backup before deletion?" "y"; then
                    safety_backup_db_before_cleanup
                fi
                echo
                print_info "Dry-run preview:"
                db_user_cleanup_python "delete_missing" 90 0 0 "$ocp"
                echo
                if ask_yes_no "Apply deletion now?" "n"; then
                    db_user_cleanup_python "delete_missing" 90 0 1 "$ocp"
                fi
                pause
                ;;
            4)
                ocp="$(ask_value "ocpasswd path" "$(get_master_ocpasswd_path)")"
                days="$(ask_number "Inactive threshold in days" "90")"
                db_user_cleanup_python "list_inactive" "$days" 0 0 "$ocp"
                pause
                ;;
            5)
                ocp="$(ask_value "ocpasswd path" "$(get_master_ocpasswd_path)")"
                days="$(ask_number "Inactive threshold in days" "90")"
                print_warn "This deletes inactive users ONLY if they are also missing from ocpasswd."
                print_info "This is the safer cleanup mode."
                if ask_yes_no "Take safety DB backup before deletion?" "y"; then
                    safety_backup_db_before_cleanup
                fi
                echo
                print_info "Dry-run preview:"
                db_user_cleanup_python "delete_inactive_missing" "$days" 0 0 "$ocp"
                echo
                if ask_yes_no "Apply deletion now?" "n"; then
                    db_user_cleanup_python "delete_inactive_missing" "$days" 0 1 "$ocp"
                fi
                pause
                ;;
            6)
                ocp="$(ask_value "ocpasswd path" "$(get_master_ocpasswd_path)")"
                days="$(ask_number "Inactive threshold in days" "180")"
                print_warn "DANGER: This can delete users from central DB even if they still exist in ocpasswd."
                print_warn "If those users remain in ocpasswd, future sync/connect may recreate them."
                print_warn "Recommended workflow: remove users from ocpasswd first, rsync to nodes, then use option 3 or 5."
                if ! ask_yes_no "I understand the risk. Continue?" "n"; then
                    pause
                    continue
                fi
                if ask_yes_no "Take safety DB backup before deletion?" "y"; then
                    safety_backup_db_before_cleanup
                fi
                echo
                print_info "Dry-run preview:"
                db_user_cleanup_python "delete_inactive_all" "$days" 1 0 "$ocp"
                echo
                if ask_yes_no "Apply deletion now?" "n"; then
                    db_user_cleanup_python "delete_inactive_all" "$days" 1 1 "$ocp"
                fi
                pause
                ;;
            7)
                vacuum_database
                pause
                ;;
            0)
                return 0
                ;;
            *)
                echo "Invalid choice"
                sleep 1
                ;;
        esac
    done
}



# =========================
# v14: exact reset snapshots + usage_log fallback recovery
# =========================

ensure_usage_recovery_schema() {
    local db="$DB_DIR/central.db"
    [[ -f "$db" ]] || { print_err "Database not found: $db"; return 1; }
    sqlite3 "$db" <<'SQLRECOVERYSCHEMA'
CREATE TABLE IF NOT EXISTS usage_reset_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    target TEXT,
    username TEXT NOT NULL,
    old_used_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_usage_reset_snapshots_batch ON usage_reset_snapshots(batch_id);
CREATE INDEX IF NOT EXISTS idx_usage_reset_snapshots_created ON usage_reset_snapshots(created_at);
SQLRECOVERYSCHEMA
}

usage_recovery_stats() {
    local db="$DB_DIR/central.db"
    ensure_usage_recovery_schema || return 1
    sqlite3 -header -column "$db" <<'SQLRECOVERYSTATS'
SELECT 'users' AS item, COUNT(*) AS value FROM users
UNION ALL
SELECT 'usage_log_rows', COUNT(*) FROM usage_log
UNION ALL
SELECT 'reset_snapshot_rows', COUNT(*) FROM usage_reset_snapshots
UNION ALL
SELECT 'reset_snapshot_batches', COUNT(DISTINCT batch_id) FROM usage_reset_snapshots;

SELECT
    datetime(MIN(created_at), 'unixepoch', 'localtime') AS oldest_usage_log,
    datetime(MAX(created_at), 'unixepoch', 'localtime') AS newest_usage_log,
    ROUND(COALESCE(SUM(bytes),0) / 1073741824.0, 3) AS total_logged_gib
FROM usage_log;
SQLRECOVERYSTATS
}

list_usage_reset_snapshot_batches() {
    local db="$DB_DIR/central.db"
    ensure_usage_recovery_schema || return 1
    sqlite3 -header -column "$db" <<'SQLLISTSNAPSHOTS'
SELECT
    batch_id,
    scope,
    COALESCE(target, '') AS target,
    COUNT(*) AS users,
    ROUND(SUM(old_used_bytes) / 1073741824.0, 3) AS old_used_total_gib,
    datetime(MAX(created_at), 'unixepoch', 'localtime') AS created_local,
    COALESCE(MAX(note), '') AS note
FROM usage_reset_snapshots
GROUP BY batch_id, scope, target
ORDER BY MAX(created_at) DESC
LIMIT 100;
SQLLISTSNAPSHOTS
}

preview_usage_reset_snapshot() {
    local batch db="$DB_DIR/central.db"
    batch="$(ask_value "Snapshot batch_id" "")"
    [[ -n "$batch" ]] || return 0
    ensure_usage_recovery_schema || return 1
    sqlite3 -header -column "$db" <<SQLPREVIEWSNAPSHOT
SELECT
    s.username,
    ROUND(s.old_used_bytes / 1073741824.0, 3) AS before_reset_gib,
    ROUND(COALESCE(u.used_bytes,0) / 1073741824.0, 3) AS current_after_reset_gib,
    ROUND((s.old_used_bytes + COALESCE(u.used_bytes,0)) / 1073741824.0, 3) AS recommended_restore_gib,
    u.groupname
FROM usage_reset_snapshots AS s
LEFT JOIN users AS u ON u.username=s.username
WHERE s.batch_id='$batch'
ORDER BY s.username;
SQLPREVIEWSNAPSHOT
}

recovery_db_backup() {
    local db="$DB_DIR/central.db"
    local out="/root/ocserv-central-before-usage-recovery-$(date +%Y%m%d-%H%M%S).db"
    sqlite3 "$db" ".backup '$out'"
    print_ok "Safety DB backup created: $out"
}

restore_usage_reset_snapshot() {
    local batch mode db="$DB_DIR/central.db" was_active=0 rc=0
    batch="$(ask_value "Snapshot batch_id to restore" "")"
    [[ -n "$batch" ]] || return 0

    ensure_usage_recovery_schema || return 1
    local count
    count="$(sqlite3 "$db" "SELECT COUNT(*) FROM usage_reset_snapshots WHERE batch_id='$(printf "%s" "$batch" | sed "s/'/''/g")';")"
    if [[ "${count:-0}" == "0" ]]; then
        print_err "Snapshot batch not found: $batch"
        return 1
    fi

    echo "1) Recommended: old value before reset + current usage accumulated after reset"
    echo "2) Exact old value: overwrite current usage with the value before reset"
    read -rp "Select [1]: " mode
    mode="${mode:-1}"

    recovery_db_backup
    if ! ask_yes_no "Apply this snapshot recovery now?" "n"; then
        return 0
    fi

    systemctl is-active --quiet ocserv-central 2>/dev/null && was_active=1 || true
    (( was_active == 1 )) && systemctl stop ocserv-central || true

    set +e
    python3 - "$db" "$batch" "$mode" <<'PYRESTORESNAPSHOT'
import sqlite3
import sys
import time

db_path, batch_id, mode = sys.argv[1:4]
con = sqlite3.connect(db_path, timeout=30)
try:
    con.execute("BEGIN IMMEDIATE")
    rows = con.execute(
        "SELECT username, old_used_bytes FROM usage_reset_snapshots WHERE batch_id=? ORDER BY username",
        (batch_id,),
    ).fetchall()
    changed = 0
    for username, old_used in rows:
        current = con.execute("SELECT used_bytes FROM users WHERE username=?", (username,)).fetchone()
        if not current:
            continue
        if mode == "2":
            new_value = int(old_used or 0)
        else:
            new_value = int(old_used or 0) + int(current[0] or 0)
        con.execute(
            "UPDATE users SET used_bytes=?, updated_at=? WHERE username=?",
            (new_value, int(time.time()), username),
        )
        changed += 1
    con.commit()
    print(f"Restored users: {changed}")
except Exception:
    con.rollback()
    raise
finally:
    con.close()
PYRESTORESNAPSHOT
    rc=$?
    set -e

    : > "$DB_DIR/quota_exhausted_users.jsonl"
    (( was_active == 1 )) && systemctl start ocserv-central || true
    if (( rc == 0 )); then
        print_ok "Snapshot recovery completed. Exhausted-quota report was cleared for fresh evaluation."
    else
        print_err "Snapshot recovery failed. API state restored; use the safety backup if needed."
    fi
    return "$rc"
}

usage_log_recovery_cutoff() {
    local choice date_text
    echo "1) Use ALL currently available usage_log records" >&2
    echo "2) Use logs from a specific local date/time" >&2
    read -rp "Select [1]: " choice
    choice="${choice:-1}"
    if [[ "$choice" == "2" ]]; then
        date_text="$(ask_value "Start local date/time, example 2026-07-01 00:00:00" "")"
        [[ -n "$date_text" ]] || { echo ""; return 0; }
        date -d "$date_text" +%s
    else
        echo "0"
    fi
}

preview_usage_log_recovery() {
    local scope target cutoff db="$DB_DIR/central.db"
    echo "1) One group"
    echo "2) One user"
    read -rp "Select: " scope
    case "$scope" in
        1) target="$(ask_value "Group name" "group2")" ;;
        2) target="$(ask_value "Username" "")" ;;
        *) return 0 ;;
    esac
    [[ -n "$target" ]] || return 0
    cutoff="$(usage_log_recovery_cutoff)"
    [[ "$cutoff" =~ ^[0-9]+$ ]] || { print_err "Invalid cutoff date/time."; return 1; }

    python3 - "$db" "$scope" "$target" "$cutoff" <<'PYPREVIEWLOGRECOVERY'
import sqlite3
import sys
import time

db_path, scope, target, cutoff_s = sys.argv[1:5]
cutoff = int(cutoff_s)
con = sqlite3.connect(db_path, timeout=30)
con.row_factory = sqlite3.Row
try:
    if scope == "1":
        users = con.execute("SELECT username, groupname, used_bytes FROM users WHERE groupname=? ORDER BY username", (target,)).fetchall()
    else:
        users = con.execute("SELECT username, groupname, used_bytes FROM users WHERE username=?", (target,)).fetchall()

    print(f"{'USERNAME':<28} {'GROUP':<14} {'CURRENT_GIB':>12} {'RECOVER_GIB':>12} {'LOG_ROWS':>10} {'OLDEST_LOG':<19}")
    print("-" * 105)
    for u in users:
        row = con.execute(
            "SELECT COALESCE(SUM(bytes),0), COUNT(*), MIN(created_at), MAX(created_at) FROM usage_log WHERE username=? AND created_at>=?",
            (u['username'], cutoff),
        ).fetchone()
        recover, count, oldest, newest = row
        oldest_text = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(oldest)) if oldest else 'none'
        print(f"{u['username']:<28} {str(u['groupname'] or ''):<14} {int(u['used_bytes'] or 0)/1073741824:>12.3f} {int(recover or 0)/1073741824:>12.3f} {int(count):>10} {oldest_text:<19}")
finally:
    con.close()
PYPREVIEWLOGRECOVERY
}

apply_usage_log_recovery() {
    local scope target cutoff db="$DB_DIR/central.db" was_active=0 rc=0
    echo "1) Recover one group"
    echo "2) Recover one user"
    read -rp "Select: " scope
    case "$scope" in
        1) target="$(ask_value "Group name" "group2")" ;;
        2) target="$(ask_value "Username" "")" ;;
        *) return 0 ;;
    esac
    [[ -n "$target" ]] || return 0
    cutoff="$(usage_log_recovery_cutoff)"
    [[ "$cutoff" =~ ^[0-9]+$ ]] || { print_err "Invalid cutoff date/time."; return 1; }

    print_warn "Fallback recovery replaces users.used_bytes with SUM(usage_log.bytes) in the selected time range."
    print_warn "If an older billing period is included, the recovered value can be too high."
    print_warn "If cleanup deleted older logs, the recovered value can be too low."
    recovery_db_backup
    if ! ask_yes_no "Apply usage_log fallback recovery now?" "n"; then
        return 0
    fi

    systemctl is-active --quiet ocserv-central 2>/dev/null && was_active=1 || true
    (( was_active == 1 )) && systemctl stop ocserv-central || true

    set +e
    python3 - "$db" "$scope" "$target" "$cutoff" <<'PYAPPLYLOGRECOVERY'
import sqlite3
import sys
import time

db_path, scope, target, cutoff_s = sys.argv[1:5]
cutoff = int(cutoff_s)
con = sqlite3.connect(db_path, timeout=60)
try:
    con.execute("BEGIN IMMEDIATE")
    con.execute("CREATE INDEX IF NOT EXISTS idx_usage_log_username_created ON usage_log(username, created_at)")
    if scope == "1":
        users = [r[0] for r in con.execute("SELECT username FROM users WHERE groupname=?", (target,)).fetchall()]
    else:
        users = [r[0] for r in con.execute("SELECT username FROM users WHERE username=?", (target,)).fetchall()]
    changed = 0
    for username in users:
        recovered = con.execute(
            "SELECT COALESCE(SUM(bytes),0) FROM usage_log WHERE username=? AND created_at>=?",
            (username, cutoff),
        ).fetchone()[0]
        con.execute(
            "UPDATE users SET used_bytes=?, updated_at=? WHERE username=?",
            (int(recovered or 0), int(time.time()), username),
        )
        changed += 1
    con.commit()
    print(f"Recovered users: {changed}")
except Exception:
    con.rollback()
    raise
finally:
    con.close()
PYAPPLYLOGRECOVERY
    rc=$?
    set -e

    : > "$DB_DIR/quota_exhausted_users.jsonl"
    (( was_active == 1 )) && systemctl start ocserv-central || true
    if (( rc == 0 )); then
        print_ok "usage_log recovery completed. Exhausted-quota report was cleared for fresh evaluation."
    else
        print_err "usage_log recovery failed. API state restored; use the safety backup if needed."
    fi
    return "$rc"
}

usage_recovery_menu() {
    while true; do
        clear
        echo "==== Ocserv Central - Used Traffic Recovery / Undo Reset ===="
        echo "1) Show recovery statistics"
        echo "2) List exact pre-reset snapshot batches"
        echo "3) Preview one snapshot batch"
        echo "4) Restore one exact snapshot batch"
        echo "5) Preview fallback recovery from usage_log"
        echo "6) Apply fallback recovery from usage_log"
        echo "0) Back"
        echo
        echo "v14 and newer create an exact snapshot automatically before user/group/all usage resets."
        echo "For resets that happened before v14, use usage_log fallback recovery."
        echo
        read -rp "Select: " choice
        case "$choice" in
            1) usage_recovery_stats; pause ;;
            2) list_usage_reset_snapshot_batches; pause ;;
            3) preview_usage_reset_snapshot; pause ;;
            4) restore_usage_reset_snapshot; pause ;;
            5) preview_usage_log_recovery; pause ;;
            6) apply_usage_log_recovery; pause ;;
            0) return 0 ;;
            *) echo "Invalid choice"; sleep 1 ;;
        esac
    done
}


# =========================
# v15: extra traffic decrease + exact adjustment snapshots
# =========================

ensure_extra_traffic_recovery_schema() {
    local db="$DB_DIR/central.db"
    [[ -f "$db" ]] || { print_err "Database not found: $db"; return 1; }
    sqlite3 "$db" <<'SQLEXTRASCHEMA'
CREATE TABLE IF NOT EXISTS extra_traffic_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    target TEXT,
    username TEXT NOT NULL,
    old_extra_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    operation TEXT NOT NULL,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_extra_traffic_snapshots_batch ON extra_traffic_snapshots(batch_id);
CREATE INDEX IF NOT EXISTS idx_extra_traffic_snapshots_created ON extra_traffic_snapshots(created_at);
SQLEXTRASCHEMA
}

extra_traffic_recovery_stats() {
    local db="$DB_DIR/central.db"
    ensure_extra_traffic_recovery_schema || return 1
    sqlite3 -header -column "$db" <<'SQLEXTRASTATS'
SELECT
    COUNT(*) AS users,
    ROUND(COALESCE(SUM(quota_extra_bytes),0) / 1073741824.0, 3) AS current_total_extra_gib,
    SUM(CASE WHEN quota_extra_bytes > 0 THEN 1 ELSE 0 END) AS users_with_extra
FROM users;

SELECT
    COUNT(*) AS snapshot_rows,
    COUNT(DISTINCT batch_id) AS snapshot_batches,
    datetime(MIN(created_at), 'unixepoch', 'localtime') AS oldest_snapshot,
    datetime(MAX(created_at), 'unixepoch', 'localtime') AS newest_snapshot
FROM extra_traffic_snapshots;
SQLEXTRASTATS
}

list_extra_traffic_snapshot_batches() {
    local db="$DB_DIR/central.db"
    ensure_extra_traffic_recovery_schema || return 1
    sqlite3 -header -column "$db" <<'SQLLISTEXTRAS'
SELECT
    batch_id,
    operation,
    scope,
    COALESCE(target, '') AS target,
    COUNT(*) AS users,
    ROUND(SUM(old_extra_bytes) / 1073741824.0, 3) AS old_extra_total_gib,
    datetime(MAX(created_at), 'unixepoch', 'localtime') AS created_local,
    COALESCE(MAX(note), '') AS note
FROM extra_traffic_snapshots
GROUP BY batch_id, operation, scope, target
ORDER BY MAX(created_at) DESC
LIMIT 100;
SQLLISTEXTRAS
}

preview_extra_traffic_snapshot() {
    local batch safe_batch db="$DB_DIR/central.db"
    batch="$(ask_value "Extra traffic snapshot batch_id" "")"
    [[ -n "$batch" ]] || return 0
    ensure_extra_traffic_recovery_schema || return 1
    safe_batch="$(printf "%s" "$batch" | sed "s/'/''/g")"
    sqlite3 -header -column "$db" <<SQLPREVIEWEXTRA
SELECT
    s.username,
    s.operation,
    ROUND(s.old_extra_bytes / 1073741824.0, 3) AS before_change_gib,
    ROUND(COALESCE(u.quota_extra_bytes,0) / 1073741824.0, 3) AS current_extra_gib,
    ROUND((COALESCE(u.quota_extra_bytes,0) - s.old_extra_bytes) / 1073741824.0, 3) AS difference_gib,
    u.groupname
FROM extra_traffic_snapshots AS s
LEFT JOIN users AS u ON u.username=s.username
WHERE s.batch_id='$safe_batch'
ORDER BY s.username;
SQLPREVIEWEXTRA
}

extra_traffic_db_backup() {
    local db="$DB_DIR/central.db"
    local out="/root/ocserv-central-before-extra-traffic-restore-$(date +%Y%m%d-%H%M%S).db"
    sqlite3 "$db" ".backup '$out'"
    print_ok "Safety DB backup created: $out"
}

restore_extra_traffic_snapshot() {
    local batch safe_batch db="$DB_DIR/central.db" was_active=0 rc=0 count
    batch="$(ask_value "Extra traffic snapshot batch_id to restore" "")"
    [[ -n "$batch" ]] || return 0
    ensure_extra_traffic_recovery_schema || return 1

    safe_batch="$(printf "%s" "$batch" | sed "s/'/''/g")"
    count="$(sqlite3 "$db" "SELECT COUNT(*) FROM extra_traffic_snapshots WHERE batch_id='$safe_batch';")"
    if [[ "${count:-0}" == "0" ]]; then
        print_err "Extra traffic snapshot batch not found: $batch"
        return 1
    fi

    print_warn "This restores the exact quota_extra_bytes value from before that operation."
    print_warn "Any later extra-traffic changes for the same users will be overwritten."
    sqlite3 -header -column "$db" <<SQLPREVIEWRESTOREEXTRA
SELECT
    s.username,
    s.operation,
    ROUND(s.old_extra_bytes / 1073741824.0, 3) AS before_change_gib,
    ROUND(COALESCE(u.quota_extra_bytes,0) / 1073741824.0, 3) AS current_extra_gib,
    u.groupname
FROM extra_traffic_snapshots AS s
LEFT JOIN users AS u ON u.username=s.username
WHERE s.batch_id='$safe_batch'
ORDER BY s.username;
SQLPREVIEWRESTOREEXTRA
    extra_traffic_db_backup

    if ! ask_yes_no "Restore this extra-traffic snapshot now?" "n"; then
        return 0
    fi

    systemctl is-active --quiet ocserv-central 2>/dev/null && was_active=1 || true
    (( was_active == 1 )) && systemctl stop ocserv-central || true

    set +e
    python3 - "$db" "$batch" <<'PYRESTOREEXTRA'
import sqlite3
import sys
import time

db_path, batch_id = sys.argv[1:3]
con = sqlite3.connect(db_path, timeout=30)
try:
    con.execute("BEGIN IMMEDIATE")
    rows = con.execute(
        "SELECT username, old_extra_bytes FROM extra_traffic_snapshots WHERE batch_id=? ORDER BY username",
        (batch_id,),
    ).fetchall()
    changed = 0
    for username, old_extra in rows:
        current = con.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        if not current:
            continue
        con.execute(
            "UPDATE users SET quota_extra_bytes=?, updated_at=? WHERE username=?",
            (max(0, int(old_extra or 0)), int(time.time()), username),
        )
        changed += 1
    con.commit()
    print(f"Restored users: {changed}")
except Exception:
    con.rollback()
    raise
finally:
    con.close()
PYRESTOREEXTRA
    rc=$?
    set -e

    (( was_active == 1 )) && systemctl start ocserv-central || true
    if (( rc == 0 )); then
        sleep 1
        master_curl "POST" "/quota-exhausted/rebuild" "{}" || true
        print_ok "Extra traffic snapshot restored and exhausted-quota report rebuilt."
    else
        print_err "Extra traffic restore failed. API state restored; use the safety backup if needed."
    fi
    return "$rc"
}

extra_traffic_recovery_menu() {
    while true; do
        clear
        echo "==== Ocserv Central - Extra Traffic History / Recovery ===="
        echo "1) Show extra traffic and snapshot statistics"
        echo "2) List extra traffic snapshot batches"
        echo "3) Preview one snapshot batch"
        echo "4) Restore one exact snapshot batch"
        echo "0) Back"
        echo
        echo "v15 records exact quota_extra_bytes values before add, decrease, set, and clear operations."
        echo
        read -rp "Select: " choice
        case "$choice" in
            1) extra_traffic_recovery_stats; pause ;;
            2) list_extra_traffic_snapshot_batches; pause ;;
            3) preview_extra_traffic_snapshot; pause ;;
            4) restore_extra_traffic_snapshot; pause ;;
            0) return 0 ;;
            *) echo "Invalid choice"; sleep 1 ;;
        esac
    done
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
        echo "18) Exhausted-quota file tools: reset / dedupe / rebuild"
        echo "19) Delete exhausted-quota file"
        echo "20) Status"
        echo "21) Show current limits.json"
        echo "22) Backup / restore / cleanup menu"
        echo "23) Restore program data directly"
        echo "24) Uninstall master"
        echo "25) Bulk traffic / quota menu"
        echo "26) Group quota / new group menu"
        echo "27) Database user cleanup / ocpasswd prune menu"
        echo "28) Restart ocserv-central API"
        echo "29) Refresh ocpasswd groups / apply current limits now"
        echo "30) Used traffic recovery / undo accidental reset"
        echo "31) Decrease added traffic from one user"
        echo "32) Extra traffic change history / restore"
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
            18) exhausted_quota_file_menu ;;
            19) delete_quota_exhausted_file; pause ;;
            20) master_status; pause ;;
            21) ensure_limits_file; jq . "$MASTER_ETC/limits.json"; pause ;;
            22) backup_cleanup_menu ;;
            23) restore_master_data; pause ;;
            24) uninstall_master; pause ;;
            25) bulk_traffic_menu ;;
            26) group_quota_menu ;;
            27) db_user_cleanup_menu ;;
            28) restart_master_api; pause ;;
            29) refresh_now_menu; pause ;;
            30) usage_recovery_menu ;;
            31) decrease_user_traffic; pause ;;
            32) extra_traffic_recovery_menu ;;
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
