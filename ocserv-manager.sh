#!/usr/bin/env bash
# Ocserv Manager v3.2.0
# Multi-instance installer and manager for ocserv on Ubuntu/Debian.
# Designed as a replacement for the original single-instance ocserv.sh.

set -Eeuo pipefail
IFS=$' \t\n'

PROGRAM_VERSION="3.2.0"
PROGRAM_NAME="Ocserv Manager"

OCSERV_ETC="/etc/ocserv"
MANAGER_ETC="/etc/ocserv-manager"
INSTANCE_ROOT="$OCSERV_ETC/instances"
STATE_ROOT="$MANAGER_ETC/instances"
BACKUP_ROOT="/root/ocserv-manager-backups"
BUILD_ROOT="/usr/local/src/ocserv-manager"
MANAGER_BIN="/usr/local/sbin/ocserv-manager"
SYSTEMD_DEFAULT="/etc/systemd/system/ocserv.service"
SYSTEMD_TEMPLATE="/etc/systemd/system/ocserv@.service"
SYSCTL_FILE="/etc/sysctl.d/90-ocserv-manager-forwarding.conf"
FIREWALL_REAPPLY_SERVICE="/etc/systemd/system/ocserv-manager-firewall.service"
AUDIT_LOG_DIR="/var/log/ocserv-manager"
AUDIT_LOG="$AUDIT_LOG_DIR/audit.log"
AUDIT_ENV="$MANAGER_ETC/audit.env"
API_DIR="/usr/local/lib/ocserv-manager"
API_SERVICE="/etc/systemd/system/ocserv-manager-api.service"
API_ENV="$MANAGER_ETC/api.env"
CENTRAL_MANAGER_BIN="/usr/local/sbin/ocserv-central-manager"
CENTRAL_INTEGRATION_DIR="/etc/ocserv-manager/central"
CENTRAL_LIB_DIR="/usr/local/lib/ocserv-manager/central"
CENTRAL_EMBED_STATE="$MANAGER_ETC/central-embedded.env"
CENTRAL_PROFILE="$CENTRAL_INTEGRATION_DIR/profile.env"
CENTRAL_EMBEDDED_VERSION="v20.4.4"
TEMPLATE_ROOT="$MANAGER_ETC/templates"
INSTANCE_BASE_ROOT="$MANAGER_ETC/config-bases"
STABILITY_BACKUP_ROOT="$BACKUP_ROOT/stability"
FIREWALL_POLICY_ROOT="$MANAGER_ETC/firewall"
FIREWALL_SNAPSHOT_ROOT="$BACKUP_ROOT/firewall"

C_RESET='\033[0m'
C_RED='\033[31m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_CYAN='\033[36m'

CURRENT_TXN_BACKUP=""
CURRENT_TXN_SERVICE=""
CURRENT_TXN_CONFIG=""

print_ok()   { echo -e "${C_GREEN}[OK]${C_RESET} $*"; }
print_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
print_err()  { echo -e "${C_RED}[ERR]${C_RESET} $*" >&2; }
print_info() { echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }

on_error() {
    local rc=$? line="${1:-?}" cmd="${2:-?}"
    print_err "Command failed (exit=$rc) at line $line: $cmd"
    if [[ -n "$CURRENT_TXN_BACKUP" && -n "$CURRENT_TXN_CONFIG" && -f "$CURRENT_TXN_BACKUP" ]]; then
        print_warn "A transactional config change was in progress; restoring the previous config."
        cp -a "$CURRENT_TXN_BACKUP" "$CURRENT_TXN_CONFIG" 2>/dev/null || true
        if [[ -n "$CURRENT_TXN_SERVICE" ]]; then
            systemctl restart "$CURRENT_TXN_SERVICE" >/dev/null 2>&1 || true
        fi
    fi
    return "$rc"
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

need_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        print_err "Run this script as root."
        exit 1
    fi
}

ensure_dirs() {
    # Runtime/state directories only. Backup directories are intentionally NOT
    # created merely by launching the manager; they are created lazily only
    # when an operation actually writes a backup.
    mkdir -p "$MANAGER_ETC" "$INSTANCE_ROOT" "$STATE_ROOT" "$BUILD_ROOT" "$API_DIR" "$CENTRAL_INTEGRATION_DIR" "$CENTRAL_LIB_DIR" "$TEMPLATE_ROOT" "$INSTANCE_BASE_ROOT" "$FIREWALL_POLICY_ROOT"
    chmod 700 "$MANAGER_ETC" "$STATE_ROOT" "$CENTRAL_INTEGRATION_DIR" "$TEMPLATE_ROOT" "$INSTANCE_BASE_ROOT" "$FIREWALL_POLICY_ROOT" 2>/dev/null || true
}

ensure_backup_root() {
    mkdir -p "$BACKUP_ROOT"
    chmod 700 "$BACKUP_ROOT" 2>/dev/null || true
}

ensure_stability_backup_root() {
    ensure_backup_root
    mkdir -p "$STABILITY_BACKUP_ROOT"
    chmod 700 "$STABILITY_BACKUP_ROOT" 2>/dev/null || true
}

pause() {
    echo
    read -r -p "Press Enter to continue..." _unused || true
}

ask_yes_no() {
    local prompt="$1" default="${2:-y}" ans
    while true; do
        if [[ "$default" == "y" ]]; then
            read -r -p "$prompt [Y/n]: " ans || true
            ans="${ans:-y}"
        else
            read -r -p "$prompt [y/N]: " ans || true
            ans="${ans:-n}"
        fi
        case "$ans" in
            y|Y|yes|YES|Yes) return 0 ;;
            n|N|no|NO|No) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

ask_value() {
    local prompt="$1" default="${2:-}" ans
    if [[ -n "$default" ]]; then
        read -r -p "$prompt [$default]: " ans || true
        printf '%s\n' "${ans:-$default}"
    else
        read -r -p "$prompt: " ans || true
        printf '%s\n' "$ans"
    fi
}

ask_nonempty() {
    local prompt="$1" default="${2:-}" ans
    while true; do
        ans="$(ask_value "$prompt" "$default")"
        if [[ -n "$ans" ]]; then
            printf '%s\n' "$ans"
            return 0
        fi
        print_warn "Value cannot be empty."
    done
}

ask_integer() {
    local prompt="$1" default="${2:-0}" min="${3:-0}" max="${4:-2147483647}" ans
    while true; do
        ans="$(ask_value "$prompt" "$default")"
        if [[ "$ans" =~ ^[0-9]+$ ]] && (( ans >= min && ans <= max )); then
            printf '%s\n' "$ans"
            return 0
        fi
        print_warn "Enter an integer between $min and $max."
    done
}

choose_menu() {
    local prompt="$1"; shift
    local -a options=("$@")
    local i choice
    echo "$prompt" >&2
    for ((i=0; i<${#options[@]}; i++)); do
        printf '%d) %s\n' "$((i+1))" "${options[$i]}" >&2
    done
    while true; do
        read -r -p "Select: " choice || true
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
            printf '%s\n' "$choice"
            return 0
        fi
        print_warn "Invalid selection." >&2
    done
}

safe_name() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]]
}

valid_username() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]]
}

valid_domain() {
    local d="$1"
    [[ ${#d} -le 253 && "$d" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

valid_email() {
    [[ "$1" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]
}

valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

valid_ipv4_cidr() {
    python3 - "$1" <<'PY' >/dev/null 2>&1
import ipaddress, sys
try:
    n=ipaddress.ip_network(sys.argv[1], strict=False)
    assert n.version == 4
except Exception:
    raise SystemExit(1)
PY
}

is_rfc1918_cidr() {
    python3 - "$1" <<'PYRFC' >/dev/null 2>&1
import ipaddress,sys
n=ipaddress.ip_network(sys.argv[1], strict=False)
allowed=[ipaddress.ip_network("10.0.0.0/8"),ipaddress.ip_network("172.16.0.0/12"),ipaddress.ip_network("192.168.0.0/16")]
assert n.version==4 and any(n.subnet_of(a) for a in allowed)
PYRFC
}

valid_ipv6_cidr() {
    python3 - "$1" <<'PY' >/dev/null 2>&1
import ipaddress, sys
try:
    n=ipaddress.ip_network(sys.argv[1], strict=False)
    assert n.version == 6
except Exception:
    raise SystemExit(1)
PY
}

normalize_cidr() {
    python3 - "$1" <<'PY'
import ipaddress,sys
print(ipaddress.ip_network(sys.argv[1], strict=False))
PY
}

normalize_ipv6_cidr() {
    python3 - "$1" <<'PY'
import ipaddress,sys
n=ipaddress.ip_network(sys.argv[1], strict=False)
assert n.version == 6
print(n)
PY
}

shell_quote() { printf '%q' "$1"; }

audit_enabled() {
    [[ -f "$AUDIT_ENV" ]] || return 1
    # shellcheck disable=SC1090
    . "$AUDIT_ENV"
    [[ "${AUDIT_ENABLED:-0}" == "1" ]]
}

audit() {
    audit_enabled || return 0
    mkdir -p "$AUDIT_LOG_DIR"
    chmod 750 "$AUDIT_LOG_DIR" 2>/dev/null || true
    printf '%s\tuser=%s\t%s\n' "$(date -Is)" "${SUDO_USER:-root}" "$*" >> "$AUDIT_LOG"
}

configure_audit_logging() {
    ensure_dirs
    if ask_yes_no "Enable manager audit logging? It records administrative changes only." "n"; then
        printf 'AUDIT_ENABLED=1\n' > "$AUDIT_ENV"
        mkdir -p "$AUDIT_LOG_DIR"
        touch "$AUDIT_LOG"
        chmod 640 "$AUDIT_LOG"
        cat > /etc/logrotate.d/ocserv-manager <<'EOF'
/var/log/ocserv-manager/audit.log {
    size 10M
    rotate 5
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
        print_ok "Audit log enabled with size-based rotation (10 MB x 5)."
    else
        printf 'AUDIT_ENABLED=0\n' > "$AUDIT_ENV"
        rm -f /etc/logrotate.d/ocserv-manager
        print_ok "Audit log disabled. Live service logs remain available through journald."
    fi
}

install_manager_self() {
    ensure_dirs
    if [[ -f "$0" && "$(readlink -f "$0" 2>/dev/null || echo "$0")" != "$MANAGER_BIN" ]]; then
        cp -a "$0" "$MANAGER_BIN"
        chmod 755 "$MANAGER_BIN"
        print_ok "Manager installed at $MANAGER_BIN"
    fi
    printf '%s\n' "$PROGRAM_VERSION" > "$MANAGER_ETC/version"
}

os_preflight() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}" in
            ubuntu|debian) ;;
            *) print_warn "This manager is designed for Ubuntu/Debian. Detected: ${PRETTY_NAME:-unknown}." ;;
        esac
    fi
    command -v systemctl >/dev/null 2>&1 || { print_err "systemd is required."; return 1; }
    command -v python3 >/dev/null 2>&1 || { print_err "python3 is required."; return 1; }
}

apt_update_once() {
    local stamp="$MANAGER_ETC/apt-update.stamp"
    if [[ ! -f "$stamp" ]] || find "$stamp" -mmin +360 -print -quit | grep -q .; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        touch "$stamp"
    fi
}

install_available_packages() {
    local -a requested=() available=() missing=()
    local p

    # Fast path: do not invoke apt at all when every requested package is
    # already installed. apt dependency solving can be surprisingly slow on
    # small VPSes even when the package is already at the newest version.
    for p in "$@"; do
        if ! dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -qx 'install ok installed'; then
            requested+=("$p")
        fi
    done
    ((${#requested[@]})) || return 0

    apt_update_once
    for p in "${requested[@]}"; do
        if apt-cache show "$p" >/dev/null 2>&1; then
            available+=("$p")
        else
            missing+=("$p")
        fi
    done
    if ((${#available[@]})); then
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y "${available[@]}"
    fi
    if ((${#missing[@]})); then
        print_warn "Packages not available on this distribution: ${missing[*]}"
    fi
}

install_runtime_dependencies() {
    install_available_packages ca-certificates curl jq python3 iproute2 iptables openssl gnutls-bin git tar xz-utils gzip procps
}

ocserv_bin() {
    local p svc execpath
    for p in /usr/local/sbin/ocserv /usr/local/bin/ocserv /usr/sbin/ocserv /usr/bin/ocserv; do
        [[ -x "$p" ]] && { readlink -f "$p" 2>/dev/null || echo "$p"; return 0; }
    done
    if command -v ocserv >/dev/null 2>&1; then
        p="$(command -v ocserv)"
        readlink -f "$p" 2>/dev/null || echo "$p"
        return 0
    fi
    # Last-resort detection from a running/installed systemd unit. This fixes
    # source installs where the binary is outside the shell PATH used by the manager.
    for svc in ocserv.service ocserv@default.service; do
        execpath="$(systemctl show "$svc" -p ExecStart --value 2>/dev/null | sed -nE 's#.*path=([^ ;}]+).*#\1#p' | head -n1 || true)"
        [[ -n "$execpath" && -x "$execpath" ]] && { readlink -f "$execpath" 2>/dev/null || echo "$execpath"; return 0; }
    done
    echo ""
}

occtl_bin() {
    if [[ -x /usr/local/bin/occtl ]]; then echo /usr/local/bin/occtl
    elif [[ -x /usr/local/sbin/occtl ]]; then echo /usr/local/sbin/occtl
    elif command -v occtl >/dev/null 2>&1; then command -v occtl
    else echo ""
    fi
}

ocpasswd_bin() {
    if [[ -x /usr/local/bin/ocpasswd ]]; then echo /usr/local/bin/ocpasswd
    elif [[ -x /usr/local/sbin/ocpasswd ]]; then echo /usr/local/sbin/ocpasswd
    elif command -v ocpasswd >/dev/null 2>&1; then command -v ocpasswd
    else echo ""
    fi
}

installed_ocserv_version() {
    local b raw v pkg meta
    b="$(ocserv_bin)"
    if [[ -n "$b" && -x "$b" ]]; then
        raw="$("$b" --version 2>&1 || "$b" -v 2>&1 || true)"
        v="$(printf '%s\n' "$raw" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+([._~-][A-Za-z0-9.+~-]+)?' | head -n1 || true)"
        [[ -n "$v" ]] && { echo "$v"; return 0; }
    fi
    # Source installs record the exact selected upstream version.
    meta="$MANAGER_ETC/ocserv-install.env"
    if [[ -f "$meta" ]]; then
        v="$(sed -n 's/^version=//p' "$meta" | head -n1)"
        [[ -n "$v" ]] && { echo "$v"; return 0; }
    fi
    # Package fallback also works if the service is running but PATH/binary discovery is unusual.
    pkg="$(dpkg-query -W -f='${Version}' ocserv 2>/dev/null || true)"
    if [[ -n "$pkg" ]]; then
        pkg="${pkg#*:}"
        v="$(printf '%s' "$pkg" | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+' || true)"
        echo "${v:-$pkg}"
        return 0
    fi
    return 0
}

installed_ocserv_features() {
    local b
    b="$(ocserv_bin)"
    [[ -n "$b" ]] || return 0
    "$b" --version 2>&1 | sed -n '1,3p'
}

online_ocserv_tags() {
    curl -fsSL --retry 3 --connect-timeout 10 \
      'https://gitlab.com/api/v4/projects/openconnect%2Focserv/repository/tags?per_page=100' \
      | jq -r '.[].name' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V -r
}

select_ocserv_install_target() {
    local choice current latest tags_count i selection custom
    current="$(installed_ocserv_version)"
    latest="$(online_ocserv_tags 2>/dev/null | head -n1 || true)"
    echo "Installed version: ${current:-not installed}" >&2
    echo "Latest upstream tag: ${latest:-unavailable}" >&2
    echo "Choose installation source:" >&2
    echo "1) Latest stable upstream source (${latest:-online lookup})" >&2
    echo "2) Choose an upstream version from online list" >&2
    echo "3) Enter a specific upstream version/tag" >&2
    echo "4) Ubuntu/Debian distribution package" >&2
    echo "0) Back" >&2
    while true; do
        read -r -p "Select: " choice || true
        case "$choice" in
            0|1|2|3|4) break ;;
            *) print_warn "Invalid selection." >&2 ;;
        esac
    done
    case "$choice" in
        0)
            printf 'back|\n'
            return 0
            ;;
        1)
            [[ -n "$latest" ]] || { print_err "Could not retrieve upstream versions." >&2; return 1; }
            printf 'source|%s\n' "$latest"
            ;;
        2)
            mapfile -t _tags < <(online_ocserv_tags)
            tags_count=${#_tags[@]}
            (( tags_count > 0 )) || { print_err "No versions returned." >&2; return 1; }
            echo "Available upstream versions:" >&2
            for ((i=0; i<tags_count && i<30; i++)); do
                printf '%d) %s\n' "$((i+1))" "${_tags[$i]}" >&2
            done
            while true; do
                read -r -p "Select version number: " selection || true
                if [[ "$selection" =~ ^[0-9]+$ ]] && (( selection>=1 && selection<=tags_count && selection<=30 )); then
                    printf 'source|%s\n' "${_tags[$((selection-1))]}"
                    return 0
                fi
                print_warn "Invalid version selection." >&2
            done
            ;;
        3)
            custom="$(ask_nonempty "Enter ocserv version/tag, e.g. 1.5.0")"
            printf 'source|%s\n' "$custom"
            ;;
        4) printf 'package|distro\n' ;;
    esac
}

backup_binaries_for_update() {
    local dest="$1" p
    mkdir -p "$dest/binaries"
    for p in /usr/local/sbin/ocserv /usr/local/bin/ocserv /usr/local/sbin/occtl /usr/local/bin/occtl /usr/local/sbin/ocpasswd /usr/local/bin/ocpasswd /usr/sbin/ocserv /usr/bin/occtl /usr/bin/ocpasswd; do
        [[ -f "$p" ]] || continue
        mkdir -p "$dest/binaries$(dirname "$p")"
        cp -a "$p" "$dest/binaries$p"
    done
}

restore_binaries_from_backup() {
    local src="$1" p rel
    [[ -d "$src/binaries" ]] || return 0
    while IFS= read -r -d '' p; do
        rel="${p#"$src/binaries"}"
        mkdir -p "$(dirname "$rel")"
        cp -a "$p" "$rel"
    done < <(find "$src/binaries" -type f -print0)
}

backup_ocserv_update_runtime() {
    local dest="$1" manifest path
    mkdir -p "$dest/update-runtime/rootfs"
    if dpkg-query -W -f='${Status}' ocserv 2>/dev/null | grep -q 'install ok installed'; then
        echo package > "$dest/update-runtime/old-method"
    elif [[ -f "$(source_install_manifest)" ]]; then
        echo source > "$dest/update-runtime/old-method"
    else
        echo unmanaged > "$dest/update-runtime/old-method"
    fi
    manifest="$(source_install_manifest)"
    if [[ -f "$manifest" ]]; then
        cp -a "$manifest" "$dest/update-runtime/old-source-manifest"
        while IFS= read -r path; do
            [[ "$path" == /usr/local/* ]] || continue
            if [[ -f "$path" || -L "$path" ]]; then
                mkdir -p "$dest/update-runtime/rootfs$(dirname "$path")"
                cp -a "$path" "$dest/update-runtime/rootfs$path"
            fi
        done < "$manifest"
    fi
}

rollback_ocserv_update_runtime() {
    local src="$1" old_method="unmanaged"
    [[ -f "$src/update-runtime/old-method" ]] && old_method="$(cat "$src/update-runtime/old-method")"
    print_warn "Rolling ocserv runtime back to previous installation method: $old_method"

    # Remove any manager-tracked source files installed by the failed update.
    remove_source_install_files || true

    case "$old_method" in
        package)
            export DEBIAN_FRONTEND=noninteractive
            apt-get install -y ocserv || print_warn "Package reinstall during rollback failed; restoring saved binaries as fallback."
            ;;
        source)
            if dpkg-query -W -f='${Status}' ocserv 2>/dev/null | grep -q 'install ok installed'; then
                DEBIAN_FRONTEND=noninteractive apt-get remove -y ocserv || true
            fi
            if [[ -d "$src/update-runtime/rootfs" ]]; then cp -a "$src/update-runtime/rootfs/." /; fi
            if [[ -f "$src/update-runtime/old-source-manifest" ]]; then
                cp -a "$src/update-runtime/old-source-manifest" "$(source_install_manifest)"
                chmod 600 "$(source_install_manifest)"
            fi
            ;;
        *) restore_binaries_from_backup "$src" ;;
    esac

    # Saved binaries are also a fallback for interrupted/unmanaged installations.
    restore_binaries_from_backup "$src" || true
    if [[ -f "$src/ocserv.service" ]]; then cp -a "$src/ocserv.service" "$SYSTEMD_DEFAULT"; elif [[ -f "$src/.no-ocserv-service" ]]; then rm -f "$SYSTEMD_DEFAULT"; fi
    if [[ -f "$src/ocserv@.service" ]]; then cp -a "$src/ocserv@.service" "$SYSTEMD_TEMPLATE"; elif [[ -f "$src/.no-ocserv-template" ]]; then rm -f "$SYSTEMD_TEMPLATE"; fi
    ldconfig || true
    systemctl daemon-reload || true
}

source_install_manifest() { printf '%s/ocserv-source-install-files.txt\n' "$MANAGER_ETC"; }

remove_source_install_files() {
    local manifest path
    manifest="$(source_install_manifest)"
    [[ -f "$manifest" ]] || return 0
    print_info "Removing files from the previous manager-tracked source installation before switching installation method."
    tac "$manifest" | while IFS= read -r path; do
        [[ "$path" == /usr/local/* ]] || continue
        [[ -f "$path" || -L "$path" ]] && rm -f "$path"
    done
    # Remove now-empty directories only, never recursive unknown content.
    awk -F/ 'NF>2{NF--; print "/" substr($0,index($0,$2))}' OFS=/ "$manifest" | sort -r -u | while read -r path; do rmdir "$path" 2>/dev/null || true; done
    rm -f "$manifest"
    ldconfig || true
}

install_ocserv_package() {
    remove_source_install_files
    apt_update_once
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y ocserv
    capture_stock_template_from_package || print_warn "Could not save the distribution sample config automatically; the manager will retry before first managed config write."
    print_ok "Installed distribution ocserv package: $(installed_ocserv_version)"
}

install_ocserv_source() {
    local version="$1" work tag_sha local_sha build_system b stage caller_pwd multiarch smoke_bin
    [[ "$version" =~ ^[A-Za-z0-9._-]+$ ]] || { print_err "Unsafe version/tag: $version"; return 1; }

    print_info "Installing build dependencies. Optional authentication/runtime dependencies are installed when available."
    install_available_packages \
        build-essential meson ninja-build pkg-config git ca-certificates curl jq \
        libgnutls28-dev nettle-dev libev-dev libreadline-dev libtasn1-bin \
        libpam0g-dev liblz4-dev libseccomp-dev libnl-route-3-dev libkrb5-dev \
        libradcli-dev libcurl4-gnutls-dev libcjose-dev libjansson-dev liboath-dev \
        libprotobuf-c-dev libtalloc-dev libhttp-parser-dev protobuf-c-compiler gnutls-bin \
        libsystemd-dev libmaxminddb-dev libwrap0-dev libssl-dev \
        gperf gawk iproute2 iputils-ping ipcalc-ng iperf3 tcpdump \
        libuid-wrapper libpam-wrapper libnss-wrapper libsocket-wrapper \
        autoconf automake libtool gettext

    # A user/custom shell can override pkg-config discovery in a way that hides
    # normal Debian/Ubuntu multiarch .pc files. Build natively with the standard
    # system paths plus /usr/local, which is what this manager supports.
    unset PKG_CONFIG_LIBDIR || true
    multiarch="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)"
    PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/lib/${multiarch:-x}/pkgconfig:/usr/lib/${multiarch:-x}/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    export PKG_CONFIG_PATH

    caller_pwd="$(pwd -P 2>/dev/null || echo /root)"
    work="$(mktemp -d "$BUILD_ROOT/build.XXXXXX")"
    # Always leave the temporary tree before deleting it. v2.2 could remove the
    # current working directory on an error, which produced getcwd() failures
    # during the outer rollback path.
    trap 'cd "${caller_pwd:-/}" 2>/dev/null || cd /; rm -rf "${work:-}" 2>/dev/null || true; trap - RETURN' RETURN

    print_info "Fetching tag $version from the official OpenConnect GitLab repository with TLS verification enabled."
    git -c http.sslVerify=true clone --depth 1 --branch "$version" --single-branch \
        https://gitlab.com/openconnect/ocserv.git "$work/src"

    git -C "$work/src" submodule update --init --recursive --depth 1

    tag_sha="$(curl -fsSL --retry 3 --connect-timeout 10 \
      "https://gitlab.com/api/v4/projects/openconnect%2Focserv/repository/tags/$version" \
      | jq -r '.commit.id // empty')"
    local_sha="$(git -C "$work/src" rev-parse HEAD)"
    if [[ -n "$tag_sha" && "$tag_sha" != "$local_sha" ]]; then
        print_err "Integrity check failed: cloned commit does not match GitLab tag commit."
        return 1
    fi
    print_ok "Source tag commit verified: ${local_sha:0:12}"
    capture_stock_template_from_source_tree "$version" "$work/src" || print_warn "Upstream sample.config was not found in the source tree; it will be retrieved on demand before configuration."

    if git -C "$work/src" tag -v "$version" >/dev/null 2>&1; then
        print_ok "Git tag signature verified by locally trusted GPG keys."
    else
        print_info "No locally verifiable tag signature was available; HTTPS + tag commit verification succeeded."
    fi

    cd "$work/src"
    if [[ -f meson.build ]]; then
        build_system="meson"
        print_info "Detected Meson build system."
        local -a meson_opts=(--buildtype=release --prefix=/usr/local)

        # OIDC is disabled by upstream by default. Enable it only when Meson will
        # be able to resolve ALL three dependencies through pkg-config. v2.2 only
        # checked the cjose header and could therefore force a setup failure.
        if pkg-config --exists libcurl cjose jansson 2>/dev/null; then
            meson_opts+=(-Doidc-auth=enabled)
            print_info "OIDC build dependencies detected; enabling OIDC authentication support."
        else
            meson_opts+=(-Doidc-auth=disabled)
            print_info "Complete OIDC build dependencies were not detected; building with upstream OIDC support disabled."
        fi

        if ! meson setup build "${meson_opts[@]}"; then
            print_warn "Meson setup with the selected optional features failed; retrying with conservative upstream defaults."
            rm -rf build
            meson setup build --buildtype=release --prefix=/usr/local -Doidc-auth=disabled
        fi
        ninja -C build

        # Production installation must not be gated by the complete upstream
        # developer/CI suite. Many ocserv tests start servers, use namespaces,
        # TUN, PAM/RADIUS fixtures and timing assumptions; they can legitimately
        # fail in VPS/container environments even after a successful build.
        smoke_bin="$work/src/build/src/ocserv"
        [[ -x "$smoke_bin" ]] || { print_err "Build completed but the ocserv executable was not produced."; return 1; }
        "$smoke_bin" --version >/dev/null
        [[ -x "$work/src/build/src/occtl/occtl" ]] || { print_err "Build completed but occtl was not produced."; return 1; }
        [[ -x "$work/src/build/src/ocpasswd/ocpasswd" ]] || { print_err "Build completed but ocpasswd was not produced."; return 1; }
        print_ok "Build smoke checks passed (ocserv, occtl, ocpasswd)."

        if [[ "${OCSERV_MANAGER_RUN_UPSTREAM_TESTS:-0}" == "1" ]]; then
            print_info "OCSERV_MANAGER_RUN_UPSTREAM_TESTS=1: running the optional upstream developer test suite."
            if ! meson test -C build --no-rebuild; then
                print_warn "Upstream developer tests reported failures on this host. The compiled binaries passed production smoke checks, so installation will continue."
            fi
        else
            print_info "Skipping the full upstream developer/CI test suite during production installation."
        fi

        stage="$work/stage"
        mkdir -p "$stage"
        DESTDIR="$stage" meson install -C build
    else
        build_system="autotools"
        print_info "Detected legacy Autotools build path."
        if [[ ! -x ./configure ]]; then
            autoreconf -fvi
        fi
        ./configure --prefix=/usr/local
        make -j"$(nproc)"
        smoke_bin="$(find "$work/src" -maxdepth 3 -type f -name ocserv -perm -111 2>/dev/null | head -n1 || true)"
        [[ -n "$smoke_bin" && -x "$smoke_bin" ]] || { print_err "Build completed but the ocserv executable was not produced."; return 1; }
        "$smoke_bin" --version >/dev/null 2>&1 || { print_err "Built ocserv executable failed its version smoke check."; return 1; }
        print_ok "Legacy build smoke check passed."
        if [[ "${OCSERV_MANAGER_RUN_UPSTREAM_TESTS:-0}" == "1" ]]; then
            print_info "OCSERV_MANAGER_RUN_UPSTREAM_TESTS=1: running optional legacy upstream tests."
            make check || print_warn "Legacy upstream developer tests reported failures on this host; installation will continue because the build smoke check passed."
        else
            print_info "Skipping the full legacy upstream developer/CI test suite during production installation."
        fi
        stage="$work/stage"
        mkdir -p "$stage"
        make DESTDIR="$stage" install
    fi

    # Only remove the distro package after the upstream build and tests succeeded.
    # This keeps the currently working package intact if compilation fails.
    if dpkg-query -W -f='${Status}' ocserv 2>/dev/null | grep -q 'install ok installed'; then
        print_info "Build passed. Removing the distribution ocserv package without purging configuration to avoid duplicate package/source ownership."
        DEBIAN_FRONTEND=noninteractive apt-get remove -y ocserv
    fi

    # Remove the previous manager-tracked source payload only after the new build has passed tests.
    # The outer updater has already backed it up for rollback.
    remove_source_install_files

    # Install from a staging tree so every source-installed file is tracked for a safe uninstall/switch back to distro packages.
    find "$stage" \( -type f -o -type l \) -printf '%p\n' | sed "s#^$stage##" | sort -u > "$(source_install_manifest).new"
    cp -a "$stage/." /
    mv "$(source_install_manifest).new" "$(source_install_manifest)"
    chmod 600 "$(source_install_manifest)"
    ldconfig || true
    b="$(ocserv_bin)"
    [[ -x "$b" ]] || { print_err "ocserv binary not found after installation."; return 1; }
    "$b" --version
    printf 'method=source\nversion=%s\ncommit=%s\nbuild_system=%s\nbinary=%s\n' \
        "$version" "$local_sha" "$build_system" "$b" > "$MANAGER_ETC/ocserv-install.env"
    audit "ocserv-installed method=source version=$version commit=$local_sha build=$build_system"
    cd "$caller_pwd" 2>/dev/null || cd /
    rm -rf "$work" 2>/dev/null || true
    trap - RETURN
    print_ok "ocserv $version installed from upstream source."
}

install_or_update_ocserv() {
    ensure_dirs
    install_runtime_dependencies
    local target method version backup active_services=() svc b
    target="$(select_ocserv_install_target)" || return 1
    method="${target%%|*}"
    version="${target#*|}"
    if [[ "$method" == "back" ]]; then
        print_info "Install/update cancelled; returning to the main menu."
        return 0
    fi
    local keep_update_backup=0
    if ask_yes_no "Create a persistent safety backup before installing/updating ocserv?" "y"; then
        ensure_backup_root
        backup="$BACKUP_ROOT/update-$(date +%Y%m%d-%H%M%S)"
        keep_update_backup=1
    else
        backup="$(mktemp -d /tmp/ocserv-manager-update-rollback.XXXXXX)"
        print_warn "No persistent update backup will be kept. A temporary rollback copy is used only while this update is running."
    fi
    mkdir -p "$backup"
    cp -a "$OCSERV_ETC" "$backup/ocserv-etc" 2>/dev/null || true
    cp -a "$MANAGER_ETC" "$backup/manager-etc" 2>/dev/null || true
    if [[ -f "$SYSTEMD_DEFAULT" ]]; then cp -a "$SYSTEMD_DEFAULT" "$backup/ocserv.service"; else touch "$backup/.no-ocserv-service"; fi
    if [[ -f "$SYSTEMD_TEMPLATE" ]]; then cp -a "$SYSTEMD_TEMPLATE" "$backup/ocserv@.service"; else touch "$backup/.no-ocserv-template"; fi
    backup_binaries_for_update "$backup"
    backup_ocserv_update_runtime "$backup"

    while IFS= read -r svc; do
        [[ -n "$svc" ]] && active_services+=("$svc")
    done < <(list_services | while read -r s; do systemctl is-active --quiet "$s" && echo "$s" || true; done)

    if [[ "$method" == "package" ]]; then
        install_ocserv_package || { rollback_ocserv_update_runtime "$backup"; return 1; }
    else
        install_ocserv_source "$version" || { rollback_ocserv_update_runtime "$backup"; return 1; }
    fi

    # The binary path may change between distro (/usr/sbin) and source (/usr/local/sbin).
    # Rebuild only the service launchers; instance configs/users/certs are untouched.
    write_systemd_units || { rollback_ocserv_update_runtime "$backup"; return 1; }

    if ! validate_all_configs; then
        print_err "One or more existing configs are not valid with the new ocserv binary. Rolling back runtime and units."
        rollback_ocserv_update_runtime "$backup"
        return 1
    fi

    for svc in "${active_services[@]}"; do
        if ! systemctl restart "$svc"; then
            print_err "$svc failed after update. Rolling back runtime and systemd units."
            rollback_ocserv_update_runtime "$backup"
            for svc in "${active_services[@]}"; do systemctl restart "$svc" >/dev/null 2>&1 || true; done
            return 1
        fi
    done
    b="$(ocserv_bin)"
    print_ok "Ocserv update/install completed without reconfiguring users, groups, certificates or instance settings."
    echo "Binary: $b"
    echo "Version: $(installed_ocserv_version)"
    if (( keep_update_backup == 1 )); then
        echo "Safety backup: $backup"
    else
        rm -rf "$backup" 2>/dev/null || true
        echo "Persistent safety backup: not created (declined)"
    fi
}

instance_state_file() {
    local instance="$1"
    printf '%s/%s.env\n' "$STATE_ROOT" "$instance"
}

instance_dir() {
    local instance="$1"
    if [[ "$instance" == "default" ]]; then
        printf '%s\n' "$OCSERV_ETC"
    else
        printf '%s/%s\n' "$INSTANCE_ROOT" "$instance"
    fi
}

standard_instance_config() {
    local instance="$1"
    printf '%s/ocserv.conf\n' "$(instance_dir "$instance")"
}

instance_config() {
    local instance="$1" f configured
    f="$(instance_state_file "$instance")"
    if [[ -f "$f" ]]; then
        configured="$(sed -n 's/^CONFIG=//p' "$f" | tail -n1)"
        if [[ -n "$configured" ]]; then
            printf '%s\n' "$configured"
            return 0
        fi
    fi
    standard_instance_config "$instance"
}

instance_passwd() {
    local instance="$1"
    local f shared
    f="$(instance_state_file "$instance")"
    if [[ -f "$f" ]]; then
        shared="$(state_get "$instance" OCPASSWD 2>/dev/null || true)"
        [[ -n "$shared" ]] && { printf '%s\n' "$shared"; return; }
    fi
    printf '%s/ocpasswd\n' "$(instance_dir "$instance")"
}

instance_socket() {
    local instance="$1" saved=""
    if [[ -f "$(instance_state_file "$instance")" ]]; then
        saved="$(state_get "$instance" OCCTL_SOCKET 2>/dev/null || true)"
        [[ -n "$saved" ]] && { printf '%s\n' "$saved"; return; }
    fi
    if [[ "$instance" == "default" ]]; then
        printf '/run/occtl.socket\n'
    else
        printf '/run/occtl-%s.socket\n' "$instance"
    fi
}

instance_pid() {
    local instance="$1"
    if [[ "$instance" == "default" ]]; then
        printf '/run/ocserv.pid\n'
    else
        printf '/run/ocserv-%s.pid\n' "$instance"
    fi
}

instance_service() {
    local instance="$1"
    if [[ "$instance" == "default" ]]; then printf 'ocserv.service\n'; else printf 'ocserv@%s.service\n' "$instance"; fi
}

state_get() {
    local instance="$1" key="$2" f
    f="$(instance_state_file "$instance")"
    [[ -f "$f" ]] || return 1
    sed -n "s/^${key}=//p" "$f" | tail -n1
}

state_set() {
    local instance="$1" key="$2" value="$3" f tmp
    f="$(instance_state_file "$instance")"
    mkdir -p "$(dirname "$f")"
    touch "$f"
    chmod 600 "$f"
    tmp="$(mktemp)"
    grep -vE "^${key}=" "$f" > "$tmp" || true
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
    mv "$tmp" "$f"
    chmod 600 "$f"
}

register_instance() {
    local instance="$1" conf="$2" passwd="$3" subnet="$4" tcp="$5" udp="$6" listen="$7" auth="$8"
    state_set "$instance" NAME "$instance"
    state_set "$instance" CONFIG "$conf"
    state_set "$instance" OCPASSWD "$passwd"
    state_set "$instance" SUBNET "$subnet"
    state_set "$instance" TCP_PORT "$tcp"
    state_set "$instance" UDP_PORT "$udp"
    state_set "$instance" LISTEN_HOST "$listen"
    state_set "$instance" AUTH_MODE "$auth"
    state_set "$instance" SERVICE "$(instance_service "$instance")"
    state_set "$instance" OCCTL_SOCKET "$(instance_socket "$instance")"
    # v2.2: raw iptables is the default. UFW is never installed, enabled, or modified
    # unless the administrator explicitly selects UFW integration for this instance.
    [[ -n "$(state_get "$instance" FIREWALL_MODE 2>/dev/null || true)" ]] || state_set "$instance" FIREWALL_MODE iptables
    state_set "$instance" UPDATED_AT "$(date -Is)"
}

list_instances() {
    local f name
    shopt -s nullglob
    for f in "$STATE_ROOT"/*.env; do
        name="$(basename "$f" .env)"
        echo "$name"
    done
    shopt -u nullglob
    if [[ -f "$OCSERV_ETC/ocserv.conf" && ! -f "$STATE_ROOT/default.env" ]]; then
        echo default
    fi
}

list_services() {
    local i
    while IFS= read -r i; do
        [[ -n "$i" ]] && instance_service "$i"
    done < <(list_instances | sort -u)
}

choose_instance() {
    local -a items=()
    local i idx
    while IFS= read -r i; do [[ -n "$i" ]] && items+=("$i"); done < <(list_instances | sort -u)
    ((${#items[@]})) || { print_err "No managed ocserv instance found." >&2; return 1; }
    echo "Instances:" >&2
    for ((idx=0; idx<${#items[@]}; idx++)); do printf '%d) %s\n' "$((idx+1))" "${items[$idx]}" >&2; done
    while true; do
        read -r -p "Select instance: " idx || true
        if [[ "$idx" =~ ^[0-9]+$ ]] && ((idx>=1 && idx<=${#items[@]})); then
            printf '%s\n' "${items[$((idx-1))]}"
            return 0
        fi
        print_warn "Invalid selection." >&2
    done
}

write_systemd_units() {
    local b
    b="$(ocserv_bin)"
    [[ -n "$b" ]] || { print_err "ocserv is not installed."; return 1; }

    cat > "$SYSTEMD_DEFAULT" <<EOF
[Unit]
Description=OpenConnect SSL VPN server (default instance)
After=network.target

[Service]
Type=simple
ExecStart=$b --foreground --pid-file=/run/ocserv.pid --config=/etc/ocserv/ocserv.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    cat > "$SYSTEMD_TEMPLATE" <<EOF
[Unit]
Description=OpenConnect SSL VPN server instance %i
After=network.target

[Service]
Type=simple
ExecStart=$b --foreground --pid-file=/run/ocserv-%i.pid --config=/etc/ocserv/instances/%i/ocserv.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

refresh_manager_boot_units_without_reconfigure() {
    local changed=0
    if [[ -n "$(ocserv_bin 2>/dev/null || true)" ]] && { grep -qs 'network-online.target' "$SYSTEMD_DEFAULT" || grep -qs 'network-online.target' "$SYSTEMD_TEMPLATE"; }; then
        write_systemd_units >/dev/null 2>&1 || true
        changed=1
    fi
    if [[ -f /etc/systemd/system/ocserv-manager-central@.service ]] && grep -q 'network-online.target' /etc/systemd/system/ocserv-manager-central@.service; then
        write_central_adapter_files >/dev/null 2>&1 || true
        changed=1
    fi
    if (( changed == 1 )); then
        systemctl daemon-reload >/dev/null 2>&1 || true
        print_ok "Removed obsolete network-online.target dependencies from existing Ocserv Manager boot units without reconfiguring instances."
    fi
}

enable_service_if_needed() {
    local svc="$1"
    if ! systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        systemctl enable "$svc" >/dev/null 2>&1
    fi
}

restart_service_bounded() {
    local svc="$1" max_seconds="${2:-15}" waited=0 state
    print_info "Starting $svc (startup timeout: ${max_seconds}s)..."
    systemctl reset-failed "$svc" >/dev/null 2>&1 || true
    systemctl restart --no-block "$svc"
    while (( waited < max_seconds * 2 )); do
        state="$(systemctl is-active "$svc" 2>/dev/null || true)"
        case "$state" in
            active) return 0 ;;
            failed) return 1 ;;
        esac
        sleep 0.5
        ((waited+=1))
    done
    print_err "$svc did not reach active state within ${max_seconds}s."
    return 1
}

start_managed_instance_bounded() {
    local instance="$1" svc
    svc="$(instance_service "$instance")"
    enable_service_if_needed "$svc"
    restart_service_bounded "$svc" 15
}

validate_config() {
    local conf="$1" b
    b="$(ocserv_bin)"
    [[ -n "$b" ]] || { print_err "ocserv binary missing."; return 1; }
    [[ -f "$conf" ]] || { print_err "Config missing: $conf"; return 1; }
    "$b" --test-config --config "$conf"
}

validate_all_configs() {
    local i conf failed=0
    while IFS= read -r i; do
        [[ -n "$i" ]] || continue
        conf="$(instance_config "$i")"
        [[ -f "$conf" ]] || continue
        if ! validate_config "$conf" >/dev/null 2>&1; then
            print_err "Invalid config for instance $i: $conf"
            failed=1
        fi
    done < <(list_instances | sort -u)
    (( failed == 0 ))
}

transactional_replace_config() {
    local instance="$1" newfile="$2" conf service rollback_file="" persistent_backup="" keep_backup=0
    conf="$(instance_config "$instance")"
    service="$(instance_service "$instance")"

    if ! validate_config "$newfile"; then
        print_err "New configuration failed ocserv --test-config. No changes applied."
        return 1
    fi

    if [[ -f "$conf" ]]; then
        if ask_yes_no "Create a persistent backup of the current $instance ocserv.conf before applying this change?" "y"; then
            ensure_backup_root
            persistent_backup="$BACKUP_ROOT/config-$instance-$(date +%Y%m%d-%H%M%S).conf"
            cp -a "$conf" "$persistent_backup"
            rollback_file="$persistent_backup"
            keep_backup=1
        else
            rollback_file="$(mktemp /tmp/ocserv-manager-config-rollback.${instance}.XXXXXX)"
            cp -a "$conf" "$rollback_file"
            print_warn "No persistent config backup will be kept. A temporary rollback copy is used only for this transaction."
        fi
    fi

    mkdir -p "$(dirname "$conf")"
    CURRENT_TXN_BACKUP="$rollback_file"
    CURRENT_TXN_CONFIG="$conf"
    CURRENT_TXN_SERVICE="$service"
    install -m 600 "$newfile" "$conf"

    if systemctl is-active --quiet "$service" 2>/dev/null; then
        if ! restart_service_bounded "$service" 15; then
            print_err "Restart failed or timed out; restoring previous config."
            if [[ -n "$rollback_file" && -f "$rollback_file" ]]; then
                cp -a "$rollback_file" "$conf"
                restart_service_bounded "$service" 15 >/dev/null 2>&1 || true
            fi
            (( keep_backup == 0 )) && rm -f "$rollback_file" 2>/dev/null || true
            CURRENT_TXN_BACKUP=""; CURRENT_TXN_CONFIG=""; CURRENT_TXN_SERVICE=""
            return 1
        fi
    fi
    CURRENT_TXN_BACKUP=""; CURRENT_TXN_CONFIG=""; CURRENT_TXN_SERVICE=""
    audit "config-updated instance=$instance backup=${persistent_backup:-declined}"
    print_ok "Configuration applied transactionally."
    if (( keep_backup == 1 )); then
        print_info "Persistent backup: $persistent_backup"
    else
        rm -f "$rollback_file" 2>/dev/null || true
        print_info "Persistent backup: not created (declined)"
    fi
}

default_route_iface() {
    ip -4 route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}'
}

default_route_src() {
    ip -4 route get 1.1.1.1 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}'
}

public_ipv4() {
    curl -4 -fsS --max-time 4 https://api.ipify.org 2>/dev/null || default_route_src
}

list_local_ipv4() {
    ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print $2"|"a[1]}' | sort -u
}

choose_listen_host() {
    local -a opts=("All IPv4 addresses (0.0.0.0)") vals=("0.0.0.0")
    local line iface ip idx
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        iface="${line%%|*}"; ip="${line#*|}"
        opts+=("$ip on $iface"); vals+=("$ip")
    done < <(list_local_ipv4)
    opts+=("Custom IP/hostname"); vals+=("CUSTOM")
    idx="$(choose_menu "Choose address for ocserv to listen on:" "${opts[@]}")"
    if [[ "${vals[$((idx-1))]}" == "CUSTOM" ]]; then
        ask_nonempty "Listen IP or hostname"
    else
        printf '%s\n' "${vals[$((idx-1))]}"
    fi
}

port_in_use() {
    local proto="$1" port="$2" listen="$3"
    if [[ "$proto" == tcp ]]; then
        ss -H -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$port$" || return 1
    else
        ss -H -lnu 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$port$" || return 1
    fi
    return 0
}


external_port_collision() {
    local instance="$1" proto="$2" port="$3" listen="$4" pid lines line local_ep existing
    pid="$(systemctl show "$(instance_service "$instance")" -p MainPID --value 2>/dev/null || echo 0)"
    if [[ "$proto" == tcp ]]; then
        lines="$(ss -H -ltnp 2>/dev/null | awk -v p=":$port" '$4 ~ p"$"')"
    else
        lines="$(ss -H -lunp 2>/dev/null | awk -v p=":$port" '$4 ~ p"$"')"
    fi
    [[ -n "$lines" ]] || return 1
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        if [[ "$pid" != 0 && "$line" == *"pid=$pid,"* ]]; then continue; fi
        local_ep="$(awk '{print $4}' <<<"$line")"
        existing="${local_ep%:*}"; existing="${existing#[}"; existing="${existing%]}"
        if [[ "$listen" == "0.0.0.0" || "$listen" == "*" || "$existing" == "*" || "$existing" == "0.0.0.0" || "$existing" == "::" || "$existing" == "$listen" ]]; then
            echo "$line"
            return 0
        fi
        if [[ ! "$listen" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then return 0; fi
    done <<<"$lines"
    return 1
}
configured_port_collision() {
    local instance="$1" listen="$2" tcp="$3" udp="$4" f n l t u
    shopt -s nullglob
    for f in "$STATE_ROOT"/*.env; do
        n="$(basename "$f" .env)"
        [[ "$n" == "$instance" ]] && continue
        l="$(sed -n 's/^LISTEN_HOST=//p' "$f" | tail -n1)"
        t="$(sed -n 's/^TCP_PORT=//p' "$f" | tail -n1)"
        u="$(sed -n 's/^UDP_PORT=//p' "$f" | tail -n1)"
        if [[ "$listen" == "0.0.0.0" || "$l" == "0.0.0.0" || "$listen" == "$l" ]]; then
            [[ "$tcp" == "$t" ]] && { print_err "TCP $tcp conflicts with instance $n on $l."; shopt -u nullglob; return 0; }
            [[ "$udp" == "$u" ]] && { print_err "UDP $udp conflicts with instance $n on $l."; shopt -u nullglob; return 0; }
        fi
    done
    shopt -u nullglob
    return 1
}

choose_port() {
    local label="$1" default="$2" choice val
    choice="$(choose_menu "$label" "443" "8443" "10443" "4443" "Custom port")"
    case "$choice" in
        1) val=443 ;; 2) val=8443 ;; 3) val=10443 ;; 4) val=4443 ;;
        5)
            while true; do
                val="$(ask_value "Port" "$default")"
                valid_port "$val" && break
                print_warn "Port must be between 1 and 65535."
            done
            ;;
    esac
    printf '%s\n' "$val"
}

choose_available_tcp_port() {
    local instance="$1" listen="$2" default="$3" port
    while true; do
        port="$(choose_port "TCP port" "$default")"
        if configured_port_collision "$instance" "$listen" "$port" 0 || \
           external_port_collision "$instance" tcp "$port" "$listen" >/dev/null 2>&1; then
            print_warn "TCP $listen:$port conflicts with another managed instance or listening service."
            continue
        fi
        printf '%s\n' "$port"
        return 0
    done
}

choose_available_udp_port() {
    local instance="$1" listen="$2" default="$3" port
    while true; do
        port="$(choose_port "UDP port" "$default")"
        if configured_port_collision "$instance" "$listen" 0 "$port" || \
           external_port_collision "$instance" udp "$port" "$listen" >/dev/null 2>&1; then
            print_warn "UDP $listen:$port conflicts with another managed instance or listening service."
            continue
        fi
        printf '%s\n' "$port"
        return 0
    done
}

configured_subnets() {
    local f n
    shopt -s nullglob
    for f in "$STATE_ROOT"/*.env; do
        n="$(sed -n 's/^SUBNET=//p' "$f" | tail -n1)"
        [[ -n "$n" ]] && echo "$n"
    done
    shopt -u nullglob
}

subnet_collides() {
    local candidate="$1" skip_instance="${2:-}"
    python3 - "$candidate" "$STATE_ROOT" "$skip_instance" <<'PY'
import ipaddress, pathlib, sys
cand=ipaddress.ip_network(sys.argv[1], strict=False)
root=pathlib.Path(sys.argv[2]); skip=sys.argv[3]
for f in root.glob('*.env'):
    if f.stem == skip: continue
    for line in f.read_text(errors='ignore').splitlines():
        if line.startswith('SUBNET='):
            try:
                other=ipaddress.ip_network(line.split('=',1)[1], strict=False)
                if cand.overlaps(other):
                    print(f"managed instance {f.stem}: {other}")
                    raise SystemExit(0)
            except ValueError: pass
# Include managed virtual-host pools too.
for vf in pathlib.Path("/etc/ocserv").glob("**/vhosts/*.conf"):
    try:
        vlines=vf.read_text(errors="ignore").splitlines()
        network=next((x.split("=",1)[1].strip() for x in vlines if x.strip().startswith("ipv4-network") and "=" in x and not x.lstrip().startswith("#")), "")
        netmask=next((x.split("=",1)[1].strip() for x in vlines if x.strip().startswith("ipv4-netmask") and "=" in x and not x.lstrip().startswith("#")), "")
        if network:
            spec=network if "/" in network else f"{network}/{netmask or '255.255.255.255'}"
            other=ipaddress.ip_network(spec, strict=False)
            if cand.overlaps(other):
                print(f"vhost {vf.name}: {other}")
                raise SystemExit(0)
    except (OSError,ValueError):
        pass
# Check connected/local non-default routes, excluding 0/0.
import subprocess
out=subprocess.run(['ip','-4','route','show'], text=True, capture_output=True).stdout
for line in out.splitlines():
    first=line.split()[0] if line.split() else ''
    if first in ('default','broadcast','local','unreachable','blackhole','prohibit','throw'): continue
    try:
        other=ipaddress.ip_network(first, strict=False)
    except Exception:
        continue
    if cand.overlaps(other):
        print(f"host route: {other}")
        raise SystemExit(0)
raise SystemExit(1)
PY
}

ipv6_subnet_collides() {
    local candidate="$1" skip_instance="${2:-}"
    python3 - "$candidate" "$STATE_ROOT" "$skip_instance" <<'PY6COL'
import ipaddress,pathlib,subprocess,sys
cand=ipaddress.ip_network(sys.argv[1],strict=False); root=pathlib.Path(sys.argv[2]); skip=sys.argv[3]
for f in root.glob('*.env'):
    if f.stem==skip: continue
    for line in f.read_text(errors='ignore').splitlines():
        if line.startswith('IPV6_NETWORK=') and line.split('=',1)[1].strip():
            try:
                other=ipaddress.ip_network(line.split('=',1)[1].strip(),strict=False)
                if cand.overlaps(other): print(f"managed instance {f.stem}: {other}"); raise SystemExit(0)
            except ValueError: pass
out=subprocess.run(['ip','-6','route','show'],text=True,capture_output=True).stdout
for line in out.splitlines():
    a=line.split()
    if not a or a[0] in ('default','unreachable','prohibit','blackhole'): continue
    try:
        other=ipaddress.ip_network(a[0],strict=False)
        if cand.overlaps(other): print(f"host route: {other}"); raise SystemExit(0)
    except ValueError: pass
raise SystemExit(1)
PY6COL
}

suggest_private_subnet() {
    local pool="$1" prefix="$2" skip="${3:-}"
    python3 - "$pool" "$prefix" "$STATE_ROOT" "$skip" <<'PY'
import ipaddress, pathlib, subprocess, sys
pool=ipaddress.ip_network(sys.argv[1]); pfx=int(sys.argv[2]); root=pathlib.Path(sys.argv[3]); skip=sys.argv[4]
used=[]
for f in root.glob('*.env'):
    if f.stem == skip: continue
    for line in f.read_text(errors='ignore').splitlines():
        if line.startswith('SUBNET='):
            try: used.append(ipaddress.ip_network(line.split('=',1)[1], strict=False))
            except: pass
for vf in pathlib.Path("/etc/ocserv").glob("**/vhosts/*.conf"):
    try:
        vlines=vf.read_text(errors="ignore").splitlines()
        network=next((x.split("=",1)[1].strip() for x in vlines if x.strip().startswith("ipv4-network") and "=" in x and not x.lstrip().startswith("#")), "")
        netmask=next((x.split("=",1)[1].strip() for x in vlines if x.strip().startswith("ipv4-netmask") and "=" in x and not x.lstrip().startswith("#")), "")
        if network:
            spec=network if "/" in network else f"{network}/{netmask or '255.255.255.255'}"
            used.append(ipaddress.ip_network(spec, strict=False))
    except Exception: pass
out=subprocess.run(['ip','-4','route','show'], text=True, capture_output=True).stdout
for line in out.splitlines():
    a=line.split()
    if not a or a[0]=='default': continue
    try: used.append(ipaddress.ip_network(a[0], strict=False))
    except: pass
for n in pool.subnets(new_prefix=pfx):
    if n.num_addresses < 8: continue
    if all(not n.overlaps(u) for u in used):
        print(n); break
PY
}

choose_subnet() {
    local instance="$1" family prefix pool suggested custom choice collision
    choice="$(choose_menu "Choose private IPv4 address family/network:" \
        "10.10.0.0/16 (preset)" \
        "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" "Custom private CIDR")"
    case "$choice" in
        1)
            custom="10.10.0.0/16"
            if collision="$(subnet_collides "$custom" "$instance" 2>/dev/null)"; then
                print_warn "Preset subnet overlaps $collision"
                ask_yes_no "Use 10.10.0.0/16 anyway?" "n" || return 1
            fi
            echo "$custom"
            return 0
            ;;
        2) pool="10.0.0.0/8" ;;
        3) pool="172.16.0.0/12" ;;
        4) pool="192.168.0.0/16" ;;
        5)
            while true; do
                custom="$(ask_nonempty "VPN IPv4 network in CIDR, e.g. 10.30.0.0/24")"
                if valid_ipv4_cidr "$custom"; then
                    custom="$(normalize_cidr "$custom")"
                    is_rfc1918_cidr "$custom" || { print_warn "Use an RFC1918 private range."; continue; }
                    if collision="$(subnet_collides "$custom" "$instance" 2>/dev/null)"; then
                        print_warn "Subnet overlaps $collision"
                        ask_yes_no "Use it anyway?" "n" && { echo "$custom"; return 0; }
                    else
                        echo "$custom"; return 0
                    fi
                else
                    print_warn "Invalid IPv4 CIDR."
                fi
            done
            ;;
    esac
    prefix="$(choose_menu "Choose subnet size:" "/24 (recommended for most installations)" "/23" "/22" "/20" "/16" "Custom prefix")"
    case "$prefix" in
        1) prefix=24 ;; 2) prefix=23 ;; 3) prefix=22 ;; 4) prefix=20 ;; 5) prefix=16 ;;
        6)
            while true; do
                prefix="$(ask_integer "Prefix length" "24" "8" "30")"
                local pool_pfx="${pool#*/}"
                (( prefix >= pool_pfx )) && break
                print_warn "Prefix /$prefix is larger than selected pool $pool."
            done
            ;;
    esac
    suggested="$(suggest_private_subnet "$pool" "$prefix" "$instance")"
    [[ -n "$suggested" ]] || { print_err "No free subnet suggestion found in $pool/$prefix."; return 1; }
    print_info "Suggested free subnet: $suggested" >&2
    if ask_yes_no "Use $suggested?" "y"; then echo "$suggested"; else
        while true; do
            custom="$(ask_nonempty "Custom IPv4 CIDR")"
            valid_ipv4_cidr "$custom" || { print_warn "Invalid CIDR."; continue; }
            custom="$(normalize_cidr "$custom")"
            is_rfc1918_cidr "$custom" || { print_warn "Use an RFC1918 private range."; continue; }
            if collision="$(subnet_collides "$custom" "$instance" 2>/dev/null)"; then
                print_warn "Subnet overlaps $collision"
                ask_yes_no "Use it anyway?" "n" || continue
            fi
            echo "$custom"; return 0
        done
    fi
}

enable_ip_forwarding() {
    local need_v6=0 f
    mkdir -p "$(dirname "$SYSCTL_FILE")"
    shopt -s nullglob
    for f in "$STATE_ROOT"/*.env; do
        grep -qE '^IPV6_NETWORK=.+$' "$f" && { need_v6=1; break; }
    done
    shopt -u nullglob
    {
        echo '# Managed by ocserv-manager. Performance/BBR tuning intentionally lives elsewhere.'
        echo 'net.ipv4.ip_forward = 1'
        (( need_v6 == 1 )) && echo 'net.ipv6.conf.all.forwarding = 1'
    } > "$SYSCTL_FILE"
    sysctl -p "$SYSCTL_FILE" >/dev/null
}

fw_comment() { printf 'ocserv-manager:%s' "$1"; }
ingress_fw_comment() { printf 'ocserv-manager:%s:ingress' "$1"; }

firewall_rule_add() {
    local table="$1"; shift
    if ! iptables -t "$table" -C "$@" >/dev/null 2>&1; then
        iptables -t "$table" -A "$@"
    fi
}

filter_rule_add() {
    if ! iptables -C "$@" >/dev/null 2>&1; then iptables -A "$@"; fi
}

ip6_firewall_rule_add() {
    local table="$1"; shift
    command -v ip6tables >/dev/null 2>&1 || return 1
    if ! ip6tables -t "$table" -C "$@" >/dev/null 2>&1; then ip6tables -t "$table" -A "$@"; fi
}

ip6_filter_rule_add() {
    command -v ip6tables >/dev/null 2>&1 || return 1
    if ! ip6tables -C "$@" >/dev/null 2>&1; then ip6tables -A "$@"; fi
}

firewall_mode_for_instance() {
    local mode
    mode="$(state_get "$1" FIREWALL_MODE 2>/dev/null || true)"
    case "$mode" in
        ufw) echo ufw ;;
        *) echo iptables ;;
    esac
}

configure_firewall_mode() {
    local instance="$1" current choice default_choice
    current="$(firewall_mode_for_instance "$instance")"
    [[ "$current" == ufw ]] && default_choice=2 || default_choice=1
    echo
    echo "==== Firewall integration: $instance ===="
    echo "1) iptables only (recommended/default)"
    echo "   - Ocserv Manager does NOT install, enable, disable, or modify UFW."
    echo "   - Scoped INPUT + FORWARD + MASQUERADE rules are managed with iptables."
    echo "2) UFW integration (optional, only for administrators who intentionally use UFW)"
    echo "   - NAT/FORWARD remains scoped iptables rules; TCP/UDP ingress is also allowed through UFW."
    echo "   - Ocserv Manager will NEVER enable UFW automatically."
    echo "Current: $current"
    while true; do
        read -r -p "Select firewall mode [$default_choice]: " choice || true
        choice="${choice:-$default_choice}"
        case "$choice" in
            1)
                state_set "$instance" FIREWALL_MODE iptables
                print_ok "Firewall mode set to iptables-only. UFW will be left completely alone."
                return 0
                ;;
            2)
                if ! command -v ufw >/dev/null 2>&1; then
                    print_info "UFW is not installed. It is optional and is NOT required by ocserv-manager."
                    if ask_yes_no "Install the UFW package for this explicitly selected mode? (It will NOT be enabled automatically)" "n"; then
                        install_available_packages ufw
                    else
                        print_warn "UFW mode was not selected because the ufw command is unavailable. Keeping iptables-only mode."
                        state_set "$instance" FIREWALL_MODE iptables
                        return 0
                    fi
                fi
                state_set "$instance" FIREWALL_MODE ufw
                print_ok "Optional UFW integration selected. The manager will not enable or disable UFW."
                return 0
                ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

remove_iptables_ingress_values() {
    local instance="$1" tcp="${2:-}" udp="${3:-}" comment
    comment="$(ingress_fw_comment "$instance")"
    if command -v iptables >/dev/null 2>&1; then
        if [[ -n "$tcp" ]]; then
            while iptables -C INPUT -p tcp --dport "$tcp" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do
                iptables -D INPUT -p tcp --dport "$tcp" -m comment --comment "$comment" -j ACCEPT
            done
        fi
        if [[ -n "$udp" ]]; then
            while iptables -C INPUT -p udp --dport "$udp" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do
                iptables -D INPUT -p udp --dport "$udp" -m comment --comment "$comment" -j ACCEPT
            done
        fi
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        if [[ -n "$tcp" ]]; then
            while ip6tables -C INPUT -p tcp --dport "$tcp" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do
                ip6tables -D INPUT -p tcp --dport "$tcp" -m comment --comment "$comment" -j ACCEPT
            done
        fi
        if [[ -n "$udp" ]]; then
            while ip6tables -C INPUT -p udp --dport "$udp" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do
                ip6tables -D INPUT -p udp --dport "$udp" -m comment --comment "$comment" -j ACCEPT
            done
        fi
    fi
}

ensure_ufw_reapply_hook() {
    local hook=/etc/ufw/after.init marker_begin='# BEGIN OCSERV-MANAGER-REAPPLY' rollback backup=""
    [[ "${OCSERV_MANAGER_BOOT_REAPPLY:-0}" == 1 ]] && return 0
    command -v ufw >/dev/null 2>&1 || return 0
    mkdir -p /etc/ufw
    if [[ -f "$hook" ]] && grep -Fq "$marker_begin" "$hook"; then return 0; fi
    rollback="$(mktemp /tmp/ocserv-manager-ufw-after-init.XXXXXX)"
    if [[ -f "$hook" ]]; then
        cp -a "$hook" "$rollback"
        if ask_yes_no "Create a persistent backup of /etc/ufw/after.init before adding the Ocserv Manager reapply hook?" "y"; then
            ensure_backup_root
            backup="$BACKUP_ROOT/ufw-after.init-$(date +%Y%m%d-%H%M%S).bak"
            cp -a "$hook" "$backup"
        else
            print_info "Persistent UFW hook backup skipped by request."
        fi
    else
        printf '#!/bin/sh\nexit 0\n' > "$rollback"
    fi
    python3 - "$hook" "$MANAGER_BIN" <<'PYUFWINIT'
from pathlib import Path
import sys
path=Path(sys.argv[1]); manager=sys.argv[2]
text=path.read_text(encoding='utf-8',errors='ignore') if path.exists() else '#!/bin/sh\nexit 0\n'
block=(
    '# BEGIN OCSERV-MANAGER-REAPPLY\n'
    '# Reapply only Ocserv Manager scoped firewall rules after UFW rebuilds its chains.\n'
    'case "${1:-}" in\n'
    '    start)\n'
    f'        {manager} --reapply-firewall >/dev/null 2>&1 || true\n'
    '        ;;\n'
    'esac\n'
    '# END OCSERV-MANAGER-REAPPLY\n'
)
if '# BEGIN OCSERV-MANAGER-REAPPLY' not in text:
    pos=text.rfind('\nexit 0')
    if pos >= 0:
        text=text[:pos].rstrip()+'\n\n'+block+text[pos:]+'\n'
    else:
        text=text.rstrip()+'\n\n'+block
path.write_text(text,encoding='utf-8')
PYUFWINIT
    chmod +x "$hook"
    if ! sh -n "$hook"; then
        if [[ -s "$rollback" ]]; then cp -a "$rollback" "$hook"; else rm -f "$hook"; fi
        rm -f "$rollback"
        print_err "Could not safely install the UFW reapply hook; previous after.init content was restored."
        return 1
    fi
    rm -f "$rollback"
    print_ok "UFW start/reload integration installed; scoped Manager rules will be reapplied after UFW rebuilds its chains."
    [[ -n "$backup" ]] && print_info "UFW hook backup: $backup"
}

remove_ufw_managed_rules() {
    local instance="$1" tcp="${2:-}" udp="${3:-}" comment="ocserv-manager:$instance" nums n
    command -v ufw >/dev/null 2>&1 || return 0
    [[ -n "$tcp" ]] || tcp="$(state_get "$instance" TCP_PORT 2>/dev/null || true)"
    [[ -n "$udp" ]] || udp="$(state_get "$instance" UDP_PORT 2>/dev/null || true)"
    # UFW supports deleting by the original rule syntax even while rules are only
    # configured and the firewall is inactive. Include our comment so an unrelated
    # administrator rule for the same port is not intentionally targeted.
    [[ -n "$tcp" ]] && ufw --force delete allow "$tcp/tcp" comment "$comment" >/dev/null 2>&1 || true
    [[ -n "$udp" ]] && ufw --force delete allow "$udp/udp" comment "$comment" >/dev/null 2>&1 || true
    # Also remove any legacy manager rules by number when UFW is active and exposes
    # comments in `status numbered`.
    nums="$(ufw status numbered 2>/dev/null | grep -F "$comment" | sed -nE 's/^\[[[:space:]]*([0-9]+)\].*/\1/p' | sort -rn || true)"
    for n in $nums; do yes | ufw delete "$n" >/dev/null 2>&1 || true; done
}

apply_ingress_firewall_for_instance() {
    local instance="$1" mode tcp udp comment ipv6
    mode="$(firewall_mode_for_instance "$instance")"
    tcp="$(state_get "$instance" TCP_PORT 2>/dev/null || echo 443)"
    udp="$(state_get "$instance" UDP_PORT 2>/dev/null || echo "$tcp")"
    ipv6="$(state_get "$instance" IPV6_NETWORK 2>/dev/null || true)"
    comment="$(ingress_fw_comment "$instance")"

    # Always remove stale rules created by the other mode first. We never touch
    # unrelated administrator rules or generic UFW settings.
    remove_iptables_ingress_values "$instance" "$tcp" "$udp"
    remove_ufw_managed_rules "$instance"

    case "$mode" in
        ufw)
            if ! command -v ufw >/dev/null 2>&1; then
                print_err "This instance is configured for UFW integration, but ufw is not installed."
                print_info "Switch the instance to iptables-only mode or install UFW explicitly."
                return 1
            fi
            ufw allow "$tcp/tcp" comment "ocserv-manager:$instance" >/dev/null
            ufw allow "$udp/udp" comment "ocserv-manager:$instance" >/dev/null
            ensure_ufw_reapply_hook || return 1
            state_set "$instance" UFW_MANAGED 1
            if ufw status 2>/dev/null | grep -q '^Status: active'; then
                print_ok "UFW ingress allows installed for TCP $tcp and UDP $udp."
            else
                print_warn "UFW rules were saved, but UFW is currently inactive. Ocserv Manager did not enable it."
            fi
            ;;
        *)
            filter_rule_add INPUT -p tcp --dport "$tcp" -m comment --comment "$comment" -j ACCEPT
            filter_rule_add INPUT -p udp --dport "$udp" -m comment --comment "$comment" -j ACCEPT
            # If the instance has IPv6 enabled, also allow its listening service over IPv6.
            if [[ -n "$ipv6" ]] && command -v ip6tables >/dev/null 2>&1; then
                ip6_filter_rule_add INPUT -p tcp --dport "$tcp" -m comment --comment "$comment" -j ACCEPT
                ip6_filter_rule_add INPUT -p udp --dport "$udp" -m comment --comment "$comment" -j ACCEPT
            fi
            state_set "$instance" UFW_MANAGED 0
            if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
                print_warn "UFW is active on this server, but this instance is iptables-only. Ocserv Manager did not modify UFW."
                print_warn "If UFW has a default-deny input policy, allow TCP $tcp and UDP $udp yourself or switch this instance to UFW integration."
            fi
            ;;
    esac
}

install_firewall_reapply_unit() {
    [[ "${OCSERV_MANAGER_BOOT_REAPPLY:-0}" == 1 ]] && return 0
    local tmp changed=0
    tmp="$(mktemp)"
    cat > "$tmp" <<EOF
[Unit]
Description=Reapply Ocserv Manager scoped firewall rules
After=network.target ufw.service

[Service]
Type=oneshot
ExecStart=$MANAGER_BIN --reapply-firewall
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    if [[ ! -f "$FIREWALL_REAPPLY_SERVICE" ]] || ! cmp -s "$tmp" "$FIREWALL_REAPPLY_SERVICE"; then
        install -m 644 "$tmp" "$FIREWALL_REAPPLY_SERVICE"
        changed=1
    fi
    rm -f "$tmp"
    (( changed == 0 )) || systemctl daemon-reload
    if ! systemctl is-enabled --quiet ocserv-manager-firewall.service 2>/dev/null; then
        systemctl enable ocserv-manager-firewall.service >/dev/null 2>&1 || true
    fi
}

reapply_all_firewall_rules() {
    local instance f domain subnet
    command -v iptables >/dev/null 2>&1 || { print_err "iptables is unavailable; cannot reapply ocserv firewall rules."; return 1; }
    export OCSERV_MANAGER_BOOT_REAPPLY=1
    enable_ip_forwarding
    while read -r instance; do
        [[ -n "$instance" ]] || continue
        [[ -f "$(instance_state_file "$instance")" ]] || continue
        apply_firewall_for_instance "$instance" || print_warn "Could not reapply base firewall rules for $instance"
        if [[ -d "$(vhost_dir "$instance")" ]]; then
            for f in "$(vhost_dir "$instance")"/*.conf; do
                [[ -f "$f" ]] || continue
                domain="$(basename "$f" .conf)"
                subnet="$(config_ipv4_cidr "$f" 2>/dev/null || true)"
                [[ -n "$subnet" ]] && apply_firewall_for_vhost "$instance" "$domain" "$subnet" || true
            done
        fi
    done < <(list_instances | sort -u)
}


migrate_legacy_firewall_persistence_once() {
    local marker="$MANAGER_ETC/firewall-persistence-migrated-v2.5" file tmp rollback changed=0
    [[ -f "$marker" ]] && return 0
    for file in /etc/iptables/rules.v4 /etc/iptables/rules.v6; do
        [[ -f "$file" ]] || continue
        if grep -Eq -- '--comment[[:space:]]+"?ocserv-manager:' "$file"; then
            rollback="$(mktemp /tmp/ocserv-manager-firewall-migrate.XXXXXX)"
            cp -a "$file" "$rollback"
            if ask_yes_no "Create a persistent backup of $(basename "$file") before removing legacy Ocserv Manager rules?" "y"; then
                ensure_backup_root
                cp -a "$file" "$BACKUP_ROOT/$(basename "$file").before-v2.5-$(date +%Y%m%d-%H%M%S)"
            else
                print_info "Persistent firewall-file backup skipped by request."
            fi
            tmp="$(mktemp)"
            if awk '!/--comment[[:space:]]+"?ocserv-manager:/' "$file" > "$tmp" && cat "$tmp" > "$file"; then
                changed=1
            else
                cp -a "$rollback" "$file"
                print_err "Could not migrate $file; original content was restored from the temporary rollback copy."
            fi
            rm -f "$tmp" "$rollback"
        fi
    done
    if (( changed == 1 )); then
        print_info "Removed legacy Ocserv Manager rules from netfilter-persistent files; unrelated persistent firewall rules were preserved."
    fi
    : > "$marker"
}

ensure_firewall_boot_persistence_for_existing_instances() {
    local first
    first="$(list_instances 2>/dev/null | head -n1 || true)"
    [[ -n "$first" ]] || return 0
    install_firewall_reapply_unit
}

valid_interface_name() {
    [[ "${1:-}" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]]
}

apply_firewall_for_instance() {
    local instance="$1" subnet iface comment ipv6 nat6
    subnet="$(state_get "$instance" SUBNET)"
    iface="$(state_get "$instance" OUT_IFACE 2>/dev/null || true)"
    [[ -n "$iface" ]] || iface="$(default_route_iface)"
    [[ -n "$iface" ]] || { print_err "Could not detect outbound interface."; return 1; }
    state_set "$instance" OUT_IFACE "$iface"
    comment="$(fw_comment "$instance")"
    ipv6="$(state_get "$instance" IPV6_NETWORK 2>/dev/null || true)"
    nat6="$(state_get "$instance" IPV6_NAT 2>/dev/null || echo 0)"

    enable_ip_forwarding
    [[ "${OCSERV_MANAGER_BOOT_REAPPLY:-0}" == 1 ]] || install_available_packages iptables

    # Scoped NAT: equivalent to the original broad MASQUERADE idea, but only VPN
    # client addresses are translated. Other services/traffic on the server are untouched.
    firewall_rule_add nat POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$comment" -j MASQUERADE
    filter_rule_add FORWARD -s "$subnet" -o "$iface" -m comment --comment "$comment" -j ACCEPT
    filter_rule_add FORWARD -d "$subnet" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT

    if [[ -n "$ipv6" ]]; then
        if command -v ip6tables >/dev/null 2>&1; then
            ip6_filter_rule_add FORWARD -s "$ipv6" -o "$iface" -m comment --comment "$comment" -j ACCEPT
            ip6_filter_rule_add FORWARD -d "$ipv6" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT
            if [[ "$nat6" == 1 ]]; then
                ip6_firewall_rule_add nat POSTROUTING -s "$ipv6" -o "$iface" -m comment --comment "$comment" -j MASQUERADE
            fi
        else
            print_warn "IPv6 pool is configured but ip6tables is unavailable; IPv6 forwarding firewall rules were not installed."
        fi
    fi

    if [[ "${OCSERV_MANAGER_BOOT_REAPPLY:-0}" == 1 && "$(firewall_mode_for_instance "$instance")" == ufw ]]; then
        # UFW persists its own ingress rules; do not rewrite its configuration at boot.
        :
    else
        apply_ingress_firewall_for_instance "$instance"
    fi
    install_firewall_reapply_unit
    audit "firewall-applied instance=$instance mode=$(firewall_mode_for_instance "$instance") subnet=$subnet ipv6=$ipv6 iface=$iface nat66=$nat6"
    print_ok "Scoped NAT/FORWARD rules applied for $subnet through $iface; ingress mode: $(firewall_mode_for_instance "$instance")."
}

remove_ipv6_firewall_values() {
    local instance="$1" ipv6="$2" iface="$3" nat6="${4:-0}" comment
    [[ -n "$ipv6" && -n "$iface" ]] || return 0
    command -v ip6tables >/dev/null 2>&1 || return 0
    comment="$(fw_comment "$instance")"
    while ip6tables -C FORWARD -s "$ipv6" -o "$iface" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do ip6tables -D FORWARD -s "$ipv6" -o "$iface" -m comment --comment "$comment" -j ACCEPT; done
    while ip6tables -C FORWARD -d "$ipv6" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do ip6tables -D FORWARD -d "$ipv6" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT; done
    while ip6tables -t nat -C POSTROUTING -s "$ipv6" -o "$iface" -m comment --comment "$comment" -j MASQUERADE >/dev/null 2>&1; do ip6tables -t nat -D POSTROUTING -s "$ipv6" -o "$iface" -m comment --comment "$comment" -j MASQUERADE; done
}

remove_firewall_for_instance() {
    local instance="$1" subnet iface comment ipv6 nat6 tcp udp
    remove_all_vhost_firewalls "$instance" 2>/dev/null || true
    subnet="$(state_get "$instance" SUBNET 2>/dev/null || true)"
    iface="$(state_get "$instance" OUT_IFACE 2>/dev/null || true)"
    ipv6="$(state_get "$instance" IPV6_NETWORK 2>/dev/null || true)"
    nat6="$(state_get "$instance" IPV6_NAT 2>/dev/null || echo 0)"
    tcp="$(state_get "$instance" TCP_PORT 2>/dev/null || true)"
    udp="$(state_get "$instance" UDP_PORT 2>/dev/null || true)"
    remove_iptables_ingress_values "$instance" "$tcp" "$udp"
    remove_ufw_managed_rules "$instance"
    if [[ -n "$subnet" ]]; then
        comment="$(fw_comment "$instance")"
        fi
    if [[ -n "$subnet" && -n "$iface" ]]; then
        comment="$(fw_comment "$instance")"
        while iptables -t nat -C POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$comment" -j MASQUERADE >/dev/null 2>&1; do
            iptables -t nat -D POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$comment" -j MASQUERADE
        done
        while iptables -C FORWARD -s "$subnet" -o "$iface" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do
            iptables -D FORWARD -s "$subnet" -o "$iface" -m comment --comment "$comment" -j ACCEPT
        done
        while iptables -C FORWARD -d "$subnet" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do
            iptables -D FORWARD -d "$subnet" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT
        done
        remove_ipv6_firewall_values "$instance" "$ipv6" "$iface" "$nat6"
    fi
    audit "firewall-removed instance=$instance"
}

# -----------------------------------------------------------------------------
# Certificates
# -----------------------------------------------------------------------------
cert_public_key_fingerprint() {
    local cert="$1"
    openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}'
}

key_public_key_fingerprint() {
    local key="$1"
    openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}'
}

validate_cert_key_pair() {
    local cert="$1" key="$2"
    [[ -r "$cert" && -r "$key" ]] || return 1
    openssl x509 -in "$cert" -noout >/dev/null 2>&1 || return 1
    openssl pkey -in "$key" -noout >/dev/null 2>&1 || return 1
    [[ "$(cert_public_key_fingerprint "$cert")" == "$(key_public_key_fingerprint "$key")" ]]
}

certificate_covers_name() {
    local cert="$1" name="$2"
    [[ -r "$cert" ]] || return 1
    if openssl x509 -help 2>&1 | grep -q -- '-checkhost'; then
        openssl x509 -in "$cert" -noout -checkhost "$name" >/dev/null 2>&1
    else
        # Conservative fallback: require exact CN/SAN textual presence.
        openssl x509 -in "$cert" -noout -subject -ext subjectAltName 2>/dev/null | grep -Fqi "$name"
    fi
}

find_existing_letsencrypt_cert() {
    local domain="$1" d cert key
    [[ -d /etc/letsencrypt/live ]] || return 1
    for d in /etc/letsencrypt/live/*; do
        [[ -d "$d" ]] || continue
        cert="$d/fullchain.pem"; key="$d/privkey.pem"
        if validate_cert_key_pair "$cert" "$key" && certificate_covers_name "$cert" "$domain"; then
            printf '%s|%s\n' "$cert" "$key"
            return 0
        fi
    done
    return 1
}

certificate_names() {
    local cert="$1"
    [[ -r "$cert" ]] || return 1
    python3 - "$cert" <<'PYCERTNAMES'
import re, subprocess, sys
cert=sys.argv[1]
p=subprocess.run(['openssl','x509','-in',cert,'-noout','-subject','-ext','subjectAltName'],text=True,capture_output=True)
if p.returncode != 0:
    raise SystemExit(1)
t=p.stdout
names=[]
for x in re.findall(r'DNS:([^,\s]+)', t):
    if x not in names: names.append(x)
for x in re.findall(r'IP Address:([^,\s]+)', t):
    if x not in names: names.append(x)
if not names:
    m=re.search(r'(?:^|[,/])\s*CN\s*=\s*([^,/]+)', t, re.M)
    if m: names.append(m.group(1).strip())
print(', '.join(names))
PYCERTNAMES
}

certificate_primary_name() {
    local cert="$1" names
    names="$(certificate_names "$cert" 2>/dev/null || true)"
    if [[ -n "$names" ]]; then
        printf '%s\n' "${names%%,*}"
    else
        openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed -nE 's/.*CN[[:space:]]*=[[:space:]]*([^,/]+).*/\1/p' | head -n1
    fi
}

list_existing_letsencrypt_certificates() {
    local d cert key names expiry
    [[ -d /etc/letsencrypt/live ]] || return 0
    for d in /etc/letsencrypt/live/*; do
        [[ -d "$d" ]] || continue
        cert="$d/fullchain.pem"; key="$d/privkey.pem"
        validate_cert_key_pair "$cert" "$key" || continue
        names="$(certificate_names "$cert" 2>/dev/null || true)"
        [[ -n "$names" ]] || names="$(basename "$d")"
        expiry="$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || true)"
        printf '%s|%s|%s|%s\n' "$cert" "$key" "$names" "$expiry"
    done
}

choose_existing_letsencrypt_certificate() {
    local -a rows=() labels=()
    local row cert key names expiry idx
    mapfile -t rows < <(list_existing_letsencrypt_certificates)
    if ((${#rows[@]} == 0)); then
        print_warn "No valid Let's Encrypt certificate/key pair was detected under /etc/letsencrypt/live." >&2
        return 1
    fi
    if ((${#rows[@]} == 1)); then
        row="${rows[0]}"; IFS='|' read -r cert key names expiry <<<"$row"
        print_info "Detected certificate automatically: $names" >&2
        [[ -n "$expiry" ]] && print_info "Expires: $expiry" >&2
        printf '%s|%s\n' "$cert" "$key"
        return 0
    fi
    for row in "${rows[@]}"; do
        IFS='|' read -r cert key names expiry <<<"$row"
        labels+=("$names | expires: ${expiry:-unknown} | $cert")
    done
    idx="$(choose_menu "Detected Let's Encrypt certificates:" "${labels[@]}")"
    row="${rows[$((idx-1))]}"; IFS='|' read -r cert key names expiry <<<"$row"
    printf '%s|%s\n' "$cert" "$key"
}

resolve_ipv4s() {
    local host="$1"
    getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u
}

server_ipv4_candidates() {
    { default_route_src || true; public_ipv4 || true; list_local_ipv4 || true; } | sed '/^$/d' | sort -u
}

letsencrypt_dns_preflight() {
    local domain="$1" resolved candidates ip found=0
    resolved="$(resolve_ipv4s "$domain" || true)"
    if [[ -z "$resolved" ]]; then
        print_err "DNS lookup for $domain returned no IPv4 address."
        return 1
    fi
    candidates="$(server_ipv4_candidates || true)"
    while read -r ip; do
        [[ -n "$ip" ]] || continue
        if grep -Fxq "$ip" <<<"$candidates"; then found=1; break; fi
    done <<<"$resolved"
    if (( found == 0 )); then
        print_warn "$domain resolves to: $(tr '\n' ' ' <<<"$resolved")"
        print_warn "Detected server IP candidates: $(tr '\n' ' ' <<<"$candidates")"
        if ! ask_yes_no "DNS does not appear to point to this server. Continue certificate request anyway?" "n"; then
            return 1
        fi
    fi
    return 0
}

port80_preflight() {
    local listeners
    listeners="$(ss -ltnp 'sport = :80' 2>/dev/null || true)"
    if [[ -n "$listeners" && $(wc -l <<<"$listeners") -gt 1 ]]; then
        print_warn "TCP port 80 is currently listening."
        echo "$listeners"
        return 1
    fi
    return 0
}

install_certbot() {
    install_available_packages certbot
    command -v certbot >/dev/null 2>&1 || { print_err "certbot could not be installed."; return 1; }
}

install_letsencrypt_reload_hook() {
    local hook="/etc/letsencrypt/renewal-hooks/deploy/ocserv-manager-reload.sh"
    mkdir -p "$(dirname "$hook")"
    cat > "$hook" <<'EOF'
#!/usr/bin/env bash
set -u
systemctl reload ocserv.service >/dev/null 2>&1 || systemctl kill -s HUP ocserv.service >/dev/null 2>&1 || true
while read -r unit _; do
    [[ "$unit" =~ ^ocserv@.+\.service$ ]] || continue
    systemctl reload "$unit" >/dev/null 2>&1 || systemctl kill -s HUP "$unit" >/dev/null 2>&1 || true
done < <(systemctl list-units --type=service --all --no-legend 'ocserv@*.service' 2>/dev/null || true)
EOF
    chmod 755 "$hook"
}

obtain_letsencrypt_certificate() {
    local domain="$1" mode="$2" email webroot cert key existing
    existing="$(find_existing_letsencrypt_cert "$domain" 2>/dev/null || true)"
    if [[ -n "$existing" ]]; then
        print_ok "An existing Let's Encrypt certificate already covers $domain."
        if ask_yes_no "Reuse it instead of requesting another certificate?" "y"; then
            printf '%s\n' "$existing"
            return 0
        fi
    fi

    letsencrypt_dns_preflight "$domain" || return 1
    install_certbot || return 1
    while true; do
        email="$(ask_nonempty "Let's Encrypt email")"
        valid_email "$email" && break
        print_warn "Invalid email format."
    done

    case "$mode" in
        standalone)
            if ! port80_preflight; then
                print_warn "Standalone mode needs port 80."
                return 1
            fi
            certbot certonly --standalone --preferred-challenges http --agree-tos --non-interactive --email "$email" -d "$domain"
            ;;
        webroot)
            webroot="$(ask_nonempty "Existing webroot directory" "/var/www/html")"
            [[ -d "$webroot" ]] || { print_err "Webroot does not exist: $webroot"; return 1; }
            certbot certonly --webroot --agree-tos --non-interactive --email "$email" -w "$webroot" -d "$domain"
            ;;
        *) return 1 ;;
    esac
    cert="/etc/letsencrypt/live/$domain/fullchain.pem"
    key="/etc/letsencrypt/live/$domain/privkey.pem"
    if ! validate_cert_key_pair "$cert" "$key"; then
        # Certbot can choose a suffixed lineage. Search by SAN instead.
        existing="$(find_existing_letsencrypt_cert "$domain" 2>/dev/null || true)"
        [[ -n "$existing" ]] || { print_err "Certificate request finished but a valid certificate/key pair could not be found."; return 1; }
        cert="${existing%%|*}"; key="${existing#*|}"
    fi
    install_letsencrypt_reload_hook
    printf '%s|%s\n' "$cert" "$key"
}

create_self_signed_server_cert() {
    local instance="$1" name="$2" dir cert key san
    dir="$(instance_dir "$instance")/certs"
    mkdir -p "$dir"
    chmod 700 "$dir"
    cert="$dir/server-cert.pem"; key="$dir/server-key.pem"
    if valid_domain "$name"; then san="DNS:$name"; else san="IP:$name"; fi
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
        -subj "/CN=$name/O=Ocserv Manager" -addext "subjectAltName=$san" \
        -keyout "$key" -out "$cert"
    chmod 600 "$key"; chmod 644 "$cert"
    printf '%s|%s\n' "$cert" "$key"
}

configure_server_certificate() {
    local instance="$1" choice domain="" pair cert key p
    choice="$(choose_menu "Server certificate:" \
        "Auto-detect/reuse an existing Let's Encrypt/wildcard certificate" \
        "Use an existing certificate and key by path" \
        "Request Let's Encrypt - standalone" \
        "Request Let's Encrypt - existing webroot" \
        "Create self-signed certificate")"
    case "$choice" in
        1)
            pair="$(choose_existing_letsencrypt_certificate)" || {
                print_warn "Choose another certificate method." >&2
                return 2
            }
            ;;
        2)
            while true; do
                cert="$(ask_nonempty "Certificate/full chain path")"
                key="$(ask_nonempty "Private key path")"
                if validate_cert_key_pair "$cert" "$key"; then pair="$cert|$key"; break; fi
                print_warn "Certificate/key pair is invalid, unreadable, encrypted, or mismatched."
            done
            ;;
        3|4)
            while true; do
                domain="$(ask_nonempty "VPN domain")"
                valid_domain "$domain" && break
                print_warn "Invalid domain."
            done
            if [[ "$choice" == 3 ]]; then pair="$(obtain_letsencrypt_certificate "$domain" standalone)" || return 1
            else pair="$(obtain_letsencrypt_certificate "$domain" webroot)" || return 1
            fi
            ;;
        5)
            p="$(public_ipv4 || true)"; [[ -n "$p" ]] || p="$(default_route_src || true)"
            domain="$(ask_nonempty "Hostname or IP to place in the self-signed certificate" "${p:-vpn.local}")"
            pair="$(create_self_signed_server_cert "$instance" "$domain")"
            ;;
    esac
    cert="${pair%%|*}"; key="${pair#*|}"
    [[ -n "$domain" ]] || domain="$(certificate_primary_name "$cert" 2>/dev/null || true)"
    state_set "$instance" SERVER_CERT "$cert"
    state_set "$instance" SERVER_KEY "$key"
    state_set "$instance" CERT_NAME "$domain"
    state_set "$instance" CERT_MODE "$choice"
    print_ok "Server certificate configured: $cert"
    [[ -n "$domain" ]] && print_info "Certificate identity detected: $domain"
}


certificate_expiry_text() {
    local cert="$1"
    [[ -r "$cert" ]] || { echo "missing"; return; }
    openssl x509 -in "$cert" -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || echo "unknown"
}

certificate_days_left() {
    local cert="$1" end now
    [[ -r "$cert" ]] || { echo -1; return; }
    end="$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2-)"
    [[ -n "$end" ]] || { echo -1; return; }
    now="$(date +%s)"
    echo $(( ($(date -d "$end" +%s) - now) / 86400 ))
}

# -----------------------------------------------------------------------------
# Authentication
# -----------------------------------------------------------------------------
choose_shared_passwd() {
    local instance="$1" default_path candidate choice=1
    default_path="$(instance_passwd "$instance")"
    if [[ "$instance" != "default" ]]; then
        local -a paths=()
        while read -r candidate; do
            [[ -n "$candidate" ]] || continue
            [[ " ${paths[*]-} " == *" $candidate "* ]] || paths+=("$candidate")
        done < <(for i in $(list_instances); do instance_passwd "$i"; done 2>/dev/null || true)
        if ((${#paths[@]})); then
            if ask_yes_no "Share an existing ocpasswd user database with another instance?" "y"; then
                echo "Available password databases:"
                local idx=1
                for candidate in "${paths[@]}"; do echo "$idx) $candidate"; ((idx++)); done
                echo "$idx) Custom path"
                while true; do
                    read -r -p "Select: " choice || true
                    [[ "$choice" =~ ^[0-9]+$ ]] || continue
                    if (( choice >=1 && choice <= ${#paths[@]} )); then
                        printf '%s\n' "${paths[$((choice-1))]}"; return
                    elif (( choice == idx )); then
                        ask_nonempty "Shared ocpasswd path"; return
                    fi
                done
            fi
        fi
    fi
    printf '%s\n' "$default_path"
}

ocserv_has_feature() {
    local needle="$1"
    installed_ocserv_features | grep -Eqi "$needle"
}

create_client_ca() {
    local instance="$1" dir ca_key ca_cert
    dir="$(instance_dir "$instance")/client-ca"
    mkdir -p "$dir"; chmod 700 "$dir"
    ca_key="$dir/ca-key.pem"; ca_cert="$dir/ca-cert.pem"
    if [[ -f "$ca_key" && -f "$ca_cert" ]]; then
        if ask_yes_no "A client CA already exists for $instance. Reuse it?" "y"; then echo "$ca_cert"; return; fi
    fi
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
        -subj "/CN=Ocserv $instance Client CA/O=Ocserv Manager" \
        -keyout "$ca_key" -out "$ca_cert"
    chmod 600 "$ca_key"; chmod 644 "$ca_cert"
    echo "$ca_cert"
}

configure_pam_service() {
    local service="$1" path="/etc/pam.d/$service"
    install_available_packages libpam0g
    if [[ ! -f "$path" ]]; then
        cat > "$path" <<'EOF'
@include common-auth
@include common-account
EOF
        chmod 644 "$path"
    fi
}

write_oidc_json_interactive() {
    local instance="$1" path url claim aud iss
    path="$(instance_dir "$instance")/oidc.json"
    url="$(ask_nonempty "OpenID configuration URL")"
    claim="$(ask_nonempty "Username claim" "preferred_username")"
    aud="$(ask_value "Required aud claim (blank to omit)" "")"
    iss="$(ask_value "Required iss claim (blank to omit)" "")"
    python3 - "$path" "$url" "$claim" "$aud" "$iss" <<'PY'
import json,sys,os
p,url,claim,aud,iss=sys.argv[1:]
obj={"openid_configuration_url":url,"user_name_claim":claim,"required_claims":{}}
if aud: obj["required_claims"]["aud"]=aud
if iss: obj["required_claims"]["iss"]=iss
os.makedirs(os.path.dirname(p),exist_ok=True)
with open(p,"w",encoding="utf-8") as f: json.dump(obj,f,indent=2)
os.chmod(p,0o600)
PY
    echo "$path"
}

configure_authentication() {
    local instance="$1" choice passwd otp pam_service gid_min ca cert_oid group_oid radius_cfg groupcfg nas sep keytab localmap freshness oidc authline
    choice="$(choose_menu "Authentication method:" \
        "Plain password (ocpasswd)" \
        "Plain password + OTP (OATH file)" \
        "PAM" \
        "Client certificate" \
        "Client certificate + plain password (both required)" \
        "RADIUS" \
        "GSSAPI/Kerberos" \
        "OpenID Connect (OIDC - specialized client support)" \
        "Advanced custom auth directive")"
    state_set "$instance" CLIENT_CA ""
    state_set "$instance" AUTH_AUX ""
    case "$choice" in
        1)
            passwd="$(choose_shared_passwd "$instance")"; mkdir -p "$(dirname "$passwd")"; touch "$passwd"; chmod 600 "$passwd"
            authline="auth = \"plain[passwd=$passwd]\""
            state_set "$instance" OCPASSWD "$passwd"
            ;;
        2)
            passwd="$(choose_shared_passwd "$instance")"; mkdir -p "$(dirname "$passwd")"; touch "$passwd"; chmod 600 "$passwd"
            otp="$(ask_nonempty "OTP users file" "$(instance_dir "$instance")/users.otp")"; mkdir -p "$(dirname "$otp")"; touch "$otp"; chmod 600 "$otp"
            authline="auth = \"plain[passwd=$passwd,otp=$otp]\""
            state_set "$instance" OCPASSWD "$passwd"; state_set "$instance" AUTH_AUX "$otp"
            ;;
        3)
            pam_service="$(ask_nonempty "PAM service name" "ocserv")"; gid_min="$(ask_integer "Minimum GID for auto-select-group" "1000" 0 2147483647)"
            configure_pam_service "$pam_service"
            authline="auth = \"pam[service=$pam_service,gid-min=$gid_min]\""
            state_set "$instance" AUTH_AUX "$pam_service"
            ;;
        4|5)
            ca="$(ask_value "Existing client CA certificate path (blank = create one)" "")"
            if [[ -z "$ca" ]]; then ca="$(create_client_ca "$instance")"; fi
            [[ -r "$ca" ]] && openssl x509 -in "$ca" -noout >/dev/null 2>&1 || { print_err "Invalid client CA certificate."; return 1; }
            cert_oid="$(ask_nonempty "Certificate username OID" "0.9.2342.19200300.100.1.1")"
            group_oid="$(ask_value "Certificate group OID (blank to disable)" "2.5.4.11")"
            state_set "$instance" CLIENT_CA "$ca"; state_set "$instance" CERT_USER_OID "$cert_oid"; state_set "$instance" CERT_GROUP_OID "$group_oid"
            if [[ "$choice" == 4 ]]; then authline='auth = "certificate"'; else
                passwd="$(choose_shared_passwd "$instance")"; mkdir -p "$(dirname "$passwd")"; touch "$passwd"; chmod 600 "$passwd"
                authline=$'auth = "certificate"\n'"auth = \"plain[passwd=$passwd]\""
                state_set "$instance" OCPASSWD "$passwd"
            fi
            ;;
        6)
            install_available_packages libradcli4 libradcli-dev
            radius_cfg="$(ask_nonempty "radcli/freeradius-client configuration file" "/etc/radcli/radiusclient.conf")"
            [[ -r "$radius_cfg" ]] || print_warn "RADIUS config does not exist yet; ocserv validation may fail until it is created."
            if ask_yes_no "Load per-user/group configuration from RADIUS attributes?" "n"; then groupcfg=true; else groupcfg=false; fi
            nas="$(ask_value "RADIUS NAS-Identifier (blank to omit)" "")"
            sep="$(choose_menu "RADIUS group separator:" "semicolon" "comma")"; [[ "$sep" == 1 ]] && sep=semicolon || sep=comma
            authline="auth = \"radius[config=$radius_cfg,groupconfig=$groupcfg,group-separator=$sep"
            [[ -n "$nas" ]] && authline+=",nas-identifier=$nas"
            authline+="]\""
            state_set "$instance" AUTH_AUX "$radius_cfg"
            ;;
        7)
            install_available_packages krb5-user libkrb5-3
            keytab="$(ask_nonempty "Kerberos keytab path" "/etc/krb5.keytab")"
            if ask_yes_no "Require local user map?" "y"; then localmap=true; else localmap=false; fi
            freshness="$(ask_integer "TGT freshness time seconds (0 = omit)" "900" 0 86400)"
            authline="auth = \"gssapi[keytab=$keytab,require-local-user-map=$localmap"
            (( freshness > 0 )) && authline+=",tgt-freshness-time=$freshness"
            authline+="]\""
            state_set "$instance" AUTH_AUX "$keytab"
            ;;
        8)
            print_warn "OIDC in ocserv is intended for Microsoft Intune VPN client interoperability; ordinary OpenConnect clients do not use it."
            oidc="$(ask_value "Existing OIDC JSON path (blank = create)" "")"
            [[ -n "$oidc" ]] || oidc="$(write_oidc_json_interactive "$instance")"
            [[ -r "$oidc" ]] || { print_err "OIDC JSON not found."; return 1; }
            authline="auth = \"oidc[config=$oidc]\""
            state_set "$instance" AUTH_AUX "$oidc"
            ;;
        9)
            authline="$(ask_nonempty 'Enter complete auth directive, e.g. auth = "pam"')"
            [[ "$authline" =~ ^[[:space:]]*(auth|enable-auth)[[:space:]]*= ]] || { print_err "Expected auth = or enable-auth = directive."; return 1; }
            ;;
    esac
    state_set "$instance" AUTH_MODE "$choice"
    state_set "$instance" AUTH_LINES "$(printf '%s' "$authline" | base64 -w0)"
    print_ok "Authentication configured."
}

decode_state_b64() {
    local instance="$1" key="$2" v
    v="$(state_get "$instance" "$key" 2>/dev/null || true)"
    [[ -n "$v" ]] && printf '%s' "$v" | base64 -d 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# Network/profile choices and deterministic configuration generation
# -----------------------------------------------------------------------------
ensure_ocserv_service_user() {
    if ! getent group ocserv >/dev/null 2>&1; then groupadd --system ocserv; fi
    if ! id ocserv >/dev/null 2>&1; then useradd --system --gid ocserv --home-dir /var/lib/ocserv --no-create-home --shell /usr/sbin/nologin ocserv; fi
}

choose_dns_servers() {
    local instance="$1" choice custom dns
    choice="$(choose_menu "DNS profile:" "Google (8.8.8.8, 8.8.4.4)" "Cloudflare (1.1.1.1, 1.0.0.1)" "Quad9 (9.9.9.9, 149.112.112.112)" "AdGuard (94.140.14.14, 94.140.15.15)" "Custom")"
    case "$choice" in
        1) dns="8.8.8.8 8.8.4.4" ;;
        2) dns="1.1.1.1 1.0.0.1" ;;
        3) dns="9.9.9.9 149.112.112.112" ;;
        4) dns="94.140.14.14 94.140.15.15" ;;
        5)
            while true; do
                custom="$(ask_nonempty "DNS servers separated by spaces")"
                if python3 - "$custom" <<'PY' >/dev/null 2>&1
import ipaddress,sys
for x in sys.argv[1].split(): ipaddress.ip_address(x)
PY
                then dns="$custom"; break; fi
                print_warn "One or more DNS addresses are invalid."
            done
            ;;
    esac
    state_set "$instance" DNS_SERVERS "$dns"
}

resolve_domains_to_noroutes() {
    local domains="$1" d ip
    for d in $domains; do
        valid_domain "$d" || { print_warn "Skipping invalid domain: $d"; continue; }
        while read -r ip; do [[ -n "$ip" ]] && echo "$ip/32"; done < <(resolve_ipv4s "$d")
    done | sort -u
}

configure_routing_profile() {
    local instance="$1" choice routes="" leak splitdns=""
    choice="$(choose_menu "Routing profile:" "Full tunnel (all traffic through VPN)" "Split tunnel (only selected networks through VPN)")"
    if [[ "$choice" == 1 ]]; then
        state_set "$instance" ROUTE_MODE full
        routes="default"
        if ask_yes_no "Enable DNS-leak protection (tunnel all DNS through VPN)?" "y"; then leak=1; else leak=0; fi
        # Full tunnel means full tunnel in this manager. We intentionally do not
        # ask for no-route/bypass exceptions here; use Split Tunnel when only
        # selected destinations should traverse the VPN.
    else
        state_set "$instance" ROUTE_MODE split
        leak=0
        echo "Enter the networks that should go through the VPN."
        while true; do
            routes="$(ask_nonempty "Route CIDRs separated by spaces")"
            local r good=1
            for r in $routes; do
                if ! valid_ipv4_cidr "$r" && ! valid_ipv6_cidr "$r"; then print_warn "Invalid route: $r"; good=0; fi
            done
            (( good == 1 )) && break
        done
        if ask_yes_no "Advertise split-DNS domains for the selected DNS servers?" "n"; then
            splitdns="$(ask_nonempty "Split-DNS domains separated by spaces")"
        fi
    fi
    state_set "$instance" ROUTES "$routes"
    # v2.4: no manager-generated bypass/no-route exceptions. Existing unmanaged
    # no-route directives remain in the preserved original config only until the
    # routing profile is explicitly applied; after that the selected profile is authoritative.
    state_set "$instance" BYPASS_CIDRS ""
    state_set "$instance" NO_ROUTES ""
    state_set "$instance" BYPASS_DOMAINS ""
    state_set "$instance" TUNNEL_ALL_DNS "$leak"
    state_set "$instance" SPLIT_DNS "$splitdns"
}


refresh_bypass_domains() {
    local instance="$1" domains manual resolved combined tmp
    [[ "$(state_get "$instance" MANAGED 2>/dev/null || echo 0)" == 1 ]] || { print_err "Domain-bypass refresh requires a manager-owned instance."; return 1; }
    domains="$(state_get "$instance" BYPASS_DOMAINS 2>/dev/null || true)"
    [[ -n "$domains" ]] || { print_warn "No bypass domains are saved for this instance."; return 0; }
    manual="$(state_get "$instance" BYPASS_CIDRS 2>/dev/null || true)"
    resolved="$(resolve_domains_to_noroutes "$domains" | tr '\n' ' ')"
    combined="${manual}${manual:+ }${resolved}"
    state_set "$instance" NO_ROUTES "$combined"
    tmp="$(mktemp)"
    generate_ocserv_config "$instance" "$tmp"
    if transactional_replace_config "$instance" "$tmp"; then
        print_ok "Bypass-domain IP snapshot refreshed: $domains"
        print_info "Current no-route entries: $combined"
        audit "bypass-domain-refresh instance=$instance domains=$domains"
    else
        print_err "Could not apply refreshed bypass-domain snapshot."
        rm -f "$tmp"
        return 1
    fi
    rm -f "$tmp"
}

configure_network_profile() {
    local instance="$1" mtu dpd mobile keepalive discovery ipv6="" ipv6_prefix=128 nat6=0 is_ula=0
    mtu="$(ask_integer "VPN MTU (0 = let ocserv choose)" "0" 0 9000)"
    keepalive="$(ask_integer "Keepalive seconds (32400 = upstream default; use the Connection Stability menu later for an aggressive 30s keepalive)" "32400" 0 86400)"
    dpd="$(ask_integer "DPD seconds" "90" 0 86400)"
    mobile="$(ask_integer "Mobile DPD seconds" "1800" 0 86400)"
    if ask_yes_no "Enable MTU discovery?" "n"; then discovery=true; else discovery=false; fi
    if ask_yes_no "Configure an IPv6 VPN pool too?" "n"; then
        while true; do
            ipv6="$(ask_nonempty "IPv6 network, e.g. fd42:100::/64")"
            if valid_ipv6_cidr "$ipv6"; then
                ipv6="$(normalize_ipv6_cidr "$ipv6")"
                if collision="$(ipv6_subnet_collides "$ipv6" "$instance" 2>/dev/null)"; then
                    print_warn "IPv6 pool overlaps $collision"
                    ask_yes_no "Use it anyway?" "n" || continue
                fi
                break
            fi
            print_warn "Invalid IPv6 network."
        done
        ipv6_prefix="$(ask_integer "IPv6 client subnet prefix (128 = one address)" "128" 64 128)"
        if python3 - "$ipv6" <<'PY6' >/dev/null 2>&1
import ipaddress,sys
n=ipaddress.ip_network(sys.argv[1],strict=False)
raise SystemExit(0 if n.subnet_of(ipaddress.ip_network('fc00::/7')) else 1)
PY6
        then is_ula=1; fi
        if (( is_ula == 1 )); then
            print_info "ULA IPv6 pools are not Internet-routable by themselves."
            if ask_yes_no "Enable NAT66 for this ULA pool on the outbound interface?" "y"; then nat6=1; fi
        else
            if ask_yes_no "Enable IPv6 NAT66? Usually no for a properly routed global prefix." "n"; then nat6=1; fi
        fi
    fi
    state_set "$instance" MTU "$mtu"; state_set "$instance" KEEPALIVE "$keepalive"; state_set "$instance" DPD "$dpd"
    state_set "$instance" MOBILE_DPD "$mobile"; state_set "$instance" MTU_DISCOVERY "$discovery"
    state_set "$instance" IPV6_NETWORK "$ipv6"; state_set "$instance" IPV6_SUBNET_PREFIX "$ipv6_prefix"; state_set "$instance" IPV6_NAT "$nat6"
}

configure_limits_and_bans() {
    local instance="$1" max_clients max_same score ban_time reset
    max_clients="$(ask_integer "Maximum total clients (0 = ocserv automatic/high default, about 8k; not literally unlimited)" "0" 0 100000)"
    max_same="$(ask_integer "Maximum simultaneous connections per username (0 = unlimited)" "0" 0 100000)"
    if ask_yes_no "Enable ocserv IP ban protection?" "y"; then
        score="$(ask_integer "Ban score threshold" "80" 1 100000)"
        ban_time="$(ask_integer "Ban duration seconds" "300" 1 604800)"
        reset="$(ask_integer "Ban score reset seconds" "1200" 1 604800)"
    else score=0; ban_time=300; reset=1200; fi
    state_set "$instance" MAX_CLIENTS "$max_clients"; state_set "$instance" MAX_SAME "$max_same"
    state_set "$instance" MAX_BAN_SCORE "$score"; state_set "$instance" BAN_TIME "$ban_time"; state_set "$instance" BAN_RESET "$reset"
}


stock_template_path() {
    local version="${1:-$(installed_ocserv_version)}" core
    core="$(printf '%s' "$version" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
    [[ -n "$core" ]] || core="unknown"
    printf '%s/ocserv-%s.sample.conf\n' "$TEMPLATE_ROOT" "$core"
}

capture_stock_template_file() {
    local version="$1" src="$2" dest
    [[ -f "$src" ]] || return 1
    dest="$(stock_template_path "$version")"
    mkdir -p "$TEMPLATE_ROOT"
    if [[ ! -s "$dest" ]]; then
        cp -a "$src" "$dest"
        chmod 600 "$dest"
        print_ok "Saved original/upstream ocserv configuration template: $dest"
    fi
}

capture_stock_template_from_source_tree() {
    local version="$1" root="$2" c
    for c in "$root/doc/sample.config" "$root/sample.config" "$root/doc/ocserv.conf"; do
        [[ -f "$c" ]] || continue
        capture_stock_template_file "$version" "$c" && return 0
    done
    return 1
}

capture_stock_template_from_package() {
    local version c tmp dest
    version="$(installed_ocserv_version)"
    dest="$(stock_template_path "$version")"
    [[ -s "$dest" ]] && return 0
    for c in \
        /usr/share/doc/ocserv/examples/sample.config \
        /usr/share/doc/ocserv/sample.config \
        /usr/share/doc/ocserv/examples/ocserv.conf \
        /usr/share/doc/ocserv/sample.config.gz \
        /usr/share/doc/ocserv/examples/sample.config.gz \
        /usr/share/doc/ocserv/examples/ocserv.conf.gz; do
        [[ -f "$c" ]] || continue
        if [[ "$c" == *.gz ]]; then
            tmp="$(mktemp)"; gzip -dc "$c" > "$tmp"
            capture_stock_template_file "$version" "$tmp"; rm -f "$tmp"; return 0
        else
            capture_stock_template_file "$version" "$c"; return 0
        fi
    done
    # On a fresh distro install /etc/ocserv/ocserv.conf is the package's original file.
    if [[ -f "$OCSERV_ETC/ocserv.conf" ]] && ! grep -qE '^# (Generated by|Based on original/upstream).*Ocserv Manager' "$OCSERV_ETC/ocserv.conf"; then
        capture_stock_template_file "$version" "$OCSERV_ETC/ocserv.conf" && return 0
    fi
    return 1
}

ensure_stock_config_template() {
    local version="${1:-$(installed_ocserv_version)}" core dest url tmp
    core="$(printf '%s' "$version" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
    [[ -n "$core" ]] || { print_err "Could not determine installed ocserv version for the original configuration template."; return 1; }
    dest="$(stock_template_path "$core")"
    [[ -s "$dest" ]] && { echo "$dest"; return 0; }
    capture_stock_template_from_package >/dev/null 2>&1 || true
    [[ -s "$dest" ]] && { echo "$dest"; return 0; }
    # Existing non-manager configuration is preferred because it preserves the exact local/original file.
    if [[ -f "$OCSERV_ETC/ocserv.conf" ]] && ! grep -qE '^# (Generated by|Based on original/upstream).*Ocserv Manager' "$OCSERV_ETC/ocserv.conf"; then
        capture_stock_template_file "$core" "$OCSERV_ETC/ocserv.conf" >/dev/null
        echo "$dest"; return 0
    fi
    # Needed when upgrading an old manager-owned minimal config: retrieve the exact
    # upstream sample for the installed tag rather than inventing a replacement file.
    url="https://gitlab.com/openconnect/ocserv/-/raw/$core/doc/sample.config"
    tmp="$(mktemp)"
    if curl -fsSL --retry 3 --connect-timeout 10 "$url" -o "$tmp" && grep -qE '^[[:space:]]*tcp-port[[:space:]]*=' "$tmp"; then
        capture_stock_template_file "$core" "$tmp" >/dev/null
        rm -f "$tmp"
        echo "$dest"; return 0
    fi
    rm -f "$tmp"
    print_err "Could not obtain the original/upstream sample.config for ocserv $core. Existing config was not modified."
    return 1
}

instance_base_config() {
    local instance="$1" saved
    saved="$(state_get "$instance" BASE_CONFIG 2>/dev/null || true)"
    if [[ -n "$saved" && -s "$saved" ]]; then echo "$saved"; return 0; fi
    printf '%s/%s.conf\n' "$INSTANCE_BASE_ROOT" "$instance"
}

ensure_instance_base_config() {
    local instance="$1" base conf template version
    base="$(instance_base_config "$instance")"
    if [[ -s "$base" ]]; then state_set "$instance" BASE_CONFIG "$base"; echo "$base"; return 0; fi
    mkdir -p "$INSTANCE_BASE_ROOT"
    conf="$(instance_config "$instance")"
    # Preserve an existing real/original/custom config byte-for-byte as the structural base.
    # Old v2.x minimal generated files are intentionally not used as a base; they are migrated
    # back onto the upstream sample on first regeneration.
    if [[ -f "$conf" ]] && ! grep -qE '^# Generated by Ocserv Manager' "$conf"; then
        cp -a "$conf" "$base"
        chmod 600 "$base"
        state_set "$instance" BASE_CONFIG "$base"
        echo "$base"; return 0
    fi
    version="$(installed_ocserv_version)"
    template="$(ensure_stock_config_template "$version")" || return 1
    cp -a "$template" "$base"
    chmod 600 "$base"
    state_set "$instance" BASE_CONFIG "$base"
    echo "$base"
}

rebase_instance_on_stock_config() {
    local instance="$1" template base tmp conf oldbase
    [[ "$(state_get "$instance" MANAGED 2>/dev/null || echo 0)" == 1 ]] || { print_err "Adopt/import the instance before rebasing its manager-owned configuration."; return 1; }
    template="$(ensure_stock_config_template "$(installed_ocserv_version)")" || return 1
    base="$(instance_base_config "$instance")"
    local keep_oldbase=0
    if [[ -f "$base" ]]; then
        if ask_yes_no "Create a persistent backup of the current base config before rebasing?" "y"; then
            ensure_backup_root
            oldbase="$BACKUP_ROOT/base-$instance-$(date +%Y%m%d-%H%M%S).conf"
            keep_oldbase=1
        else
            oldbase="$(mktemp /tmp/ocserv-manager-base-rollback.${instance}.XXXXXX)"
        fi
        cp -a "$base" "$oldbase"
    else
        oldbase=""
    fi
    cp -a "$template" "$base"; chmod 600 "$base"; state_set "$instance" BASE_CONFIG "$base"
    tmp="$(mktemp)"
    if generate_ocserv_config "$instance" "$tmp" && transactional_replace_config "$instance" "$tmp"; then
        print_ok "Instance $instance now uses the original/upstream ocserv sample as its base; only manager-controlled values were changed."
        if (( keep_oldbase == 1 )) && [[ -f "$oldbase" ]]; then print_info "Previous base backup: $oldbase"; else rm -f "$oldbase" 2>/dev/null || true; fi
    else
        [[ -f "$oldbase" ]] && cp -a "$oldbase" "$base" || true
        rm -f "$tmp"; return 1
    fi
    rm -f "$tmp"
}

ensure_connection_state_defaults() {
    local instance="$1" source v
    source="$(instance_base_config "$instance")"
    [[ -s "$source" ]] || source="$(instance_config "$instance")"
    config_or_default() {
        local key="$1" fallback="$2" x=""
        [[ -s "$source" ]] && x="$(parse_config_value "$source" "$key" 2>/dev/null || true)"
        printf '%s\n' "${x:-$fallback}"
    }
    [[ -n "$(state_get "$instance" COOKIE_TIMEOUT 2>/dev/null || true)" ]] || state_set "$instance" COOKIE_TIMEOUT "$(config_or_default cookie-timeout 300)"
    [[ -n "$(state_get "$instance" PERSISTENT_COOKIES 2>/dev/null || true)" ]] || state_set "$instance" PERSISTENT_COOKIES "$(config_or_default persistent-cookies false)"
    [[ -n "$(state_get "$instance" DENY_ROAMING 2>/dev/null || true)" ]] || state_set "$instance" DENY_ROAMING "$(config_or_default deny-roaming false)"
    [[ -n "$(state_get "$instance" REKEY_TIME 2>/dev/null || true)" ]] || state_set "$instance" REKEY_TIME "$(config_or_default rekey-time 172800)"
    [[ -n "$(state_get "$instance" REKEY_METHOD 2>/dev/null || true)" ]] || state_set "$instance" REKEY_METHOD "$(config_or_default rekey-method ssl)"
    [[ -n "$(state_get "$instance" SWITCH_TO_TCP_TIMEOUT 2>/dev/null || true)" ]] || state_set "$instance" SWITCH_TO_TCP_TIMEOUT "$(config_or_default switch-to-tcp-timeout 25)"
    if [[ -z "$(state_get "$instance" IDLE_TIMEOUT 2>/dev/null || true)" ]]; then
        v="$(parse_config_value "$source" idle-timeout 2>/dev/null || true)"; state_set "$instance" IDLE_TIMEOUT "${v:-disabled}"
    fi
    if [[ -z "$(state_get "$instance" MOBILE_IDLE_TIMEOUT 2>/dev/null || true)" ]]; then
        v="$(parse_config_value "$source" mobile-idle-timeout 2>/dev/null || true)"; state_set "$instance" MOBILE_IDLE_TIMEOUT "${v:-disabled}"
    fi
}


ensure_instance_layout() {
    local instance="$1" dir
    dir="$(instance_dir "$instance")"
    # config-per-user/config-per-group are optional features and their
    # directories are created only when explicitly enabled.
    mkdir -p "$dir"
    chmod 700 "$dir" 2>/dev/null || true
}

ensure_supplemental_config_state() {
    local instance="$1" source val
    source="$(instance_base_config "$instance")"
    [[ -f "$source" ]] || source="$(instance_config "$instance")"

    if [[ -z "$(state_get "$instance" CONFIG_PER_USER_ENABLED 2>/dev/null || true)" ]]; then
        val="$(parse_config_value "$source" config-per-user 2>/dev/null || true)"
        if [[ -n "$val" ]]; then
            state_set "$instance" CONFIG_PER_USER_ENABLED 1
            state_set "$instance" CONFIG_PER_USER_DIR "$val"
        else
            state_set "$instance" CONFIG_PER_USER_ENABLED 0
            state_set "$instance" CONFIG_PER_USER_DIR "$(instance_dir "$instance")/config-per-user/"
        fi
    fi
    [[ -n "$(state_get "$instance" CONFIG_PER_USER_DIR 2>/dev/null || true)" ]] || state_set "$instance" CONFIG_PER_USER_DIR "$(instance_dir "$instance")/config-per-user/"

    if [[ -z "$(state_get "$instance" CONFIG_PER_GROUP_ENABLED 2>/dev/null || true)" ]]; then
        val="$(parse_config_value "$source" config-per-group 2>/dev/null || true)"
        if [[ -n "$val" ]]; then
            state_set "$instance" CONFIG_PER_GROUP_ENABLED 1
            state_set "$instance" CONFIG_PER_GROUP_DIR "$val"
        else
            state_set "$instance" CONFIG_PER_GROUP_ENABLED 0
            state_set "$instance" CONFIG_PER_GROUP_DIR "$(instance_dir "$instance")/config-per-group/"
        fi
    fi
    [[ -n "$(state_get "$instance" CONFIG_PER_GROUP_DIR 2>/dev/null || true)" ]] || state_set "$instance" CONFIG_PER_GROUP_DIR "$(instance_dir "$instance")/config-per-group/"
}

generate_ocserv_config() {
    local instance="$1" out="$2" base settings
    ensure_ocserv_service_user
    ensure_connection_state_defaults "$instance"
    base="$(ensure_instance_base_config "$instance")" || return 1
    ensure_supplemental_config_state "$instance"
    settings="$(mktemp)"

    local listen tcp udp subnet cert key auth_b64 ca cert_oid group_oid max_clients max_same score ban_time ban_reset dns mtu keepalive dpd mobile discovery routes no_routes tunnel splitdns ipv6 ipv6_prefix dir sock pid central=0 central_hook
    local cookie persistent roaming rekey_time rekey_method idle mobile_idle switch_tcp cpu_enabled cpg_enabled cpu_dir cpg_dir
    listen="$(state_get "$instance" LISTEN_HOST 2>/dev/null || echo 0.0.0.0)"
    tcp="$(state_get "$instance" TCP_PORT 2>/dev/null || echo 443)"; udp="$(state_get "$instance" UDP_PORT 2>/dev/null || echo "$tcp")"
    subnet="$(state_get "$instance" SUBNET)"; cert="$(state_get "$instance" SERVER_CERT)"; key="$(state_get "$instance" SERVER_KEY)"
    auth_b64="$(state_get "$instance" AUTH_LINES 2>/dev/null || true)"; ca="$(state_get "$instance" CLIENT_CA 2>/dev/null || true)"
    cert_oid="$(state_get "$instance" CERT_USER_OID 2>/dev/null || true)"; group_oid="$(state_get "$instance" CERT_GROUP_OID 2>/dev/null || true)"
    max_clients="$(state_get "$instance" MAX_CLIENTS 2>/dev/null || echo 0)"; max_same="$(state_get "$instance" MAX_SAME 2>/dev/null || echo 0)"
    score="$(state_get "$instance" MAX_BAN_SCORE 2>/dev/null || echo 80)"; ban_time="$(state_get "$instance" BAN_TIME 2>/dev/null || echo 300)"; ban_reset="$(state_get "$instance" BAN_RESET 2>/dev/null || echo 1200)"
    dns="$(state_get "$instance" DNS_SERVERS 2>/dev/null || true)"; mtu="$(state_get "$instance" MTU 2>/dev/null || echo 0)"; keepalive="$(state_get "$instance" KEEPALIVE 2>/dev/null || echo 32400)"
    dpd="$(state_get "$instance" DPD 2>/dev/null || echo 90)"; mobile="$(state_get "$instance" MOBILE_DPD 2>/dev/null || echo 1800)"; discovery="$(state_get "$instance" MTU_DISCOVERY 2>/dev/null || echo false)"
    routes="$(state_get "$instance" ROUTES 2>/dev/null || true)"; no_routes="$(state_get "$instance" NO_ROUTES 2>/dev/null || true)"; tunnel="$(state_get "$instance" TUNNEL_ALL_DNS 2>/dev/null || echo 0)"
    splitdns="$(state_get "$instance" SPLIT_DNS 2>/dev/null || true)"; ipv6="$(state_get "$instance" IPV6_NETWORK 2>/dev/null || true)"; ipv6_prefix="$(state_get "$instance" IPV6_SUBNET_PREFIX 2>/dev/null || echo 128)"
    dir="$(instance_dir "$instance")"; sock="$(instance_socket "$instance")"; pid="$(instance_pid "$instance")"
    [[ "$(state_get "$instance" CENTRAL_ENABLED 2>/dev/null || echo 0)" == 1 ]] && central=1
    central_hook="$(state_get "$instance" CENTRAL_HOOK 2>/dev/null || true)"
    cookie="$(state_get "$instance" COOKIE_TIMEOUT)"; persistent="$(state_get "$instance" PERSISTENT_COOKIES)"; roaming="$(state_get "$instance" DENY_ROAMING)"
    rekey_time="$(state_get "$instance" REKEY_TIME)"; rekey_method="$(state_get "$instance" REKEY_METHOD)"; idle="$(state_get "$instance" IDLE_TIMEOUT)"; mobile_idle="$(state_get "$instance" MOBILE_IDLE_TIMEOUT)"; switch_tcp="$(state_get "$instance" SWITCH_TO_TCP_TIMEOUT)"
    cpu_enabled="$(state_get "$instance" CONFIG_PER_USER_ENABLED 2>/dev/null || echo 0)"; cpg_enabled="$(state_get "$instance" CONFIG_PER_GROUP_ENABLED 2>/dev/null || echo 0)"
    cpu_dir="$(state_get "$instance" CONFIG_PER_USER_DIR 2>/dev/null || echo "$dir/config-per-user/")"; cpg_dir="$(state_get "$instance" CONFIG_PER_GROUP_DIR 2>/dev/null || echo "$dir/config-per-group/")"

    jq -n \
      --arg instance "$instance" --arg listen "$listen" --arg tcp "$tcp" --arg udp "$udp" --arg subnet "$subnet" \
      --arg cert "$cert" --arg key "$key" --arg auth_b64 "$auth_b64" --arg ca "$ca" --arg cert_oid "$cert_oid" --arg group_oid "$group_oid" \
      --arg max_clients "$max_clients" --arg max_same "$max_same" --arg score "$score" --arg ban_time "$ban_time" --arg ban_reset "$ban_reset" \
      --arg dns "$dns" --arg mtu "$mtu" --arg keepalive "$keepalive" --arg dpd "$dpd" --arg mobile "$mobile" --arg discovery "$discovery" \
      --arg routes "$routes" --arg no_routes "$no_routes" --arg tunnel "$tunnel" --arg splitdns "$splitdns" --arg ipv6 "$ipv6" --arg ipv6_prefix "$ipv6_prefix" \
      --arg dir "$dir" --arg sock "$sock" --arg pid "$pid" --arg central "$central" --arg central_hook "$central_hook" \
      --arg cookie "$cookie" --arg persistent "$persistent" --arg roaming "$roaming" --arg rekey_time "$rekey_time" --arg rekey_method "$rekey_method" \
      --arg idle "$idle" --arg mobile_idle "$mobile_idle" --arg switch_tcp "$switch_tcp" \
      --arg cpu_enabled "$cpu_enabled" --arg cpg_enabled "$cpg_enabled" --arg cpu_dir "$cpu_dir" --arg cpg_dir "$cpg_dir" \
      '{instance:$instance,listen:$listen,tcp:$tcp,udp:$udp,subnet:$subnet,cert:$cert,key:$key,auth_b64:$auth_b64,ca:$ca,cert_oid:$cert_oid,group_oid:$group_oid,max_clients:$max_clients,max_same:$max_same,score:$score,ban_time:$ban_time,ban_reset:$ban_reset,dns:$dns,mtu:$mtu,keepalive:$keepalive,dpd:$dpd,mobile:$mobile,discovery:$discovery,routes:$routes,no_routes:$no_routes,tunnel:$tunnel,splitdns:$splitdns,ipv6:$ipv6,ipv6_prefix:$ipv6_prefix,dir:$dir,sock:$sock,pid:$pid,central:$central,central_hook:$central_hook,cookie:$cookie,persistent:$persistent,roaming:$roaming,rekey_time:$rekey_time,rekey_method:$rekey_method,idle:$idle,mobile_idle:$mobile_idle,switch_tcp:$switch_tcp,cpu_enabled:$cpu_enabled,cpg_enabled:$cpg_enabled,cpu_dir:$cpu_dir,cpg_dir:$cpg_dir}' > "$settings"

    python3 - "$base" "$out" "$settings" <<'PYCFG'
import base64, json, re, sys
from pathlib import Path
base, out, settings = map(Path, sys.argv[1:4])
d = json.loads(settings.read_text())
lines = base.read_text(encoding='utf-8', errors='ignore').splitlines()
# Global directives must stay before the first vhost section.
cut = next((i for i,l in enumerate(lines) if re.match(r'^\s*\[vhost:', l, re.I)), len(lines))
global_lines, tail = lines[:cut], lines[cut:]

# Upstream sample.config intentionally contains an ACTIVE demonstration vhost
# [vhost:www.example.com] that points at ../tests/certs/*.pem inside the source
# tree. When the sample is used as a production base those files do not exist.
# Preserve the example text, but comment out its active directives so it cannot
# become a real vhost or break `ocserv --test-config`. Custom/local vhosts are
# otherwise preserved unchanged.
def disable_upstream_test_vhost(section_lines):
    if not section_lines:
        return section_lines
    result = []
    i = 0
    while i < len(section_lines):
        m = re.match(r'^\s*\[vhost:([^]]+)\]\s*$', section_lines[i], re.I)
        if not m:
            result.append(section_lines[i]); i += 1; continue
        j = i + 1
        while j < len(section_lines) and not re.match(r'^\s*\[vhost:', section_lines[j], re.I):
            j += 1
        block = section_lines[i:j]
        domain = m.group(1).strip().lower()
        test_block = domain == 'www.example.com' and any('../tests/certs/' in x for x in block)
        if test_block:
            result.append('# ocserv-manager: upstream example vhost disabled for production validation')
            for line in block:
                if line.strip() and not line.lstrip().startswith('#'):
                    result.append('# ocserv-manager disabled upstream example: ' + line)
                else:
                    result.append(line)
        else:
            result.extend(block)
        i = j
    return result

tail = disable_upstream_test_vhost(tail)

def active_re(key):
    return re.compile(r'^\s*' + re.escape(key) + r'\s*=')

def comment_re(key):
    return re.compile(r'^\s*#+\s*' + re.escape(key) + r'\s*=')

def set_scalar(key, value):
    global global_lines
    value = str(value)
    ar, cr = active_re(key), comment_re(key)
    active = [i for i,l in enumerate(global_lines) if ar.match(l)]
    if active:
        global_lines[active[0]] = f'{key} = {value}'
        for i in active[1:]:
            global_lines[i] = '# ocserv-manager disabled duplicate: ' + global_lines[i].lstrip()
        return
    commented = [i for i,l in enumerate(global_lines) if cr.match(l)]
    if commented:
        global_lines[commented[0]] = f'{key} = {value}'
    else:
        global_lines.append(f'{key} = {value}')

def disable_scalar(key):
    ar = active_re(key)
    for i,l in enumerate(global_lines):
        if ar.match(l):
            global_lines[i] = '# ocserv-manager disabled: ' + l.lstrip()

def set_multi(key, values):
    ar = active_re(key)
    for i,l in enumerate(global_lines):
        if ar.match(l):
            global_lines[i] = '# ocserv-manager base value: ' + l.lstrip()
    vals = [str(x).strip() for x in values if str(x).strip()]
    if vals:
        global_lines.append(f'# ocserv-manager managed {key} values')
        global_lines.extend(f'{key} = {v}' for v in vals)

def words(s): return [x for x in str(s or '').split() if x]
def truth(v): return str(v).lower() in ('1','true','yes','on')

def set_ipv4_pool(cidr):
    import ipaddress
    n=ipaddress.ip_network(str(cidr), strict=False)
    # Preserve the structural form used by the real base config. If it uses
    # ipv4-network + ipv4-netmask, keep that form; if it uses CIDR, keep CIDR.
    ar_net, ar_mask = active_re('ipv4-network'), active_re('ipv4-netmask')
    active_net = next((l for l in global_lines if ar_net.match(l)), '')
    active_mask = next((l for l in global_lines if ar_mask.match(l)), '')
    if active_mask or (active_net and '/' not in active_net.split('=',1)[1]):
        set_scalar('ipv4-network', str(n.network_address))
        set_scalar('ipv4-netmask', str(n.netmask))
    else:
        set_scalar('ipv4-network', str(n))
        disable_scalar('ipv4-netmask')

def disable_if_exact(key, value):
    ar=active_re(key)
    for i,l in enumerate(global_lines):
        if ar.match(l):
            current=l.split('=',1)[1].strip().strip('\"') if '=' in l else ''
            if current == value:
                global_lines[i]='# ocserv-manager disabled upstream example: ' + l.lstrip()

def disable_if_manager_central_hook(key):
    ar=active_re(key)
    for i,l in enumerate(global_lines):
        if ar.match(l):
            current=l.split('=',1)[1].strip().strip('\"') if '=' in l else ''
            if (
                '/usr/local/lib/ocserv-manager/central/' in current
                or current in (
                    '/usr/local/sbin/ocserv-central-connect.sh',
                    '/usr/local/sbin/ocserv-central-disconnect.sh',
                    '/usr/local/sbin/ocserv-central-hook.sh',
                )
            ):
                global_lines[i]='# ocserv-manager disabled Central hook: ' + l.lstrip()

auth = ''
if d.get('auth_b64'):
    try: auth = base64.b64decode(d['auth_b64']).decode('utf-8', 'ignore')
    except Exception: auth = ''
auth_values = []
for x in auth.splitlines():
    x = x.strip()
    if not x: continue
    m = re.match(r'^auth\s*=\s*(.*)$', x)
    auth_values.append(m.group(1).strip() if m else x)
set_multi('auth', auth_values)
if d['listen'] and d['listen'] not in ('0.0.0.0','::','*'):
    set_scalar('listen-host', d['listen'])
else:
    disable_scalar('listen-host')
set_scalar('tcp-port', d['tcp']); set_scalar('udp-port', d['udp'])
set_scalar('occtl-socket-file', d['sock']); set_scalar('socket-file', f"/run/ocserv-{d['instance']}-socket")
set_scalar('server-cert', d['cert']); set_scalar('server-key', d['key'])
if d['ca']:
    set_scalar('ca-cert', d['ca'])
    if d['cert_oid']: set_scalar('cert-user-oid', d['cert_oid'])
    if d['group_oid']: set_scalar('cert-group-oid', d['group_oid'])
else:
    disable_scalar('ca-cert')
    disable_scalar('cert-user-oid')
    disable_scalar('cert-group-oid')
set_scalar('max-clients', d['max_clients']); set_scalar('max-same-clients', d['max_same'])
set_scalar('max-ban-score', d['score']); set_scalar('ban-time', d['ban_time']); set_scalar('ban-reset-time', d['ban_reset'])
set_scalar('cookie-timeout', d['cookie'])
if truth(d['persistent']): set_scalar('persistent-cookies', 'true')
else: disable_scalar('persistent-cookies')
set_scalar('deny-roaming', 'true' if truth(d['roaming']) else 'false')
set_scalar('rekey-time', d['rekey_time']); set_scalar('rekey-method', d['rekey_method'])
if str(d['idle']).lower() == 'disabled': disable_scalar('idle-timeout')
else: set_scalar('idle-timeout', d['idle'])
if str(d['mobile_idle']).lower() == 'disabled': disable_scalar('mobile-idle-timeout')
else: set_scalar('mobile-idle-timeout', d['mobile_idle'])
set_scalar('use-occtl', 'true'); set_scalar('pid-file', d['pid'])
if str(d['central']) == '1':
    hook = d['central_hook'] or '/usr/local/lib/ocserv-manager/central/hook.sh'
    set_scalar('connect-script', hook); set_scalar('disconnect-script', hook)
else:
    # Preserve user-owned scripts from the original base config. Only disable a
    # manager-owned Central hook if an older base snapshot happened to contain it.
    disable_if_manager_central_hook('connect-script'); disable_if_manager_central_hook('disconnect-script')
set_ipv4_pool(d['subnet'])
disable_if_exact('default-domain', 'example.com')
if d['ipv6']:
    set_scalar('ipv6-network', d['ipv6']); set_scalar('ipv6-subnet-prefix', d['ipv6_prefix'])
else:
    disable_scalar('ipv6-network'); disable_scalar('ipv6-subnet-prefix')
set_scalar('tunnel-all-dns', 'true' if truth(d['tunnel']) else 'false')
set_multi('dns', words(d['dns'])); set_multi('split-dns', words(d['splitdns']))
if str(d['mtu']).isdigit() and int(d['mtu']) > 0: set_scalar('mtu', d['mtu'])
else: disable_scalar('mtu')
set_scalar('keepalive', d['keepalive']); set_scalar('dpd', d['dpd']); set_scalar('mobile-dpd', d['mobile'])
set_scalar('switch-to-tcp-timeout', d['switch_tcp'])
set_scalar('try-mtu-discovery', 'true' if truth(d['discovery']) else 'false')
set_multi('route', words(d['routes'])); set_multi('no-route', words(d['no_routes']))
if truth(d.get('cpu_enabled')): set_scalar('config-per-user', d['cpu_dir'])
else: disable_scalar('config-per-user')
if truth(d.get('cpg_enabled')): set_scalar('config-per-group', d['cpg_dir'])
else: disable_scalar('config-per-group')
header = [
    f'# Based on original/upstream ocserv configuration; managed by Ocserv Manager for instance {d["instance"]}.',
    '# Unmanaged comments/options from the base file are preserved. Only selected directives are changed.',
]
Path(out).write_text('\n'.join(header + global_lines + tail).rstrip() + '\n', encoding='utf-8')
PYCFG
    rm -f "$settings"

    # Manager-created SNI vhosts remain explicit sections after the preserved base config.
    local vf dir2
    dir2="$(instance_dir "$instance")"
    if [[ -d "$dir2/vhosts" ]]; then
        for vf in "$dir2"/vhosts/*.conf; do
            [[ -f "$vf" ]] || continue
            printf '\n' >> "$out"
            cat "$vf" >> "$out"
        done
    fi
    chmod 600 "$out"
}

# -----------------------------------------------------------------------------
# Dynamic groups and user management
# -----------------------------------------------------------------------------
group_dir() {
    local instance="$1"
    ensure_supplemental_config_state "$instance"
    state_get "$instance" CONFIG_PER_GROUP_DIR 2>/dev/null || printf '%s/config-per-group/\n' "$(instance_dir "$instance")"
}

user_dir() {
    local instance="$1"
    ensure_supplemental_config_state "$instance"
    state_get "$instance" CONFIG_PER_USER_DIR 2>/dev/null || printf '%s/config-per-user/\n' "$(instance_dir "$instance")"
}

supplemental_feature_enabled() {
    local instance="$1" kind="$2" key
    [[ "$kind" == user ]] && key=CONFIG_PER_USER_ENABLED || key=CONFIG_PER_GROUP_ENABLED
    [[ "$(state_get "$instance" "$key" 2>/dev/null || echo 0)" == 1 ]]
}

apply_supplemental_config_state() {
    local instance="$1" tmp
    if [[ "$(state_get "$instance" MANAGED 2>/dev/null || echo 0)" != 1 ]]; then
        print_err "This instance is in preservation/imported mode. Adopt it before changing config-per-user/config-per-group from the Manager."
        return 1
    fi
    tmp="$(mktemp)"
    if generate_ocserv_config "$instance" "$tmp" && transactional_replace_config "$instance" "$tmp"; then
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

set_supplemental_feature() {
    local instance="$1" kind="$2" action="$3" enable_key dir_key old_enable old_dir default_dir path
    ensure_supplemental_config_state "$instance"
    if [[ "$kind" == user ]]; then
        enable_key=CONFIG_PER_USER_ENABLED; dir_key=CONFIG_PER_USER_DIR; default_dir="$(instance_dir "$instance")/config-per-user/"
    else
        enable_key=CONFIG_PER_GROUP_ENABLED; dir_key=CONFIG_PER_GROUP_DIR; default_dir="$(instance_dir "$instance")/config-per-group/"
    fi
    old_enable="$(state_get "$instance" "$enable_key" 2>/dev/null || echo 0)"
    old_dir="$(state_get "$instance" "$dir_key" 2>/dev/null || echo "$default_dir")"

    case "$action" in
        enable)
            path="$(ask_value "Absolute directory for config-per-$kind" "$old_dir")"
            [[ "$path" == /* ]] || { print_err "Use an absolute directory path."; return 1; }
            mkdir -p "$path"; chmod 700 "$path" 2>/dev/null || true
            state_set "$instance" "$dir_key" "$path"
            state_set "$instance" "$enable_key" 1
            ;;
        disable)
            state_set "$instance" "$enable_key" 0
            ;;
        path)
            path="$(ask_value "New absolute directory for config-per-$kind" "$old_dir")"
            [[ "$path" == /* ]] || { print_err "Use an absolute directory path."; return 1; }
            mkdir -p "$path"; chmod 700 "$path" 2>/dev/null || true
            state_set "$instance" "$dir_key" "$path"
            ;;
        *) return 1 ;;
    esac

    if ! apply_supplemental_config_state "$instance"; then
        state_set "$instance" "$enable_key" "$old_enable"
        state_set "$instance" "$dir_key" "$old_dir"
        print_warn "Supplemental-config state rolled back because the ocserv config could not be applied."
        return 1
    fi
    print_ok "config-per-$kind updated. Existing supplemental files were not deleted."
}

supplemental_files_menu() {
    local instance="$1" kind="$2" dir choice name file editor
    while true; do
        [[ "$kind" == user ]] && dir="$(user_dir "$instance")" || dir="$(group_dir "$instance")"
        echo
        echo "==== config-per-$kind files: $instance ===="
        echo "Directory: $dir"
        echo "1) List files"
        echo "2) Show one file"
        echo "3) Edit/create one raw file"
        echo "4) Delete one file"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) [[ -d "$dir" ]] && find "$dir" -maxdepth 1 -type f -printf '%f\n' | sort || echo "No directory/files yet."; pause ;;
            2) name="$(ask_nonempty "File name (username/group name)")"; safe_name "$name" || { print_err "Invalid file name."; pause; continue; }; file="${dir%/}/$name"; [[ -f "$file" ]] && cat "$file" || print_warn "File not found."; pause ;;
            3)
                name="$(ask_nonempty "File name (username/group name)")"; safe_name "$name" || { print_err "Invalid file name."; pause; continue; }
                mkdir -p "$dir"; file="${dir%/}/$name"; touch "$file"; chmod 600 "$file"
                install_available_packages nano
                editor="${EDITOR:-nano}"; "$editor" "$file"
                if validate_config "$(instance_config "$instance")"; then reload_instance "$instance" || true; else print_warn "Main config validation failed after editing supplemental file; review the file before reconnecting users."; fi
                ;;
            4) name="$(ask_nonempty "File name to delete")"; safe_name "$name" || { print_err "Invalid file name."; pause; continue; }; file="${dir%/}/$name"; [[ -f "$file" ]] || { print_warn "File not found."; pause; continue; }; ask_yes_no "Delete $file?" "n" && rm -f "$file"; ;;
            0) return 0 ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

supplemental_config_menu() {
    local instance="$1" choice ustate gstate udir gdir
    ensure_supplemental_config_state "$instance"
    while true; do
        ustate="$(state_get "$instance" CONFIG_PER_USER_ENABLED 2>/dev/null || echo 0)"; gstate="$(state_get "$instance" CONFIG_PER_GROUP_ENABLED 2>/dev/null || echo 0)"
        udir="$(user_dir "$instance")"; gdir="$(group_dir "$instance")"
        echo
        echo "==== Per-user / Per-group supplemental configuration: $instance ===="
        echo "config-per-user:  $([[ "$ustate" == 1 ]] && echo enabled || echo disabled) | $udir"
        echo "config-per-group: $([[ "$gstate" == 1 ]] && echo enabled || echo disabled) | $gdir"
        echo "1) Enable config-per-user"
        echo "2) Disable config-per-user"
        echo "3) Change config-per-user directory"
        echo "4) Manage config-per-user files"
        echo "5) Enable config-per-group"
        echo "6) Disable config-per-group"
        echo "7) Change config-per-group directory"
        echo "8) Manage config-per-group files"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) set_supplemental_feature "$instance" user enable; pause ;;
            2) set_supplemental_feature "$instance" user disable; pause ;;
            3) set_supplemental_feature "$instance" user path; pause ;;
            4) supplemental_files_menu "$instance" user ;;
            5) set_supplemental_feature "$instance" group enable; pause ;;
            6) set_supplemental_feature "$instance" group disable; pause ;;
            7) set_supplemental_feature "$instance" group path; pause ;;
            8) supplemental_files_menu "$instance" group ;;
            0) return 0 ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

list_groups() {
    local instance="$1" dir f passwd
    dir="$(group_dir "$instance")"
    { if [[ -d "$dir" ]]; then for f in "$dir"/*; do [[ -f "$f" ]] && basename "$f"; done; fi
      passwd="$(instance_passwd "$instance")"; [[ -f "$passwd" ]] && awk -F: 'NF>=2{n=split($2,a,","); for(i=1;i<=n;i++) if(a[i] != "" && a[i] != "*") print a[i]}' "$passwd"; } | sort -u
}

validate_group_name() { safe_name "$1" && [[ "$1" != "default" ]]; }

choose_user_groups() {
    local instance="$1" allow_none="${2:-1}" prompt="${3:-Select group(s)}" input manual g idx
    local -a groups=() selected=()
    mapfile -t groups < <(list_groups "$instance")
    if (( ${#groups[@]} == 0 )); then
        print_info "No existing groups were found for this instance." >&2
        if (( allow_none == 1 )); then manual="$(ask_value "Enter group name(s), comma-separated; blank = no group" "")"; else manual="$(ask_value "Enter group name(s), comma-separated" "")"; fi
        printf '%s\n' "$manual"
        return 0
    fi
    echo "$prompt" >&2
    for idx in "${!groups[@]}"; do printf '%d) %s\n' "$((idx+1))" "${groups[$idx]}" >&2; done
    echo "m) Enter group name(s) manually" >&2
    (( allow_none == 1 )) && echo "0) No explicit group / wildcard (*)" >&2
    echo "You may select multiple existing groups with comma-separated numbers, e.g. 1,3." >&2
    while true; do
        read -r -p "Select group(s): " input || true
        input="${input// /}"
        if (( allow_none == 1 )) && [[ -z "$input" || "$input" == 0 ]]; then
            printf '*\n'
            return 0
        fi
        if [[ "$input" == m || "$input" == M ]]; then
            manual="$(ask_value "Enter group name(s), comma-separated" "")"
            IFS=',' read -r -a selected <<<"$manual"
            for g in "${selected[@]}"; do [[ -z "$g" ]] || validate_group_name "$g" || { print_warn "Invalid group: $g" >&2; manual=""; break; }; done
            [[ -n "$manual" ]] && { printf '%s\n' "$manual"; return 0; }
            continue
        fi
        IFS=',' read -r -a selected <<<"$input"
        manual=""
        local ok=1 n
        for n in "${selected[@]}"; do
            [[ "$n" =~ ^[0-9]+$ ]] && (( n>=1 && n<=${#groups[@]} )) || { ok=0; break; }
            [[ -z "$manual" ]] || manual+=","
            manual+="${groups[$((n-1))]}"
        done
        if (( ok == 1 )) && [[ -n "$manual" ]]; then printf '%s\n' "$manual"; return 0; fi
        print_warn "Invalid group selection." >&2
    done
}

create_or_edit_group() {
    local instance="$1" group="${2:-}" file max_mode max dir
    ensure_supplemental_config_state "$instance"
    if ! supplemental_feature_enabled "$instance" group; then
        print_info "config-per-group is disabled for this instance. Group-specific max-same-clients cannot apply until it is enabled."
        if ask_yes_no "Enable config-per-group now?" "n"; then
            set_supplemental_feature "$instance" group enable || return 1
        else
            print_info "No group config was changed. Users may still carry group labels in ocpasswd."
            return 0
        fi
    fi
    while [[ -z "$group" ]] || ! validate_group_name "$group"; do
        group="$(ask_nonempty "Group name")"
        validate_group_name "$group" || print_warn "Use letters/numbers/dot/underscore/hyphen only; 'default' is reserved."
    done
    dir="$(group_dir "$instance")"; mkdir -p "$dir"; chmod 700 "$dir" 2>/dev/null || true
    file="${dir%/}/$group"
    max_mode="$(choose_menu "Group simultaneous-connection policy:" "Inherit instance/global max-same-clients" "Unlimited for this group" "Use an exact group limit")"
    case "$max_mode" in
        1) max="" ;;
        2) max="0" ;;
        3) max="$(ask_integer "Exact max simultaneous connections for this group" "1" 1 100000)" ;;
    esac
    python3 - "$file" "$group" "$max" <<'PYGROUP'
from pathlib import Path
import re,sys
path=Path(sys.argv[1]); group=sys.argv[2]; value=sys.argv[3]
if path.exists(): lines=path.read_text(encoding='utf-8', errors='ignore').splitlines()
else: lines=[f'# Group supplemental config: {group}', '# Ocserv Manager changes only max-same-clients; other directives may be maintained manually.']
pat=re.compile(r'^\s*max-same-clients\s*=')
idx=[i for i,l in enumerate(lines) if pat.match(l)]
if value:
    if idx:
        lines[idx[0]]=f'max-same-clients = {value}'
        for i in idx[1:]: lines[i]='# ocserv-manager disabled duplicate: '+lines[i].lstrip()
    else:
        lines.append(f'max-same-clients = {value}')
else:
    for i in idx: lines[i]='# ocserv-manager disabled (inherit): '+lines[i].lstrip()
path.write_text('\n'.join(lines).rstrip()+'\n', encoding='utf-8')
PYGROUP
    chmod 600 "$file"
    audit "group-max-same-upsert instance=$instance group=$group max=${max:-inherit}"
    print_ok "Group saved. Ocserv Manager changed only max-same-clients; other directives in the group file were preserved."
    reload_instance "$instance" || true
}

delete_group() {
    local instance="$1" group file passwd users dir
    group="$(ask_nonempty "Group to delete")"; dir="$(group_dir "$instance")"; file="${dir%/}/$group"
    [[ -f "$file" ]] || { print_err "Group supplemental config not found."; return 1; }
    passwd="$(instance_passwd "$instance")"
    users="$(awk -F: -v g="$group" '$2 ~ "(^|,)"g"(,|$)" {print $1}' "$passwd" 2>/dev/null || true)"
    if [[ -n "$users" ]]; then
        print_warn "Users still assigned to this group:"
        echo "$users"
        ask_yes_no "Delete only the group supplemental config? User group labels in ocpasswd will remain." "n" || return 0
    fi
    rm -f "$file"; audit "group-delete-config instance=$instance group=$group"; print_ok "Group supplemental config deleted."
    reload_instance "$instance" || true
}

show_groups() {
    local instance="$1" g file dir
    dir="$(group_dir "$instance")"
    while read -r g; do
        [[ -n "$g" ]] || continue
        echo "===== $g ====="
        file="${dir%/}/$g"
        [[ -f "$file" ]] && cat "$file" || echo "(group exists in user database; no supplemental config)"
        echo
    done < <(list_groups "$instance")
}

passwd_for_instance() {
    local p
    p="$(instance_passwd "$1")"; mkdir -p "$(dirname "$p")"; touch "$p"; chmod 600 "$p"; echo "$p"
}

create_user() {
    local instance="$1" passwd username group="" bin
    passwd="$(passwd_for_instance "$instance")"; bin="$(ocpasswd_bin)"
    [[ -x "$bin" ]] || { print_err "ocpasswd not found."; return 1; }
    while true; do
        read -r -p "Username (blank = cancel): " username || true
        if [[ -z "$username" ]]; then
            print_info "User creation cancelled. You can create users later from the Users menu."
            return 0
        fi
        if ! valid_username "$username"; then
            print_warn "Username must be 1-32 characters: English letters, numbers, . _ -"
            continue
        fi
        if grep -qE "^${username//./\.}:" "$passwd"; then
            print_warn "User already exists: $username"
            print_info "Enter a different username, or leave Username blank to return to the Users menu."
            continue
        fi
        break
    done
    if ask_yes_no "Assign this user to a group?" "y"; then
        group="$(choose_user_groups "$instance" 0 "Available groups for this instance:")"
        [[ -n "$group" ]] || { print_info "No group selected; user creation cancelled."; return 0; }
    else
        # ocpasswd's default no-explicit-group representation is '*'. Keep it
        # explicit so Manager edits never produce an invalid/ambiguous empty field.
        group="*"
    fi
    "$bin" -c "$passwd" -g "$group" "$username"
    audit "user-create instance=$instance username=$username group=$group"
    print_ok "User created only if ocpasswd accepted the password input successfully."
}

change_user_password() {
    local instance="$1" user passwd bin current_group
    passwd="$(passwd_for_instance "$instance")"; bin="$(ocpasswd_bin)"; user="$(ask_nonempty "Username")"
    grep -qE "^${user//./\.}:" "$passwd" || { print_err "User not found."; return 1; }
    current_group="$(awk -F: -v u="$user" '$1==u{print $2; exit}' "$passwd")"
    if [[ -n "$current_group" ]]; then "$bin" -c "$passwd" -g "$current_group" "$user"; else "$bin" -c "$passwd" "$user"; fi
    audit "user-password instance=$instance username=$user"; print_ok "Password changed and existing group membership was preserved."
}
lock_unlock_user() {
    local instance="$1" op="$2" user passwd bin flag
    passwd="$(passwd_for_instance "$instance")"; bin="$(ocpasswd_bin)"; user="$(ask_nonempty "Username")"
    grep -qE "^${user//./\\.}:" "$passwd" || { print_err "User not found."; return 1; }
    [[ "$op" == lock ]] && flag=-l || flag=-u
    "$bin" "$flag" -c "$passwd" "$user"
    audit "user-$op instance=$instance username=$user"; print_ok "User $op completed."
}

delete_user() {
    local instance="$1" user passwd bin
    passwd="$(passwd_for_instance "$instance")"; bin="$(ocpasswd_bin)"; user="$(ask_nonempty "Username")"
    grep -qE "^${user//./\\.}:" "$passwd" || { print_err "User not found."; return 1; }
    if ask_yes_no "Disconnect $user before deletion?" "y"; then occtl_exec "$instance" disconnect user "$user" >/dev/null 2>&1 || true; fi
    "$bin" -d -c "$passwd" "$user"
    audit "user-delete instance=$instance username=$user"; print_ok "User deleted."
}

change_user_group() {
    local instance="$1" passwd user groups
    passwd="$(passwd_for_instance "$instance")"; user="$(ask_nonempty "Username")"
    grep -qE "^${user//./\\.}:" "$passwd" || { print_err "User not found."; return 1; }
    groups="$(choose_user_groups "$instance" 1 "Available groups for this instance:")"
    local g
    IFS=',' read -r -a _groups <<<"$groups"
    for g in "${_groups[@]}"; do
        [[ -z "$g" || "$g" == "*" ]] || validate_group_name "$g" || { print_err "Invalid group: $g"; return 1; }
    done
    if ask_yes_no "Create a backup of ocpasswd before changing this user's group?" "y"; then
        ensure_backup_root
        cp -a "$passwd" "$BACKUP_ROOT/ocpasswd-$(basename "$passwd")-$(date +%Y%m%d-%H%M%S)"
    else
        print_info "ocpasswd backup skipped by request."
    fi
    python3 - "$passwd" "$user" "$groups" <<'PY'
import os,sys,tempfile
p,user,groups=sys.argv[1:]
found=False
out=[]
with open(p,encoding='utf-8',errors='ignore') as f:
    for line in f:
        raw=line.rstrip('\n')
        parts=raw.split(':',2)
        if len(parts)>=3 and parts[0]==user:
            out.append(f"{parts[0]}:{groups}:{parts[2]}")
            found=True
        else: out.append(raw)
if not found: raise SystemExit(2)
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(p),prefix='.ocpasswd.')
os.close(fd)
with open(tmp,'w',encoding='utf-8') as f: f.write('\n'.join(out)+'\n')
os.chmod(tmp,0o600); os.replace(tmp,p)
PY
    audit "user-group-change instance=$instance username=$user groups=$groups"
    if [[ "$groups" == "*" ]]; then
        print_ok "User changed to wildcard/no-explicit-group form: $user:*:<password-hash-preserved>"
    else
        print_ok "User group changed without changing the password hash."
    fi
}

show_users_file_safe() {
    local instance="$1" passwd
    passwd="$(passwd_for_instance "$instance")"
    echo "Username : Group(s) : Password-state"
    awk -F: 'NF>=3{state=($3 ~ /^!/ ? "locked" : "set"); print $1 " : " $2 " : " state}' "$passwd"
}

occtl_exec() {
    local instance="$1"; shift
    local b sock
    b="$(occtl_bin)"; [[ -x "$b" ]] || return 127
    sock="$(instance_socket "$instance")"
    timeout 8 "$b" -s "$sock" "$@"
}

occtl_json() {
    local instance="$1"; shift
    occtl_exec "$instance" --json "$@"
}

connected_users_count() {
    # Never pass occtl JSON as a command-line argument. Busy servers can return
    # hundreds/thousands of session objects and exceed Linux ARG_MAX.
    local instance="$1" tmp rc
    tmp="$(mktemp)"
    if ! occtl_json "$instance" show users >"$tmp" 2>/dev/null; then
        rm -f "$tmp"
        echo 0
        return 0
    fi
    python3 - "$tmp" <<'PYCOUNT'
import json,sys
try:
    with open(sys.argv[1], 'r', encoding='utf-8', errors='replace') as f:
        x=json.load(f)
except Exception:
    print(0)
    raise SystemExit(0)
if isinstance(x,list):
    print(len(x))
elif isinstance(x,dict):
    for k in ('users','connections','sessions'):
        if isinstance(x.get(k),list):
            print(len(x[k])); break
    else:
        vals=[v for v in x.values() if isinstance(v,dict)]
        print(len(vals))
else:
    print(0)
PYCOUNT
    rc=$?
    rm -f "$tmp"
    (( rc == 0 )) || echo 0
    return 0
}

show_connected_users() {
    local instance="$1"
    if ! occtl_json "$instance" show users | jq .; then print_err "Could not query occtl for $instance."; return 1; fi
}

show_session_clients() {
    local instance="$1" tmp
    tmp="$(mktemp)"
    if ! occtl_json "$instance" show sessions all > "$tmp"; then rm -f "$tmp"; print_err "Could not query sessions."; return 1; fi
    python3 - "$tmp" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
rows=x if isinstance(x,list) else next((v for k,v in x.items() if isinstance(v,list)), []) if isinstance(x,dict) else []
if not rows and isinstance(x,dict): rows=[v for v in x.values() if isinstance(v,dict)]
for r in rows:
    if not isinstance(r,dict): continue
    def pick(*ks):
        for k in ks:
            if k in r and r[k] not in (None,''): return r[k]
        return ''
    print(f"{pick('username','user')}\t{pick('user-agent','user_agent','user agent')}\t{pick('device-type','device_type','device')}\t{pick('remote-ip','remote_ip','ip')}" )
PY
    rm -f "$tmp"
}

user_management_menu() {
    local instance="$1" choice user mode
    mode="$(state_get "$instance" AUTH_MODE 2>/dev/null || echo imported)"
    if [[ ! "$mode" =~ ^(1|2|5|imported)$ ]]; then
        print_warn "This instance is not configured for plain-password authentication. ocpasswd users can still be managed, but they will not authenticate unless plain auth is enabled."
    fi
    while true; do
        echo
        echo "==== Users: $instance ===="
        echo "1) Create user"
        echo "2) Change password"
        echo "3) Lock user"
        echo "4) Unlock user"
        echo "5) Delete user"
        echo "6) Change user group"
        echo "7) List users (password hashes hidden)"
        echo "8) Show connected users (JSON)"
        echo "9) Connected user count"
        echo "10) Show session client/software information"
        echo "11) Disconnect user"
        echo "12) config-per-user / config-per-group settings"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) create_user "$instance" || true; pause ;;
            2) change_user_password "$instance" || true; pause ;;
            3) lock_unlock_user "$instance" lock || true; pause ;;
            4) lock_unlock_user "$instance" unlock || true; pause ;;
            5) delete_user "$instance" || true; pause ;;
            6) change_user_group "$instance" || true; pause ;;
            7) show_users_file_safe "$instance" || true; pause ;;
            8) show_connected_users "$instance" || true; pause ;;
            9) echo "Connected sessions/users reported: $(connected_users_count "$instance")"; pause ;;
            10) show_session_clients "$instance" || true; pause ;;
            11) user="$(ask_nonempty "Username")"; if occtl_exec "$instance" disconnect user "$user"; then print_ok "Disconnect requested."; else print_err "Disconnect failed."; fi; pause ;;
            12) supplemental_config_menu "$instance" || true ;;
            0) return 0 ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

group_management_menu() {
    local instance="$1" choice
    while true; do
        echo
        echo "==== Groups: $instance ===="
        echo "1) List groups and settings"
        echo "2) Create/edit group"
        echo "3) Delete group supplemental config"
        echo "4) config-per-user / config-per-group settings"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) show_groups "$instance"; pause ;;
            2) create_or_edit_group "$instance"; pause ;;
            3) delete_group "$instance"; pause ;;
            4) supplemental_config_menu "$instance" ;;
            0) return 0 ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# Instance creation and basic lifecycle
# -----------------------------------------------------------------------------
choose_instance_name_for_create() {
    local mode name
    mode="$(choose_menu "Installation layout:" "Default/legacy layout: /etc/ocserv/ocserv.conf" "Named multi-instance layout: /etc/ocserv/instances/<name>/")"
    if [[ "$mode" == 1 ]]; then echo default; return; fi
    while true; do
        name="$(ask_nonempty "Instance name")"
        safe_name "$name" && [[ "$name" != default ]] || { print_warn "Invalid/reserved name."; continue; }
        if [[ -f "$(instance_state_file "$name")" || -f "$(instance_config "$name")" ]]; then print_warn "Instance already exists."; continue; fi
        echo "$name"; return
    done
}

create_instance_wizard() {
    need_root; ensure_dirs; install_runtime_dependencies
    local b instance conf passwd listen tcp udp subnet auth tmp svc
    ensure_ocserv_service_user
    b="$(ocserv_bin)"
    if [[ -z "$b" ]]; then
        print_info "ocserv is not installed yet."
        install_or_update_ocserv || return 1
    fi
    write_systemd_units
    instance="$(choose_instance_name_for_create)"
    conf="$(instance_config "$instance")"
    if [[ -f "$conf" ]]; then
        print_warn "Existing config found: $conf"
        if ask_yes_no "Import the existing installation instead of overwriting it?" "y"; then import_existing_config "$conf" "$instance"; return; fi
        ask_yes_no "Continue and replace it transactionally?" "n" || return 0
    fi
    ensure_instance_layout "$instance"
    listen="$(choose_listen_host)"
    tcp="$(choose_available_tcp_port "$instance" "$listen" 443)"
    udp="$(choose_available_udp_port "$instance" "$listen" "$tcp")"
    subnet="$(choose_subnet "$instance")"
    # Register early so all later helper functions resolve correct paths.
    passwd="$(instance_passwd "$instance")"
    register_instance "$instance" "$conf" "$passwd" "$subnet" "$tcp" "$udp" "$listen" "pending"
    state_set "$instance" OUT_IFACE "$(default_route_iface || true)"

    while ! configure_server_certificate "$instance"; do
        print_warn "Certificate setup did not complete. Choose again."
    done
    configure_authentication "$instance" || return 1
    choose_dns_servers "$instance"
    configure_limits_and_bans "$instance"
    configure_network_profile "$instance"
    configure_routing_profile "$instance"
    configure_firewall_mode "$instance"
    if ask_yes_no "Open per-instance Firewall setup now? You can also configure it later." "n"; then firewall_manager_menu "$instance"; fi
    state_set "$instance" CENTRAL_ENABLED 0
    state_set "$instance" MANAGED 1

    tmp="$(mktemp)"; generate_ocserv_config "$instance" "$tmp"
    if ! transactional_replace_config "$instance" "$tmp"; then
        print_err "Generated config was not installed. File kept at $tmp for diagnostics."
        return 1
    fi
    rm -f "$tmp"
    apply_firewall_for_instance "$instance"
    svc="$(instance_service "$instance")"
    enable_service_if_needed "$svc"
    if restart_service_bounded "$svc" 15; then
        print_ok "Instance $instance is running."
    else
        print_err "Instance failed to start promptly; showing service status and recent logs."
        systemctl status "$svc" --no-pager -l || true
        journalctl -u "$svc" -n 50 --no-pager || true
        return 1
    fi
    audit "instance-create instance=$instance tcp=$tcp udp=$udp subnet=$subnet"
    if [[ "$(state_get "$instance" AUTH_MODE 2>/dev/null || true)" =~ ^(1|2|5)$ ]] && ask_yes_no "Create an ocpasswd user now? You can also do this later from Users -> Create user." "n"; then
        create_user "$instance"
    fi
    # Central is managed globally from the integrated Central console. New
    # instances are attached silently only when the admin explicitly enabled
    # AUTO_ATTACH in that console earlier.
    if central_auto_attach_enabled; then
        central_attach_instance_from_profile "$instance" 0 || print_warn "Central auto-attach failed for $instance. Open Central Manager -> Local ocserv instances to retry."
    fi
    print_ok "Instance creation completed: $instance"
}

start_instance() { systemctl start "$(instance_service "$1")"; audit "instance-start instance=$1"; }
stop_instance() { systemctl stop "$(instance_service "$1")"; audit "instance-stop instance=$1"; }
restart_instance() { systemctl restart "$(instance_service "$1")"; audit "instance-restart instance=$1"; }
reload_instance() {
    local instance="$1" svc
    svc="$(instance_service "$instance")"
    if systemctl is-active --quiet "$svc"; then systemctl reload "$svc" 2>/dev/null || occtl_exec "$instance" reload; fi
}

show_instance_status() {
    local instance="$1" svc cert
    svc="$(instance_service "$instance")"; cert="$(state_get "$instance" SERVER_CERT 2>/dev/null || true)"
    echo "Instance: $instance"
    echo "Service: $svc ($(systemctl is-active "$svc" 2>/dev/null || true))"
    echo "Config: $(instance_config "$instance")"
    echo "Listen: $(state_get "$instance" LISTEN_HOST 2>/dev/null || echo '?'):$(state_get "$instance" TCP_PORT 2>/dev/null || echo '?') TCP / $(state_get "$instance" UDP_PORT 2>/dev/null || echo '?') UDP"
    echo "Subnet: $(state_get "$instance" SUBNET 2>/dev/null || echo '?')"
    echo "Users DB: $(instance_passwd "$instance")"
    echo "Connected: $(connected_users_count "$instance")"
    if [[ -n "$cert" ]]; then echo "Certificate expires: $(certificate_expiry_text "$cert") ($(certificate_days_left "$cert") days)"; fi
    echo "Central integration: $(state_get "$instance" CENTRAL_ENABLED 2>/dev/null || echo 0)"
}

show_instance_logs() {
    local instance="$1" lines
    lines="$(ask_integer "Number of journal lines" "100" 1 10000)"
    journalctl -u "$(instance_service "$instance")" -n "$lines" --no-pager
}

# -----------------------------------------------------------------------------
# Integrated Central Manager v20 multi-instance transport (per-instance runtime, single Central UI)
# -----------------------------------------------------------------------------
write_central_adapter_files() {
    mkdir -p "$CENTRAL_LIB_DIR" "$CENTRAL_INTEGRATION_DIR"
    chmod 700 "$CENTRAL_INTEGRATION_DIR"

    cat > "$CENTRAL_LIB_DIR/hook-common.sh" <<'HOOK'
#!/usr/bin/env bash
set -u
ENV_FILE="${OCSERV_MANAGER_CENTRAL_ENV:-}"
[[ -n "$ENV_FILE" && -r "$ENV_FILE" ]] || { logger -t ocserv-manager-central "missing per-instance central env"; exit 1; }
# shellcheck disable=SC1090
. "$ENV_FILE"
API_URL="${API_URL:-}"
API_TOKEN="${API_TOKEN:-}"
NODE_ID="${NODE_ID:-$(hostname -s)}"
SOURCE_ID="${SOURCE_ID:-$NODE_ID}"
API_TIMEOUT="${API_TIMEOUT:-5}"
FAIL_MODE="${FAIL_MODE:-closed}"
log(){ logger -t ocserv-manager-central "instance=${INSTANCE:-?} $*"; }
if [[ -z "$API_URL" || -z "$API_TOKEN" ]]; then
    log "missing API_URL/API_TOKEN"
    [[ "$FAIL_MODE" == open ]] && exit 0 || exit 1
fi
post_json(){
    local path="$1" payload="$2" response rc
    set +e
    response="$(curl -sS -m "$API_TIMEOUT" -H 'Content-Type: application/json' -H "X-API-Token: $API_TOKEN" -d "$payload" "$API_URL$path" 2>&1)"
    rc=$?
    set -e
    printf '%s\n' "$rc" "$response"
}
if [[ "${REASON:-}" == connect ]]; then
    payload="$(jq -n --arg node_id "$NODE_ID" --arg source_id "$SOURCE_ID" --arg ocserv_id "${ID:-}" --arg username "${USERNAME:-}" --arg groupname "${GROUPNAME:-}" --arg ip_real "${IP_REAL:-}" --arg ip_remote "${IP_REMOTE:-}" '{node_id:$node_id,source_id:$source_id,ocserv_id:$ocserv_id,username:$username,groupname:$groupname,ip_real:$ip_real,ip_remote:$ip_remote}')"
    mapfile -t result < <(post_json /connect "$payload")
    rc="${result[0]:-1}"; response="${result[*]:1}"
    if [[ "$rc" != 0 ]]; then log "connect API error rc=$rc $response"; [[ "$FAIL_MODE" == open ]] && exit 0 || exit 1; fi
    allow="$(jq -r '.allow // false' <<<"$response" 2>/dev/null || echo false)"
    reason="$(jq -r '.reason // "api error"' <<<"$response" 2>/dev/null || echo 'api error')"
    if [[ "$allow" == true ]]; then log "allow user=${USERNAME:-?} id=${ID:-?}"; exit 0; fi
    log "deny user=${USERNAME:-?} reason=$reason"; exit 1
elif [[ "${REASON:-}" == disconnect ]]; then
    payload="$(jq -n --arg node_id "$NODE_ID" --arg source_id "$SOURCE_ID" --arg ocserv_id "${ID:-}" --arg username "${USERNAME:-}" --argjson bytes_in "${STATS_BYTES_IN:-0}" --argjson bytes_out "${STATS_BYTES_OUT:-0}" '{node_id:$node_id,source_id:$source_id,ocserv_id:$ocserv_id,username:$username,bytes_in:$bytes_in,bytes_out:$bytes_out}')"
    curl -sS -m "$API_TIMEOUT" -H 'Content-Type: application/json' -H "X-API-Token: $API_TOKEN" -d "$payload" "$API_URL/disconnect" >/dev/null 2>&1 || true
    exit 0
fi
exit 0
HOOK
    chmod 755 "$CENTRAL_LIB_DIR/hook-common.sh"

    cat > "$CENTRAL_LIB_DIR/agent.py" <<'PY'
#!/usr/bin/env python3
import json, os, subprocess, sys, time, urllib.request
instance=sys.argv[1]
env_path=f"/etc/ocserv-manager/central/{instance}.env"
def load_env(path):
    out={}
    with open(path,encoding='utf-8',errors='ignore') as f:
        for line in f:
            line=line.strip()
            if line and not line.startswith('#') and '=' in line:
                k,v=line.split('=',1); out[k.strip()]=v.strip().strip('"').strip("'")
    return out
e=load_env(env_path)
API_URL=e.get('API_URL','').rstrip('/'); API_TOKEN=e.get('API_TOKEN',''); NODE_ID=e.get('NODE_ID',f"{subprocess.getoutput('hostname -s').strip()}:{instance}")
SOURCE_ID=e.get('SOURCE_ID',NODE_ID); PASSWD=e.get('OCPASSWD_PATH','')
INTERVAL=max(5,int(e.get('INTERVAL','30'))); API_TIMEOUT=max(1,int(e.get('API_TIMEOUT','5'))); SOCKET=e.get('OCCTL_SOCKET','')
def log(msg): subprocess.run(['logger','-t','ocserv-manager-central',f'instance={instance} {msg}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def request(path,data):
    req=urllib.request.Request(API_URL+path,data=json.dumps(data).encode(),headers={'Content-Type':'application/json','X-API-Token':API_TOKEN},method='POST')
    with urllib.request.urlopen(req,timeout=API_TIMEOUT) as r: return json.loads(r.read().decode())
def occtl(*args):
    cmd=['occtl']
    if SOCKET: cmd += ['-s',SOCKET]
    cmd += list(args)
    return subprocess.check_output(cmd,text=True,stderr=subprocess.DEVNULL)
def find_user_objects(obj):
    rows=[]
    if isinstance(obj,dict):
        low={str(k).lower():k for k in obj}
        if any(k in low for k in ('username','user','name')) and any(k in low for k in ('id','session_id','session-id','sid')): rows.append(obj)
        for v in obj.values(): rows.extend(find_user_objects(v))
    elif isinstance(obj,list):
        for v in obj: rows.extend(find_user_objects(v))
    return rows
def pick(o,names,default=''):
    low={str(k).lower():k for k in o}
    for n in names:
        if n in low: return o[low[n]]
    return default
def number(v):
    if isinstance(v,(int,float)): return int(v)
    s=''.join(c for c in str(v) if c.isdigit())
    return int(s or 0)
def sessions():
    data=json.loads(occtl('--json','show','users'))
    out=[]
    for o in find_user_objects(data):
        oid=str(pick(o,['id','session_id','session-id','sid']))
        user=str(pick(o,['username','user','name']))
        group=str(pick(o,['groupname','group','authgroup','auth_group']))
        total=number(pick(o,['total_bytes','total-bytes','bytes','traffic'],0))
        if not total: total=number(pick(o,['rx','bytes_in','bytes-in','received'],0))+number(pick(o,['tx','bytes_out','bytes-out','sent'],0))
        if oid and user: out.append({'ocserv_id':oid,'username':user,'groupname':group,'total_bytes':total})
    return out
def passwd_users():
    out=[]
    if not PASSWD or not os.path.isfile(PASSWD):
        raise FileNotFoundError(f'ocpasswd not available: {PASSWD}')
    try:
        with open(PASSWD,encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith('#'): continue
                parts=line.split(':',2)
                if len(parts)<2 or not parts[0].strip(): continue
                groups=[x.strip() for x in parts[1].split(',') if x.strip()]
                group=next((g for g in groups if any(c.isdigit() for c in g)), groups[0] if groups else 'group1')
                out.append({'username':parts[0].strip(),'groupname':group})
    except Exception as ex:
        log(f'ocpasswd read error: {ex}')
        raise
    return out
last_source_sig=None
last_source_sync=0
def source_sig():
    try:
        st=os.stat(PASSWD); return (st.st_mtime_ns,st.st_size)
    except Exception: return None
def sync_source(force=False):
    global last_source_sig,last_source_sync
    sig=source_sig(); now=time.time()
    if not force and sig==last_source_sig and now-last_source_sync < 600:
        return {'ok':True,'skipped':True}
    users=passwd_users()
    r=request('/sync-source',{'source_id':SOURCE_ID,'node_id':NODE_ID,'users':users,'complete':True})
    last_source_sig=sig; last_source_sync=now
    return r
def disconnect(oid):
    try: occtl('disconnect','id',str(oid))
    except Exception: pass
if not API_URL or not API_TOKEN: log('missing API_URL/API_TOKEN'); raise SystemExit(1)
log(f'started node_id={NODE_ID} source_id={SOURCE_ID} socket={SOCKET} passwd={PASSWD}')
while True:
    try:
        try:
            sr=sync_source(force=(last_source_sync==0))
            conflicts=sr.get('conflicts',[]) if isinstance(sr,dict) else []
            if conflicts: log(f'authority conflicts: {conflicts[:5]}')
        except Exception as ex:
            # Backward-compatible migration path: a v19 Master has no
            # /sync-source endpoint. Do not stop heartbeat/quota enforcement.
            log(f'authority sync unavailable (Master may still be v19): {ex}')
        r=request('/heartbeat',{'node_id':NODE_ID,'source_id':SOURCE_ID,'sessions':sessions()})
        for oid in r.get('disconnect_ids',[]): log(f'disconnect id={oid} by central policy'); disconnect(oid)
    except Exception as ex: log(f'agent error: {ex}')
    time.sleep(INTERVAL)
PY
    chmod 755 "$CENTRAL_LIB_DIR/agent.py"

    cat > /etc/systemd/system/ocserv-manager-central@.service <<EOF
[Unit]
Description=Ocserv Manager Central quota/session agent for %i
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $CENTRAL_LIB_DIR/agent.py %i
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

central_env_file() { printf '%s/%s.env\n' "$CENTRAL_INTEGRATION_DIR" "$1"; }
central_agent_service() { printf 'ocserv-manager-central@%s.service\n' "$1"; }

write_central_wrapper() {
    local instance="$1" wrapper="$CENTRAL_LIB_DIR/hook-$instance.sh" envf
    envf="$(central_env_file "$instance")"
    cat > "$wrapper" <<EOF
#!/usr/bin/env bash
export OCSERV_MANAGER_CENTRAL_ENV='$envf'
exec '$CENTRAL_LIB_DIR/hook-common.sh'
EOF
    chmod 755 "$wrapper"
    state_set "$instance" CENTRAL_HOOK "$wrapper"
}

detect_local_central_token() {
    systemctl show ocserv-central -p Environment --value 2>/dev/null | tr ' ' '\n' | sed -n 's/^API_TOKEN=//p' | tail -n1 || true
}

central_write_profile_values() {
    local api="$1" token="$2" interval="${3:-30}" timeout="${4:-5}" fail="${5:-closed}" auto="${6:-1}"
    [[ -n "$api" && -n "$token" ]] || { print_err "Central API URL/token are required."; return 1; }
    mkdir -p "$CENTRAL_INTEGRATION_DIR"
    cat > "$CENTRAL_PROFILE" <<EOF
API_URL="$api"
API_TOKEN="$token"
INTERVAL="$interval"
API_TIMEOUT="$timeout"
FAIL_MODE="$fail"
AUTO_ATTACH="$auto"
EOF
    chmod 600 "$CENTRAL_PROFILE"
}

central_register_detected_instances_for_attach() {
    local conf instance
    while read -r conf; do
        [[ -f "$conf" ]] || continue
        if [[ "$conf" == /etc/ocserv/ocserv.conf ]]; then instance=default; else instance="$(basename "$(dirname "$conf")")"; fi
        [[ -f "$(instance_state_file "$instance")" ]] || import_existing_config "$conf" "$instance" >/dev/null || true
    done < <(detect_existing_installations | sort -u)
}

# Exact modern equivalent of the old v19 "Install both master and node on this server":
# use the local Master and attach every local ocserv instance as its own source-aware Node.
central_attach_all_local_master() {
    local token i failed=0 count=0 token_preview
    token="$(detect_local_central_token)"
    [[ -n "$token" ]] || { print_err "Local Central Master token was not detected. Install/start the Master first."; return 1; }
    central_register_detected_instances_for_attach
    central_write_profile_values "http://127.0.0.1:8088" "$token" 30 5 closed 1 || return 1
    token_preview="${token:0:8}...${token: -4}"
    echo
    print_info "Local Central API/Node profile selected automatically:"
    echo "  API URL: http://127.0.0.1:8088"
    echo "  API token: $token_preview (masked)"
    echo "  Live check interval: 30 seconds"
    echo "  API timeout: 5 seconds"
    echo "  Failure policy: fail-closed"
    echo "  Auto-attach new local instances: enabled"
    while read -r i; do
        [[ -n "$i" ]] || continue
        count=$((count+1))
        central_attach_instance_from_profile "$i" 0 || failed=$((failed+1))
    done < <(list_instances | sort -u)
    (( count > 0 )) || { print_warn "No local ocserv instance was detected. Master is ready; create/import an instance and it can be auto-attached later."; return 0; }
    if (( failed > 0 )); then
        print_err "$failed of $count local instance(s) could not be attached to Central."
        return 1
    fi
    print_ok "Local Master + $count ocserv Node instance(s) are integrated. API: http://127.0.0.1:8088"
}

central_sync_local_master_profile() {
    local token i failed=0 updated=0
    token="$(detect_local_central_token)"
    [[ -n "$token" ]] || { print_err "Local Central Master token was not detected."; return 1; }
    [[ -f "$CENTRAL_PROFILE" ]] || return 0
    central_profile_load
    case "${API_URL:-}" in
        http://127.0.0.1:8088|http://localhost:8088)
            central_write_profile_values "http://127.0.0.1:8088" "$token" "${INTERVAL:-30}" "${API_TIMEOUT:-5}" "${FAIL_MODE:-closed}" "${AUTO_ATTACH:-0}" || return 1
            ;;
        *)
            # A deliberately remote profile must not be silently replaced by the local Master.
            return 0
            ;;
    esac
    while read -r i; do
        [[ -n "$i" ]] || continue
        [[ "$(state_get "$i" CENTRAL_ENABLED 2>/dev/null || echo 0)" == 1 ]] || continue
        updated=$((updated+1))
        central_attach_instance_from_profile "$i" 0 || failed=$((failed+1))
    done < <(list_instances | sort -u)
    if (( updated > 0 )); then
        if (( failed == 0 )); then
            print_ok "Local Central API token/profile synchronized to $updated attached instance(s)."
        else
            print_warn "$failed of $updated attached instance(s) could not be synchronized to the local Master profile."
            return 1
        fi
    fi
    return 0
}

central_read_env_value() {
    local file="$1" key="$2"
    [[ -r "$file" ]] || return 1
    sed -n -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*[\\\"']?([^\\\"']*)[\\\"']?[[:space:]]*$/\\1/p" "$file" | tail -n1
}

# Import the old v19 single-node connection values into the shared v20 profile,
# then attach all local Manager instances without asking the same settings again.
central_import_v19_node_env() {
    local envf="$1" api token interval timeout fail
    [[ -r "$envf" ]] || { print_err "v19 node.env not found/readable: $envf"; return 1; }
    api="$(central_read_env_value "$envf" API_URL || true)"
    token="$(central_read_env_value "$envf" API_TOKEN || true)"
    interval="$(central_read_env_value "$envf" INTERVAL || true)"; interval="${interval:-30}"
    timeout="$(central_read_env_value "$envf" API_TIMEOUT || true)"; timeout="${timeout:-5}"
    fail="$(central_read_env_value "$envf" FAIL_MODE || true)"; fail="${fail:-closed}"
    case "$api" in ""|*MASTER_SERVER_IP*|http://master:8088|http://MASTER:8088) api="http://127.0.0.1:8088";; esac
    [[ -n "$token" ]] || token="$(detect_local_central_token)"
    [[ -n "$token" ]] || { print_err "No API token was found in the v19 node settings or local Master."; return 1; }
    central_register_detected_instances_for_attach
    central_write_profile_values "$api" "$token" "$interval" "$timeout" "$fail" 1 || return 1
    local i count=0 failed=0
    while read -r i; do
        [[ -n "$i" ]] || continue; count=$((count+1))
        central_attach_instance_from_profile "$i" 0 || failed=$((failed+1))
    done < <(list_instances | sort -u)
    (( failed == 0 )) || return 1
    print_ok "Imported v19 Node API settings and attached $count local instance(s)."
}

central_default_node_id() {
    local instance="$1" host mid
    host="$(hostname -s 2>/dev/null || hostname)"
    mid="$(tr -dc 'A-Za-z0-9' </etc/machine-id 2>/dev/null | head -c 8 || true)"
    if [[ -n "$mid" ]]; then printf '%s-%s:%s\n' "$host" "$mid" "$instance"; else printf '%s:%s\n' "$host" "$instance"; fi
}

central_profile_load() {
    API_URL="" API_TOKEN="" INTERVAL="30" API_TIMEOUT="5" FAIL_MODE="closed" AUTO_ATTACH="0"
    if [[ -f "$CENTRAL_PROFILE" ]]; then
        # shellcheck disable=SC1090
        . "$CENTRAL_PROFILE"
    fi
}

central_profile_configure() {
    local api token interval timeout fail auto=0 local_token i attached=0 failed=0
    install_runtime_dependencies; install_available_packages curl jq python3
    local_token="$(detect_local_central_token)"
    if systemctl is-active --quiet ocserv-central 2>/dev/null && [[ -n "$local_token" ]]; then
        print_info "A local Central Master is active. It can be used by every local ocserv instance."
        api="$(ask_nonempty "Central API URL" "http://127.0.0.1:8088")"
        token="$(ask_nonempty "Central API token" "$local_token")"
    else
        api="$(ask_nonempty "Central API URL" "http://127.0.0.1:8088")"
        token="$(ask_nonempty "Central API token")"
    fi
    interval="$(ask_integer "Live quota/expiry check interval seconds" "30" 5 3600)"
    timeout="$(ask_integer "Central API timeout seconds" "5" 1 60)"
    if ask_yes_no "If Central API is unreachable, temporarily allow new VPN connections? (fail-open weakens enforcement)" "n"; then fail=open; else fail=closed; fi
    if ask_yes_no "Automatically attach NEW ocserv instances to Central using this profile?" "n"; then auto=1; fi
    central_write_profile_values "$api" "$token" "$interval" "$timeout" "$fail" "$auto" || return 1
    print_ok "Shared Central connection profile saved."

    while read -r i; do
        [[ -n "$i" ]] || continue
        [[ "$(state_get "$i" CENTRAL_ENABLED 2>/dev/null || echo 0)" == 1 ]] && attached=$((attached+1))
    done < <(list_instances | sort -u)

    if (( attached > 0 )); then
        echo
        print_info "$attached local ocserv instance(s) are already attached to Central."
        if ask_yes_no "Apply the new API/agent profile to all currently attached instances now?" "y"; then
            while read -r i; do
                [[ -n "$i" ]] || continue
                [[ "$(state_get "$i" CENTRAL_ENABLED 2>/dev/null || echo 0)" == 1 ]] || continue
                central_attach_instance_from_profile "$i" 0 || failed=$((failed+1))
            done < <(list_instances | sort -u)
            if (( failed == 0 )); then
                print_ok "New Central API/agent settings applied to all attached instances."
            else
                print_warn "$failed attached instance(s) could not be updated. Check their agent logs."
            fi
        else
            print_warn "Profile was saved, but existing attached instances keep their previous env until you re-attach/apply it."
        fi
    fi
}

central_auto_attach_enabled() {
    [[ -f "$CENTRAL_PROFILE" ]] || return 1
    central_profile_load
    [[ "${AUTO_ATTACH:-0}" == 1 ]]
}

# Imported/preservation-mode instances must not be regenerated from incomplete
# manager state merely to attach Central. Patch only the four Central/occtl
# directives and preserve every unrelated line in the real ocserv.conf.
central_patch_imported_config() {
    local instance="$1" mode="$2" wrapper="${3:-}" conf tmp socket
    conf="$(instance_config "$instance")"
    [[ -f "$conf" ]] || { print_err "Imported instance config not found: $conf"; return 1; }
    socket="$(instance_socket "$instance")"
    tmp="$(mktemp)"; cp -a "$conf" "$tmp"
    python3 - "$tmp" "$mode" "$wrapper" "$socket" <<'PYIMPCENTRAL'
import re, sys
from pathlib import Path
path=Path(sys.argv[1]); mode=sys.argv[2]; wrapper=sys.argv[3]; socket=sys.argv[4]
lines=path.read_text(encoding='utf-8',errors='ignore').splitlines()
start='# BEGIN OCSERV-MANAGER-CENTRAL-IMPORTED'
end='# END OCSERV-MANAGER-CENTRAL-IMPORTED'
preserved='# ocserv-manager central preserved: '
legacy='# ocserv-manager removed legacy v19 Central hook: '

# First remove a previous manager block and restore only user-owned directives
# that this patch preserved. Legacy v19 hook paths deliberately remain disabled.
out=[]; inside=False
for line in lines:
    if line.strip()==start:
        inside=True; continue
    if inside:
        if line.strip()==end: inside=False
        continue
    if line.startswith(preserved):
        out.append(line[len(preserved):]); continue
    out.append(line)
lines=out
if mode != 'enable':
    path.write_text('\n'.join(lines).rstrip()+'\n',encoding='utf-8')
    raise SystemExit(0)

cut=next((i for i,l in enumerate(lines) if re.match(r'^\s*\[vhost:',l,re.I)),len(lines))
global_lines,tail=lines[:cut],lines[cut:]
keys=('use-occtl','occtl-socket-file','connect-script','disconnect-script')
legacy_paths={
 '/usr/local/sbin/ocserv-central-connect.sh',
 '/usr/local/sbin/ocserv-central-disconnect.sh',
 '/usr/local/sbin/ocserv-central-hook.sh',
}
for i,line in enumerate(global_lines):
    if line.lstrip().startswith('#'): continue
    for key in keys:
        if re.match(r'^\s*'+re.escape(key)+r'\s*=',line):
            value=line.split('=',1)[1].strip().strip('"').strip("'") if '=' in line else ''
            if key in ('connect-script','disconnect-script') and value in legacy_paths:
                global_lines[i]=legacy+line
            else:
                global_lines[i]=preserved+line
            break
block=[start,'use-occtl = true',f'occtl-socket-file = {socket}',f'connect-script = {wrapper}',f'disconnect-script = {wrapper}',end]
new=global_lines+['']+block+([''] if tail else [])+tail
path.write_text('\n'.join(new).rstrip()+'\n',encoding='utf-8')
PYIMPCENTRAL
    if transactional_replace_config "$instance" "$tmp"; then
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

central_attach_instance_from_profile() {
    local instance="$1" interactive="${2:-1}" envf node source_id tmp svc passwd
    [[ -f "$CENTRAL_PROFILE" ]] || {
        if [[ "$interactive" == 1 ]]; then central_profile_configure; else return 1; fi
    }
    central_profile_load
    [[ -n "${API_URL:-}" && -n "${API_TOKEN:-}" ]] || { print_err "Central profile is incomplete."; return 1; }
    install_runtime_dependencies; install_available_packages curl jq python3
    write_central_adapter_files
    write_central_wrapper "$instance"
    node="$(central_default_node_id "$instance")"
    source_id="$node"
    passwd="$(instance_passwd "$instance")"
    envf="$(central_env_file "$instance")"
    cat > "$envf" <<EOF
INSTANCE="$instance"
SOURCE_ID="$source_id"
API_URL="$API_URL"
API_TOKEN="$API_TOKEN"
NODE_ID="$node"
INTERVAL="${INTERVAL:-30}"
API_TIMEOUT="${API_TIMEOUT:-5}"
FAIL_MODE="${FAIL_MODE:-closed}"
OCCTL_SOCKET="$(instance_socket "$instance")"
OCPASSWD_PATH="$passwd"
EOF
    chmod 600 "$envf"
    state_set "$instance" CENTRAL_ENABLED 1
    state_set "$instance" CENTRAL_SOURCE_ID "$source_id"
    if [[ "$(state_get "$instance" MANAGED 2>/dev/null || echo 0)" == 1 ]]; then
        tmp="$(mktemp)"
        generate_ocserv_config "$instance" "$tmp"
        transactional_replace_config "$instance" "$tmp"
        rm -f "$tmp"
    else
        central_patch_imported_config "$instance" enable "$CENTRAL_LIB_DIR/hook-$instance.sh" || {
            state_set "$instance" CENTRAL_ENABLED 0; state_set "$instance" CENTRAL_SOURCE_ID ""; return 1;
        }
    fi
    svc="$(central_agent_service "$instance")"
    systemctl enable --now "$svc"
    if curl -fsS -m "${API_TIMEOUT:-5}" -H "X-API-Token: $API_TOKEN" "$API_URL/health" | jq . >/dev/null 2>&1; then
        print_ok "Central attached: $instance -> source $source_id"
    else
        print_warn "Central adapter is installed for $instance, but API health check failed. Check URL/token/network."
    fi
    audit "central-attach instance=$instance source=$source_id api=$API_URL"
}

configure_central_for_instance() {
    # Backward-compatible internal alias. All user-facing management is now in
    # the Central console's multi-instance menu.
    central_attach_instance_from_profile "$1" 1
}

central_detach_instance() {
    local instance="$1" quiet="${2:-0}" envf svc api token source_id tmp
    envf="$(central_env_file "$instance")"
    api="" token="" source_id="$(state_get "$instance" CENTRAL_SOURCE_ID 2>/dev/null || true)"
    if [[ -f "$envf" ]]; then
        # shellcheck disable=SC1090
        . "$envf"
        api="${API_URL:-}"; token="${API_TOKEN:-}"; source_id="${SOURCE_ID:-${source_id:-$(central_default_node_id "$instance")}}"
    fi
    # Tell v20 Master to remove only this authority source. Failure is non-fatal:
    # the local hook must still be removable even when the Master is offline.
    if [[ -n "$api" && -n "$token" && -n "$source_id" ]]; then
        curl -fsS -m "${API_TIMEOUT:-5}" -X POST -H 'Content-Type: application/json' -H "X-API-Token: $token" \
            -d "$(jq -n --arg source_id "$source_id" '{source_id:$source_id}')" "$api/remove-source" >/dev/null 2>&1 || true
    fi
    svc="$(central_agent_service "$instance")"
    systemctl disable --now "$svc" >/dev/null 2>&1 || true
    state_set "$instance" CENTRAL_ENABLED 0
    state_set "$instance" CENTRAL_SOURCE_ID ""
    if [[ "$(state_get "$instance" MANAGED 2>/dev/null || echo 0)" == 1 ]]; then
        tmp="$(mktemp)"
        if generate_ocserv_config "$instance" "$tmp" && transactional_replace_config "$instance" "$tmp"; then :; else
            rm -f "$tmp"; return 1
        fi
        rm -f "$tmp"
    else
        central_patch_imported_config "$instance" disable || return 1
    fi
    rm -f "$envf" "$CENTRAL_LIB_DIR/hook-$instance.sh"
    audit "central-detach instance=$instance source=$source_id"
    [[ "$quiet" == 1 ]] || print_ok "Central detached from $instance."
}

disable_central_for_instance() { central_detach_instance "$1" 0; }

central_instances_status() {
    local i enabled svc source passwd sock any=0
    printf '%-20s %-10s %-30s %-28s %-s\n' "INSTANCE" "CENTRAL" "SOURCE-ID" "OCPASSWD" "AGENT"
    while read -r i; do
        [[ -n "$i" ]] || continue; any=1
        enabled="$(state_get "$i" CENTRAL_ENABLED 2>/dev/null || echo 0)"
        source="$(state_get "$i" CENTRAL_SOURCE_ID 2>/dev/null || true)"; source="${source:-$(central_default_node_id "$i")}"
        passwd="$(instance_passwd "$i" 2>/dev/null || echo '?')"
        svc="$(systemctl is-active "$(central_agent_service "$i")" 2>/dev/null || echo inactive)"
        [[ "$enabled" == 1 ]] || svc="disabled"
        printf '%-20s %-10s %-30s %-28s %-s\n' "$i" "$enabled" "$source" "$passwd" "$svc"
    done < <(list_instances | sort -u)
    (( any == 1 )) || echo "No ocserv instances found."
    if [[ -f "$CENTRAL_PROFILE" ]]; then
        local token_preview
        central_profile_load
        token_preview="${API_TOKEN:0:8}...${API_TOKEN: -4}"
        echo
        echo "Shared API URL: $API_URL"
        echo "Shared API token: $token_preview (masked)"
        echo "Live check interval: ${INTERVAL:-30} seconds"
        echo "API timeout: ${API_TIMEOUT:-5} seconds"
        echo "Failure policy: ${FAIL_MODE:-closed}"
        echo "Auto-attach new instances: ${AUTO_ATTACH:-0}"
    fi
}

central_force_sync_instance() {
    local instance="$1" svc
    svc="$(central_agent_service "$instance")"
    [[ "$(state_get "$instance" CENTRAL_ENABLED 2>/dev/null || echo 0)" == 1 ]] || { print_warn "$instance is not attached."; return 1; }
    systemctl restart "$svc"
    sleep 1
    journalctl -u "$svc" -n 12 --no-pager || true
}

migrate_central_multi_instance_v20_once() {
    local marker="$CENTRAL_INTEGRATION_DIR/.v20-migrated" i envf node passwd changed=0
    [[ -f "$marker" ]] && return 0
    # Only do work when an existing v2.5-style attachment is present.
    local any=0
    while read -r i; do
        [[ -n "$i" ]] || continue
        [[ "$(state_get "$i" CENTRAL_ENABLED 2>/dev/null || echo 0)" == 1 ]] && { any=1; break; }
    done < <(list_instances | sort -u)
    if (( any == 0 )); then
        : > "$marker"; chmod 600 "$marker"; return 0
    fi
    print_info "Migrating existing Central attachments to native v20 source synchronization (no ocserv reconfigure)."
    write_central_adapter_files
    while read -r i; do
        [[ -n "$i" ]] || continue
        [[ "$(state_get "$i" CENTRAL_ENABLED 2>/dev/null || echo 0)" == 1 ]] || continue
        envf="$(central_env_file "$i")"
        [[ -f "$envf" ]] || continue
        node="$(sed -n 's/^NODE_ID=//p' "$envf" | tail -n1 | tr -d '"')"; node="${node:-$(central_default_node_id "$i")}"
        passwd="$(instance_passwd "$i")"
        grep -q '^SOURCE_ID=' "$envf" || { echo "SOURCE_ID=\"$node\"" >> "$envf"; changed=1; }
        grep -q '^OCPASSWD_PATH=' "$envf" || { echo "OCPASSWD_PATH=\"$passwd\"" >> "$envf"; changed=1; }
        chmod 600 "$envf"
        state_set "$i" CENTRAL_SOURCE_ID "$node"
        systemctl restart "$(central_agent_service "$i")" >/dev/null 2>&1 || true
    done < <(list_instances | sort -u)
    : > "$marker"; chmod 600 "$marker"
    audit "central-v20-migration changed=$changed"
    print_ok "Existing Central attachments migrated to v20 source-aware agents."
}

central_instances_menu() {
    local choice instance i auto
    while true; do
        echo; echo "==== Central - Local ocserv instances (multi-instance) ===="
        echo "Every attached instance has its own occtl socket, Node ID, source ID and ocpasswd authority."
        echo "The Master receives user/group snapshots from each instance; a single Master-side OCPASSWD_PATH is no longer required for these attached sources."
        echo "1) List instances / attachment status"
        echo "2) Configure shared Central API/agent profile (URL/token/interval/timeout/fail-mode)"
        echo "3) Attach one instance"
        echo "4) Attach ALL discovered instances"
        echo "5) Detach one instance"
        echo "6) Detach ALL instances"
        echo "7) Force user/group + session sync for one instance"
        echo "8) Agent logs for one instance"
        echo "9) Toggle auto-attach for newly created instances"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) central_instances_status; pause;;
            2) central_profile_configure; pause;;
            3) instance="$(choose_instance)" && central_attach_instance_from_profile "$instance" 1; pause;;
            4)
                [[ -f "$CENTRAL_PROFILE" ]] || central_profile_configure
                while read -r i; do [[ -n "$i" ]] && central_attach_instance_from_profile "$i" 0 || true; done < <(list_instances | sort -u)
                pause;;
            5) instance="$(choose_instance)" && central_detach_instance "$instance" 0; pause;;
            6)
                ask_yes_no "Detach Central from ALL local ocserv instances?" "n" || continue
                while read -r i; do [[ -n "$i" ]] && [[ "$(state_get "$i" CENTRAL_ENABLED 2>/dev/null || echo 0)" == 1 ]] && central_detach_instance "$i" 1 || true; done < <(list_instances | sort -u)
                print_ok "All local instances detached."; pause;;
            7) instance="$(choose_instance)" && central_force_sync_instance "$instance"; pause;;
            8) instance="$(choose_instance)" && journalctl -u "$(central_agent_service "$instance")" -n 100 --no-pager; pause;;
            9)
                [[ -f "$CENTRAL_PROFILE" ]] || central_profile_configure
                central_profile_load
                if [[ "${AUTO_ATTACH:-0}" == 1 ]]; then auto=0; else auto=1; fi
                sed -i -E "s/^AUTO_ATTACH=.*/AUTO_ATTACH=\"$auto\"/" "$CENTRAL_PROFILE"
                print_ok "Auto-attach new instances: $auto"; pause;;
            0) return;;
            *) print_warn "Invalid selection.";;
        esac
    done
}

extract_embedded_central_manager() {
    local destination="$1"
    mkdir -p "$(dirname "$destination")"
    cat > "$destination" <<'__OCSERV_MANAGER_EMBEDDED_CENTRAL_V20_7F3A1D__'
#!/usr/bin/env bash
# ocserv-central-manager v20.4.4
# Native multi-instance source synchronization: each ocserv instance can publish its own ocpasswd authority and occtl session stream.
# Adds safe in-place program update for Manager, Master API, Node Agent, hooks, and cleanup code without reconfigure.
# Keeps v18 prune controls, v17 threshold export, v16 real ocpasswd prune/group export, v15 extra-traffic decrease/history, v14 reset recovery, v13 authoritative group refresh, v12 cleanup+VACUUM, v10 exhausted tools, and v8 unlimited groups.
# ocserv-central-manager.sh
# Central concurrent-session and quota controller for multiple ocserv nodes.
# Target OS: Ubuntu/Debian (including Ubuntu 24.04 and newer supported releases)
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

PROGRAM_VERSION="v20.4.4"
API_VERSION="2.4"
UPDATE_BACKUP_ROOT="/root/ocserv-central-update-backups"
MASTER_VERSION_FILE="/etc/ocserv-central/installed-version"
NODE_VERSION_FILE="/etc/ocserv-central-node/installed-version"

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

# Never let terminal-clearing break the Central console. Minimal/cloud images may
# not ship `clear`, and TERM may be unset/unsupported.
safe_clear() {
    if [[ -t 1 ]] && [[ -n "${TERM:-}" ]] && [[ "${TERM:-}" != "dumb" ]] && command -v clear >/dev/null 2>&1; then
        clear 2>/dev/null || true
    fi
}

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
REMOVE_MISSING_USERS = os.getenv("REMOVE_MISSING_USERS", "0") == "1"
EXHAUSTED_LOG_DEFAULT = os.getenv("EXHAUSTED_LOG_PATH", "/var/lib/ocserv-central/quota_exhausted_users.jsonl")
GIB = 1024 * 1024 * 1024


def human_bytes(value: int | None) -> str | None:
    """Format byte counters with IEC units while preserving exact raw byte fields."""
    if value is None:
        return None
    n = max(0, int(value))
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    x = float(n)
    unit = units[0]
    for unit in units:
        if x < 1024.0 or unit == units[-1]:
            break
        x /= 1024.0
    if unit == "B":
        return f"{int(x)} {unit}"
    if x >= 100:
        return f"{x:.1f} {unit}"
    if x >= 10:
        return f"{x:.2f} {unit}"
    return f"{x:.3f} {unit}"


app = FastAPI(title="ocserv-central", version="2.4")

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

        # v20: authoritative users/groups can come from multiple ocserv instances.
        # source_id normally equals hostname:instance and is independent of the
        # Master filesystem, so remote nodes and separate ocpasswd databases work.
        con.execute("""
        CREATE TABLE IF NOT EXISTS authority_sources (
            source_id TEXT PRIMARY KEY,
            node_id TEXT,
            last_seen INTEGER NOT NULL,
            users_count INTEGER NOT NULL DEFAULT 0
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS authority_users (
            source_id TEXT NOT NULL,
            username TEXT NOT NULL,
            groupname TEXT,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (source_id, username)
        )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_authority_users_username ON authority_users(username)")
        if not column_exists(con, "sessions", "source_id"):
            con.execute("ALTER TABLE sessions ADD COLUMN source_id TEXT")

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

def delete_user_rows_everywhere(con, usernames: list[str]):
    """Delete all central-DB rows tied to usernames. The users table is deleted last."""
    usernames = sorted({str(u) for u in usernames if str(u)})
    if not usernames:
        return {}

    table_names = [
        row["name"]
        for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    ]
    totals: dict[str, int] = {}

    def delete_from_table(table: str):
        safe_table = table.replace('"', '""')
        cols = [row["name"] for row in con.execute(f'PRAGMA table_info("{safe_table}")').fetchall()]
        if "username" not in cols:
            return
        deleted = 0
        for i in range(0, len(usernames), 500):
            chunk = usernames[i:i + 500]
            placeholders = ",".join("?" for _ in chunk)
            cur = con.execute(
                f'DELETE FROM "{safe_table}" WHERE username IN ({placeholders})',
                chunk,
            )
            deleted += max(0, int(cur.rowcount or 0))
        totals[table] = deleted

    for table in table_names:
        if table != "users":
            delete_from_table(table)
    if "users" in table_names:
        delete_from_table("users")
    return totals


def sync_ocpasswd_to_db():
    """Synchronize the optional Master-local fallback ocpasswd.

    v20 authority_sources are additive and take precedence for their own
    sessions. Automatic prune considers the UNION of all published sources plus
    this local fallback, so one Master-side ocpasswd can no longer delete users
    that legitimately belong to another instance/node.
    """
    parsed_users = parse_ocpasswd()
    t = now()
    removed_usernames: list[str] = []
    removed_table_rows: dict[str, int] = {}
    prune_skipped_reason = None

    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        source_rows=con.execute("SELECT DISTINCT username FROM authority_users").fetchall()
        source_usernames={r["username"] for r in source_rows}
        source_count=int(con.execute("SELECT COUNT(*) AS c FROM authority_sources").fetchone()["c"] or 0)
        for u in parsed_users:
            if u["username"] in source_usernames:
                con.execute("""
                    INSERT OR IGNORE INTO users(username, groupname, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at)
                    VALUES (?, ?, 0, 0, ?, 0, 0)
                """,(u["username"],u["groupname"],t))
            else:
                con.execute("""
                    INSERT INTO users(username, groupname, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at)
                    VALUES (?, ?, 0, 0, ?, 0, 0)
                    ON CONFLICT(username) DO UPDATE SET groupname=excluded.groupname,updated_at=excluded.updated_at
                """,(u["username"],u["groupname"],t))

        if REMOVE_MISSING_USERS:
            local_usernames={u["username"] for u in parsed_users}
            if source_count > 0:
                authoritative=source_usernames | local_usernames
                if not authoritative:
                    prune_skipped_reason="all authority sources currently contain zero users; automatic prune skipped for safety"
                else:
                    db_usernames=[row["username"] for row in con.execute("SELECT username FROM users ORDER BY username").fetchall()]
                    removed_usernames=[u for u in db_usernames if u not in authoritative]
                    removed_table_rows=delete_user_rows_everywhere(con,removed_usernames)
            else:
                # Legacy v19 behavior when no v20 source has registered yet.
                if not os.path.exists(OCPASSWD_PATH):
                    prune_skipped_reason="ocpasswd file does not exist and no authority sources are registered"
                elif not parsed_users:
                    prune_skipped_reason="ocpasswd has zero parsed users; automatic prune skipped for safety"
                else:
                    db_usernames=[row["username"] for row in con.execute("SELECT username FROM users ORDER BY username").fetchall()]
                    removed_usernames=[u for u in db_usernames if u not in local_usernames]
                    removed_table_rows=delete_user_rows_everywhere(con,removed_usernames)

    for username in removed_usernames:
        remove_from_exhausted_log(username)

    return {
        "ok": True,
        "ocpasswd_path": OCPASSWD_PATH,
        "users_found": len(parsed_users),
        "authority_sources": source_count,
        "authority_users": len(source_usernames),
        "remove_missing_users": REMOVE_MISSING_USERS,
        "removed_users_count": len(removed_usernames),
        "removed_usernames": removed_usernames[:100],
        "removed_usernames_truncated": len(removed_usernames) > 100,
        "removed_table_rows": removed_table_rows,
        "prune_skipped_reason": prune_skipped_reason,
    }

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

def authoritative_group_for_user(username: str, fallback_group: str | None = None, source_id: str | None = None) -> str | None:
    """Return the source-specific authoritative group when v20 source sync is available.

    For shared ocpasswd deployments, the same username/group may appear in many
    sources and remains one global Central account.  If separate sources reuse a
    username with different groups, the source_id resolves the correct group for
    that session and the conflict is surfaced by /sync-source.
    """
    if source_id:
        try:
            with db() as con:
                row = con.execute(
                    "SELECT groupname FROM authority_users WHERE source_id=? AND username=?",
                    (source_id, username),
                ).fetchone()
            if row and row["groupname"]:
                return row["groupname"]
        except Exception:
            pass
    db_group = get_user_group_from_db(username)
    if db_group:
        return db_group
    if fallback_group:
        return pick_primary_group(fallback_group)
    return None

def authority_conflicts(con=None):
    own = con is None
    if own: con = db()
    try:
        rows = con.execute("""
            SELECT username, COUNT(DISTINCT COALESCE(groupname,'')) AS groups_count,
                   GROUP_CONCAT(DISTINCT COALESCE(groupname,'')) AS groups
            FROM authority_users
            GROUP BY username
            HAVING COUNT(DISTINCT COALESCE(groupname,'')) > 1
            ORDER BY username
        """).fetchall()
        return [{"username":r["username"],"groups":r["groups"]} for r in rows]
    finally:
        if own: con.close()

def reconcile_authority_users_to_central():
    """Merge all published authority sources into the global users table.

    Identical usernames across sources are intentionally one global account,
    preserving the original global-session/quota semantics. Source-specific
    group lookup still prevents stale/wrong group enforcement on each session.
    """
    t=now()
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        rows=con.execute("""
            SELECT username, MIN(groupname) AS groupname
            FROM authority_users GROUP BY username
        """).fetchall()
        for r in rows:
            con.execute("""
                INSERT INTO users(username, groupname, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at)
                VALUES (?, ?, 0, 0, ?, 0, 0)
                ON CONFLICT(username) DO UPDATE SET updated_at=excluded.updated_at
            """,(r["username"],r["groupname"],t))
            # Update the stored global group only when all sources agree.
            gs=con.execute("SELECT DISTINCT groupname FROM authority_users WHERE username=? AND groupname IS NOT NULL AND groupname!=''",(r["username"],)).fetchall()
            if len(gs)==1:
                con.execute("UPDATE users SET groupname=?, updated_at=? WHERE username=?",(gs[0]["groupname"],t,r["username"]))
        if REMOVE_MISSING_USERS and rows:
            authoritative={r["username"] for r in rows}
            # Preserve any users still present in the legacy/local fallback ocpasswd.
            authoritative.update(u["username"] for u in parse_ocpasswd())
            db_users=[r["username"] for r in con.execute("SELECT username FROM users").fetchall()]
            missing=[u for u in db_users if u not in authoritative]
            delete_user_rows_everywhere(con,missing)
    return {"users":len(rows),"conflicts":authority_conflicts()}

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
    source_id: str | None = None
    ocserv_id: str
    username: str
    groupname: str | None = None
    ip_real: str | None = None
    ip_remote: str | None = None

class DisconnectReq(BaseModel):
    node_id: str
    source_id: str | None = None
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
    source_id: str | None = None
    sessions: list[HeartbeatSession]

class AuthorityUser(BaseModel):
    username: str
    groupname: str | None = None

class SourceSyncReq(BaseModel):
    source_id: str
    node_id: str
    users: list[AuthorityUser]
    complete: bool = True

class SourceRemoveReq(BaseModel):
    source_id: str

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
    return {"ok": True, "version": "2.4", "time": now(), "multi_instance_sources": True}

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

@app.post("/sync-source")
def sync_source(req: SourceSyncReq, request: Request, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    source_id=req.source_id.strip()
    if not source_id:
        raise HTTPException(status_code=400,detail="empty source_id")
    t=now()
    clean={}
    for u in req.users:
        name=u.username.strip()
        if name:
            clean[name]=pick_primary_group(u.groupname) if u.groupname else "group1"
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        con.execute("""INSERT INTO authority_sources(source_id,node_id,last_seen,users_count) VALUES(?,?,?,?)
            ON CONFLICT(source_id) DO UPDATE SET node_id=excluded.node_id,last_seen=excluded.last_seen,users_count=excluded.users_count""",
            (source_id,req.node_id,t,len(clean)))
        if req.complete:
            con.execute("DELETE FROM authority_users WHERE source_id=?",(source_id,))
        con.executemany("INSERT OR REPLACE INTO authority_users(source_id,username,groupname,updated_at) VALUES(?,?,?,?)",
            [(source_id,u,g,t) for u,g in clean.items()])
    merged=reconcile_authority_users_to_central()
    update_node(req.node_id,request,0)
    return {"ok":True,"source_id":source_id,"users_found":len(clean),"conflicts":merged.get("conflicts",[])}

@app.post("/remove-source")
def remove_source(req: SourceRemoveReq, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        con.execute("DELETE FROM authority_users WHERE source_id=?",(req.source_id,))
        con.execute("DELETE FROM authority_sources WHERE source_id=?",(req.source_id,))
    merged=reconcile_authority_users_to_central()
    return {"ok":True,"source_id":req.source_id,"remaining_users":merged.get("users",0),"conflicts":merged.get("conflicts",[])}

@app.get("/sources")
def list_sources(x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    with db() as con:
        sources=[dict(r) for r in con.execute("SELECT * FROM authority_sources ORDER BY source_id").fetchall()]
    return {"sources":sources,"conflicts":authority_conflicts()}

@app.post("/connect")
def connect(req: ConnectReq, request: Request, x_api_token: str | None = Header(default=None)):
    auth(x_api_token)
    t = now()
    sync_ocpasswd_to_db()
    update_node(req.node_id, request, 0)

    # v13: ocpasswd/central DB is authoritative for group changes.
    # Do not trust a stale GROUPNAME coming from ocserv/session state.
    req.groupname = authoritative_group_for_user(req.username, req.groupname, req.source_id)

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
             started_at, last_seen, last_total_bytes, active, source_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?)
            """,
            (req.node_id, req.ocserv_id, req.username, req.groupname, req.ip_real, req.ip_remote, t, t, req.source_id)
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
        effective_group = authoritative_group_for_user(req.username, row["groupname"], req.source_id)
        _, quota_bytes = effective_limits(req.username, effective_group)
        if quota_bytes > 0 and row["used_bytes"] >= quota_bytes:
            log_quota_exhausted(req.username, effective_group, row["used_bytes"], quota_bytes, "disconnect quota exceeded")

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
            s.groupname = authoritative_group_for_user(s.username, s.groupname, req.source_id)

            con.execute(
                """
                INSERT OR IGNORE INTO users(username, groupname, used_bytes, disabled, updated_at, quota_extra_bytes, expires_at)
                VALUES (?, ?, 0, 0, ?, 0, 0)
                """,
                (s.username, s.groupname, t)
            )
            if s.groupname:
                # Keep the global users.groupname stable when multiple authority
                # sources intentionally use the same username with different groups.
                gs=con.execute("SELECT DISTINCT groupname FROM authority_users WHERE username=? AND groupname IS NOT NULL AND groupname!=''",(s.username,)).fetchall()
                if len(gs) <= 1:
                    con.execute("UPDATE users SET groupname=?, updated_at=? WHERE username=?", (s.groupname, t, s.username))

            old = con.execute("SELECT last_total_bytes FROM sessions WHERE node_id=? AND ocserv_id=?", (req.node_id, s.ocserv_id)).fetchone()
            old_total = old["last_total_bytes"] if old else 0
            new_total = max(0, int(s.total_bytes))
            delta = max(0, new_total - old_total)

            if old:
                con.execute(
                    """
                    UPDATE sessions
                    SET last_seen=?, last_total_bytes=?, active=1, username=?, groupname=?, source_id=?
                    WHERE node_id=? AND ocserv_id=?
                    """,
                    (t, new_total, s.username, s.groupname, req.source_id, req.node_id, s.ocserv_id)
                )
            else:
                con.execute(
                    """
                    INSERT INTO sessions
                    (node_id, ocserv_id, username, groupname, started_at, last_seen, last_total_bytes, active, source_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (req.node_id, s.ocserv_id, s.username, s.groupname, t, t, new_total, req.source_id)
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
        sessions = con.execute("SELECT node_id, source_id, ocserv_id, groupname, ip_real, ip_remote, started_at, last_seen, active FROM sessions WHERE username=? AND active=1", (username,)).fetchall()

    max_sessions, quota_bytes = effective_limits(username, user["groupname"] if user else None)
    used = max(0, int(user["used_bytes"] or 0)) if user else 0
    quota_unlimited = quota_bytes <= 0
    remaining_bytes = None if quota_unlimited else max(0, int(quota_bytes) - used)
    exhausted = False if quota_unlimited else used >= int(quota_bytes)

    # Backward compatibility:
    # - remaining_bytes used to be 0 for unlimited quota. That was ambiguous.
    # - v11 returns null for unlimited and also adds remaining_bytes_compat=0.
    session_items = []
    for row in sessions:
        item = dict(row)
        real_ip = str(item.get("ip_real") or "")
        item["client_ip_reported_by_ocserv"] = item.get("ip_real")
        item["vpn_assigned_ip"] = item.get("ip_remote")
        item["ip_real_is_loopback"] = real_ip in ("127.0.0.1", "::1") or real_ip.startswith("127.")
        if item["ip_real_is_loopback"]:
            item["ip_real_note"] = "ocserv sees a local proxy/forward as the peer; this is not the original Internet client IP"
        session_items.append(item)

    return {
        "user": dict(user) if user else None,
        "limits": {
            "max_sessions": max_sessions,
            "quota_human": None if quota_unlimited else human_bytes(int(quota_bytes)),
            "used_human": human_bytes(used),
            "remaining_human": None if quota_unlimited else human_bytes(remaining_bytes),
            "quota_bytes": int(quota_bytes),
            "used_bytes": used,
            "remaining_bytes": remaining_bytes,
            "remaining_bytes_compat": 0 if remaining_bytes is None else remaining_bytes,
            "quota_gib": (round(int(quota_bytes) / GIB, 6) if quota_bytes > 0 else None),
            "used_gib": round(used / GIB, 6),
            "remaining_gib": (round(remaining_bytes / GIB, 6) if remaining_bytes is not None else None),
            "quota_unlimited": quota_unlimited,
            "exhausted": exhausted,
        },
        "expired": account_is_expired(username),
        "current_group_authoritative": user["groupname"] if user else None,
        "active_sessions": session_items
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
        rows = con.execute("SELECT node_id, source_id, ocserv_id, username, groupname, ip_real, ip_remote, started_at, last_seen, last_total_bytes, active FROM sessions WHERE active=1 ORDER BY username, node_id").fetchall()
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
            f"Add {req.gb} GB extra traffic",
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
            f"Decrease {req.gb} GB extra traffic",
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
            con, "all", "all-users", None, "bulk-add", f"Add {req.gb} GB to all users"
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
        "added_gib_per_user": round(add_bytes / GIB, 6),
        "before_total_extra_bytes": before_total,
        "after_total_extra_bytes": after_total,
        "before_total_extra_gib": round(before_total / GIB, 6),
        "after_total_extra_gib": round(after_total / GIB, 6),
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
            f"Decrease {req.gb} GB from all users",
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
        "before_total_extra_gib": round(before_total / GIB, 6),
        "after_total_extra_gib": round(after_total / GIB, 6),
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
            con, "all", "all-users", None, "bulk-set", f"Set all users extra traffic to {req.gb} GB"
        )
        con.execute("UPDATE users SET quota_extra_bytes = ?, updated_at=?", (set_bytes, t))
        count = int(con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"])

    rebuild_result = rebuild_exhausted_log_from_db() if req.clear_exhausted else None
    return {
        "ok": True,
        "users_updated": count,
        "extra_traffic_gb": float(req.gb),
        "extra_traffic_bytes": set_bytes,
        "extra_traffic_gib": round(set_bytes / GIB, 6),
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
        "quota_extra_gib": 0.0,
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
        "used_gib": 0.0,
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

extract_groups_from_all_authorities() {
    local db="$DB_DIR/central.db"
    if [[ -f "$db" ]]; then
        sqlite3 "$db" "SELECT DISTINCT groupname FROM authority_users WHERE groupname IS NOT NULL AND groupname != '' UNION SELECT DISTINCT groupname FROM users WHERE groupname IS NOT NULL AND groupname != '' ORDER BY 1;" 2>/dev/null || true
    fi
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

    if [[ "$ocpasswd" == "__central_sources__" ]]; then
        mapfile -t groups < <(extract_groups_from_all_authorities)
        if [[ "${#groups[@]}" -eq 0 ]]; then
            print_warn "No groups have been synchronized by authority sources yet. Attach/start Node instances first, then retry."
            return 0
        fi
    else
        if [[ ! -f "$ocpasswd" ]]; then
            print_warn "ocpasswd not found: $ocpasswd"
            return 0
        fi
        mapfile -t groups < <(extract_groups_from_ocpasswd "$ocpasswd")
        if [[ "${#groups[@]}" -eq 0 ]]; then
            print_warn "No groups found in $ocpasswd"
            return 0
        fi
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
    local remove_missing="$4"

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
Environment=REMOVE_MISSING_USERS=$remove_missing
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
    ocpasswd_path="$(ask_value "Optional local fallback ocpasswd path on Master (multi-instance Nodes sync their own databases)" "$ocpasswd_default")"

    local ttl
    ttl="$(ask_number "Session TTL in seconds, used to expire dead sessions" "120")"

    local existing_remove legacy_disable remove_default remove_missing="0"
    existing_remove="$(systemctl show ocserv-central -p Environment --value 2>/dev/null | tr ' ' '\n' | sed -n 's/^REMOVE_MISSING_USERS=//p' | tail -n1 || true)"
    legacy_disable="$(systemctl show ocserv-central -p Environment --value 2>/dev/null | tr ' ' '\n' | sed -n 's/^DISABLE_MISSING_USERS=//p' | tail -n1 || true)"
    remove_default="n"
    if [[ "$existing_remove" == "1" || "$legacy_disable" == "1" ]]; then
        remove_default="y"
    fi

    echo
    print_warn "If enabled, a username that no longer exists in ocpasswd is REMOVED from central DB, not disabled."
    print_warn "Its central users/session/usage_log/recovery rows are deleted. A safety DB backup is made during reconfigure before the immediate prune."
    if ask_yes_no "Remove users from central DB when they are removed from ocpasswd? Safer answer: no" "$remove_default"; then
        remove_missing="1"
    fi

    ensure_limits_file
    configure_features
    configure_groups_from_ocpasswd "$ocpasswd_path"

    # v16: when this policy is enabled during an update/reconfigure, clean up users that
    # were deleted from ocpasswd in the past but are still present in central.db.
    if [[ "$remove_missing" == "1" && -f "$DB_DIR/central.db" && -f "$ocpasswd_path" ]]; then
        echo
        print_info "v16 immediate ocpasswd prune: checking old central DB users missing from ocpasswd..."
        if ask_yes_no "Create a safety DB backup before this immediate prune?" "y"; then safety_backup_db_before_cleanup; fi
        db_user_cleanup_python "stats" 90 0 0 "$ocpasswd_path" || true
        db_user_cleanup_python "delete_missing" 90 0 1 "$ocpasswd_path" || true
    fi

    write_master_app

    if [[ ! -d "$APP_DIR/venv" ]]; then
        python3 -m venv "$APP_DIR/venv"
    fi

    "$APP_DIR/venv/bin/pip" install --upgrade pip
    "$APP_DIR/venv/bin/pip" install fastapi uvicorn pydantic

    write_master_service "$token" "$ocpasswd_path" "$ttl" "$remove_missing"

    systemctl daemon-reload
    systemctl enable ocserv-central
    systemctl restart ocserv-central

    sleep 1
    if [[ "$remove_missing" == "1" ]]; then
        print_info "Running final ocpasswd sync/prune with v16 API..."
        curl -sS -X POST -H "X-API-Token: $token" "http://127.0.0.1:8088/sync-ocpasswd" | jq . || true
        curl -sS -X POST -H "X-API-Token: $token" -H "Content-Type: application/json" -d '{}' "http://127.0.0.1:8088/quota-exhausted/rebuild" | jq . || true
    fi
    systemctl status ocserv-central --no-pager || true

    echo
    print_ok "Master installed."
    print_info "Default/local API URL: http://127.0.0.1:8088"
    print_info "Remote nodes may replace 127.0.0.1 with this Master server's reachable IP/hostname."
    print_info "API token: $token"
    print_warn "Keep this token safe. Use it on all nodes."
    if [[ -x /usr/local/sbin/ocserv-manager ]] && /usr/local/sbin/ocserv-manager --central-capability >/dev/null 2>&1; then
        /usr/local/sbin/ocserv-manager --central-sync-local-master-profile || \
            print_warn "Master is healthy, but one or more existing local attached instances could not be synchronized to the current API token/profile."
    fi
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

    logger(f"started legacy-node version=2.0 node_id={NODE_ID} interval={INTERVAL}")

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
        echo "$conf" > "$NODE_ETC/ocserv_conf_path"
        if ask_yes_no "Save a persistent copy of the original ocserv.conf for future Legacy Node uninstall/restore?" "y"; then
            cp -a "$conf" "$NODE_ETC/original_ocserv.conf"
            print_ok "Original ocserv.conf backup saved: $NODE_ETC/original_ocserv.conf"
        else
            print_warn "Original config backup skipped; Legacy Node uninstall will only remove the Central block instead of restoring this exact file."
        fi
    fi

    if ask_yes_no "Create a versioned ocserv.conf backup before applying the Legacy Node hook?" "y"; then
        cp -a "$conf" "$NODE_ETC/backup/ocserv.conf.$(date +%Y%m%d-%H%M%S)"
    fi

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
    api_url="$(ask_value "Central API URL" "http://127.0.0.1:8088")"
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
    local envline token ttl remove token_preview
    echo
    print_info "Master service:"
    systemctl status ocserv-central --no-pager || true
    envline="$(systemctl show ocserv-central -p Environment --value 2>/dev/null || true)"
    token="$(printf '%s\n' "$envline" | tr ' ' '\n' | sed -n 's/^API_TOKEN=//p' | tail -n1)"
    ttl="$(printf '%s\n' "$envline" | tr ' ' '\n' | sed -n 's/^SESSION_TTL=//p' | tail -n1)"
    remove="$(printf '%s\n' "$envline" | tr ' ' '\n' | sed -n 's/^REMOVE_MISSING_USERS=//p' | tail -n1)"
    token_preview="${token:0:8}...${token: -4}"
    echo
    print_info "Master API settings:"
    echo "Local API URL: http://127.0.0.1:8088"
    echo "Listener: 0.0.0.0:8088 (remote reachability still depends on host/network firewall)"
    [[ -n "$token" ]] && echo "API token: $token_preview (masked)"
    echo "Session TTL: ${ttl:-120} seconds"
    echo "Remove missing ocpasswd users: ${remove:-0}"
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

list_authority_sources() {
    master_curl "GET" "/sources"
}

show_user() {
    local u
    u="$(ask_value "Username" "")"
    [[ -z "$u" ]] && return 0
    master_curl "GET" "/user/$u"
}


export_group_usage_file() {
    need_root
    local group safe_group out token db limits rc
    db="$DB_DIR/central.db"
    limits="$MASTER_ETC/limits.json"

    if [[ ! -f "$db" ]]; then
        print_err "Database not found: $db"
        return 1
    fi
    ensure_limits_file

    echo
    list_group_limits || true
    echo
    group="$(ask_value "Group name to export, example group2 or *" "")"
    [[ -n "$group" ]] || return 0

    token="$(master_token_from_systemd)"
    if [[ -n "$token" ]] && systemctl is-active --quiet ocserv-central 2>/dev/null; then
        print_info "Syncing ocpasswd before export so current group membership is used..."
        curl -fsS -X POST -H "X-API-Token: $token" \
            "http://127.0.0.1:8088/sync-ocpasswd" >/dev/null || \
            print_warn "API sync failed; export will use the current central DB state."
    else
        print_warn "ocserv-central API is not active or token was not found; export will use current DB state."
    fi

    if [[ "$group" == "*" ]]; then
        safe_group="unlimited"
    else
        safe_group="$(printf '%s' "$group" | sed 's/[^A-Za-z0-9._-]/_/g')"
        [[ -n "$safe_group" ]] || safe_group="group"
    fi
    mkdir -p "$DB_DIR/exports"
    out="$(ask_value "Output TXT file" "$DB_DIR/exports/group-${safe_group}-usage-$(date +%Y%m%d-%H%M%S).txt")"
    mkdir -p "$(dirname "$out")"

    set +e
    python3 - "$db" "$limits" "$group" "$out" <<'PYEXPORTGROUP'
import json
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

DB_PATH, LIMITS_PATH, GROUP, OUT_PATH = sys.argv[1:5]
GIB = 1024 ** 3

try:
    limits = json.loads(Path(LIMITS_PATH).read_text(encoding="utf-8"))
except Exception as exc:
    print(f"ERROR: cannot read limits.json: {exc}", file=sys.stderr)
    sys.exit(2)

features = limits.get("features", {}) or {}
quota_enabled = bool(features.get("quota", True))
session_enabled = bool(features.get("session_limit", True))
expiry_enabled = bool(features.get("account_expiry", False))

def group_number(groupname):
    import re
    if not groupname:
        return 1
    g = str(groupname).strip().lower()
    if g in ("*", "unlimited", "unlimit", "nolimit", "no-limit", "no_limit", "all"):
        return 999999
    m = re.search(r"(\d+)", str(groupname))
    return int(m.group(1)) if m else 1

def fmt_gib(value):
    return f"{int(value or 0) / GIB:.6f}"

def fmt_time(ts):
    ts = int(ts or 0)
    if ts <= 0:
        return "none"
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")

con = sqlite3.connect(DB_PATH, timeout=30)
con.row_factory = sqlite3.Row
try:
    rows = con.execute(
        """
        SELECT username, groupname, used_bytes, quota_extra_bytes, expires_at, disabled, updated_at
        FROM users
        WHERE groupname=?
        ORDER BY username
        """,
        (GROUP,),
    ).fetchall()
finally:
    con.close()

if not rows:
    print(f"ERROR: no central DB users found in group: {GROUP}", file=sys.stderr)
    sys.exit(3)

group_cfg = (limits.get("groups", {}) or {}).get(GROUP, {}) or {}
user_cfgs = limits.get("users", {}) or {}
default_quota_gb = float(limits.get("default_quota_gb", 0) or 0)

records = []
for row in rows:
    username = row["username"]
    user_cfg = user_cfgs.get(username, {}) or {}

    max_sessions = group_number(GROUP) if session_enabled else 999999
    if session_enabled and "max_sessions" in group_cfg:
        group_ms = int(group_cfg["max_sessions"])
        max_sessions = 999999 if group_ms <= 0 else group_ms
    if session_enabled and "max_sessions" in user_cfg:
        user_ms = int(user_cfg["max_sessions"])
        if user_ms < 0:
            max_sessions = 999999
        elif user_ms > 0:
            max_sessions = user_ms

    quota_source = "quota_feature_disabled"
    base_quota_gb = 0.0
    if quota_enabled:
        if "quota_gb" in user_cfg:
            quota_source = "user_override"
            base_quota_gb = float(user_cfg.get("quota_gb", 0) or 0)
        elif "quota_gb" in group_cfg:
            quota_source = "group"
            base_quota_gb = float(group_cfg.get("quota_gb", 0) or 0)
        else:
            quota_source = "default"
            base_quota_gb = default_quota_gb

    base_quota_bytes = int(base_quota_gb * GIB) if quota_enabled and base_quota_gb > 0 else 0
    extra_bytes = int(row["quota_extra_bytes"] or 0)
    effective_quota_bytes = base_quota_bytes + extra_bytes if base_quota_bytes > 0 else 0
    used_bytes = int(row["used_bytes"] or 0)
    unlimited = effective_quota_bytes <= 0
    remaining_bytes = None if unlimited else max(0, effective_quota_bytes - used_bytes)
    exhausted = False if unlimited else used_bytes >= effective_quota_bytes
    expires_at = int(row["expires_at"] or 0)
    expired = bool(expiry_enabled and expires_at > 0 and expires_at <= int(time.time()))

    records.append({
        "username": username,
        "used_bytes": used_bytes,
        "used_gib": fmt_gib(used_bytes),
        "quota_source": quota_source,
        "base_quota_gib": f"{base_quota_gb:.6f}" if base_quota_bytes > 0 else "unlimited",
        "extra_bytes": extra_bytes,
        "extra_gib": fmt_gib(extra_bytes),
        "effective_quota_bytes": effective_quota_bytes,
        "effective_quota_gib": fmt_gib(effective_quota_bytes) if not unlimited else "unlimited",
        "remaining_bytes": remaining_bytes,
        "remaining_gib": fmt_gib(remaining_bytes) if remaining_bytes is not None else "unlimited",
        "quota_unlimited": unlimited,
        "exhausted": exhausted,
        "max_sessions": "unlimited" if max_sessions >= 999999 else str(max_sessions),
        "expires_at": fmt_time(expires_at),
        "expired": expired,
        "disabled": bool(row["disabled"]),
        "updated_at": fmt_time(row["updated_at"]),
    })

out = Path(OUT_PATH)
out.parent.mkdir(parents=True, exist_ok=True)
now_iso = datetime.now().astimezone().isoformat(timespec="seconds")
total_used = sum(r["used_bytes"] for r in records)
finite = [r for r in records if not r["quota_unlimited"]]
total_remaining = sum(int(r["remaining_bytes"] or 0) for r in finite)

with out.open("w", encoding="utf-8") as f:
    f.write("Ocserv Central Group Usage Export\n")
    f.write(f"Generated at: {now_iso}\n")
    f.write(f"Group: {GROUP}\n")
    f.write(f"Users: {len(records)}\n")
    f.write(f"Total used GiB: {total_used / GIB:.6f}\n")
    f.write(f"Finite quota users: {len(finite)}\n")
    f.write(f"Unlimited quota users: {sum(1 for r in records if r['quota_unlimited'])}\n")
    f.write(f"Exhausted users: {sum(1 for r in records if r['exhausted'])}\n")
    f.write(f"Disabled users: {sum(1 for r in records if r['disabled'])}\n")
    f.write(f"Expired users: {sum(1 for r in records if r['expired'])}\n")
    f.write(f"Total remaining GiB for finite users: {total_remaining / GIB:.6f}\n")
    f.write("\n")
    headers = [
        "USERNAME", "USED_GIB", "USED_BYTES", "QUOTA_SOURCE", "BASE_QUOTA_GIB",
        "EXTRA_GIB", "EXTRA_BYTES", "EFFECTIVE_QUOTA_GIB", "EFFECTIVE_QUOTA_BYTES",
        "REMAINING_GIB", "REMAINING_BYTES", "QUOTA_UNLIMITED", "EXHAUSTED",
        "MAX_SESSIONS", "EXPIRES_AT", "EXPIRED", "DISABLED", "UPDATED_AT",
    ]
    f.write("\t".join(headers) + "\n")
    for r in records:
        values = [
            r["username"], r["used_gib"], str(r["used_bytes"]), r["quota_source"], r["base_quota_gib"],
            r["extra_gib"], str(r["extra_bytes"]), r["effective_quota_gib"], str(r["effective_quota_bytes"]),
            r["remaining_gib"], "unlimited" if r["remaining_bytes"] is None else str(r["remaining_bytes"]),
            str(r["quota_unlimited"]).lower(), str(r["exhausted"]).lower(), r["max_sessions"],
            r["expires_at"], str(r["expired"]).lower(), str(r["disabled"]).lower(), r["updated_at"],
        ]
        f.write("\t".join(values) + "\n")

print(f"Exported users: {len(records)}")
print(f"Output file: {out}")
PYEXPORTGROUP
    rc=$?
    set -e

    if (( rc != 0 )); then
        print_err "Group usage export failed."
        return "$rc"
    fi

    print_ok "Group usage export completed."
    ls -lh "$out" 2>/dev/null || true
    print_info "Read it with: cat '$out'"
}


export_usage_threshold_file() {
    need_root
    local threshold safe_threshold out token db limits rc
    db="$DB_DIR/central.db"
    limits="$MASTER_ETC/limits.json"

    if [[ ! -f "$db" ]]; then
        print_err "Database not found: $db"
        return 1
    fi
    ensure_limits_file

    threshold="$(ask_number "Minimum used traffic in GiB, users at or above this value will be exported" "50")"

    token="$(master_token_from_systemd)"
    if [[ -n "$token" ]] && systemctl is-active --quiet ocserv-central 2>/dev/null; then
        print_info "Syncing ocpasswd before export so current users and groups are used..."
        curl -fsS -X POST -H "X-API-Token: $token" \
            "http://127.0.0.1:8088/sync-ocpasswd" >/dev/null || \
            print_warn "API sync failed; export will use the current central DB state."
    else
        print_warn "ocserv-central API is not active or token was not found; export will use current DB state."
    fi

    safe_threshold="$(printf '%s' "$threshold" | sed 's/[^0-9.]/_/g; s/[.]/_/g')"
    [[ -n "$safe_threshold" ]] || safe_threshold="threshold"

    mkdir -p "$DB_DIR/exports"
    out="$(ask_value "Output TXT file" "$DB_DIR/exports/usage-at-least-${safe_threshold}GiB-$(date +%Y%m%d-%H%M%S).txt")"
    mkdir -p "$(dirname "$out")"

    set +e
    python3 - "$db" "$limits" "$threshold" "$out" <<'PYEXPORTTHRESHOLD'
import json
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

DB_PATH, LIMITS_PATH, THRESHOLD_GIB_RAW, OUT_PATH = sys.argv[1:5]
GIB = 1024 ** 3

try:
    threshold_gib = float(THRESHOLD_GIB_RAW)
except ValueError:
    print(f"ERROR: invalid threshold: {THRESHOLD_GIB_RAW}", file=sys.stderr)
    sys.exit(2)

if threshold_gib < 0:
    print("ERROR: threshold cannot be negative", file=sys.stderr)
    sys.exit(2)

threshold_bytes = int(threshold_gib * GIB)

try:
    limits = json.loads(Path(LIMITS_PATH).read_text(encoding="utf-8"))
except Exception as exc:
    print(f"ERROR: cannot read limits.json: {exc}", file=sys.stderr)
    sys.exit(2)

features = limits.get("features", {}) or {}
quota_enabled = bool(features.get("quota", True))
session_enabled = bool(features.get("session_limit", True))
expiry_enabled = bool(features.get("account_expiry", False))
group_cfgs = limits.get("groups", {}) or {}
user_cfgs = limits.get("users", {}) or {}
default_quota_gb = float(limits.get("default_quota_gb", 0) or 0)

def group_number(groupname):
    import re
    if not groupname:
        return 1
    g = str(groupname).strip().lower()
    if g in ("*", "unlimited", "unlimit", "nolimit", "no-limit", "no_limit", "all"):
        return 999999
    m = re.search(r"(\d+)", str(groupname))
    return int(m.group(1)) if m else 1

def fmt_gib(value):
    return f"{int(value or 0) / GIB:.6f}"

def fmt_time(ts):
    ts = int(ts or 0)
    if ts <= 0:
        return "none"
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")

con = sqlite3.connect(DB_PATH, timeout=30)
con.row_factory = sqlite3.Row
try:
    rows = con.execute(
        """
        SELECT username, groupname, used_bytes, quota_extra_bytes, expires_at, disabled, updated_at
        FROM users
        WHERE used_bytes >= ?
        ORDER BY used_bytes DESC, username ASC
        """,
        (threshold_bytes,),
    ).fetchall()
finally:
    con.close()

records = []
for row in rows:
    username = row["username"]
    groupname = row["groupname"] or ""
    group_cfg = group_cfgs.get(groupname, {}) or {}
    user_cfg = user_cfgs.get(username, {}) or {}

    max_sessions = group_number(groupname) if session_enabled else 999999
    if session_enabled and "max_sessions" in group_cfg:
        group_ms = int(group_cfg["max_sessions"])
        max_sessions = 999999 if group_ms <= 0 else group_ms
    if session_enabled and "max_sessions" in user_cfg:
        user_ms = int(user_cfg["max_sessions"])
        if user_ms < 0:
            max_sessions = 999999
        elif user_ms > 0:
            max_sessions = user_ms

    quota_source = "quota_feature_disabled"
    base_quota_gb = 0.0
    if quota_enabled:
        if "quota_gb" in user_cfg:
            quota_source = "user_override"
            base_quota_gb = float(user_cfg.get("quota_gb", 0) or 0)
        elif "quota_gb" in group_cfg:
            quota_source = "group"
            base_quota_gb = float(group_cfg.get("quota_gb", 0) or 0)
        else:
            quota_source = "default"
            base_quota_gb = default_quota_gb

    base_quota_bytes = int(base_quota_gb * GIB) if quota_enabled and base_quota_gb > 0 else 0
    extra_bytes = int(row["quota_extra_bytes"] or 0)
    effective_quota_bytes = base_quota_bytes + extra_bytes if base_quota_bytes > 0 else 0
    used_bytes = int(row["used_bytes"] or 0)
    unlimited = effective_quota_bytes <= 0
    remaining_bytes = None if unlimited else max(0, effective_quota_bytes - used_bytes)
    exhausted = False if unlimited else used_bytes >= effective_quota_bytes
    expires_at = int(row["expires_at"] or 0)
    expired = bool(expiry_enabled and expires_at > 0 and expires_at <= int(time.time()))

    records.append({
        "username": username,
        "groupname": groupname,
        "used_bytes": used_bytes,
        "used_gib": fmt_gib(used_bytes),
        "quota_source": quota_source,
        "base_quota_gib": f"{base_quota_gb:.6f}" if base_quota_bytes > 0 else "unlimited",
        "extra_bytes": extra_bytes,
        "extra_gib": fmt_gib(extra_bytes),
        "effective_quota_bytes": effective_quota_bytes,
        "effective_quota_gib": fmt_gib(effective_quota_bytes) if not unlimited else "unlimited",
        "remaining_bytes": remaining_bytes,
        "remaining_gib": fmt_gib(remaining_bytes) if remaining_bytes is not None else "unlimited",
        "quota_unlimited": unlimited,
        "exhausted": exhausted,
        "max_sessions": "unlimited" if max_sessions >= 999999 else str(max_sessions),
        "expires_at": fmt_time(expires_at),
        "expired": expired,
        "disabled": bool(row["disabled"]),
        "updated_at": fmt_time(row["updated_at"]),
    })

out = Path(OUT_PATH)
out.parent.mkdir(parents=True, exist_ok=True)
now_iso = datetime.now().astimezone().isoformat(timespec="seconds")
total_used = sum(r["used_bytes"] for r in records)

with out.open("w", encoding="utf-8") as f:
    f.write("Ocserv Central Usage Threshold Export\n")
    f.write(f"Generated at: {now_iso}\n")
    f.write(f"Minimum used traffic GiB: {threshold_gib:.6f}\n")
    f.write(f"Minimum used traffic bytes: {threshold_bytes}\n")
    f.write("Comparison: used_bytes >= threshold_bytes\n")
    f.write(f"Matched users: {len(records)}\n")
    f.write(f"Total used GiB of matched users: {total_used / GIB:.6f}\n")
    f.write(f"Exhausted matched users: {sum(1 for r in records if r['exhausted'])}\n")
    f.write(f"Disabled matched users: {sum(1 for r in records if r['disabled'])}\n")
    f.write(f"Expired matched users: {sum(1 for r in records if r['expired'])}\n")
    f.write("\n")

    headers = [
        "USERNAME", "GROUP", "USED_GIB", "USED_BYTES", "QUOTA_SOURCE", "BASE_QUOTA_GIB",
        "EXTRA_GIB", "EXTRA_BYTES", "EFFECTIVE_QUOTA_GIB", "EFFECTIVE_QUOTA_BYTES",
        "REMAINING_GIB", "REMAINING_BYTES", "QUOTA_UNLIMITED", "EXHAUSTED",
        "MAX_SESSIONS", "EXPIRES_AT", "EXPIRED", "DISABLED", "UPDATED_AT",
    ]
    f.write("\t".join(headers) + "\n")

    for r in records:
        values = [
            r["username"], r["groupname"], r["used_gib"], str(r["used_bytes"]),
            r["quota_source"], r["base_quota_gib"], r["extra_gib"], str(r["extra_bytes"]),
            r["effective_quota_gib"], str(r["effective_quota_bytes"]), r["remaining_gib"],
            "unlimited" if r["remaining_bytes"] is None else str(r["remaining_bytes"]),
            str(r["quota_unlimited"]).lower(), str(r["exhausted"]).lower(), r["max_sessions"],
            r["expires_at"], str(r["expired"]).lower(), str(r["disabled"]).lower(), r["updated_at"],
        ]
        f.write("\t".join(values) + "\n")

print(f"Threshold GiB: {threshold_gib:.6f}")
print(f"Matched users: {len(records)}")
print(f"Output file: {out}")
PYEXPORTTHRESHOLD
    rc=$?
    set -e

    if (( rc != 0 )); then
        print_err "Usage threshold export failed."
        return "$rc"
    fi

    print_ok "Usage threshold export completed."
    ls -lh "$out" 2>/dev/null || true
    print_info "Read it with: cat '$out'"
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
        safe_clear
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
    local out tmp
    out="$(ask_value "Full backup output file" "/root/ocserv-central-full-$(date +%Y%m%d-%H%M%S).tar.gz")"

    # Use SQLite's online backup API rather than archiving a live central.db/WAL
    # pair directly. This produces a transactionally consistent database while
    # the API is running.
    tmp="$(make_temp_backup_root)"
    copy_master_common_to_tmp "$tmp"
    sqlite_backup_to_tmp "$tmp" "full" "yes"
    write_backup_metadata "$tmp" "full-consistent"
    mkdir -p "$(dirname "$out")"
    tar -czf "$out" -C "$tmp" .
    rm -rf "$tmp"
    print_ok "Full consistent backup saved: $out"
    ls -lh "$out" 2>/dev/null || true
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

create_transactional_central_safety_backup() {
    local out="$1" tmp
    tmp="$(make_temp_backup_root)"
    copy_master_common_to_tmp "$tmp"
    sqlite_backup_to_tmp "$tmp" "full" "yes"
    write_backup_metadata "$tmp" "pre-restore-transactional-safety"
    mkdir -p "$(dirname "$out")"
    if ! tar -czf "$out" -C "$tmp" .; then
        rm -rf "$tmp"
        return 1
    fi
    rm -rf "$tmp"
    chmod 600 "$out" 2>/dev/null || true
    validate_central_backup_archive "$out"
}

central_backup_candidates() {
    local d
    for d in /root /root/ocserv-central-backups; do
        [[ -d "$d" ]] || continue
        find "$d" -maxdepth 1 -type f -name 'ocserv-central-*.tar.gz' -printf '%T@\t%p\n' 2>/dev/null || true
    done | sort -nr | cut -f2-
}

validate_central_backup_archive() {
    local archive="$1"
    python3 - "$archive" <<'PYCBV'
import pathlib, sys, tarfile

archive = sys.argv[1]
restore_roots = (
    'etc/ocserv-central',
    'var/lib/ocserv-central',
    'etc/systemd/system/ocserv-central.service',
)
migration_only_roots = (
    'etc/ocserv-central-node',
    'etc/systemd/system/ocserv-central-agent.service',
)
legacy_app_root = 'opt/ocserv-central'
structural = {
    '', '.', 'opt', 'etc', 'etc/systemd', 'etc/systemd/system',
    'var', 'var/lib',
}
metadata_files = {'OCSERV_CENTRAL_BACKUP_INFO.txt', 'OCSERV_CENTRAL_V19_MIGRATION_INFO.txt'}

def clean_name(name):
    if name.startswith('/'):
        raise ValueError(f'absolute archive path: {name}')
    while name.startswith('./'):
        name = name[2:]
    p = pathlib.PurePosixPath(name)
    if '..' in p.parts:
        raise ValueError(f'parent traversal: {name}')
    return str(p) if str(p) != '.' else ''

def under(path, root):
    return path == root or path.startswith(root.rstrip('/') + '/')

try:
    with tarfile.open(archive, 'r:gz') as t:
        found_payload = False
        for m in t.getmembers():
            clean = clean_name(m.name)
            if m.isdev() or m.isfifo():
                raise ValueError(f'device/FIFO entry: {clean}')

            # Backups created by older Central versions include /opt/ocserv-central,
            # commonly including Python venv symlinks such as bin/python -> /usr/bin/python3
            # or relative links containing '..'. Application code/venv is deliberately
            # NOT restored: the current embedded Central runtime is rebuilt after data
            # restore. Therefore those legacy app links are safe to accept and ignore.
            if under(clean, legacy_app_root):
                found_payload = True
                continue

            if clean in structural or clean in metadata_files:
                continue

            if any(under(clean, root) for root in restore_roots):
                found_payload = True
                # Restored configuration/database/service paths must remain link-free.
                # This prevents a backup from redirecting a restored file outside the
                # Central-owned destination while still accepting legacy venv links.
                if m.issym() or m.islnk():
                    raise ValueError(f'link is not allowed in restorable Central data: {clean} -> {m.linkname}')
                continue

            # v19 migration bundles may carry legacy Node settings. They are never
            # copied directly into the new runtime; the unified Manager reads them
            # from staging and converts them to the source-aware v20 profile. Keep
            # them link-free for the same reason as Master configuration/data.
            if any(under(clean, root) for root in migration_only_roots):
                found_payload = True
                if m.issym() or m.islnk():
                    raise ValueError(f'link is not allowed in v19 migration data: {clean} -> {m.linkname}')
                continue

            raise ValueError(f'unexpected archive path: {clean}')

        if not found_payload:
            raise ValueError('not an ocserv-central backup')
except Exception as e:
    print(str(e), file=sys.stderr)
    raise SystemExit(1)
PYCBV
}

extract_central_backup_safe() {
    local archive="$1" destination="$2"
    python3 - "$archive" "$destination" <<'PYCBE'
import pathlib, sys, tarfile

archive, dest = sys.argv[1:]
restore_roots = (
    'etc/ocserv-central',
    'var/lib/ocserv-central',
    'etc/systemd/system/ocserv-central.service',
)
migration_only_roots = (
    'etc/ocserv-central-node',
    'etc/systemd/system/ocserv-central-agent.service',
)
structural = {
    '', '.', 'opt', 'etc', 'etc/systemd', 'etc/systemd/system',
    'var', 'var/lib',
}
metadata_files = {'OCSERV_CENTRAL_BACKUP_INFO.txt', 'OCSERV_CENTRAL_V19_MIGRATION_INFO.txt'}

def clean_name(name):
    if name.startswith('/'):
        raise SystemExit(f'unsafe absolute archive path: {name}')
    while name.startswith('./'):
        name = name[2:]
    p = pathlib.PurePosixPath(name)
    if '..' in p.parts:
        raise SystemExit(f'unsafe parent traversal: {name}')
    return str(p) if str(p) != '.' else ''

def under(path, root):
    return path == root or path.startswith(root.rstrip('/') + '/')

with tarfile.open(archive, 'r:gz') as t:
    selected = []
    for m in t.getmembers():
        clean = clean_name(m.name)
        if m.isdev() or m.isfifo():
            raise SystemExit(f'unsafe archive member: {clean}')

        # Never extract old /opt/ocserv-central application/venv content.  It is
        # rebuilt from the embedded current Central version after restore.  This
        # also makes historical backups containing absolute/relative venv symlinks
        # restorable without weakening extraction safety.
        if clean == 'opt/ocserv-central' or clean.startswith('opt/ocserv-central/'):
            continue

        if clean in structural:
            if m.isdir():
                selected.append(m)
            continue

        if clean in metadata_files:
            if m.isfile():
                selected.append(m)
            continue

        if any(under(clean, root) for root in restore_roots):
            if m.issym() or m.islnk():
                raise SystemExit(f'unsafe link in restorable Central data: {clean}')
            if m.isdir() or m.isfile():
                selected.append(m)
            else:
                raise SystemExit(f'unsupported archive member type: {clean}')
            continue

        if any(under(clean, root) for root in migration_only_roots):
            if m.issym() or m.islnk():
                raise SystemExit(f'unsafe link in v19 migration data: {clean}')
            if m.isdir() or m.isfile():
                selected.append(m)
            else:
                raise SystemExit(f'unsupported migration member type: {clean}')
            continue

        raise SystemExit(f'unexpected archive path: {clean}')

    try:
        t.extractall(dest, members=selected, filter='data')
    except TypeError:
        # Python <3.12 fallback. Validation above restricts extraction to regular
        # files/directories under fixed Central-owned relative paths only.
        t.extractall(dest, members=selected)
PYCBE
}

restore_master_data() {
    need_root
    local in="${1:-}" choice i staging rollback was_active=0 was_enabled="" had_app=0 had_etc=0 had_db=0 had_service=0
    local -a candidates=()
    if [[ -z "$in" ]]; then
        mapfile -t candidates < <(central_backup_candidates)
    fi

    if [[ -z "$in" ]] && (( ${#candidates[@]} == 1 )); then
        print_info "Detected Central backup: ${candidates[0]}"
        if ask_yes_no "Use this detected backup?" "y"; then in="${candidates[0]}"; fi
    elif [[ -z "$in" ]] && (( ${#candidates[@]} > 1 )); then
        echo "Detected Central backups (newest first):"
        for i in "${!candidates[@]}"; do
            printf '%d) %s  [%s]\n' "$((i+1))" "${candidates[$i]}" "$(du -h "${candidates[$i]}" 2>/dev/null | awk '{print $1}')"
        done
        echo "$(( ${#candidates[@]} + 1 ))) Enter another path manually"
        echo "0) Cancel"
        while true; do
            read -r -p "Select backup: " choice || true
            [[ "$choice" =~ ^[0-9]+$ ]] || { echo "Enter a number."; continue; }
            if (( choice == 0 )); then return 0; fi
            if (( choice >= 1 && choice <= ${#candidates[@]} )); then in="${candidates[$((choice-1))]}"; break; fi
            if (( choice == ${#candidates[@]} + 1 )); then break; fi
            echo "Invalid selection."
        done
    fi

    [[ -n "$in" ]] || in="$(ask_value "Backup tar.gz path to restore" "")"
    [[ -z "$in" ]] && return 0
    [[ -f "$in" ]] || { print_err "Backup file not found: $in"; return 1; }

    if ! validate_central_backup_archive "$in"; then
        print_err "Backup archive failed safety/format validation. Nothing was changed."
        return 1
    fi

    staging="$(mktemp -d /tmp/ocserv-central-restore.XXXXXX)"
    rollback="$(mktemp -d /tmp/ocserv-central-rollback.XXXXXX)"
    trap 'rm -rf "$staging" "$rollback"; trap - RETURN' RETURN
    extract_central_backup_safe "$in" "$staging" || { print_err "Could not safely extract backup. Nothing was changed."; return 1; }

    # Validate non-database payloads before touching the installed service.
    if [[ -f "$staging/etc/ocserv-central/limits.json" ]]; then
        if ! python3 -m json.tool "$staging/etc/ocserv-central/limits.json" >/dev/null 2>&1; then
            print_err "Backup limits.json is not valid JSON. Nothing was changed."
            return 1
        fi
    fi
    if [[ ! -f "$staging/etc/systemd/system/ocserv-central.service" && ! -f "$MASTER_SERVICE" ]]; then
        print_err "This backup does not contain the Central Master service definition (for example, a DB-only backup) and no Master is currently installed."
        print_info "DB-only backups are intended to restore data into an already configured Master. On a clean server use Full, Lightweight/Recommended, Config+DB custom backup, or install the Master first."
        return 1
    fi

    # Backup DB integrity is checked before touching the installed service.
    if [[ -f "$staging/var/lib/ocserv-central/central.db" ]]; then
        command -v sqlite3 >/dev/null 2>&1 || install_packages
        if [[ "$(sqlite3 "$staging/var/lib/ocserv-central/central.db" 'PRAGMA integrity_check;' 2>/dev/null | head -n1)" != ok ]]; then
            print_err "Backup central.db failed SQLite integrity_check. Nothing was changed."
            return 1
        fi
    fi

    print_warn "Restore is transactional: only Central Manager paths are replaced; ocserv, firewall, SSH and unrelated system files are not restored from this archive."
    ask_yes_no "Continue with this Central restore?" "n" || return 0

    if [[ -d "$APP_DIR" || -d "$MASTER_ETC" || -d "$DB_DIR" || -f "$MASTER_SERVICE" ]]; then
        local persistent_safety
        if ask_yes_no "Create a persistent Central safety backup before restore?" "y"; then
            persistent_safety="/root/ocserv-central-before-restore-$(date +%Y%m%d-%H%M%S).tar.gz"
            print_info "Creating persistent pre-restore safety backup: $persistent_safety"
            if ! create_transactional_central_safety_backup "$persistent_safety"; then
                print_err "Could not create and validate the requested persistent safety backup. Restore was cancelled before changing anything."
                rm -f "$persistent_safety" 2>/dev/null || true
                return 1
            fi
        else
            print_warn "Persistent pre-restore backup skipped by request. Transactional rollback still uses a temporary private copy that is removed when the operation finishes."
        fi
    fi

    systemctl is-active --quiet ocserv-central 2>/dev/null && was_active=1 || true
    was_enabled="$(systemctl is-enabled ocserv-central 2>/dev/null || true)"
    for _cmd in python3 sqlite3 curl jq; do command -v "$_cmd" >/dev/null 2>&1 || { install_packages; break; }; done
    # Mirror the exact current Central paths in the temporary rollback tree.
    # This avoids assumptions about directory basenames and keeps rollback exact.
    [[ -d "$APP_DIR" ]] && { had_app=1; mkdir -p "$rollback$(dirname "$APP_DIR")"; cp -a "$APP_DIR" "$rollback$APP_DIR"; }
    [[ -d "$MASTER_ETC" ]] && { had_etc=1; mkdir -p "$rollback$(dirname "$MASTER_ETC")"; cp -a "$MASTER_ETC" "$rollback$MASTER_ETC"; }
    [[ -d "$DB_DIR" ]] && { had_db=1; mkdir -p "$rollback$(dirname "$DB_DIR")"; cp -a "$DB_DIR" "$rollback$DB_DIR"; }
    [[ -f "$MASTER_SERVICE" ]] && { had_service=1; mkdir -p "$rollback$(dirname "$MASTER_SERVICE")"; cp -a "$MASTER_SERVICE" "$rollback$MASTER_SERVICE"; }

    local rollback_restore=0
    systemctl stop ocserv-central >/dev/null 2>&1 || true

    # Restore configuration/database from backup. Old application code/venv is
    # deliberately not trusted; the embedded current v20 code is rewritten below.
    if [[ -d "$staging/etc/ocserv-central" ]]; then rm -rf "$MASTER_ETC"; mkdir -p "$(dirname "$MASTER_ETC")"; cp -a "$staging/etc/ocserv-central" "$MASTER_ETC"; fi
    if [[ -d "$staging/var/lib/ocserv-central" ]]; then rm -rf "$DB_DIR"; mkdir -p "$(dirname "$DB_DIR")"; cp -a "$staging/var/lib/ocserv-central" "$DB_DIR"; fi
    if [[ -f "$staging/etc/systemd/system/ocserv-central.service" ]]; then mkdir -p "$(dirname "$MASTER_SERVICE")"; cp -a "$staging/etc/systemd/system/ocserv-central.service" "$MASTER_SERVICE"; fi

    mkdir -p "$APP_DIR" "$MASTER_ETC" "$DB_DIR"
    # Active sessions are runtime state and cannot survive a real restore/reboot.
    # Keep their history rows, but mark them inactive so stale sessions cannot
    # consume global session limits after recovery.
    if [[ -f "$DB_DIR/central.db" ]]; then
        sqlite3 "$DB_DIR/central.db" "UPDATE sessions SET active=0 WHERE active!=0;" >/dev/null 2>&1 || true
    fi
    write_master_app
    ensure_limits_file
    if ! ensure_master_runtime_without_reconfigure; then rollback_restore=1; fi
    systemctl daemon-reload

    if (( rollback_restore == 0 )); then
        if [[ ! -f "$MASTER_SERVICE" ]]; then
            print_err "Backup did not contain a Master service and no existing service was available."
            rollback_restore=1
        elif ! systemctl start ocserv-central; then
            print_err "Central API service could not start after restore."
            rollback_restore=1
        elif ! wait_for_master_health 20; then
            print_err "Central API failed /health after restore."
            journalctl -u ocserv-central -n 80 --no-pager 2>/dev/null || true
            rollback_restore=1
        else
            local restored_token
            restored_token="$(master_token_from_systemd)"
            if [[ -z "$restored_token" ]] || ! curl -fsS --max-time 3 -H "X-API-Token: $restored_token" http://127.0.0.1:8088/config | jq -e '.features and .groups and .users' >/dev/null 2>&1; then
                print_err "Central API health endpoint is up, but the authenticated configuration check failed after restore."
                rollback_restore=1
            elif [[ -f "$DB_DIR/central.db" && "$(sqlite3 "$DB_DIR/central.db" 'PRAGMA integrity_check;' 2>/dev/null | head -n1)" != ok ]]; then
                print_err "Restored central.db failed the post-restore SQLite integrity check."
                rollback_restore=1
            fi
        fi
    fi

    if (( rollback_restore == 1 )); then
        print_warn "Restore failed validation/startup. Rolling Central Manager back to the exact pre-restore state."
        systemctl stop ocserv-central >/dev/null 2>&1 || true
        rm -rf "$APP_DIR" "$MASTER_ETC" "$DB_DIR"; rm -f "$MASTER_SERVICE"
        (( had_app == 1 )) && { mkdir -p "$(dirname "$APP_DIR")"; cp -a "$rollback$APP_DIR" "$APP_DIR"; }
        (( had_etc == 1 )) && { mkdir -p "$(dirname "$MASTER_ETC")"; cp -a "$rollback$MASTER_ETC" "$MASTER_ETC"; }
        (( had_db == 1 )) && { mkdir -p "$(dirname "$DB_DIR")"; cp -a "$rollback$DB_DIR" "$DB_DIR"; }
        (( had_service == 1 )) && { mkdir -p "$(dirname "$MASTER_SERVICE")"; cp -a "$rollback$MASTER_SERVICE" "$MASTER_SERVICE"; }
        systemctl daemon-reload
        [[ "$was_enabled" == enabled ]] && systemctl enable ocserv-central >/dev/null 2>&1 || systemctl disable ocserv-central >/dev/null 2>&1 || true
        (( was_active == 1 )) && systemctl start ocserv-central >/dev/null 2>&1 || true
        print_err "Restore was rolled back; the previous Central installation was preserved."
        return 1
    fi

    # Enable at boot only after the API is confirmed healthy. Preserve previous
    # enablement; on a clean recovery, offer the expected persistent service.
    if [[ "$was_enabled" == enabled ]]; then
        systemctl enable ocserv-central >/dev/null 2>&1 || true
    elif (( had_service == 0 )) && [[ -f "$staging/etc/systemd/system/ocserv-central.service" ]]; then
        if ask_yes_no "Central API is healthy. Enable it automatically at boot?" "y"; then systemctl enable ocserv-central >/dev/null 2>&1 || true; fi
    fi

    print_ok "Central backup restored and API health-check passed."
    print_info "Restored backup: $in"

    # Old v19 and current backups use the same restore path. Once the Master data
    # is healthy, optionally connect all local Manager-owned ocserv instances to
    # this restored local Master. This replaces the old dedicated migration wizard.
    if manager_multi_instance_available && systemctl is-active --quiet ocserv-central 2>/dev/null; then
        if ask_yes_no "Attach all local ocserv instances to this restored Master now?" "y"; then
            if /usr/local/sbin/ocserv-manager --central-attach-all-local-master; then
                print_ok "Local ocserv instances were attached to the restored Central Master."
            else
                print_warn "Central data restore succeeded, but one or more local instance attachments failed. The restored data was kept."
            fi
        fi
    fi
}


# v20.4: legacy v19 backup compatibility is handled by the normal transactional
# Backup / Restore path. No separate migration wizard is required.

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
    if ask_yes_no "Automatically create a DB safety backup before each scheduled cleanup run? (The timer cannot ask interactively at run time.)" "n"; then
        backup_before="1"
        backup_dir="$(ask_value "Directory for automatic safety DB backups" "/root")"
    else
        backup_before="0"
        backup_dir="/root"
    fi

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

run_central_menu_action() {
    local rc=0
    if "$@"; then
        return 0
    else
        rc=$?
        print_warn "Operation returned code $rc. Central Manager will stay open so you can review, retry, or go back."
        return 0
    fi
}

backup_cleanup_menu() {
    while true; do
        safe_clear
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
            1) run_central_menu_action usage_log_stats; pause ;;
            2) run_central_menu_action backup_master_full; pause ;;
            3) run_central_menu_action backup_master_lightweight; pause ;;
            4) run_central_menu_action backup_master_config_only; pause ;;
            5) run_central_menu_action backup_master_db_only; pause ;;
            6) run_central_menu_action backup_master_custom; pause ;;
            7) run_central_menu_action restore_master_data; pause ;;
            8) run_central_menu_action cleanup_usage_logs; pause ;;
            9) run_central_menu_action vacuum_database; pause ;;
            10) run_central_menu_action configure_auto_cleanup_timer; pause ;;
            11) run_central_menu_action disable_auto_cleanup_timer; pause ;;
            12) run_central_menu_action show_cleanup_timer_status; pause ;;
            13) run_central_menu_action backup_master_recommended_default; pause ;;
            14) run_central_menu_action default_cleanup_usage_log_with_vacuum; pause ;;
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
        safe_clear
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
    current_url="${API_URL:-http://127.0.0.1:8088}"
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
            if ask_yes_no "Create a backup of the current ocserv.conf before restoring the saved original config?" "y"; then
                mkdir -p "$NODE_ETC/backup"
                cp -a "$conf" "$NODE_ETC/backup/ocserv.conf.before-restore.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
            fi
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

    local make_backup="${3:-0}"
    python3 - "$db" "$limits" "$group" "$action" "$make_backup" <<'PYGROUPOVERRIDE'
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time

DB, LIMITS, GROUP, ACTION, MAKE_BACKUP = sys.argv[1:6]
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
    backup = ""
    if MAKE_BACKUP == "1":
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
            local make_backup=0
            if ask_yes_no "Create a limits.json backup before removing these user quota overrides?" "y"; then make_backup=1; fi
            result="$(group_manual_quota_overrides_json "$group" "remove-quota" "$make_backup")"
            print_ok "Removed manual quota override from $(jq -r '.removed_quota_overrides // 0' <<<"$result") user(s)."
            print_info "New group quota now applies to those users immediately."
            print_info "limits.json backup: $(jq -r 'if (.backup // "") == "" then "not created" else .backup end' <<<"$result")"
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
        safe_clear
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
        safe_clear
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
    if ! ask_yes_no "Create a persistent DB backup before usage recovery?" "y"; then
        print_info "Persistent usage-recovery backup skipped by request."
        return 0
    fi
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

    if ! ask_yes_no "Apply this snapshot recovery now?" "n"; then
        return 0
    fi
    recovery_db_backup

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

    print(f"{'USERNAME':<28} {'GROUP':<14} {'CURRENT_BYTES':>18} {'RECOVER_BYTES':>18} {'LOG_ROWS':>10} {'OLDEST_LOG':<19}")
    print("-" * 125)
    for u in users:
        row = con.execute(
            "SELECT COALESCE(SUM(bytes),0), COUNT(*), MIN(created_at), MAX(created_at) FROM usage_log WHERE username=? AND created_at>=?",
            (u['username'], cutoff),
        ).fetchone()
        recover, count, oldest, newest = row
        oldest_text = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(oldest)) if oldest else 'none'
        print(f"{u['username']:<28} {str(u['groupname'] or ''):<14} {int(u['used_bytes'] or 0):>18} {int(recover or 0):>18} {int(count):>10} {oldest_text:<19}")
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
    if ! ask_yes_no "Apply usage_log fallback recovery now?" "n"; then
        return 0
    fi
    recovery_db_backup

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
        safe_clear
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
    if ! ask_yes_no "Create a persistent DB backup before extra-traffic recovery?" "y"; then
        print_info "Persistent extra-traffic recovery backup skipped by request."
        return 0
    fi
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

    if ! ask_yes_no "Restore this extra-traffic snapshot now?" "n"; then
        return 0
    fi
    extra_traffic_db_backup

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
        safe_clear
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



# =========================
# v18: one-click manual prune and policy toggle without reconfigure
# =========================

count_parseable_ocpasswd_users() {
    local ocp="$1"
    python3 - "$ocp" <<'PYCOUNTOCP'
import os
import sys

path = sys.argv[1]
if not os.path.isfile(path):
    print(0)
    raise SystemExit(0)

count = 0
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 2)
        if len(parts) >= 2 and parts[0].strip():
            count += 1
print(count)
PYCOUNTOCP
}

count_db_users_missing_from_ocpasswd() {
    local db="$1"
    local ocp="$2"
    python3 - "$db" "$ocp" <<'PYCOUNTMISSING'
import os
import sqlite3
import sys

db_path, ocp_path = sys.argv[1:3]

ocp_users = set()
if os.path.isfile(ocp_path):
    with open(ocp_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":", 2)
            if len(parts) >= 2 and parts[0].strip():
                ocp_users.add(parts[0].strip())

con = sqlite3.connect(db_path, timeout=30)
try:
    db_users = {
        row[0]
        for row in con.execute("SELECT username FROM users")
        if row[0]
    }
finally:
    con.close()

print(len(db_users - ocp_users))
PYCOUNTMISSING
}

prune_missing_users_now() {
    need_root

    local ocp db parsed_count missing_count
    db="$DB_DIR/central.db"
    ocp="$(ask_value "ocpasswd path" "$(get_master_ocpasswd_path)")"

    if [[ ! -f "$db" ]]; then
        print_err "Database not found: $db"
        return 1
    fi

    if [[ ! -f "$ocp" ]]; then
        print_err "ocpasswd file does not exist: $ocp"
        print_warn "Prune was cancelled. No database rows were changed."
        return 1
    fi

    parsed_count="$(count_parseable_ocpasswd_users "$ocp")"
    if [[ ! "$parsed_count" =~ ^[0-9]+$ ]] || (( parsed_count <= 0 )); then
        print_err "ocpasswd has zero parseable users."
        print_warn "Prune was cancelled by the safety guard. No database rows were changed."
        return 1
    fi

    missing_count="$(count_db_users_missing_from_ocpasswd "$db" "$ocp")"
    if [[ ! "$missing_count" =~ ^[0-9]+$ ]]; then
        print_err "Could not calculate missing-user count."
        return 1
    fi

    echo
    print_info "ocpasswd path: $ocp"
    print_info "Parseable ocpasswd users: $parsed_count"
    print_info "Central DB users missing from ocpasswd: $missing_count"
    echo

    if (( missing_count == 0 )); then
        print_ok "No stale users were found. Nothing needs to be removed."
        return 0
    fi

    print_info "Users selected by the dry-run preview:"
    db_user_cleanup_python "list_missing" 90 0 0 "$ocp"
    echo
    print_warn "The selected usernames will be removed from central DB tables."
    print_warn "This operation does not edit ocpasswd."
    print_info "You will be asked whether to create a persistent DB backup before deletion."

    if ! ask_yes_no "Remove these missing users now?" "n"; then
        print_info "Prune cancelled. Nothing was deleted."
        return 0
    fi

    if ask_yes_no "Create a safety DB backup before deletion?" "y"; then safety_backup_db_before_cleanup; fi

    db_user_cleanup_python "delete_missing" 90 0 1 "$ocp"

    # Rebuild the exhausted report so deleted usernames do not remain there.
    if systemctl is-active --quiet ocserv-central 2>/dev/null; then
        master_curl "POST" "/quota-exhausted/rebuild" "{}" || \
            print_warn "Users were deleted, but exhausted-quota rebuild failed."
    else
        print_warn "API is not active; exhausted-quota file was not rebuilt automatically."
        print_info "After starting the API, use Master menu 18 -> Rebuild if needed."
    fi

    print_ok "Manual ocpasswd prune completed without reconfigure."
}

current_remove_missing_policy() {
    local value=""
    if [[ -f "$MASTER_SERVICE" ]]; then
        value="$(
            sed -n 's/^[[:space:]]*Environment=REMOVE_MISSING_USERS=//p' "$MASTER_SERVICE" |
            tail -n1
        )"
    fi
    if [[ -z "$value" ]]; then
        value="$(
            systemctl show ocserv-central -p Environment --value 2>/dev/null |
            tr ' ' '\n' |
            sed -n 's/^REMOVE_MISSING_USERS=//p' |
            tail -n1
        )"
    fi
    [[ "$value" == "1" ]] && echo "1" || echo "0"
}

set_remove_missing_policy_in_service() {
    local new_value="$1"

    if [[ ! -f "$MASTER_SERVICE" ]]; then
        print_err "Master service file not found: $MASTER_SERVICE"
        print_info "Install the Master first."
        return 1
    fi

    if ask_yes_no "Create a backup of the Central systemd service before changing prune policy?" "y"; then
        cp -a "$MASTER_SERVICE" \
            "/root/ocserv-central.service.before-prune-policy-$(date +%Y%m%d-%H%M%S).bak"
    else
        print_info "Central service-file backup skipped by request."
    fi

    if grep -qE '^[[:space:]]*Environment=REMOVE_MISSING_USERS=' "$MASTER_SERVICE"; then
        sed -i -E \
            "s|^[[:space:]]*Environment=REMOVE_MISSING_USERS=.*$|Environment=REMOVE_MISSING_USERS=$new_value|" \
            "$MASTER_SERVICE"
    else
        sed -i \
            "/^[[:space:]]*Environment=SESSION_TTL=/a Environment=REMOVE_MISSING_USERS=$new_value" \
            "$MASTER_SERVICE"
    fi

    systemctl daemon-reload
    systemctl restart ocserv-central

    if systemctl is-active --quiet ocserv-central; then
        print_ok "Automatic missing-user removal policy updated. API is active."
    else
        print_err "Policy file was updated, but ocserv-central is not active."
        systemctl status ocserv-central --no-pager || true
        return 1
    fi
}

configure_remove_missing_policy_without_reconfigure() {
    need_root

    local current default_answer new_value
    current="$(current_remove_missing_policy)"
    if [[ "$current" == "1" ]]; then
        print_info "Current automatic prune policy: ENABLED"
        default_answer="y"
    else
        print_info "Current automatic prune policy: DISABLED"
        default_answer="n"
    fi

    echo
    print_info "When enabled, every API ocpasswd sync removes central DB users that no longer exist in ocpasswd."
    print_info "The API safety guard skips removal if ocpasswd is missing or has zero parseable users."
    print_warn "This setting changes only the systemd policy and restarts the API; Master reconfigure is not required."

    if ask_yes_no "Enable automatic removal on every ocpasswd sync?" "$default_answer"; then
        new_value="1"
    else
        new_value="0"
    fi

    if [[ "$new_value" == "$current" ]]; then
        print_ok "The selected policy is already active. No change was needed."
    else
        set_remove_missing_policy_in_service "$new_value" || return 1
    fi

    if [[ "$new_value" == "1" ]]; then
        echo
        if ask_yes_no "Run a protected manual prune now as well?" "n"; then
            prune_missing_users_now
        fi
    fi
}


# =========================
# v20: safe code update without reconfigure
# =========================

copy_update_backup_if_exists() {
    local source="$1"
    local backup_root="$2"
    local relative destination

    [[ -e "$source" ]] || return 0

    relative="${source#/}"
    destination="$backup_root/$relative"
    mkdir -p "$(dirname "$destination")"
    cp -a "$source" "$destination"
}

create_update_backup_bundle() {
    local backup_root="$1"

    mkdir -p "$backup_root"

    # Configuration and service definitions are copied even though the updater
    # intentionally does not rewrite them.
    copy_update_backup_if_exists "$MASTER_SERVICE" "$backup_root"
    copy_update_backup_if_exists "$MASTER_ETC/limits.json" "$backup_root"
    copy_update_backup_if_exists "$NODE_ETC/node.env" "$backup_root"
    copy_update_backup_if_exists "$NODE_ETC/ocserv_conf_path" "$backup_root"
    copy_update_backup_if_exists "$NODE_AGENT_SERVICE" "$backup_root"
    copy_update_backup_if_exists "$HOOK_SCRIPT" "$backup_root"
    copy_update_backup_if_exists "$CONNECT_WRAPPER" "$backup_root"
    copy_update_backup_if_exists "$DISCONNECT_WRAPPER" "$backup_root"
    copy_update_backup_if_exists "$AGENT_SCRIPT" "$backup_root"
    copy_update_backup_if_exists "$CLEANUP_SCRIPT" "$backup_root"
    copy_update_backup_if_exists "$CLEANUP_ENV" "$backup_root"
    copy_update_backup_if_exists "$CLEANUP_SERVICE" "$backup_root"
    copy_update_backup_if_exists "$CLEANUP_TIMER" "$backup_root"
    copy_update_backup_if_exists "$APP_DIR/app.py" "$backup_root"
    copy_update_backup_if_exists "$MANAGER_BIN" "$backup_root"

    if [[ -f "$DB_DIR/central.db" ]]; then
        mkdir -p "$backup_root/var/lib/ocserv-central"
        print_info "Creating SQLite safety backup before code migration..."
        sqlite3 "$DB_DIR/central.db" \
            ".backup '$backup_root/var/lib/ocserv-central/central.db'" || {
                print_err "Could not create SQLite safety backup."
                return 1
            }
    fi

    print_ok "Update safety backup created: $backup_root"
}

master_installation_detected() {
    [[ -f "$MASTER_SERVICE" || -f "$APP_DIR/app.py" || -f "$DB_DIR/central.db" ]]
}

node_installation_detected() {
    [[ -f "$NODE_ETC/node.env" || -f "$NODE_AGENT_SERVICE" || -f "$AGENT_SCRIPT" || -f "$HOOK_SCRIPT" ]]
}

validate_existing_master_configuration() {
    if [[ ! -f "$MASTER_SERVICE" ]]; then
        print_err "Master service file not found: $MASTER_SERVICE"
        print_info "A first-time Master installation still requires Install / reconfigure master."
        return 1
    fi

    local missing=0 key
    for key in API_TOKEN DB_PATH LIMITS_PATH OCPASSWD_PATH SESSION_TTL; do
        if ! grep -qE "^[[:space:]]*Environment=${key}=" "$MASTER_SERVICE"; then
            print_err "Existing Master service is missing required setting: $key"
            missing=1
        fi
    done

    if (( missing != 0 )); then
        print_warn "The current installation is incomplete. Update was stopped before changing API code."
        return 1
    fi

    return 0
}

ensure_master_runtime_without_reconfigure() {
    mkdir -p "$APP_DIR" "$MASTER_ETC" "$DB_DIR"

    if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
        print_info "Creating missing Master Python virtual environment..."
        python3 -m venv "$APP_DIR/venv"
    fi

    if ! "$APP_DIR/venv/bin/python" -c \
        'import fastapi, uvicorn, pydantic' >/dev/null 2>&1; then
        print_info "Installing missing Master Python dependencies..."
        "$APP_DIR/venv/bin/pip" install --upgrade pip
        "$APP_DIR/venv/bin/pip" install fastapi uvicorn pydantic
    fi
}

wait_for_master_health() {
    local attempts="${1:-20}"
    local i response

    for ((i=1; i<=attempts; i++)); do
        response="$(curl -fsS --max-time 2 http://127.0.0.1:8088/health 2>/dev/null || true)"
        if [[ -n "$response" ]] && echo "$response" | jq -e '.ok == true' >/dev/null 2>&1; then
            echo "$response" | jq .
            return 0
        fi
        sleep 1
    done
    return 1
}

restore_master_app_after_failed_update() {
    local backup_root="$1"
    local old_app="$backup_root/${APP_DIR#/}/app.py"

    if [[ -f "$old_app" ]]; then
        print_warn "Restoring previous Master API code..."
        cp -a "$old_app" "$APP_DIR/app.py"
        systemctl restart ocserv-central 2>/dev/null || true
    else
        print_warn "No previous app.py was available for automatic rollback."
    fi
}

apply_master_code_update_without_reconfigure() {
    local backup_root="$1"
    local was_active=0 was_enabled="unknown"

    validate_existing_master_configuration || return 1

    systemctl is-active --quiet ocserv-central 2>/dev/null && was_active=1 || true
    was_enabled="$(systemctl is-enabled ocserv-central 2>/dev/null || true)"

    print_info "Updating Master API code without changing configuration..."
    ensure_master_runtime_without_reconfigure

    write_master_app
    chmod 755 "$APP_DIR/app.py"

    if ! python3 -m py_compile "$APP_DIR/app.py"; then
        print_err "New Master API code failed Python syntax validation."
        restore_master_app_after_failed_update "$backup_root"
        return 1
    fi

    # The existing service file is intentionally preserved. It contains the
    # remembered token, paths, TTL, and pruning policy.
    systemctl daemon-reload

    if (( was_active == 1 )); then
        print_info "Restarting the previously active Master API..."
        if ! systemctl restart ocserv-central; then
            print_err "Master API restart failed."
            restore_master_app_after_failed_update "$backup_root"
            return 1
        fi

        if ! wait_for_master_health 20; then
            print_err "Master API did not pass health-check after update."
            journalctl -u ocserv-central -n 80 --no-pager || true
            restore_master_app_after_failed_update "$backup_root"
            return 1
        fi
        print_ok "Master API updated and health-check passed."
    else
        print_info "Master API was stopped before update; it remains stopped."
        if [[ "$was_enabled" == "enabled" ]]; then
            print_info "Its enabled-on-boot state remains enabled."
        fi
    fi

    mkdir -p "$(dirname "$MASTER_VERSION_FILE")"
    printf '%s\n' "$PROGRAM_VERSION" > "$MASTER_VERSION_FILE"
}

restore_node_code_after_failed_update() {
    local backup_root="$1"
    local source destination

    for destination in \
        "$HOOK_SCRIPT" \
        "$CONNECT_WRAPPER" \
        "$DISCONNECT_WRAPPER" \
        "$AGENT_SCRIPT" \
        "$NODE_AGENT_SERVICE"
    do
        source="$backup_root/${destination#/}"
        if [[ -f "$source" ]]; then
            cp -a "$source" "$destination"
        fi
    done
    systemctl daemon-reload
    systemctl restart ocserv-central-agent 2>/dev/null || true
}

apply_node_code_update_without_reconfigure() {
    local backup_root="$1"
    local was_active=0 was_enabled="unknown"

    if [[ ! -f "$NODE_ETC/node.env" ]]; then
        print_err "Node configuration not found: $NODE_ETC/node.env"
        print_info "A first-time Node installation still requires Install / reconfigure node."
        return 1
    fi

    systemctl is-active --quiet ocserv-central-agent 2>/dev/null && was_active=1 || true
    was_enabled="$(systemctl is-enabled ocserv-central-agent 2>/dev/null || true)"

    print_info "Updating Node Agent and hook code without changing node.env or ocserv.conf..."
    write_node_files

    if ! bash -n "$HOOK_SCRIPT" ||
       ! bash -n "$CONNECT_WRAPPER" ||
       ! bash -n "$DISCONNECT_WRAPPER" ||
       ! python3 -m py_compile "$AGENT_SCRIPT"; then
        print_err "New Node code failed syntax validation."
        restore_node_code_after_failed_update "$backup_root"
        return 1
    fi

    systemctl daemon-reload

    if [[ "$was_enabled" == "enabled" ]]; then
        systemctl enable ocserv-central-agent >/dev/null 2>&1 || true
    else
        systemctl disable ocserv-central-agent >/dev/null 2>&1 || true
    fi

    if (( was_active == 1 )); then
        if ! systemctl restart ocserv-central-agent; then
            print_err "Node Agent restart failed."
            restore_node_code_after_failed_update "$backup_root"
            return 1
        fi
        print_ok "Node Agent code updated and restarted."
    else
        systemctl stop ocserv-central-agent >/dev/null 2>&1 || true
        print_info "Node Agent was stopped before update; it remains stopped."
    fi

    # Hook scripts are executed from disk on every connect/disconnect. ocserv
    # itself does not need a restart because their configured paths are unchanged.
    print_info "ocserv.conf was not rewritten and ocserv was not restarted."

    mkdir -p "$(dirname "$NODE_VERSION_FILE")"
    printf '%s\n' "$PROGRAM_VERSION" > "$NODE_VERSION_FILE"
}

apply_cleanup_code_update_without_reconfigure() {
    if [[ -f "$CLEANUP_SCRIPT" || -f "$CLEANUP_SERVICE" || -f "$CLEANUP_TIMER" ]]; then
        print_info "Updating installed cleanup helper code while preserving cleanup.env and timer settings..."
        write_cleanup_script
        bash -n "$CLEANUP_SCRIPT"
        print_ok "Cleanup helper code updated."
    fi
}

show_preserved_update_settings() {
    echo
    print_info "The following existing values were preserved:"
    [[ -f "$MASTER_SERVICE" ]] && echo "- Master systemd Environment values: token, DB path, limits path, ocpasswd path, TTL, prune policy" || true
    [[ -f "$MASTER_ETC/limits.json" ]] && echo "- $MASTER_ETC/limits.json" || true
    [[ -f "$DB_DIR/central.db" ]] && echo "- $DB_DIR/central.db" || true
    [[ -f "$NODE_ETC/node.env" ]] && echo "- $NODE_ETC/node.env" || true
    [[ -f "$NODE_ETC/ocserv_conf_path" ]] && echo "- Existing ocserv.conf and hook path configuration" || true
    [[ -f "$CLEANUP_ENV" ]] && echo "- $CLEANUP_ENV" || true
    return 0
}

apply_program_update_without_reconfigure() {
    need_root

    local master_found=0 node_found=0
    local master_result="not-installed"
    local node_result="not-installed"
    local timestamp backup_root

    master_installation_detected && master_found=1 || true
    node_installation_detected && node_found=1 || true

    echo "==== Apply Program Update Without Reconfigure ===="
    print_info "Manager package version: $PROGRAM_VERSION"
    print_info "Master API version in this package: $API_VERSION"
    echo
    echo "Detected components:"
    echo "- Master: $([[ "$master_found" == "1" ]] && echo yes || echo no)"
    echo "- Node:   $([[ "$node_found" == "1" ]] && echo yes || echo no)"
    echo

    if (( master_found == 0 && node_found == 0 )); then
        print_warn "No installed Master or Node component was detected."
        print_info "The Manager itself will still be installed, but first-time setup requires the normal install menu."
    fi

    timestamp="$(date +%Y%m%d-%H%M%S)"
    local keep_update_backup=0
    if ask_yes_no "Create a persistent Central update backup before applying code updates?" "y"; then
        backup_root="$UPDATE_BACKUP_ROOT/$timestamp-$PROGRAM_VERSION"
        keep_update_backup=1
    else
        backup_root="$(mktemp -d /tmp/ocserv-central-update-rollback.XXXXXX)"
        print_warn "No persistent Central update backup will be kept; the temporary rollback bundle exists only for this update."
    fi

    if ! create_update_backup_bundle "$backup_root"; then
        print_err "Update stopped because the rollback bundle could not be created."
        return 1
    fi

    # Install this exact script as the persistent manager only after its own
    # syntax has already been validated by the shell that is running it.
    install_self_manager
    if [[ -f "$MANAGER_BIN" ]]; then
        printf '%s\n' "$PROGRAM_VERSION" > /etc/ocserv-central-manager-version
    fi

    if (( master_found == 1 )); then
        if apply_master_code_update_without_reconfigure "$backup_root"; then
            master_result="updated"
        else
            master_result="failed-rolled-back"
        fi
    fi

    if (( node_found == 1 )); then
        if apply_node_code_update_without_reconfigure "$backup_root"; then
            node_result="updated"
        else
            node_result="failed-rolled-back"
        fi
    fi

    apply_cleanup_code_update_without_reconfigure || \
        print_warn "Cleanup helper update failed; other component results are unchanged."

    show_preserved_update_settings

    echo
    echo "Update result:"
    echo "- Manager: installed $PROGRAM_VERSION"
    echo "- Master:  $master_result"
    echo "- Node:    $node_result"
    if (( keep_update_backup == 1 )); then echo "- Backup:  $backup_root"; else echo "- Backup:  not kept (declined)"; fi

    if [[ "$master_result" == "failed-rolled-back" || "$node_result" == "failed-rolled-back" ]]; then
        print_err "One or more components failed and were rolled back where possible."
        (( keep_update_backup == 0 )) && rm -rf "$backup_root" 2>/dev/null || true
        return 1
    fi

    print_ok "Program update completed without reconfigure."
    (( keep_update_backup == 0 )) && rm -rf "$backup_root" 2>/dev/null || true
}

apply_master_update_menu() {
    need_root
    local timestamp backup_root
    timestamp="$(date +%Y%m%d-%H%M%S)"
    local keep_backup=0
    if ask_yes_no "Create a persistent Master update backup?" "y"; then backup_root="$UPDATE_BACKUP_ROOT/$timestamp-$PROGRAM_VERSION-master"; keep_backup=1; else backup_root="$(mktemp -d /tmp/ocserv-central-master-update-rollback.XXXXXX)"; fi
    create_update_backup_bundle "$backup_root" || return 1
    install_self_manager
    apply_master_code_update_without_reconfigure "$backup_root"
    apply_cleanup_code_update_without_reconfigure || true
    show_preserved_update_settings
    print_ok "Master code update completed without reconfigure."
    (( keep_backup == 0 )) && rm -rf "$backup_root" 2>/dev/null || true
}

apply_node_update_menu() {
    need_root
    local timestamp backup_root
    timestamp="$(date +%Y%m%d-%H%M%S)"
    local keep_backup=0
    if ask_yes_no "Create a persistent Node update backup?" "y"; then backup_root="$UPDATE_BACKUP_ROOT/$timestamp-$PROGRAM_VERSION-node"; keep_backup=1; else backup_root="$(mktemp -d /tmp/ocserv-central-node-update-rollback.XXXXXX)"; fi
    create_update_backup_bundle "$backup_root" || return 1
    install_self_manager
    apply_node_code_update_without_reconfigure "$backup_root"
    show_preserved_update_settings
    print_ok "Node code update completed without reconfigure."
    (( keep_backup == 0 )) && rm -rf "$backup_root" 2>/dev/null || true
}

master_menu() {
    while true; do
        safe_clear
        echo "==== Ocserv Central - Master Menu ===="
        echo "1) Install / reconfigure master (API token / TTL / prune / features)"
        echo "2) Configure features: session limit / quota"
        echo "3) Configure group limits from synchronized authority sources"
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
        echo "33) Export usage information for one group to a TXT file"
        echo "34) Export users at or above a used-traffic threshold to a TXT file"
        echo "35) Prune central DB users missing from ocpasswd now"
        echo "36) Configure automatic ocpasswd prune without reconfigure"
        echo "37) Apply Master/API code update without reconfigure"
        echo "38) List synchronized authority sources / conflicts"
        echo "0) Back"
        echo
        read -rp "Select: " choice
        case "$choice" in
            1) install_master; pause ;;
            2) configure_features; systemctl restart ocserv-central 2>/dev/null || true; pause ;;
            3)
                configure_groups_from_ocpasswd "__central_sources__"
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
            33) export_group_usage_file; pause ;;
            34) export_usage_threshold_file; pause ;;
            35) prune_missing_users_now; pause ;;
            36) configure_remove_missing_policy_without_reconfigure; pause ;;
            37) apply_master_update_menu; pause ;;
            38) list_authority_sources; pause ;;
            0) return 0 ;;
            *) echo "Invalid choice"; sleep 1 ;;
        esac
    done
}

node_menu() {
    while true; do
        safe_clear
        echo "==== Ocserv Central - Node Menu ===="
        echo "1) Install / reconfigure node"
        echo "2) Edit node API settings"
        echo "3) Enable live quota agent"
        echo "4) Disable live quota agent"
        echo "5) Status / logs"
        echo "6) Test API connection"
        echo "7) Re-apply ocserv.conf hook"
        echo "8) Uninstall node and restore ocserv.conf"
        echo "9) Apply Node code update without reconfigure"
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
            9) apply_node_update_menu; pause ;;
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

manager_multi_instance_available() {
    [[ -x /usr/local/sbin/ocserv-manager ]] && /usr/local/sbin/ocserv-manager --central-capability >/dev/null 2>&1
}

open_manager_multi_instance() {
    if manager_multi_instance_available; then
        /usr/local/sbin/ocserv-manager --central-instances
    else
        print_warn "Ocserv Manager multi-instance registry is not available on this host. Use the legacy single-instance Node menu instead."
        pause
    fi
}

# Modern source-aware equivalent of the old v19 "Install both master and node on this server".
# Install/reconfigure the local Master first, then delegate local-instance discovery and
# per-instance Node/source attachment to the parent Ocserv Manager. Keeping this bridge
# inside Central prevents the UI from referencing a missing shell function and avoids
# duplicating multi-instance registry logic in two places.
install_both_master_and_local_nodes() {
    need_root

    print_info "Step 1/2: installing or reconfiguring the local Central Master..."
    if ! install_master; then
        print_err "Central Master installation/reconfiguration failed. Local instances were not attached."
        return 1
    fi

    if ! wait_for_master_health 20 >/dev/null; then
        print_err "Central Master did not pass the local health check at http://127.0.0.1:8088/health."
        print_info "Local instances were not attached. Check: journalctl -u ocserv-central -n 100 --no-pager"
        return 1
    fi

    print_info "Step 2/2: attaching all local ocserv instances as source-aware Nodes..."
    if ! manager_multi_instance_available; then
        print_err "The parent Ocserv Manager multi-instance capability is not available."
        print_info "Master is installed and healthy, but no local instance was attached automatically."
        print_info "Run this from the full Ocserv Manager package, or use the legacy single-instance Node menu only for standalone installs."
        return 1
    fi

    if ! /usr/local/sbin/ocserv-manager --central-attach-all-local-master; then
        print_err "Central Master is running, but one or more local ocserv instances could not be attached."
        print_info "Open: Local ocserv instances / Node integration to inspect or retry individual instances."
        return 1
    fi

    print_ok "Central Master and all detected local ocserv instance Node integrations are ready."
    return 0
}

central_self_test_handlers() {
    local fn missing=0
    local handlers=(
        master_menu
        open_manager_multi_instance
        install_both_master_and_local_nodes
        node_menu
        full_status
        uninstall_node
        uninstall_master
        apply_program_update_without_reconfigure
        install_master
        install_node
        apply_master_update_menu
        apply_node_update_menu
    )
    for fn in "${handlers[@]}"; do
        if ! declare -F "$fn" >/dev/null 2>&1; then
            print_err "Central handler is referenced but not defined: $fn"
            missing=1
        fi
    done
    if (( missing != 0 )); then
        return 1
    fi

    # Regression guard for set -e: display/report helpers must not fail merely
    # because an optional file is absent. This exact class of bug previously
    # made a successful Central update return exit=1 after Master health passed.
    if ! (
        MASTER_SERVICE="/nonexistent/ocserv-central.service"
        MASTER_ETC="/nonexistent/ocserv-central"
        DB_DIR="/nonexistent/ocserv-central-db"
        NODE_ETC="/nonexistent/ocserv-central-node"
        CLEANUP_ENV="/nonexistent/ocserv-central-cleanup.env"
        show_preserved_update_settings >/dev/null
    ); then
        print_err "Central nonfatal-helper self-test failed: show_preserved_update_settings returned nonzero with optional files absent."
        return 1
    fi

    echo "Central handler/runtime self-test: OK (${#handlers[@]} required handlers + nonfatal update-report helper)."
    return 0
}

main_menu() {
    need_root
    while true; do
        safe_clear
        echo "=============================================="
        echo "       Ocserv Central Manager v20.4.4"
        echo "=============================================="
        echo "1) Master server menu"
        echo "2) Local ocserv instances / Node integration (multi-instance, recommended)"
        echo "3) Install both Master and Node(s) on this server (all local ocserv instances)"
        echo "4) Legacy single-instance Node menu (standalone/non-Manager installs)"
        echo "5) Full status"
        echo "6) Uninstall legacy Node part"
        echo "7) Uninstall Master part"
        echo "8) Apply program update without reconfigure"
        echo "0) Exit"
        echo
        read -rp "Select: " choice
        case "$choice" in
            1) master_menu ;;
            2) open_manager_multi_instance ;;
            3) install_both_master_and_local_nodes; pause ;;
            4) node_menu ;;
            5) full_status; if manager_multi_instance_available; then echo; /usr/local/sbin/ocserv-manager --central-instances-status; fi; pause ;;
            6) uninstall_node; pause ;;
            7) uninstall_master; pause ;;
            8) apply_program_update_without_reconfigure; pause ;;
            0) exit 0 ;;
            *) echo "Invalid choice"; sleep 1 ;;
        esac
    done
}

case "${1:-}" in
    --apply-update)
        apply_program_update_without_reconfigure
        exit $?
        ;;
    --apply-master-update)
        apply_master_update_menu
        exit $?
        ;;
    --apply-node-update)
        apply_node_update_menu
        exit $?
        ;;
    --install-master)
        install_master
        exit $?
        ;;
    --install-node)
        install_node
        exit $?
        ;;
    --install-both)
        install_both_master_and_local_nodes
        exit $?
        ;;
    --master-menu)
        master_menu
        exit $?
        ;;
    --node-menu)
        node_menu
        exit $?
        ;;
    --full-status)
        full_status
        exit $?
        ;;
    --uninstall-master)
        uninstall_master
        exit $?
        ;;
    --uninstall-node)
        uninstall_node
        exit $?
        ;;
    --self-test-handlers)
        central_self_test_handlers
        exit $?
        ;;
    --version|-V)
        echo "ocserv-central-manager $PROGRAM_VERSION"
        exit 0
        ;;
    --help|-h)
        cat <<'EOHELP'
ocserv-central-manager v20.4.4 (embedded in Ocserv Manager)
  --install-master       Install/reconfigure Master
  --install-node         Install/reconfigure legacy single-config Node
  --install-both         Install Master + attach all local ocserv instances as Nodes
  --master-menu          Open Master feature menu
  --node-menu            Open legacy single-instance Node feature menu
  --full-status          Show Central status
  --uninstall-master     Safely uninstall Master (interactive preservation choices)
  --uninstall-node       Safely uninstall Node and restore ocserv hook backup
  --apply-update         Update installed Central components without reconfigure
  --apply-master-update  Update Master code without reconfigure
  --apply-node-update    Update Node code without reconfigure
  --self-test-handlers   Validate that all required menu/CLI handlers exist
  --version              Show version
EOHELP
        exit 0
        ;;
esac

main_menu
__OCSERV_MANAGER_EMBEDDED_CENTRAL_V20_7F3A1D__
    chmod 700 "$destination"
}

embedded_central_sha256() {
    local tmp hash
    tmp="$(mktemp)"
    extract_embedded_central_manager "$tmp"
    hash="$(sha256sum "$tmp" | awk '{print $1}')"
    rm -f "$tmp"
    printf '%s\n' "$hash"
}

central_manager_installed() {
    [[ -x "$CENTRAL_MANAGER_BIN" ]]
}

install_embedded_central_manager_code() {
    local tmp current_hash new_hash backup=""
    need_root
    ensure_dirs
    tmp="$(mktemp)"
    extract_embedded_central_manager "$tmp"
    bash -n "$tmp" || { rm -f "$tmp"; print_err "Embedded Central Manager failed syntax validation."; return 1; }
    "$tmp" --self-test-handlers >/dev/null || { rm -f "$tmp"; print_err "Embedded Central Manager failed handler self-test; runtime was not replaced."; return 1; }
    new_hash="$(sha256sum "$tmp" | awk '{print $1}')"
    current_hash=""
    [[ -f "$CENTRAL_MANAGER_BIN" ]] && current_hash="$(sha256sum "$CENTRAL_MANAGER_BIN" | awk '{print $1}')"
    if [[ "$current_hash" == "$new_hash" ]]; then
        rm -f "$tmp"
        print_ok "Integrated Central Manager $CENTRAL_EMBEDDED_VERSION is already installed and current."
        return 0
    fi
    if [[ -f "$CENTRAL_MANAGER_BIN" ]] && ask_yes_no "Create a persistent backup of the currently installed Central Manager code before replacing it?" "y"; then
        ensure_backup_root
        backup="$BACKUP_ROOT/central-code-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$backup"
        cp -a "$CENTRAL_MANAGER_BIN" "$backup/ocserv-central-manager.previous"
    fi
    install -m 700 "$tmp" "$CENTRAL_MANAGER_BIN"
    rm -f "$tmp"
    cat > "$CENTRAL_EMBED_STATE" <<EOF
EMBEDDED_VERSION="$CENTRAL_EMBEDDED_VERSION"
EMBEDDED_SHA256="$new_hash"
INSTALLED_AT="$(date -Is)"
EOF
    chmod 600 "$CENTRAL_EMBED_STATE"
    print_ok "Integrated Central Manager installed from this single Ocserv Manager script: $CENTRAL_MANAGER_BIN"
    if [[ -n "$backup" ]]; then
        print_info "Previous Central Manager code backup: $backup"
    fi
    return 0
}

update_embedded_central_without_reconfigure() {
    local tmp
    need_root
    tmp="$(mktemp)"
    extract_embedded_central_manager "$tmp"
    bash -n "$tmp" || { rm -f "$tmp"; print_err "Embedded Central Manager failed syntax validation."; return 1; }
    "$tmp" --self-test-handlers >/dev/null || { rm -f "$tmp"; print_err "Embedded Central Manager failed handler self-test; update was not applied."; return 1; }
    if [[ -x "$CENTRAL_MANAGER_BIN" || -f /etc/systemd/system/ocserv-central.service || -f /etc/systemd/system/ocserv-central-agent.service ]]; then
        print_info "Applying integrated Central $CENTRAL_EMBEDDED_VERSION code update without reconfigure..."
        "$tmp" --apply-update
        local rc=$?
        if (( rc == 0 )); then
            install -m 700 "$tmp" "$CENTRAL_MANAGER_BIN"
            cat > "$CENTRAL_EMBED_STATE" <<EOF
EMBEDDED_VERSION="$CENTRAL_EMBEDDED_VERSION"
EMBEDDED_SHA256="$(sha256sum "$tmp" | awk '{print $1}')"
INSTALLED_AT="$(date -Is)"
EOF
            chmod 600 "$CENTRAL_EMBED_STATE"
        fi
        rm -f "$tmp"
        return "$rc"
    fi
    install -m 700 "$tmp" "$CENTRAL_MANAGER_BIN"
    rm -f "$tmp"
    print_ok "Central Manager code installed. No Central Master/Node components were configured, so no reconfigure was needed."
}

launch_embedded_central() {
    install_embedded_central_manager_code || return 1
    "$CENTRAL_MANAGER_BIN" "${1:-}"
}

integrated_central_status() {
    echo "Integrated Central source: $CENTRAL_EMBEDDED_VERSION (inside $PROGRAM_NAME)"
    if central_manager_installed; then
        echo "Central runtime command: installed ($CENTRAL_MANAGER_BIN)"
        "$CENTRAL_MANAGER_BIN" --version 2>/dev/null || true
    else
        echo "Central runtime command: not installed (feature is optional)"
    fi
    echo "Master service: $(systemctl is-active ocserv-central 2>/dev/null || echo not-installed)"
    echo "Legacy Central Node service: $(systemctl is-active ocserv-central-agent 2>/dev/null || echo not-installed)"
    echo "Native multi-instance sources/adapters:"
    local i any=0
    while read -r i; do
        [[ -n "$i" ]] || continue
        if [[ "$(state_get "$i" CENTRAL_ENABLED 2>/dev/null || echo 0)" == 1 ]]; then
            any=1
            echo "- $i: $(systemctl is-active "$(central_agent_service "$i")" 2>/dev/null || echo inactive)"
        fi
    done < <(list_instances | sort -u)
    (( any == 1 )) || echo "- none"
}

central_menu() {
    local rc=0
    migrate_central_multi_instance_v20_once
    print_info "Opening the integrated Ocserv Central Manager console."
    print_info "Master, multi-instance Node integration, quota, expiry, global sessions, backup/restore, cleanup, status and updates are managed inside this single console."
    if ! install_embedded_central_manager_code; then
        print_err "Could not install/update the embedded Central Manager runtime."
        return 0
    fi

    # Run Central as a child console, but never let an internal UI/runtime error
    # terminate the parent Ocserv Manager under `set -e`/ERR trap.
    if "$CENTRAL_MANAGER_BIN"; then
        rc=0
    else
        rc=$?
    fi
    if (( rc != 0 )); then
        print_err "Integrated Central Manager exited with code $rc."
        print_info "The parent Ocserv Manager is still running. Central runtime: $CENTRAL_MANAGER_BIN"
        print_info "Diagnostic commands: $CENTRAL_MANAGER_BIN --version ; bash -n $CENTRAL_MANAGER_BIN"
        if [[ -z "${TERM:-}" ]]; then
            print_warn "TERM is empty. The Central console no longer requires terminal clearing, but setting TERM=xterm-256color is recommended for interactive SSH sessions."
        fi
        pause
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Backup / restore / import / migration
# -----------------------------------------------------------------------------
backup_metadata() {
    local out="$1"
    {
        echo "program=$PROGRAM_NAME"
        echo "program_version=$PROGRAM_VERSION"
        echo "embedded_central_version=$CENTRAL_EMBEDDED_VERSION"
        echo "created_at=$(date -Is)"
        echo "hostname=$(hostname -f 2>/dev/null || hostname)"
        echo "ocserv_version=$(installed_ocserv_version)"
        echo "instances=$(list_instances | tr '\n' ' ')"
    } > "$out"
}

create_backup_archive() {
    local include_le="${1:-0}" include_central="${2:-0}" label="${3:-manual}" dest_root="${4:-$BACKUP_ROOT}" stamp staging archive i cert key p
    stamp="$(date +%Y%m%d-%H%M%S)"
    if [[ "$dest_root" == "$BACKUP_ROOT" ]]; then ensure_backup_root; else mkdir -p "$dest_root"; fi
    staging="$(mktemp -d "$dest_root/.staging.XXXXXX")"
    archive="$dest_root/ocserv-manager-$label-$stamp.tar.gz"
    mkdir -p "$staging/rootfs/etc/systemd/system" "$staging/meta"
    backup_metadata "$staging/meta/manifest.txt"
    cp -a "$OCSERV_ETC" "$staging/rootfs/etc/" 2>/dev/null || true
    cp -a "$MANAGER_ETC" "$staging/rootfs/etc/" 2>/dev/null || true
    for p in "$SYSTEMD_DEFAULT" "$SYSTEMD_TEMPLATE" /etc/systemd/system/ocserv-manager-central@.service "$API_SERVICE"; do
        [[ -e "$p" ]] && cp -a "$p" "$staging/rootfs/etc/systemd/system/"
    done
    mkdir -p "$staging/rootfs/usr/local/sbin" "$staging/rootfs/usr/local/lib"
    [[ -e "$MANAGER_BIN" ]] && cp -a "$MANAGER_BIN" "$staging/rootfs/usr/local/sbin/"
    [[ -e "$CENTRAL_MANAGER_BIN" ]] && cp -a "$CENTRAL_MANAGER_BIN" "$staging/rootfs/usr/local/sbin/"
    [[ -d /usr/local/lib/ocserv-manager ]] && cp -a /usr/local/lib/ocserv-manager "$staging/rootfs/usr/local/lib/"
    iptables-save > "$staging/meta/iptables.rules" 2>/dev/null || true
    systemctl list-unit-files 'ocserv*.service' --no-legend > "$staging/meta/systemd-units.txt" 2>/dev/null || true

    # Copy referenced custom certificate/key files if they live outside /etc/ocserv.
    mkdir -p "$staging/external-certs"
    while IFS= read -r i; do
        [[ -n "$i" ]] || continue
        for p in "$(state_get "$i" SERVER_CERT 2>/dev/null || true)" "$(state_get "$i" SERVER_KEY 2>/dev/null || true)" "$(state_get "$i" CLIENT_CA 2>/dev/null || true)"; do
            [[ -f "$p" ]] || continue
            if [[ "$p" != /etc/ocserv/* && "$p" != /etc/letsencrypt/* ]]; then
                local safe
                safe="$(printf '%s' "$p" | sed 's#^/##; s#/#__#g')"
                cp -L -a "$p" "$staging/external-certs/$safe" || true
                printf '%s\t%s\n' "$safe" "$p" >> "$staging/meta/external-cert-map.tsv"
            fi
        done
    done < <(list_instances | sort -u)

    if [[ "$include_le" == 1 && -d /etc/letsencrypt ]]; then
        mkdir -p "$staging/rootfs/etc"
        cp -a /etc/letsencrypt "$staging/rootfs/etc/"
    fi
    if [[ "$include_central" == 1 ]]; then
        for p in /etc/ocserv-central /etc/ocserv-central-node /var/lib/ocserv-central /opt/ocserv-central; do
            if [[ -e "$p" ]]; then mkdir -p "$staging/rootfs$(dirname "$p")"; cp -a "$p" "$staging/rootfs$(dirname "$p")/"; fi
        done
        for p in /etc/systemd/system/ocserv-central.service /etc/systemd/system/ocserv-central-agent.service /etc/systemd/system/ocserv-central-cleanup.service /etc/systemd/system/ocserv-central-cleanup.timer; do
            [[ -e "$p" ]] && cp -a "$p" "$staging/rootfs/etc/systemd/system/"
        done
    fi
    tar -C "$staging" -czf "$archive" .
    rm -rf "$staging"
    chmod 600 "$archive"
    audit "backup-create archive=$archive letsencrypt=$include_le central=$include_central"
    echo "$archive"
}

backup_interactive() {
    local le=0 central=0 archive
    [[ -d /etc/letsencrypt ]] && ask_yes_no "Include /etc/letsencrypt (contains private keys and possibly certificates unrelated to ocserv)?" "n" && le=1
    [[ -d /etc/ocserv-central || -d /var/lib/ocserv-central ]] && ask_yes_no "Include Central Manager database/configuration too?" "y" && central=1
    archive="$(create_backup_archive "$le" "$central" manual)"
    print_ok "Backup created: $archive"
}

validate_manager_archive() {
    local archive="$1"
    [[ -f "$archive" ]] || return 1
    python3 - "$archive" <<'PYMGRVAL'
import pathlib, posixpath, sys, tarfile
archive=sys.argv[1]
allowed_prefixes=(
    'rootfs/etc/ocserv',
    'rootfs/etc/ocserv-manager',
    'rootfs/etc/letsencrypt',
    'rootfs/etc/ocserv-central',
    'rootfs/etc/ocserv-central-node',
    'rootfs/var/lib/ocserv-central',
    'rootfs/opt/ocserv-central',
    'rootfs/usr/local/lib/ocserv-manager',
)
allowed_exact={
    'rootfs/usr/local/sbin/ocserv-manager',
    'rootfs/usr/local/sbin/ocserv-central-manager',
    'rootfs/etc/systemd/system/ocserv.service',
    'rootfs/etc/systemd/system/ocserv@.service',
    'rootfs/etc/systemd/system/ocserv-manager-central@.service',
    'rootfs/etc/systemd/system/ocserv-manager-api.service',
    'rootfs/etc/systemd/system/ocserv-manager-firewall.service',
    'rootfs/etc/systemd/system/ocserv-central.service',
    'rootfs/etc/systemd/system/ocserv-central-agent.service',
    'rootfs/etc/systemd/system/ocserv-central-cleanup.service',
    'rootfs/etc/systemd/system/ocserv-central-cleanup.timer',
}
parent_dirs={
    '.', 'rootfs','rootfs/etc','rootfs/etc/systemd','rootfs/etc/systemd/system',
    'rootfs/usr','rootfs/usr/local','rootfs/usr/local/sbin','rootfs/usr/local/lib',
    'rootfs/var','rootfs/var/lib','rootfs/opt','meta','external-certs'
}
def allowed(name, isdir=False):
    if name in parent_dirs: return True
    if name=='meta' or name.startswith('meta/'): return True
    if name=='external-certs' or name.startswith('external-certs/'): return True
    if name in allowed_exact: return True
    return any(name==p or name.startswith(p.rstrip('/')+'/') for p in allowed_prefixes)
def safe_link(member, clean):
    target=member.linkname
    if target.startswith('/'): return False
    resolved=posixpath.normpath(posixpath.join(posixpath.dirname(clean), target))
    if resolved.startswith('../') or resolved=='..': return False
    # Links must stay inside the same manager-owned allowed area. This also
    # permits normal Let's Encrypt live -> ../../archive links.
    return allowed(resolved)
try:
    with tarfile.open(archive,'r:gz') as t:
        members=t.getmembers()
        if not members: raise ValueError('empty archive')
        has_rootfs=False
        for m in members:
            raw=m.name
            if raw.startswith('/'): raise ValueError('absolute path')
            clean=raw[2:] if raw.startswith('./') else raw
            clean=clean.rstrip('/') or '.'
            parts=pathlib.PurePosixPath(clean).parts
            if '..' in parts: raise ValueError('parent traversal')
            if m.isdev() or m.isfifo(): raise ValueError('device/FIFO entry')
            if not allowed(clean, m.isdir()): raise ValueError(f'unexpected backup path: {clean}')
            if m.issym() or m.islnk():
                if not safe_link(m, clean): raise ValueError(f'unsafe link: {clean} -> {m.linkname}')
            if clean=='rootfs' or clean.startswith('rootfs/'):
                has_rootfs=True
        if not has_rootfs: raise ValueError('backup has no rootfs payload')
except Exception as e:
    print(e, file=sys.stderr)
    raise SystemExit(1)
PYMGRVAL
}

extract_manager_archive_safe() {
    local archive="$1" destination="$2"
    validate_manager_archive "$archive" || return 1
    python3 - "$archive" "$destination" <<'PYMGREX'
import sys, tarfile
archive,dest=sys.argv[1:]
with tarfile.open(archive,'r:gz') as t:
    try:
        t.extractall(dest, filter='data')
    except TypeError:
        t.extractall(dest)
PYMGREX
}

apply_manager_extracted_payload() {
    local tmp="$1" mapline safe original
    [[ -d "$tmp/rootfs" ]] || return 1
    cp -a "$tmp/rootfs/." /
    if [[ -f "$tmp/meta/external-cert-map.tsv" ]]; then
        while IFS=$'\t' read -r safe original; do
            [[ -f "$tmp/external-certs/$safe" && "$original" == /* && "$original" != *'..'* ]] || continue
            mkdir -p "$(dirname "$original")"
            cp -a "$tmp/external-certs/$safe" "$original"
            chmod 600 "$original" 2>/dev/null || true
        done < "$tmp/meta/external-cert-map.tsv"
    fi
}

restore_manager_safety_archive() {
    local safety="$1" tmp i
    print_warn "Rolling Manager/ocserv files back to the pre-restore safety backup."
    # Remove only manager-owned configuration trees so files introduced by the
    # failed restore do not survive the rollback.
    rm -rf "$OCSERV_ETC" "$MANAGER_ETC" /usr/local/lib/ocserv-manager
    rm -f "$SYSTEMD_DEFAULT" "$SYSTEMD_TEMPLATE" /etc/systemd/system/ocserv-manager-central@.service "$API_SERVICE" "$FIREWALL_REAPPLY_SERVICE"
    tmp="$(mktemp -d /tmp/ocserv-manager-safety.XXXXXX)"
    if ! extract_manager_archive_safe "$safety" "$tmp"; then
        rm -rf "$tmp"
        print_err "CRITICAL: automatic rollback archive could not be extracted. Safety backup remains at: $safety"
        return 1
    fi
    apply_manager_extracted_payload "$tmp" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
    systemctl daemon-reload >/dev/null 2>&1 || true
    write_systemd_units >/dev/null 2>&1 || true
    while read -r i; do [[ -n "$i" ]] && apply_firewall_for_instance "$i" >/dev/null 2>&1 || true; done < <(list_instances | sort -u)
    validate_all_configs >/dev/null 2>&1 || print_warn "Safety backup was restored but one or more configs still need manual inspection."
    return 0
}

restore_backup_interactive() {
    local archive safety tmp i include_le_safety=0 failed=0
    archive="$(ask_nonempty "Backup archive path")"
    validate_manager_archive "$archive" || { print_err "Archive validation failed, contains unsafe/unexpected paths, or is not an Ocserv Manager backup."; return 1; }
    echo "Backup manifest:"
    tar -xOzf "$archive" ./meta/manifest.txt 2>/dev/null || true
    ask_yes_no "Restore this backup transactionally?" "n" || return 0
    tar -tzf "$archive" 2>/dev/null | grep -qE '^\./?rootfs/etc/letsencrypt(/|$)' && include_le_safety=1 || true
    local keep_safety=0 safety_root
    if ask_yes_no "Create a persistent current-state backup before restore?" "y"; then
        safety_root="$BACKUP_ROOT"; keep_safety=1
    else
        safety_root="$(mktemp -d /tmp/ocserv-manager-restore-rollback.XXXXXX)"
        print_warn "Persistent restore backup skipped. A temporary rollback archive will be removed after the restore/rollback finishes."
    fi
    safety="$(create_backup_archive "$include_le_safety" 1 before-restore "$safety_root")"
    (( keep_safety == 1 )) && print_ok "Persistent current-state safety backup: $safety"
    tmp="$(mktemp -d /tmp/ocserv-manager-restore.XXXXXX)"
    if ! extract_manager_archive_safe "$archive" "$tmp"; then
        rm -rf "$tmp"; print_err "Safe extraction failed. Nothing was changed."; return 1
    fi

    # Stop only manager-owned control services while their files may be replaced.
    systemctl stop ocserv-manager-api >/dev/null 2>&1 || true
    if [[ -d "$tmp/rootfs/etc/ocserv-central" || -d "$tmp/rootfs/var/lib/ocserv-central" || -d "$tmp/rootfs/opt/ocserv-central" ]]; then
        systemctl stop ocserv-central >/dev/null 2>&1 || true
    fi

    apply_manager_extracted_payload "$tmp" || failed=1
    rm -rf "$tmp"
    systemctl daemon-reload >/dev/null 2>&1 || failed=1
    write_systemd_units >/dev/null 2>&1 || failed=1

    if (( failed == 0 )) && ! validate_all_configs; then
        print_err "Restored files contain an invalid ocserv configuration."
        failed=1
    fi

    if (( failed == 0 )); then
        while read -r i; do
            [[ -n "$i" ]] || continue
            if ! apply_firewall_for_instance "$i"; then failed=1; break; fi
        done < <(list_instances | sort -u)
    fi

    if (( failed == 0 )); then
        while read -r i; do
            [[ -n "$i" ]] || continue
            if systemctl is-enabled --quiet "$(instance_service "$i")" 2>/dev/null || systemctl is-active --quiet "$(instance_service "$i")" 2>/dev/null; then
                if ! systemctl restart "$(instance_service "$i")"; then failed=1; break; fi
            fi
        done < <(list_instances | sort -u)
    fi

    if (( failed == 1 )); then
        restore_manager_safety_archive "$safety" || true
        print_err "Restore failed and automatic rollback was attempted."
        (( keep_safety == 1 )) && print_info "Safety backup: $safety"
        if (( keep_safety == 0 )); then rm -f "$safety" 2>/dev/null || true; rmdir "$safety_root" 2>/dev/null || true; fi
        return 1
    fi

    ensure_firewall_boot_persistence_for_existing_instances
    systemctl try-restart ocserv-manager-api >/dev/null 2>&1 || true
    if [[ -f /etc/systemd/system/ocserv-central.service ]]; then
        # Keep Central code compatible with this Manager without changing its saved settings.
        update_embedded_central_without_reconfigure || print_warn "Central data was restored, but its code refresh/health check reported an issue. Open Central Manager status before relying on it."
    fi
    audit "backup-restore archive=$archive safety=$([[ $keep_safety == 1 ]] && echo "$safety" || echo declined)"
    print_ok "Transactional restore completed."
    if (( keep_safety == 1 )); then print_info "Safety backup kept at: $safety"; else rm -f "$safety" 2>/dev/null || true; rmdir "$safety_root" 2>/dev/null || true; print_info "Persistent safety backup: not created (declined)"; fi
}

parse_config_value() {
    local conf="$1" key="$2"
    awk -v k="$key" '
      /^[[:space:]]*\[vhost:/ {exit}
      /^[[:space:]]*#/ {next}
      {line=$0; sub(/^[[:space:]]*/,"",line); if(index(line,k)==1){rest=substr(line,length(k)+1); if(rest ~ /^[[:space:]]*=/){sub(/^[[:space:]]*=[[:space:]]*/,"",rest); gsub(/^"|"$/,"",rest); print rest; exit}}}
    ' "$conf"
}

parse_plain_passwd_from_config() {
    local conf="$1"
    sed -nE '/^[[:space:]]*auth[[:space:]]*=/s/.*passwd=([^],"]+).*/\1/p' "$conf" | head -n1
}

import_existing_config() {
    local conf="$1" instance="${2:-}" listen tcp udp subnet netmask passwd auth cert key sock service
    [[ -f "$conf" ]] || { print_err "Config not found: $conf"; return 1; }
    if [[ -z "$instance" ]]; then
        if [[ "$conf" == /etc/ocserv/ocserv.conf ]]; then instance=default; else
            instance="$(ask_nonempty "Name to register this existing instance under")"; safe_name "$instance" || { print_err "Invalid name."; return 1; }
        fi
    fi
    listen="$(parse_config_value "$conf" listen-host)"; listen="${listen:-0.0.0.0}"
    tcp="$(parse_config_value "$conf" tcp-port)"; tcp="${tcp:-443}"
    udp="$(parse_config_value "$conf" udp-port)"; udp="${udp:-$tcp}"
    subnet="$(parse_config_value "$conf" ipv4-network)"; subnet="${subnet:-192.168.100.0/24}"
    if [[ "$subnet" != */* ]]; then
        netmask="$(parse_config_value "$conf" ipv4-netmask)"
        if [[ -n "$netmask" ]]; then subnet="$(python3 - "$subnet" "$netmask" <<'PY'
import ipaddress,sys
print(ipaddress.ip_network(f"{sys.argv[1]}/{sys.argv[2]}",strict=False))
PY
)"; else subnet="$subnet/24"; fi
    fi
    passwd="$(parse_plain_passwd_from_config "$conf")"; passwd="${passwd:-$(instance_passwd "$instance")}"
    auth="$(grep -E '^[[:space:]]*auth[[:space:]]*=' "$conf" | head -n1 | sed 's/^[[:space:]]*//' || true)"
    cert="$(parse_config_value "$conf" server-cert)"; key="$(parse_config_value "$conf" server-key)"; sock="$(parse_config_value "$conf" occtl-socket-file)"
    ensure_instance_layout "$instance"
    register_instance "$instance" "$conf" "$passwd" "$subnet" "$tcp" "$udp" "$listen" "imported"
    state_set "$instance" CONFIG "$conf"; state_set "$instance" MANAGED 0
    state_set "$instance" SERVER_CERT "$cert"; state_set "$instance" SERVER_KEY "$key"
    [[ -n "$sock" ]] && state_set "$instance" OCCTL_SOCKET "$sock"
    state_set "$instance" AUTH_LINES "$(printf '%s' "$auth" | base64 -w0)"
    service="$(instance_service "$instance")"; state_set "$instance" SERVICE "$service"
    audit "instance-import instance=$instance config=$conf"
    print_ok "Existing installation registered without rewriting its config or users."
    print_info "It remains in preservation/imported mode. If you adopt it, this exact config becomes the structural base and the manager changes only selected/required directives."
}

detect_existing_installations() {
    local conf
    [[ -f /etc/ocserv/ocserv.conf ]] && echo "/etc/ocserv/ocserv.conf"
    find "$INSTANCE_ROOT" -mindepth 2 -maxdepth 2 -name ocserv.conf -type f 2>/dev/null | sort || true
    while read -r conf; do [[ -f "$conf" ]] && echo "$conf"; done < <(systemctl cat ocserv.service 2>/dev/null | sed -nE 's/.*--config(=|[[:space:]])([^[:space:]]+).*/\2/p')
}

import_existing_menu() {
    local -a configs=(); local c idx instance
    mapfile -t configs < <(detect_existing_installations | sort -u)
    if ((${#configs[@]}==0)); then print_warn "No existing ocserv configuration was detected."; return 0; fi
    echo "Detected configs:"
    for idx in "${!configs[@]}"; do echo "$((idx+1))) ${configs[$idx]}"; done
    idx="$(ask_integer "Select config" "1" 1 "${#configs[@]}")"
    c="${configs[$((idx-1))]}"
    if [[ "$c" == /etc/ocserv/ocserv.conf ]]; then instance=default; else instance="$(basename "$(dirname "$c")")"; fi
    import_existing_config "$c" "$instance"
}

adopt_imported_instance() {
    local instance="$1" oldconf tmp passwd
    [[ "$(state_get "$instance" MANAGED 2>/dev/null || echo 0)" == 0 ]] || { print_info "Instance is already manager-owned."; return 0; }
    oldconf="$(state_get "$instance" CONFIG 2>/dev/null || instance_config "$instance")"
    print_warn "Adoption preserves the existing config as the structural base. The manager will change only the directives selected/required by the wizard and keep the remaining original comments/options."
    ask_yes_no "Proceed with interactive adoption/reconfiguration?" "n" || return 0
    # Manager-owned instances use the canonical layout. The imported source is preserved.
    local managed_conf
    managed_conf="$(standard_instance_config "$instance")"
    mkdir -p "$(dirname "$managed_conf")"
    if [[ "$oldconf" != "$managed_conf" ]]; then
        cp -a "$oldconf" "$managed_conf.imported-copy"
    fi
    mkdir -p "$INSTANCE_BASE_ROOT"
    cp -a "$oldconf" "$INSTANCE_BASE_ROOT/$instance.conf"
    chmod 600 "$INSTANCE_BASE_ROOT/$instance.conf"
    state_set "$instance" BASE_CONFIG "$INSTANCE_BASE_ROOT/$instance.conf"
    state_set "$instance" CONFIG "$managed_conf"
    while ! configure_server_certificate "$instance"; do :; done
    configure_authentication "$instance"
    choose_dns_servers "$instance"; configure_limits_and_bans "$instance"; configure_network_profile "$instance"; configure_routing_profile "$instance"
    state_set "$instance" CENTRAL_ENABLED 0; state_set "$instance" MANAGED 1
    tmp="$(mktemp)"; generate_ocserv_config "$instance" "$tmp"; transactional_replace_config "$instance" "$tmp"; rm -f "$tmp"
    apply_firewall_for_instance "$instance"; write_systemd_units
    start_managed_instance_bounded "$instance" || { print_err "Imported instance did not start promptly."; return 1; }
    print_ok "Imported installation adopted."
}

migrate_default_to_named_instance() {
    local target source=default olddir newdir newsub tcp udp listen tmp
    [[ -f /etc/ocserv/ocserv.conf ]] || { print_err "Default config not found."; return 1; }
    [[ -f "$(instance_state_file default)" ]] || import_existing_config /etc/ocserv/ocserv.conf default
    target="$(ask_nonempty "New named instance name" "default1")"; safe_name "$target" && [[ "$target" != default ]] || { print_err "Invalid name."; return 1; }
    [[ ! -e "$(instance_state_file "$target")" ]] || { print_err "Target already exists."; return 1; }
    print_info "Migration uses a copy; the original default instance remains untouched until you explicitly delete it."
    newdir="$(instance_dir "$target")"; mkdir -p "$newdir"
    cp -a /etc/ocserv/ocpasswd "$newdir/ocpasswd" 2>/dev/null || touch "$newdir/ocpasswd"
    listen="$(state_get default LISTEN_HOST 2>/dev/null || echo 0.0.0.0)"
    tcp="$(choose_available_tcp_port "$target" "$listen" 8443)"; udp="$(choose_available_udp_port "$target" "$listen" "$tcp")"; newsub="$(choose_subnet "$target")"
    cp -a "$(instance_state_file default)" "$(instance_state_file "$target")"
    ensure_supplemental_config_state default
    local source_cpu source_cpg source_cpu_dir source_cpg_dir
    source_cpu="$(state_get default CONFIG_PER_USER_ENABLED 2>/dev/null || echo 0)"
    source_cpg="$(state_get default CONFIG_PER_GROUP_ENABLED 2>/dev/null || echo 0)"
    source_cpu_dir="$(user_dir default)"; source_cpg_dir="$(group_dir default)"
    state_set "$target" CONFIG_PER_USER_ENABLED "$source_cpu"
    state_set "$target" CONFIG_PER_GROUP_ENABLED "$source_cpg"
    state_set "$target" CONFIG_PER_USER_DIR "$newdir/config-per-user/"
    state_set "$target" CONFIG_PER_GROUP_DIR "$newdir/config-per-group/"
    if [[ "$source_cpu" == 1 && -d "$source_cpu_dir" ]]; then cp -a "$source_cpu_dir" "$newdir/config-per-user"; fi
    if [[ "$source_cpg" == 1 && -d "$source_cpg_dir" ]]; then cp -a "$source_cpg_dir" "$newdir/config-per-group"; fi
    local source_base target_base
    source_base="$(ensure_instance_base_config default)" || return 1
    target_base="$INSTANCE_BASE_ROOT/$target.conf"; cp -a "$source_base" "$target_base"; chmod 600 "$target_base"
    state_set "$target" BASE_CONFIG "$target_base"
    state_set "$target" NAME "$target"; state_set "$target" CONFIG "$(standard_instance_config "$target")"; state_set "$target" OCPASSWD "$newdir/ocpasswd"
    state_set "$target" TCP_PORT "$tcp"; state_set "$target" UDP_PORT "$udp"; state_set "$target" SUBNET "$newsub"; state_set "$target" IPV6_NETWORK ""; state_set "$target" IPV6_NAT 0; state_set "$target" SERVICE "$(instance_service "$target")"; state_set "$target" OCCTL_SOCKET "$(instance_socket "$target")"; state_set "$target" MANAGED 1
    # If default was merely imported, collect missing manager settings through adoption-style wizard.
    if [[ "$(state_get default MANAGED 2>/dev/null || echo 0)" != 1 ]]; then
        print_info "The source was not manager-owned; configure the new copy now."
        while ! configure_server_certificate "$target"; do :; done
        configure_authentication "$target"; choose_dns_servers "$target"; configure_limits_and_bans "$target"; configure_network_profile "$target"; configure_routing_profile "$target"; state_set "$target" CENTRAL_ENABLED 0
    fi
    tmp="$(mktemp)"; generate_ocserv_config "$target" "$tmp"; transactional_replace_config "$target" "$tmp"; rm -f "$tmp"
    apply_firewall_for_instance "$target"; write_systemd_units
    start_managed_instance_bounded "$target" || { print_err "Migrated instance did not start promptly."; return 1; }
    print_ok "Migration copy created as $target. The original default installation was preserved."
}

# -----------------------------------------------------------------------------
# Clone/delete instances
# -----------------------------------------------------------------------------
clone_instance() {
    local source="$1" target listen tcp udp subnet olddir newdir shared tmp certreuse
    [[ "$(state_get "$source" MANAGED 2>/dev/null || echo 0)" == 1 ]] || { print_err "Clone currently requires a manager-owned source instance. Adopt imported instances first."; return 1; }
    while true; do target="$(ask_nonempty "New instance name")"; safe_name "$target" && [[ "$target" != default && ! -e "$(instance_state_file "$target")" ]] && break; print_warn "Invalid or existing name."; done
    olddir="$(instance_dir "$source")"; newdir="$(instance_dir "$target")"; mkdir -p "$newdir"
    cp -a "$olddir/." "$newdir/"
    cp -a "$(instance_state_file "$source")" "$(instance_state_file "$target")"
    local source_base target_base
    source_base="$(ensure_instance_base_config "$source")" || return 1
    target_base="$INSTANCE_BASE_ROOT/$target.conf"; cp -a "$source_base" "$target_base"; chmod 600 "$target_base"
    state_set "$target" BASE_CONFIG "$target_base"
    listen="$(choose_listen_host)"
    tcp="$(choose_available_tcp_port "$target" "$listen" 8443)"
    udp="$(choose_available_udp_port "$target" "$listen" "$tcp")"
    subnet="$(choose_subnet "$target")"
    state_set "$target" NAME "$target"; state_set "$target" CONFIG "$(standard_instance_config "$target")"; state_set "$target" LISTEN_HOST "$listen"; state_set "$target" TCP_PORT "$tcp"; state_set "$target" UDP_PORT "$udp"; state_set "$target" SUBNET "$subnet"; state_set "$target" IPV6_NETWORK ""; state_set "$target" IPV6_NAT 0; state_set "$target" SERVICE "$(instance_service "$target")"; state_set "$target" OCCTL_SOCKET "$(instance_socket "$target")"
    state_set "$target" CENTRAL_ENABLED 0; state_set "$target" CENTRAL_HOOK ""
    if ask_yes_no "Share the source user database with the clone?" "y"; then
        state_set "$target" OCPASSWD "$(instance_passwd "$source")"
    else
        state_set "$target" OCPASSWD "$newdir/ocpasswd"
        [[ -f "$olddir/ocpasswd" ]] && cp -a "$olddir/ocpasswd" "$newdir/ocpasswd" || touch "$newdir/ocpasswd"
        chmod 600 "$newdir/ocpasswd"
        # Replace plain auth password path when present.
        local auth
        auth="$(decode_state_b64 "$target" AUTH_LINES)"
        auth="${auth//$(instance_passwd "$source")/$newdir\/ocpasswd}"
        state_set "$target" AUTH_LINES "$(printf '%s' "$auth" | base64 -w0)"
    fi
    if ! ask_yes_no "Reuse the source server certificate/key?" "y"; then
        while ! configure_server_certificate "$target"; do :; done
    fi
    tmp="$(mktemp)"; generate_ocserv_config "$target" "$tmp"; transactional_replace_config "$target" "$tmp"; rm -f "$tmp"
    apply_firewall_for_instance "$target"; write_systemd_units
    start_managed_instance_bounded "$target" || { print_err "Cloned instance did not start promptly."; return 1; }
    audit "instance-clone source=$source target=$target"
    print_ok "Cloned $source to $target."
}

passwd_referenced_elsewhere() {
    local instance="$1" target="$2" i p
    while read -r i; do
        [[ -n "$i" && "$i" != "$instance" ]] || continue
        p="$(instance_passwd "$i" 2>/dev/null || true)"
        [[ "$p" == "$target" ]] && return 0
    done < <(list_instances | sort -u)
    return 1
}

delete_instance() {
    local instance="$1" backup="" passwd dir svc cpu_dir cpg_dir
    svc="$(instance_service "$instance")"; passwd="$(instance_passwd "$instance" 2>/dev/null || true)"; dir="$(instance_dir "$instance")"
    cpu_dir="$(user_dir "$instance" 2>/dev/null || true)"; cpg_dir="$(group_dir "$instance" 2>/dev/null || true)"
    print_warn "This will stop and unregister instance $instance from Ocserv Manager."
    ask_yes_no "Continue?" "n" || return 0
    if ask_yes_no "Create a full safety backup first?" "y"; then backup="$(create_backup_archive 0 1 before-delete-$instance)"; print_ok "Backup: $backup"; fi
    systemctl disable --now "$svc" >/dev/null 2>&1 || true
    if [[ "$(state_get "$instance" CENTRAL_ENABLED 2>/dev/null || echo 0)" == 1 ]]; then
        central_detach_instance "$instance" 1 || print_warn "Central source deregistration could not be confirmed; local adapter files will still be removed."
    else
        systemctl disable --now "$(central_agent_service "$instance")" >/dev/null 2>&1 || true
    fi
    remove_firewall_for_instance "$instance"
    if [[ "$instance" == default ]]; then
        rm -f /etc/ocserv/ocserv.conf
        print_info "Supplemental configs, virtual hosts and certificates are preserved by default; deletion requires an explicit separate confirmation."
        if [[ -n "$cpu_dir" && -d "$cpu_dir" && "$cpu_dir" == /etc/ocserv/* ]] && ask_yes_no "Delete config-per-user directory $cpu_dir too?" "n"; then rm -rf -- "$cpu_dir"; fi
        if [[ -n "$cpg_dir" && -d "$cpg_dir" && "$cpg_dir" == /etc/ocserv/* ]] && ask_yes_no "Delete config-per-group directory $cpg_dir too?" "n"; then rm -rf -- "$cpg_dir"; fi
        [[ -d /etc/ocserv/defaults ]] && ask_yes_no "Delete /etc/ocserv/defaults too?" "n" && rm -rf /etc/ocserv/defaults
        [[ -d /etc/ocserv/vhosts ]] && ask_yes_no "Delete /etc/ocserv/vhosts too?" "n" && rm -rf /etc/ocserv/vhosts
        if [[ -d /etc/ocserv/certs || -d /etc/ocserv/client-ca ]]; then
            if ask_yes_no "Delete manager-local certificate directories /etc/ocserv/certs and /etc/ocserv/client-ca too?" "n"; then
                rm -rf /etc/ocserv/certs /etc/ocserv/client-ca
            fi
        fi
        if [[ -n "$passwd" && "$passwd" == /etc/ocserv/ocpasswd ]] && ! passwd_referenced_elsewhere "$instance" "$passwd"; then
            if ask_yes_no "Delete the default ocpasswd user database too?" "n"; then rm -f "$passwd"; fi
        fi
    else
        if [[ -n "$passwd" && "$passwd" != "$dir/ocpasswd" && -f "$dir/ocpasswd" ]]; then rm -f "$dir/ocpasswd"; fi
        rm -rf "$dir"
    fi
    rm -f "$(instance_state_file "$instance")" "$(central_env_file "$instance")" "$CENTRAL_LIB_DIR/hook-$instance.sh" "$INSTANCE_BASE_ROOT/$instance.conf"
    if ! find "$STATE_ROOT" -maxdepth 1 -type f -name '*.env' -print -quit 2>/dev/null | grep -q .; then
        systemctl disable --now ocserv-manager-firewall.service >/dev/null 2>&1 || true
        rm -f "$FIREWALL_REAPPLY_SERVICE"
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    audit "instance-delete instance=$instance backup=$backup"
    print_ok "Instance $instance removed. Supplemental files, certificates, shared user databases and unrelated files were preserved unless you explicitly chose to delete them."
}

# -----------------------------------------------------------------------------
# Virtual hosts (SNI) within an ocserv process
# -----------------------------------------------------------------------------
vhost_dir() { printf '%s/vhosts\n' "$(instance_dir "$1")"; }

vhost_fw_comment() { printf 'ocserv-manager:vhost:%s:%s\n' "$1" "$2"; }

apply_firewall_for_vhost() {
    local instance="$1" domain="$2" subnet="$3" iface comment
    iface="$(state_get "$instance" OUT_IFACE 2>/dev/null || true)"
    [[ -n "$iface" ]] || iface="$(default_route_iface)"
    [[ -n "$iface" ]] || { print_err "Could not detect outbound interface for vhost $domain."; return 1; }
    comment="$(vhost_fw_comment "$instance" "$domain")"
    enable_ip_forwarding
    [[ "${OCSERV_MANAGER_BOOT_REAPPLY:-0}" == 1 ]] || install_available_packages iptables
    firewall_rule_add nat POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$comment" -j MASQUERADE
    filter_rule_add FORWARD -s "$subnet" -o "$iface" -m comment --comment "$comment" -j ACCEPT
    filter_rule_add FORWARD -d "$subnet" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT
    install_firewall_reapply_unit
    audit "vhost-firewall-applied instance=$instance domain=$domain subnet=$subnet iface=$iface"
}

remove_firewall_for_vhost_values() {
    local instance="$1" domain="$2" subnet="$3" iface comment
    iface="$(state_get "$instance" OUT_IFACE 2>/dev/null || true)"
    [[ -n "$subnet" && -n "$iface" ]] || return 0
    comment="$(vhost_fw_comment "$instance" "$domain")"
    while iptables -t nat -C POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$comment" -j MASQUERADE >/dev/null 2>&1; do
        iptables -t nat -D POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$comment" -j MASQUERADE
    done
    while iptables -C FORWARD -s "$subnet" -o "$iface" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do
        iptables -D FORWARD -s "$subnet" -o "$iface" -m comment --comment "$comment" -j ACCEPT
    done
    while iptables -C FORWARD -d "$subnet" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do
        iptables -D FORWARD -d "$subnet" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT
    done
}

config_ipv4_cidr() {
    local file="$1" network netmask
    network="$(sed -n 's/^[[:space:]]*ipv4-network[[:space:]]*=[[:space:]]*//p' "$file" | head -n1)"
    [[ -n "$network" ]] || return 1
    if [[ "$network" == */* ]]; then normalize_cidr "$network"; return; fi
    netmask="$(sed -n 's/^[[:space:]]*ipv4-netmask[[:space:]]*=[[:space:]]*//p' "$file" | head -n1)"
    [[ -n "$netmask" ]] || netmask="255.255.255.255"
    python3 - "$network" "$netmask" <<'PYV4CIDR'
import ipaddress,sys
print(ipaddress.ip_network(f"{sys.argv[1]}/{sys.argv[2]}", strict=False))
PYV4CIDR
}

cidr_network_and_netmask() {
    python3 - "$1" <<'PYV4PAIR'
import ipaddress,sys
n=ipaddress.ip_network(sys.argv[1], strict=False)
print(n.network_address)
print(n.netmask)
PYV4PAIR
}

remove_all_vhost_firewalls() {
    local instance="$1" dir f domain subnet
    dir="$(vhost_dir "$instance")"
    [[ -d "$dir" ]] || return 0
    for f in "$dir"/*.conf; do
        [[ -f "$f" ]] || continue
        domain="$(basename "$f" .conf)"
        subnet="$(config_ipv4_cidr "$f" 2>/dev/null || true)"
        [[ -n "$subnet" ]] && remove_firewall_for_vhost_values "$instance" "$domain" "$subnet"
    done
}

vhost_self_signed_cert() {
    local instance="$1" domain="$2" dir cert key
    dir="$(instance_dir "$instance")/vhost-certs/$domain"; mkdir -p "$dir"; chmod 700 "$dir"
    cert="$dir/fullchain.pem"; key="$dir/privkey.pem"
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 -subj "/CN=$domain/O=Ocserv Manager VHost" -addext "subjectAltName=DNS:$domain" -keyout "$key" -out "$cert"
    chmod 600 "$key"; chmod 644 "$cert"; echo "$cert|$key"
}

vhost_certificate_pair() {
    local instance="$1" domain="$2" choice pair cert key existing
    existing="$(find_existing_letsencrypt_cert "$domain" 2>/dev/null || true)"
    if [[ -n "$existing" ]] && ask_yes_no "Reuse detected Let's Encrypt/wildcard certificate for $domain?" "y"; then echo "$existing"; return; fi
    choice="$(choose_menu "Certificate for vhost $domain:" "Existing certificate/key paths" "Request Let's Encrypt standalone" "Request Let's Encrypt webroot" "Self-signed")"
    case "$choice" in
        1) while true; do cert="$(ask_nonempty "Certificate/fullchain path")"; key="$(ask_nonempty "Private key path")"; validate_cert_key_pair "$cert" "$key" && { echo "$cert|$key"; return; }; print_warn "Invalid pair."; done ;;
        2) obtain_letsencrypt_certificate "$domain" standalone ;;
        3) obtain_letsencrypt_certificate "$domain" webroot ;;
        4) vhost_self_signed_cert "$instance" "$domain" ;;
    esac
}

vhost_auth_block() {
    local instance="$1" choice passwd otp service gid ca oid group radius groupcfg keytab oidc line
    choice="$(choose_menu "VHost authentication:" "Plain/ocpasswd" "Plain + OTP" "PAM" "Certificate" "Certificate + plain" "RADIUS" "GSSAPI" "OIDC" "Custom directive")"
    case "$choice" in
        1) passwd="$(ask_value "ocpasswd path" "$(instance_passwd "$instance")")"; touch "$passwd"; chmod 600 "$passwd"; echo "auth = \"plain[passwd=$passwd]\"" ;;
        2) passwd="$(ask_value "ocpasswd path" "$(instance_passwd "$instance")")"; otp="$(ask_nonempty "OTP file")"; touch "$passwd" "$otp"; chmod 600 "$passwd" "$otp"; echo "auth = \"plain[passwd=$passwd,otp=$otp]\"" ;;
        3) service="$(ask_nonempty "PAM service" "ocserv")"; gid="$(ask_integer "Minimum GID" "1000" 0 2147483647)"; configure_pam_service "$service"; echo "auth = \"pam[service=$service,gid-min=$gid]\"" ;;
        4|5)
            ca="$(ask_nonempty "Client CA certificate path")"; oid="$(ask_nonempty "Certificate username OID" "0.9.2342.19200300.100.1.1")"
            echo 'auth = "certificate"'
            if [[ "$choice" == 5 ]]; then passwd="$(ask_value "ocpasswd path" "$(instance_passwd "$instance")")"; echo "auth = \"plain[passwd=$passwd]\""; fi
            echo "ca-cert = $ca"; echo "cert-user-oid = $oid"
            ;;
        6) radius="$(ask_nonempty "RADIUS config path" "/etc/radcli/radiusclient.conf")"; if ask_yes_no "Use RADIUS groupconfig?" "n"; then groupcfg=true; else groupcfg=false; fi; echo "auth = \"radius[config=$radius,groupconfig=$groupcfg]\"" ;;
        7) keytab="$(ask_nonempty "Kerberos keytab" "/etc/krb5.keytab")"; echo "auth = \"gssapi[keytab=$keytab,require-local-user-map=true]\"" ;;
        8) oidc="$(ask_value "OIDC JSON path (blank=create)" "")"; [[ -n "$oidc" ]] || oidc="$(write_oidc_json_interactive "$instance")"; echo "auth = \"oidc[config=$oidc]\"" ;;
        9) line="$(ask_nonempty 'Complete auth/enable-auth directive')"; echo "$line" ;;
    esac
}

create_vhost() {
    local instance="$1" domain dir file pair cert key subnet dns routes tunnel maxsame auth tmp vcpu=0 vcpg=0 vcpu_dir vcpg_dir
    [[ "$(state_get "$instance" MANAGED 2>/dev/null || echo 0)" == 1 ]] || { print_err "VHost manager requires a manager-owned base instance."; return 1; }
    while true; do domain="$(ask_nonempty "Virtual host domain/SNI")"; valid_domain "$domain" && break; print_warn "Invalid domain."; done
    dir="$(vhost_dir "$instance")"; mkdir -p "$dir"; file="$dir/$domain.conf"
    [[ ! -f "$file" ]] || { print_err "VHost already exists."; return 1; }
    print_info "Virtual hosts share the process listen IP and TCP/UDP ports; ocserv selects them by TLS SNI."
    pair="$(vhost_certificate_pair "$instance" "$domain")" || return 1; cert="${pair%%|*}"; key="${pair#*|}"
    auth="$(vhost_auth_block "$instance")"
    subnet="$(choose_subnet "__vhost_${instance}")"
    dns="$(ask_value "VHost DNS servers" "$(state_get "$instance" DNS_SERVERS)")"
    if ask_yes_no "Full tunnel for this vhost?" "y"; then routes=default; if ask_yes_no "Tunnel all DNS for this vhost?" "y"; then tunnel=true; else tunnel=false; fi
    else routes="$(ask_nonempty "VHost route CIDRs separated by spaces")"; tunnel=false; fi
    maxsame="$(ask_integer "VHost max-same-clients (0=unlimited)" "0" 0 100000)"
    if ask_yes_no "Enable config-per-user for this vhost?" "n"; then vcpu=1; vcpu_dir="$(instance_dir "$instance")/vhost-config/$domain/users/"; mkdir -p "$vcpu_dir"; chmod 700 "$vcpu_dir"; fi
    if ask_yes_no "Enable config-per-group for this vhost?" "n"; then vcpg=1; vcpg_dir="$(instance_dir "$instance")/vhost-config/$domain/groups/"; mkdir -p "$vcpg_dir"; chmod 700 "$vcpg_dir"; fi
    {
        echo "# Managed virtual host: $domain"
        echo "[vhost:$domain]"
        echo "$auth"
        echo "server-cert = $cert"; echo "server-key = $key"
        local v4net v4mask
        { read -r v4net; read -r v4mask; } < <(cidr_network_and_netmask "$subnet")
        echo "ipv4-network = $v4net"
        echo "ipv4-netmask = $v4mask"
        echo "max-same-clients = $maxsame"
        local x; for x in $dns; do echo "dns = $x"; done
        echo "tunnel-all-dns = $tunnel"
        for x in $routes; do echo "route = $x"; done
        [[ "$vcpu" == 1 ]] && echo "config-per-user = $vcpu_dir"
        [[ "$vcpg" == 1 ]] && echo "config-per-group = $vcpg_dir"
        echo "cisco-client-compat = true"
    } > "$file"
    tmp="$(mktemp)"; generate_ocserv_config "$instance" "$tmp"
    if transactional_replace_config "$instance" "$tmp"; then
        if apply_firewall_for_vhost "$instance" "$domain" "$subnet"; then
            print_ok "VHost $domain created with scoped NAT/FORWARD rules."
            audit "vhost-create instance=$instance domain=$domain subnet=$subnet"
        else
            print_err "VHost firewall setup failed. Rolling the vhost configuration back."
            rm -f "$file"
            generate_ocserv_config "$instance" "$tmp"
            transactional_replace_config "$instance" "$tmp" || true
            return 1
        fi
    else
        rm -f "$file"
        print_err "VHost validation failed; vhost file removed."
    fi
    rm -f "$tmp"
}

list_vhosts() {
    local instance="$1" f dir
    dir="$(vhost_dir "$instance")"; [[ -d "$dir" ]] || { echo "No virtual hosts."; return; }
    for f in "$dir"/*.conf; do [[ -f "$f" ]] || continue; echo "===== $(basename "$f" .conf) ====="; grep -E '^\[vhost:|^auth|^server-cert|^ipv4-network|^ipv4-netmask|^dns|^route|^max-same' "$f" || true; echo; done
}

delete_vhost() {
    local instance="$1" domain file tmp subnet vbackup
    domain="$(ask_nonempty "VHost domain to delete")"; file="$(vhost_dir "$instance")/$domain.conf"
    [[ -f "$file" ]] || { print_err "VHost not found."; return 1; }
    ask_yes_no "Delete virtual host $domain?" "n" || return 0
    subnet="$(config_ipv4_cidr "$file" 2>/dev/null || true)"
    local keep_vbackup=0
    if ask_yes_no "Create a persistent backup of this vhost before deletion?" "y"; then
        ensure_backup_root
        vbackup="$BACKUP_ROOT/vhost-$domain-$(date +%Y%m%d-%H%M%S).conf"
        keep_vbackup=1
    else
        vbackup="$(mktemp /tmp/ocserv-manager-vhost-rollback.XXXXXX)"
    fi
    cp -a "$file" "$vbackup"; rm -f "$file"
    tmp="$(mktemp)"; generate_ocserv_config "$instance" "$tmp"
    if transactional_replace_config "$instance" "$tmp"; then
        [[ -n "$subnet" ]] && remove_firewall_for_vhost_values "$instance" "$domain" "$subnet"
        audit "vhost-delete instance=$instance domain=$domain"; print_ok "VHost deleted."
    else
        cp -a "$vbackup" "$file"
        generate_ocserv_config "$instance" "$tmp"
        transactional_replace_config "$instance" "$tmp" || true
        print_err "Could not safely apply vhost deletion; the vhost file was restored automatically."
        rm -f "$tmp"
        return 1
    fi
    rm -f "$tmp"
    (( keep_vbackup == 0 )) && rm -f "$vbackup" 2>/dev/null || true
}

vhost_menu() {
    local instance="$1" choice
    while true; do
        echo; echo "==== Virtual Hosts: $instance ===="
        echo "1) List virtual hosts"; echo "2) Create virtual host"; echo "3) Delete virtual host"; echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in 1) list_vhosts "$instance"; pause;; 2) create_vhost "$instance"; pause;; 3) delete_vhost "$instance"; pause;; 0) return;; *) print_warn "Invalid selection.";; esac
    done
}

# -----------------------------------------------------------------------------
# Diagnostics, dashboard, certificates and reconfiguration
# -----------------------------------------------------------------------------
port_is_listening() {
    local proto="$1" port="$2" listen="$3"
    if [[ "$proto" == tcp ]]; then ss -ltnH 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" {found=1} END{exit !found}'
    else ss -lunH 2>/dev/null | awk -v p=":$port" '$5 ~ p"$" || $4 ~ p"$" {found=1} END{exit !found}'
    fi
}

run_instance_diagnostics() {
    local instance="$1" svc conf tcp udp listen subnet iface cert days ok=1 bbr
    svc="$(instance_service "$instance")"; conf="$(instance_config "$instance")"; tcp="$(state_get "$instance" TCP_PORT 2>/dev/null || echo 443)"; udp="$(state_get "$instance" UDP_PORT 2>/dev/null || echo "$tcp")"; listen="$(state_get "$instance" LISTEN_HOST 2>/dev/null || echo 0.0.0.0)"; subnet="$(state_get "$instance" SUBNET 2>/dev/null || true)"; iface="$(state_get "$instance" OUT_IFACE 2>/dev/null || default_route_iface || true)"; cert="$(state_get "$instance" SERVER_CERT 2>/dev/null || parse_config_value "$conf" server-cert || true)"
    echo "==== Diagnostics: $instance ===="
    if validate_config "$conf" >/dev/null 2>&1; then print_ok "Config passes ocserv --test-config"; else print_err "Config validation failed"; ok=0; fi
    if systemctl is-active --quiet "$svc"; then print_ok "$svc is active"; else print_err "$svc is not active"; ok=0; fi
    if port_is_listening tcp "$tcp" "$listen"; then print_ok "TCP $tcp is listening"; else print_warn "TCP $tcp not detected as listening"; ok=0; fi
    if port_is_listening udp "$udp" "$listen"; then print_ok "UDP $udp is listening"; else print_warn "UDP $udp not detected as listening (DTLS may be unavailable)"; fi
    if occtl_exec "$instance" show status >/dev/null 2>&1; then print_ok "occtl socket works: $(instance_socket "$instance")"; else print_err "occtl socket query failed"; ok=0; fi
    if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" == 1 ]]; then print_ok "IPv4 forwarding enabled"; else print_err "IPv4 forwarding disabled"; ok=0; fi
    local fwmode natmode ingress forward inchain fwdchain postchain
    fwmode="$(firewall_mode_for_instance "$instance")"
    natmode="$(state_get "$instance" FIREWALL_BASE_NAT_MODE 2>/dev/null || echo masquerade)"
    ingress="$(state_get "$instance" FIREWALL_BASE_INGRESS 2>/dev/null || echo 1)"
    forward="$(state_get "$instance" FIREWALL_BASE_FORWARD 2>/dev/null || echo 1)"
    inchain="$(firewall_chain_name "$instance" input)"; fwdchain="$(firewall_chain_name "$instance" forward)"; postchain="$(firewall_chain_name "$instance" postrouting)"
    print_info "Firewall backend: $fwmode"
    if [[ "$natmode" == none ]]; then
        print_info "Base IPv4 NAT is intentionally disabled."
    elif iptables -t nat -S "$postchain" 2>/dev/null | grep -Fq "ocserv-manager:$instance:v3:base-nat"; then
        print_ok "Managed base IPv4 NAT rule present in $postchain ($natmode)."
    else
        print_err "Managed base IPv4 NAT rule missing from $postchain"; ok=0
    fi
    if [[ "$forward" == 0 ]]; then
        print_info "Base VPN FORWARD pair is intentionally disabled."
    elif iptables -S "$fwdchain" 2>/dev/null | grep -Fq "ocserv-manager:$instance:v3:base-forward-out"; then
        print_ok "Managed base FORWARD rules present in $fwdchain."
    else
        print_err "Managed base FORWARD rule missing from $fwdchain"; ok=0
    fi
    if [[ "$ingress" == 0 ]]; then
        print_info "Managed base ingress is intentionally disabled."
    elif [[ "$fwmode" == iptables ]]; then
        if iptables -S "$inchain" 2>/dev/null | grep -Fq "ocserv-manager:$instance:v3:base-tcp" && iptables -S "$inchain" 2>/dev/null | grep -Fq "ocserv-manager:$instance:v3:base-udp"; then
            print_ok "iptables managed ingress rules present for TCP $tcp / UDP $udp in $inchain"
        else
            print_err "iptables managed ingress rule missing"; ok=0
        fi
    elif command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -Fq "ocserv-manager:$instance:v3:base-"; then print_ok "UFW managed ingress rules found"; else print_warn "UFW backend selected but managed port rules were not found"; ok=0; fi
    else
        print_err "UFW backend selected but ufw command is unavailable"; ok=0
    fi
    if [[ -n "$cert" && -r "$cert" ]]; then
        days="$(certificate_days_left "$cert")"; [[ "$days" =~ ^-?[0-9]+$ ]] || days=-1
        if (( days >= 30 )); then print_ok "Certificate valid for about $days more days"; elif (( days >= 0 )); then print_warn "Certificate expires in about $days days"; else print_err "Certificate missing/expired/unreadable"; ok=0; fi
    else print_err "Server certificate missing/unreadable"; ok=0; fi
    bbr="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
    print_info "TCP congestion control: $bbr (report only; this manager intentionally does not configure BBR)."
    if [[ "$(state_get "$instance" CENTRAL_ENABLED 2>/dev/null || echo 0)" == 1 ]]; then
        if systemctl is-active --quiet "$(central_agent_service "$instance")"; then print_ok "Central live agent active"; else print_warn "Central integration enabled but agent inactive"; fi
    fi
    echo
    echo "Recent service warnings/errors:"
    journalctl -u "$svc" -p warning -n 20 --no-pager 2>/dev/null || true
    (( ok == 1 )) && print_ok "Core diagnostic checks passed." || print_warn "One or more diagnostic checks need attention."
}


stability_snapshot() {
    local instance="$1" label="${2:-manual}" stamp dir conf state
    stamp="$(date +%Y%m%d-%H%M%S)"
    ensure_stability_backup_root
    dir="$STABILITY_BACKUP_ROOT/$instance/$stamp-$label"
    mkdir -p "$dir"
    state="$(instance_state_file "$instance")"; conf="$(instance_config "$instance")"
    [[ -f "$state" ]] && cp -a "$state" "$dir/state.env"
    [[ -f "$conf" ]] && cp -a "$conf" "$dir/ocserv.conf"
    printf 'instance=%s\nlabel=%s\ncreated_at=%s\n' "$instance" "$label" "$(date -Is)" > "$dir/meta.txt"
    chmod -R go-rwx "$dir" 2>/dev/null || true
    echo "$dir"
}

show_connection_stability_values() {
    local instance="$1"
    ensure_connection_state_defaults "$instance"
    echo "Current connection/roaming values for $instance:"
    echo "- keepalive: $(state_get "$instance" KEEPALIVE 2>/dev/null || echo unknown)"
    echo "- dpd: $(state_get "$instance" DPD 2>/dev/null || echo unknown)"
    echo "- mobile-dpd: $(state_get "$instance" MOBILE_DPD 2>/dev/null || echo unknown)"
    echo "- switch-to-tcp-timeout: $(state_get "$instance" SWITCH_TO_TCP_TIMEOUT)"
    echo "- try-mtu-discovery: $(state_get "$instance" MTU_DISCOVERY 2>/dev/null || echo false)"
    echo "- cookie-timeout: $(state_get "$instance" COOKIE_TIMEOUT)"
    echo "- persistent-cookies: $(state_get "$instance" PERSISTENT_COOKIES)"
    echo "- deny-roaming: $(state_get "$instance" DENY_ROAMING)"
    echo "- idle-timeout: $(state_get "$instance" IDLE_TIMEOUT)"
    echo "- mobile-idle-timeout: $(state_get "$instance" MOBILE_IDLE_TIMEOUT)"
    echo "- rekey-time/method: $(state_get "$instance" REKEY_TIME) / $(state_get "$instance" REKEY_METHOD)"
}

apply_connection_stability_profile() {
    local instance="$1" profile="$2" snapshot tmp
    [[ "$(state_get "$instance" MANAGED 2>/dev/null || echo 0)" == 1 ]] || { print_err "Connection profiles require a manager-owned instance. Adopt the imported instance first."; return 1; }
    local keep_snapshot=0
    if ask_yes_no "Save a persistent pre-change stability snapshot?" "y"; then
        snapshot="$(stability_snapshot "$instance" "$profile")"
        keep_snapshot=1
    else
        snapshot="$(mktemp -d /tmp/ocserv-stability-rollback.XXXXXX)"
        [[ -f "$(instance_state_file "$instance")" ]] && cp -a "$(instance_state_file "$instance")" "$snapshot/state.env"
        [[ -f "$(instance_config "$instance")" ]] && cp -a "$(instance_config "$instance")" "$snapshot/ocserv.conf"
        print_info "Persistent stability snapshot skipped; temporary rollback state will be removed when finished."
    fi
    ensure_connection_state_defaults "$instance"
    case "$profile" in
        upstream)
            state_set "$instance" KEEPALIVE 32400
            state_set "$instance" DPD 90
            state_set "$instance" MOBILE_DPD 1800
            state_set "$instance" SWITCH_TO_TCP_TIMEOUT 25
            state_set "$instance" MTU_DISCOVERY false
            state_set "$instance" COOKIE_TIMEOUT 300
            state_set "$instance" PERSISTENT_COOKIES false
            state_set "$instance" DENY_ROAMING false
            state_set "$instance" IDLE_TIMEOUT disabled
            state_set "$instance" MOBILE_IDLE_TIMEOUT disabled
            state_set "$instance" REKEY_TIME 172800
            state_set "$instance" REKEY_METHOD ssl
            ;;
        mobile-stable)
            # Opt-in aggressive keepalive for problematic mobile/NAT paths; upstream default remains 32400.
            state_set "$instance" KEEPALIVE 30
            state_set "$instance" DPD 90
            state_set "$instance" MOBILE_DPD 1800
            state_set "$instance" SWITCH_TO_TCP_TIMEOUT 25
            state_set "$instance" MTU_DISCOVERY true
            state_set "$instance" COOKIE_TIMEOUT 1800
            state_set "$instance" PERSISTENT_COOKIES false
            state_set "$instance" DENY_ROAMING false
            state_set "$instance" IDLE_TIMEOUT disabled
            state_set "$instance" MOBILE_IDLE_TIMEOUT disabled
            state_set "$instance" REKEY_TIME 172800
            state_set "$instance" REKEY_METHOD ssl
            ;;
        aggressive-roaming)
            state_set "$instance" KEEPALIVE 30
            state_set "$instance" DPD 90
            state_set "$instance" MOBILE_DPD 1800
            state_set "$instance" SWITCH_TO_TCP_TIMEOUT 25
            state_set "$instance" MTU_DISCOVERY true
            state_set "$instance" COOKIE_TIMEOUT 86400
            state_set "$instance" PERSISTENT_COOKIES true
            state_set "$instance" DENY_ROAMING false
            state_set "$instance" IDLE_TIMEOUT disabled
            state_set "$instance" MOBILE_IDLE_TIMEOUT disabled
            state_set "$instance" REKEY_TIME 172800
            state_set "$instance" REKEY_METHOD ssl
            ;;
        *) print_err "Unknown stability profile: $profile"; return 1 ;;
    esac
    tmp="$(mktemp)"
    if generate_ocserv_config "$instance" "$tmp" && transactional_replace_config "$instance" "$tmp"; then
        rm -f "$tmp"
        audit "connection-profile instance=$instance profile=$profile snapshot=$([[ $keep_snapshot == 1 ]] && echo "$snapshot" || echo declined)"
        print_ok "Connection profile '$profile' applied."
        if (( keep_snapshot == 1 )); then print_info "Exact pre-change snapshot: $snapshot"; else rm -rf "$snapshot" 2>/dev/null || true; fi
        return 0
    fi
    rm -f "$tmp"
    print_err "Profile could not be applied. Restoring saved state."
    [[ -f "$snapshot/state.env" ]] && cp -a "$snapshot/state.env" "$(instance_state_file "$instance")"
    (( keep_snapshot == 0 )) && rm -rf "$snapshot" 2>/dev/null || true
    return 1
}

restore_stability_snapshot() {
    local instance="$1" root="$STABILITY_BACKUP_ROOT/$instance" choice idx dir tmp current
    [[ -d "$root" ]] || { print_warn "No stability snapshots exist for $instance."; return 0; }
    mapfile -t _stability_snaps < <(find "$root" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -r)
    ((${#_stability_snaps[@]})) || { print_warn "No stability snapshots exist for $instance."; return 0; }
    echo "Available stability snapshots:"
    for idx in "${!_stability_snaps[@]}"; do echo "$((idx+1))) ${_stability_snaps[$idx]}"; done
    choice="$(ask_integer "Select snapshot to restore" "1" 1 "${#_stability_snaps[@]}")"
    dir="$root/${_stability_snaps[$((choice-1))]}"
    [[ -f "$dir/ocserv.conf" && -f "$dir/state.env" ]] || { print_err "Snapshot is incomplete: $dir"; return 1; }
    validate_config "$dir/ocserv.conf" >/dev/null || { print_err "Saved config does not validate with the currently installed ocserv version."; return 1; }
    current=""
    if ask_yes_no "Save a persistent snapshot of the current stability settings before restore?" "y"; then current="$(stability_snapshot "$instance" before-restore)"; fi
    if transactional_replace_config "$instance" "$dir/ocserv.conf"; then
        cp -a "$dir/state.env" "$(instance_state_file "$instance")"
        audit "connection-profile-restore instance=$instance restored=$dir safety=${current:-declined}"
        print_ok "Connection settings and exact config restored from: $dir"
        [[ -n "$current" ]] && print_info "A safety snapshot of the state before restore was saved at: $current" || print_info "Pre-restore persistent snapshot: not created (declined)"
    else
        print_err "Restore failed; current configuration was left/rolled back by the transactional config handler."
        return 1
    fi
}

custom_connection_stability_settings() {
    local instance="$1" snapshot tmp val
    [[ "$(state_get "$instance" MANAGED 2>/dev/null || echo 0)" == 1 ]] || { print_err "Custom connection settings require a manager-owned instance."; return 1; }
    local keep_snapshot=0
    if ask_yes_no "Save a persistent pre-change stability snapshot?" "y"; then
        snapshot="$(stability_snapshot "$instance" custom)"; keep_snapshot=1
    else
        snapshot="$(mktemp -d /tmp/ocserv-stability-custom-rollback.XXXXXX)"
        [[ -f "$(instance_state_file "$instance")" ]] && cp -a "$(instance_state_file "$instance")" "$snapshot/state.env"
        print_info "Persistent stability snapshot skipped; temporary rollback state will be removed when finished."
    fi
    ensure_connection_state_defaults "$instance"
    state_set "$instance" KEEPALIVE "$(ask_integer "Keepalive seconds" "$(state_get "$instance" KEEPALIVE 2>/dev/null || echo 30)" 0 86400)"
    state_set "$instance" DPD "$(ask_integer "DPD seconds" "$(state_get "$instance" DPD 2>/dev/null || echo 90)" 0 86400)"
    state_set "$instance" MOBILE_DPD "$(ask_integer "Mobile DPD seconds" "$(state_get "$instance" MOBILE_DPD 2>/dev/null || echo 1800)" 0 86400)"
    state_set "$instance" SWITCH_TO_TCP_TIMEOUT "$(ask_integer "Switch-to-TCP recovery timeout seconds" "$(state_get "$instance" SWITCH_TO_TCP_TIMEOUT)" 0 86400)"
    state_set "$instance" COOKIE_TIMEOUT "$(ask_integer "Reconnect cookie timeout seconds" "$(state_get "$instance" COOKIE_TIMEOUT)" 0 604800)"
    if ask_yes_no "Enable persistent-cookies? This improves recovery for some broken/mobile clients but weakens logout semantics." "n"; then state_set "$instance" PERSISTENT_COOKIES true; else state_set "$instance" PERSISTENT_COOKIES false; fi
    if ask_yes_no "Allow roaming between public IPs/networks?" "y"; then state_set "$instance" DENY_ROAMING false; else state_set "$instance" DENY_ROAMING true; fi
    if ask_yes_no "Enable MTU discovery?" "y"; then state_set "$instance" MTU_DISCOVERY true; else state_set "$instance" MTU_DISCOVERY false; fi
    tmp="$(mktemp)"
    if generate_ocserv_config "$instance" "$tmp" && transactional_replace_config "$instance" "$tmp"; then
        rm -f "$tmp"; print_ok "Custom connection stability settings applied."; if (( keep_snapshot == 1 )); then print_info "Pre-change snapshot: $snapshot"; else rm -rf "$snapshot" 2>/dev/null || true; fi
    else
        rm -f "$tmp"; [[ -f "$snapshot/state.env" ]] && cp -a "$snapshot/state.env" "$(instance_state_file "$instance")"; (( keep_snapshot == 0 )) && rm -rf "$snapshot" 2>/dev/null || true; return 1
    fi
}

connection_stability_menu() {
    local instance="$1" choice
    while true; do
        echo; echo "==== Connection Stability / Mobile Roaming: $instance ===="
        echo "1) Show current connection timers/settings"
        echo "2) Apply Mobile/NAT stable profile (30s keepalive; persistent cookies OFF)"
        echo "3) Apply Aggressive roaming profile (persistent cookies ON; security tradeoff)"
        echo "4) Apply upstream/default connection profile"
        echo "5) Custom connection stability settings"
        echo "6) Restore a previous stability snapshot"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) show_connection_stability_values "$instance"; pause ;;
            2) apply_connection_stability_profile "$instance" mobile-stable; pause ;;
            3) print_warn "Persistent cookies remain usable until timeout even after manual disconnect. Use only if the roaming/reconnect benefit is worth that tradeoff."; ask_yes_no "Apply aggressive roaming profile?" "n" && apply_connection_stability_profile "$instance" aggressive-roaming; pause ;;
            4) apply_connection_stability_profile "$instance" upstream; pause ;;
            5) custom_connection_stability_settings "$instance"; pause ;;
            6) restore_stability_snapshot "$instance"; pause ;;
            0) return ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

repair_instance_menu() {
    local instance="$1" choice tmp
    while true; do
        echo; echo "==== Repair: $instance ===="
        echo "1) Reapply scoped ingress/forwarding/NAT rules"
        echo "2) Rebuild systemd units"
        echo "3) Reapply saved manager state onto the preserved original/base config"
        echo "4) Restart service"
        echo "5) Reinstall Let's Encrypt reload hook"
        echo "6) Restart Central live agent"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) remove_firewall_for_instance "$instance"; apply_firewall_for_instance "$instance"; pause ;;
            2) write_systemd_units; print_ok "systemd units rebuilt."; pause ;;
            3)
                [[ "$(state_get "$instance" MANAGED 2>/dev/null || echo 0)" == 1 ]] || { print_warn "Imported config is preservation-only; adopt it first."; pause; continue; }
                tmp="$(mktemp)"; generate_ocserv_config "$instance" "$tmp"; transactional_replace_config "$instance" "$tmp"; rm -f "$tmp"; pause ;;
            4) restart_instance "$instance"; pause ;;
            5) install_letsencrypt_reload_hook; print_ok "Reload hook installed."; pause ;;
            6) systemctl restart "$(central_agent_service "$instance")"; pause ;;
            0) return ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

status_dashboard() {
    local version binary i svc active tcp udp listen subnet connected cert days
    version="$(installed_ocserv_version)"; binary="$(ocserv_bin)"
    echo "==== $PROGRAM_NAME Dashboard ===="
    echo "Manager version: $PROGRAM_VERSION"
    echo "ocserv version: ${version:-not installed}"
    echo "ocserv binary: ${binary:-not found}"
    echo "Outbound interface: $(default_route_iface || echo unknown)"
    echo "IPv4 forwarding: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)"
    echo "Firewall: per-instance simple setup; iptables is default, UFW is opt-in and never auto-enabled."
    echo "Advanced rules remain available under Firewall -> Advanced and stay isolated in manager-owned chains."
    echo
    printf '%-18s %-9s %-23s %-18s %-10s %-10s\n' "INSTANCE" "STATE" "LISTEN" "SUBNET" "ONLINE" "CERT-DAYS"
    while read -r i; do
        [[ -n "$i" ]] || continue
        svc="$(instance_service "$i")"; active="$(systemctl is-active "$svc" 2>/dev/null || echo unknown)"
        tcp="$(state_get "$i" TCP_PORT 2>/dev/null || echo '?')"; udp="$(state_get "$i" UDP_PORT 2>/dev/null || echo '?')"; listen="$(state_get "$i" LISTEN_HOST 2>/dev/null || echo '*')"; subnet="$(state_get "$i" SUBNET 2>/dev/null || echo '?')"; connected="$(connected_users_count "$i" 2>/dev/null || echo 0)"; cert="$(state_get "$i" SERVER_CERT 2>/dev/null || true)"; days="$(certificate_days_left "$cert" 2>/dev/null || echo -1)"
        printf '%-18s %-9s %-23s %-18s %-10s %-10s\n' "$i" "$active" "$listen:$tcp/$udp" "$subnet" "$connected" "$days"
    done < <(list_instances | sort -u)

    echo
    echo "==== Boot dependency audit ===="
    local unit unit_path found_online=0
    for unit in ocserv.service 'ocserv@.service' ocserv-manager-firewall.service 'ocserv-manager-central@.service'; do
        unit_path="/etc/systemd/system/$unit"
        [[ -f "$unit_path" ]] || continue
        if grep -q 'network-online.target' "$unit_path" 2>/dev/null; then
            echo "WARN: $unit still references network-online.target"
            found_online=1
        else
            echo "OK:   $unit does not wait for network-online.target"
        fi
    done
    (( found_online == 0 )) && echo "Manager-owned boot units do not request network-online.target."

    if command -v systemd-analyze >/dev/null 2>&1; then
        echo
        echo "Slowest boot jobs (read-only):"
        systemd-analyze blame 2>/dev/null | head -n 12 || true
    fi
}

certificate_manager() {
    local choice instance cert tmp
    while true; do
        echo; echo "==== Certificate Manager ===="
        echo "1) Show certificate status for all instances"
        echo "2) Change certificate for a manager-owned instance"
        echo "3) Run certbot renew"
        echo "4) Install/repair ocserv certificate reload hook"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1)
                while read -r instance; do [[ -n "$instance" ]] || continue; cert="$(state_get "$instance" SERVER_CERT 2>/dev/null || true)"; echo "$instance: ${cert:-unknown} | expires $(certificate_expiry_text "$cert") | days $(certificate_days_left "$cert")"; done < <(list_instances | sort -u); pause ;;
            2)
                instance="$(choose_instance)" || continue
                [[ "$(state_get "$instance" MANAGED 2>/dev/null || echo 0)" == 1 ]] || { print_warn "Adopt imported config before using deterministic certificate replacement."; pause; continue; }
                while ! configure_server_certificate "$instance"; do :; done
                tmp="$(mktemp)"; generate_ocserv_config "$instance" "$tmp"; transactional_replace_config "$instance" "$tmp"; rm -f "$tmp"; pause ;;
            3) install_certbot; certbot renew; install_letsencrypt_reload_hook; pause ;;
            4) install_letsencrypt_reload_hook; print_ok "Hook installed."; pause ;;
            0) return ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

remove_firewall_values() {
    local instance="$1" subnet="$2" iface="$3" comment
    [[ -n "$subnet" ]] || return 0
    comment="$(fw_comment "$instance")"
    [[ -n "$iface" ]] || return 0
    while iptables -t nat -C POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$comment" -j MASQUERADE >/dev/null 2>&1; do iptables -t nat -D POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$comment" -j MASQUERADE; done
    while iptables -C FORWARD -s "$subnet" -o "$iface" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do iptables -D FORWARD -s "$subnet" -o "$iface" -m comment --comment "$comment" -j ACCEPT; done
    while iptables -C FORWARD -d "$subnet" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do iptables -D FORWARD -d "$subnet" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT; done
}

reconfigure_managed_instance() {
    local instance="$1" state backup_state choice listen tcp udp subnet oldsub oldiface oldipv6 oldnat6 oldtcp oldudp oldfw tmp
    state="$(instance_state_file "$instance")"
    [[ "$(state_get "$instance" MANAGED 2>/dev/null || echo 0)" == 1 ]] || { adopt_imported_instance "$instance"; return; }
    local keep_state_backup=0
    if ask_yes_no "Create a persistent backup of the current instance state before reconfigure?" "y"; then
        ensure_backup_root
        backup_state="$BACKUP_ROOT/state-$instance-$(date +%Y%m%d-%H%M%S).env"
        keep_state_backup=1
    else
        backup_state="$(mktemp /tmp/ocserv-manager-state-rollback.${instance}.XXXXXX)"
    fi
    cp -a "$state" "$backup_state"
    oldsub="$(state_get "$instance" SUBNET)"; oldiface="$(state_get "$instance" OUT_IFACE 2>/dev/null || true)"
    oldipv6="$(state_get "$instance" IPV6_NETWORK 2>/dev/null || true)"; oldnat6="$(state_get "$instance" IPV6_NAT 2>/dev/null || echo 0)"
    oldtcp="$(state_get "$instance" TCP_PORT 2>/dev/null || echo 443)"; oldudp="$(state_get "$instance" UDP_PORT 2>/dev/null || echo "$oldtcp")"; oldfw="$(firewall_mode_for_instance "$instance")"
    echo "Reconfigure sections. Existing values are preserved unless the selected section is changed."
    while true; do
        choice="$(choose_menu "Select section:" "Listen IP and TCP/UDP ports" "VPN subnet" "Server certificate" "Authentication" "DNS" "Client/session and ban limits" "MTU/DPD/keepalive/IPv6 network profile" "Full/split routing, DNS leak and bypass" "Firewall integration (iptables default / optional UFW)" "Open advanced per-instance Firewall Manager" "Finish and apply" "Cancel")"
        case "$choice" in
            1)
                listen="$(choose_listen_host)"; tcp="$(choose_available_tcp_port "$instance" "$listen" "$(state_get "$instance" TCP_PORT)")"; udp="$(choose_available_udp_port "$instance" "$listen" "$tcp")"; state_set "$instance" LISTEN_HOST "$listen"; state_set "$instance" TCP_PORT "$tcp"; state_set "$instance" UDP_PORT "$udp" ;;
            2) subnet="$(choose_subnet "$instance")"; state_set "$instance" SUBNET "$subnet" ;;
            3) while ! configure_server_certificate "$instance"; do :; done ;;
            4) configure_authentication "$instance" ;;
            5) choose_dns_servers "$instance" ;;
            6) configure_limits_and_bans "$instance" ;;
            7) configure_network_profile "$instance" ;;
            8) configure_routing_profile "$instance" ;;
            9) configure_firewall_mode "$instance" ;;
            10) firewall_manager_menu "$instance" ;;
            11) break ;;
            12) cp -a "$backup_state" "$state"; print_info "Changes cancelled."; return 0 ;;
        esac
    done
    tmp="$(mktemp)"; generate_ocserv_config "$instance" "$tmp"
    if ! validate_config "$tmp"; then cp -a "$backup_state" "$state"; rm -f "$tmp"; print_err "Generated config failed validation; state rolled back."; return 1; fi
    if ! transactional_replace_config "$instance" "$tmp"; then cp -a "$backup_state" "$state"; rm -f "$tmp"; return 1; fi
    rm -f "$tmp"
    remove_firewall_values "$instance" "$oldsub" "$oldiface"
    remove_ipv6_firewall_values "$instance" "$oldipv6" "$oldiface" "$oldnat6"
    remove_iptables_ingress_values "$instance" "$oldtcp" "$oldudp"
    remove_ufw_managed_rules "$instance" "$oldtcp" "$oldudp"
    apply_firewall_for_instance "$instance"
    audit "instance-reconfigure instance=$instance state_backup=$([[ $keep_state_backup == 1 ]] && echo "$backup_state" || echo declined) old_firewall=$oldfw new_firewall=$(firewall_mode_for_instance "$instance")"
    (( keep_state_backup == 0 )) && rm -f "$backup_state" 2>/dev/null || true
    print_ok "Reconfiguration applied."
}

advanced_edit_config() {
    local instance="$1" conf tmp editor
    conf="$(instance_config "$instance")"; [[ -f "$conf" ]] || { print_err "Config missing."; return 1; }
    install_available_packages nano
    tmp="$(mktemp)"; cp -a "$conf" "$tmp"; editor="${EDITOR:-nano}"
    "$editor" "$tmp"
    if cmp -s "$tmp" "$conf"; then rm -f "$tmp"; print_info "No changes."; return; fi
    if transactional_replace_config "$instance" "$tmp"; then
        state_set "$instance" MANAGED 0
        print_warn "Raw config edit accepted. This instance is now marked preservation/imported mode so future manager regeneration will not silently overwrite manual directives."
    fi
    rm -f "$tmp"
}

configuration_menu() {
    local instance="$1" choice
    while true; do
        echo; echo "==== Configuration: $instance ===="
        echo "1) Show config"; echo "2) Validate config"; echo "3) Guided reconfigure (patches the preserved original config structure)"; echo "4) Advanced raw edit (switches to preservation mode)"; echo "5) Restore exact version sample as base, then reapply selected values"; echo "6) config-per-user / config-per-group settings"; echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) cat "$(instance_config "$instance")"; pause;;
            2) validate_config "$(instance_config "$instance")" && print_ok "Valid." || print_err "Invalid."; pause;;
            3) reconfigure_managed_instance "$instance"; pause;;
            4) advanced_edit_config "$instance"; pause;;
            5) if ask_yes_no "Replace the preserved base with the official sample for the installed ocserv version? Current config is safety-backed up transactionally." "n"; then rebase_instance_on_stock_config "$instance"; fi; pause;;
            6) supplemental_config_menu "$instance";;
            0) return;;
            *) print_warn "Invalid selection.";;
        esac
    done
}

# -----------------------------------------------------------------------------
# Optional read-only JSON/API output
# -----------------------------------------------------------------------------
json_status() {
    local only="${1:-}" i svc active cert days obj first=1
    printf '{"manager_version":%s,"ocserv_version":%s,"instances":[' \
        "$(jq -Rn --arg v "$PROGRAM_VERSION" '$v')" "$(jq -Rn --arg v "$(installed_ocserv_version)" '$v')"
    while read -r i; do
        [[ -n "$i" ]] || continue
        [[ -z "$only" || "$i" == "$only" ]] || continue
        svc="$(instance_service "$i")"; active="$(systemctl is-active "$svc" 2>/dev/null || echo unknown)"; cert="$(state_get "$i" SERVER_CERT 2>/dev/null || true)"; days="$(certificate_days_left "$cert" 2>/dev/null || echo -1)"
        obj="$(jq -n \
            --arg name "$i" --arg service "$svc" --arg state "$active" \
            --arg config "$(instance_config "$i")" --arg listen "$(state_get "$i" LISTEN_HOST 2>/dev/null || echo '')" \
            --arg tcp "$(state_get "$i" TCP_PORT 2>/dev/null || echo '')" --arg udp "$(state_get "$i" UDP_PORT 2>/dev/null || echo '')" \
            --arg subnet "$(state_get "$i" SUBNET 2>/dev/null || echo '')" --arg cert "$cert" \
            --argjson cert_days "${days:--1}" --argjson connected "$(connected_users_count "$i")" \
            --arg central "$(state_get "$i" CENTRAL_ENABLED 2>/dev/null || echo 0)" \
            '{name:$name,service:$service,state:$state,config:$config,listen_host:$listen,tcp_port:($tcp|tonumber? // $tcp),udp_port:($udp|tonumber? // $udp),subnet:$subnet,connected:$connected,certificate:$cert,certificate_days_left:$cert_days,central_enabled:($central=="1")}')"
        (( first == 1 )) || printf ','
        first=0; printf '%s' "$obj"
    done < <(list_instances | sort -u)
    printf ']}\n'
}

gen_api_token() { openssl rand -hex 32; }

write_readonly_api() {
    mkdir -p "$API_DIR"
    cat > "$API_DIR/api.py" <<'PY'
#!/usr/bin/env python3
import json, os, subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
MANAGER=os.environ.get('MANAGER','/usr/local/sbin/ocserv-manager')
TOKEN=os.environ.get('API_TOKEN','')
BIND=os.environ.get('API_BIND','127.0.0.1')
PORT=int(os.environ.get('API_PORT','8090'))
class H(BaseHTTPRequestHandler):
    def sendj(self,code,obj):
        b=json.dumps(obj,ensure_ascii=False).encode(); self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)
    def auth(self): return bool(TOKEN) and self.headers.get('X-API-Token','')==TOKEN
    def do_GET(self):
        if self.path=='/health': return self.sendj(200,{'ok':True,'service':'ocserv-manager-api'})
        if not self.auth(): return self.sendj(401,{'ok':False,'error':'unauthorized'})
        if self.path=='/status': args=[MANAGER,'--json-status']
        elif self.path.startswith('/instance/'):
            name=self.path.split('/',2)[2]
            if not name or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-' for c in name): return self.sendj(400,{'ok':False,'error':'invalid instance'})
            args=[MANAGER,'--json-status',name]
        else: return self.sendj(404,{'ok':False,'error':'not found'})
        try:
            out=subprocess.check_output(args,text=True,stderr=subprocess.DEVNULL,timeout=15)
            return self.sendj(200,json.loads(out))
        except Exception as e: return self.sendj(500,{'ok':False,'error':str(e)})
    def log_message(self,fmt,*args): pass
ThreadingHTTPServer((BIND,PORT),H).serve_forever()
PY
    chmod 755 "$API_DIR/api.py"
    cat > "$API_SERVICE" <<EOF
[Unit]
Description=Ocserv Manager read-only JSON API
After=network.target

[Service]
Type=simple
EnvironmentFile=$API_ENV
ExecStart=/usr/bin/python3 $API_DIR/api.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

configure_readonly_api() {
    local bind port token existing=""
    ensure_dirs; install_runtime_dependencies; install_manager_self
    [[ -f "$API_ENV" ]] && existing="$(sed -n 's/^API_TOKEN=//p' "$API_ENV" | tr -d '"' | tail -n1)"
    echo "This API is read-only: health/status/instance status. It cannot create users or change ocserv configuration."
    bind="$(ask_value "API bind address" "127.0.0.1")"
    if [[ "$bind" == "0.0.0.0" || "$bind" == "::" ]]; then
        print_warn "Public binding exposes a token-authenticated HTTP endpoint. Put it behind TLS/firewall or a trusted private network."
        ask_yes_no "Continue with public binding?" "n" || return 0
    fi
    port="$(ask_integer "API TCP port" "8090" 1 65535)"
    token="$(ask_value "API token" "${existing:-$(gen_api_token)}")"
    cat > "$API_ENV" <<EOF
MANAGER="$MANAGER_BIN"
API_TOKEN="$token"
API_BIND="$bind"
API_PORT="$port"
EOF
    chmod 600 "$API_ENV"; write_readonly_api; systemctl enable --now ocserv-manager-api
    print_ok "Read-only API enabled on $bind:$port"
    print_info "Token: $token"
    print_info "Endpoints: GET /health, GET /status, GET /instance/<name>. Status endpoints require X-API-Token."
    audit "readonly-api-enable bind=$bind port=$port"
}

disable_readonly_api() {
    systemctl disable --now ocserv-manager-api >/dev/null 2>&1 || true
    rm -f "$API_SERVICE" "$API_ENV" "$API_DIR/api.py"
    systemctl daemon-reload
    audit "readonly-api-disable"
    print_ok "Read-only API disabled."
}

api_menu() {
    local choice
    while true; do
        echo; echo "==== JSON / Read-only API ===="
        echo "1) Print JSON status now"; echo "2) Enable/reconfigure read-only HTTP API"; echo "3) Disable API"; echo "4) API service status"; echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) json_status | jq .; pause;; 2) configure_readonly_api; pause;; 3) disable_readonly_api; pause;; 4) systemctl status ocserv-manager-api --no-pager || true; pause;; 0) return;; *) print_warn "Invalid selection.";; esac
    done
}

# -----------------------------------------------------------------------------
# Firewall Manager v3.2 - per-instance policy, tunnel optimization and isolated chains
# -----------------------------------------------------------------------------
firewall_policy_file() { printf '%s/%s.json\n' "$FIREWALL_POLICY_ROOT" "$1"; }
firewall_chain_hash() { printf '%s' "$1" | sha256sum | awk '{print toupper(substr($1,1,8))}'; }
firewall_chain_name() {
    local instance="$1" role="$2" h
    h="$(firewall_chain_hash "$instance")"
    case "$role" in
        input) echo "OCM${h}I" ;;
        forward) echo "OCM${h}F" ;;
        output) echo "OCM${h}O" ;;
        prerouting) echo "OCM${h}P" ;;
        postrouting) echo "OCM${h}N" ;;
        *) return 1 ;;
    esac
}

ensure_firewall_v3_defaults() {
    local instance="$1" mode
    mode="$(firewall_mode_for_instance "$instance")"
    [[ -n "$(state_get "$instance" FIREWALL_BASE_INGRESS 2>/dev/null || true)" ]] || state_set "$instance" FIREWALL_BASE_INGRESS 1
    [[ -n "$(state_get "$instance" FIREWALL_BASE_FORWARD 2>/dev/null || true)" ]] || state_set "$instance" FIREWALL_BASE_FORWARD 1
    [[ -n "$(state_get "$instance" FIREWALL_BASE_NAT_MODE 2>/dev/null || true)" ]] || state_set "$instance" FIREWALL_BASE_NAT_MODE masquerade
    [[ -n "$(state_get "$instance" FIREWALL_BASE_SNAT_IP 2>/dev/null || true)" ]] || state_set "$instance" FIREWALL_BASE_SNAT_IP ""
    [[ -n "$(state_get "$instance" FIREWALL_GLOBAL_MASQUERADE 2>/dev/null || true)" ]] || state_set "$instance" FIREWALL_GLOBAL_MASQUERADE 0
    [[ -n "$(state_get "$instance" FIREWALL_PRIMARY_ROUTE 2>/dev/null || true)" ]] || state_set "$instance" FIREWALL_PRIMARY_ROUTE ""
    [[ -n "$(state_get "$instance" FIREWALL_MODE 2>/dev/null || true)" ]] || state_set "$instance" FIREWALL_MODE "$mode"
}

ensure_firewall_policy_file() {
    local instance="$1" file tun iface id tmp
    ensure_dirs
    ensure_firewall_v3_defaults "$instance"
    file="$(firewall_policy_file "$instance")"
    if [[ ! -f "$file" ]]; then
        printf '{\n  "version": 1,\n  "instance": %s,\n  "rules": []\n}\n' "$(jq -Rn --arg v "$instance" '$v')" > "$file"
        chmod 600 "$file"
        # Preserve v2.9 extra-interface forwarding behavior by converting it into ordinary
        # managed stateful FORWARD rules. This is configuration migration, not a backup.
        tun="$(state_get "$instance" TUN_FORWARD_IFACES 2>/dev/null || true)"
        tun="${tun//,/ }"
        for iface in $tun; do
            valid_interface_name "$iface" || continue
            id="migrated-forward-$(printf '%s' "$iface" | sha256sum | cut -c1-8)"
            tmp="$(mktemp)"
            jq --arg id "$id" --arg out "$iface" \
               '.rules += [{id:$id,enabled:true,kind:"forward_pair",family:"ipv4",source:"@vpn",destination:"any",in_iface:"",out_iface:$out,action:"ACCEPT",return_established:true,description:("Migrated v2.9 extra forwarding via " + $out)}]' \
               "$file" > "$tmp" && mv "$tmp" "$file"
            if [[ -d "$(vhost_dir "$instance" 2>/dev/null || true)" ]]; then
                local vf vsub vid
                for vf in "$(vhost_dir "$instance")"/*.conf; do
                    [[ -f "$vf" ]] || continue
                    vsub="$(config_ipv4_cidr "$vf" 2>/dev/null || true)"; [[ -n "$vsub" ]] || continue
                    vid="migrated-vhost-$(printf '%s|%s' "$vsub" "$iface" | sha256sum | cut -c1-8)"; tmp="$(mktemp)"
                    jq --arg id "$vid" --arg out "$iface" --arg src "$vsub" '.rules += [{id:$id,enabled:true,kind:"forward_pair",family:"ipv4",source:$src,destination:"any",in_iface:"",out_iface:$out,action:"ACCEPT",return_established:true,description:("Migrated v2.9 vhost extra forwarding via " + $out)}]' "$file" > "$tmp" && mv "$tmp" "$file"
                done
            fi
        done
    fi
    jq -e '.version == 1 and (.rules|type=="array")' "$file" >/dev/null 2>&1 || {
        print_err "Invalid firewall policy file: $file"
        return 1
    }
}

firewall_rule_comment() { printf 'ocserv-manager:%s:v3:%s' "$1" "$2"; }
firewall_hook_comment() { printf 'ocserv-manager:%s:v3:hook:%s' "$1" "$2"; }

fw_cmd_for_family() {
    case "$1" in
        ipv6) command -v ip6tables >/dev/null 2>&1 && echo ip6tables || return 1 ;;
        *) command -v iptables >/dev/null 2>&1 && echo iptables || return 1 ;;
    esac
}

fw_chain_exists() {
    local cmd="$1" table="$2" chain="$3"
    "$cmd" -t "$table" -S "$chain" >/dev/null 2>&1
}

fw_ensure_chain_hook() {
    local family="$1" table="$2" builtin="$3" chain="$4" instance="$5" role="$6" position="${7:-append}" cmd comment
    cmd="$(fw_cmd_for_family "$family")" || return 0
    fw_chain_exists "$cmd" "$table" "$chain" || "$cmd" -t "$table" -N "$chain"
    comment="$(firewall_hook_comment "$instance" "$role")"
    if ! "$cmd" -t "$table" -C "$builtin" -m comment --comment "$comment" -j "$chain" >/dev/null 2>&1; then
        if [[ "$position" == insert ]]; then
            "$cmd" -t "$table" -I "$builtin" 1 -m comment --comment "$comment" -j "$chain"
        else
            "$cmd" -t "$table" -A "$builtin" -m comment --comment "$comment" -j "$chain"
        fi
    fi
}

fw_ensure_instance_chains() {
    local instance="$1" family="$2" in fwd out pre post
    in="$(firewall_chain_name "$instance" input)"
    fwd="$(firewall_chain_name "$instance" forward)"
    out="$(firewall_chain_name "$instance" output)"
    pre="$(firewall_chain_name "$instance" prerouting)"
    post="$(firewall_chain_name "$instance" postrouting)"
    fw_ensure_chain_hook "$family" filter INPUT "$in" "$instance" input insert
    fw_ensure_chain_hook "$family" filter FORWARD "$fwd" "$instance" forward insert
    fw_ensure_chain_hook "$family" filter OUTPUT "$out" "$instance" output append
    fw_ensure_chain_hook "$family" nat PREROUTING "$pre" "$instance" prerouting insert || true
    fw_ensure_chain_hook "$family" nat POSTROUTING "$post" "$instance" postrouting append || true
    # Expert rules may use mangle/raw for MARK/CONNMARK/NOTRACK-style workflows.
    fw_ensure_chain_hook "$family" mangle PREROUTING "$pre" "$instance" mangle-prerouting insert || true
    fw_ensure_chain_hook "$family" mangle INPUT "$in" "$instance" mangle-input insert || true
    fw_ensure_chain_hook "$family" mangle FORWARD "$fwd" "$instance" mangle-forward insert || true
    fw_ensure_chain_hook "$family" mangle OUTPUT "$out" "$instance" mangle-output append || true
    fw_ensure_chain_hook "$family" mangle POSTROUTING "$post" "$instance" mangle-postrouting append || true
    fw_ensure_chain_hook "$family" raw PREROUTING "$pre" "$instance" raw-prerouting insert || true
    fw_ensure_chain_hook "$family" raw OUTPUT "$out" "$instance" raw-output append || true
}

fw_flush_instance_chains() {
    local instance="$1" family="$2" cmd role chain table
    cmd="$(fw_cmd_for_family "$family")" || return 0
    for role in input forward output; do
        chain="$(firewall_chain_name "$instance" "$role")"
        fw_chain_exists "$cmd" filter "$chain" && "$cmd" -t filter -F "$chain" || true
    done
    for role in prerouting postrouting; do
        chain="$(firewall_chain_name "$instance" "$role")"
        fw_chain_exists "$cmd" nat "$chain" && "$cmd" -t nat -F "$chain" || true
    done
    for role in prerouting input forward output postrouting; do
        chain="$(firewall_chain_name "$instance" "$role")"
        fw_chain_exists "$cmd" mangle "$chain" && "$cmd" -t mangle -F "$chain" || true
    done
    for role in prerouting output; do
        chain="$(firewall_chain_name "$instance" "$role")"
        fw_chain_exists "$cmd" raw "$chain" && "$cmd" -t raw -F "$chain" || true
    done
}

fw_remove_chain_hook_and_chain() {
    local family="$1" table="$2" builtin="$3" chain="$4" instance="$5" role="$6" cmd comment
    cmd="$(fw_cmd_for_family "$family")" || return 0
    comment="$(firewall_hook_comment "$instance" "$role")"
    while "$cmd" -t "$table" -C "$builtin" -m comment --comment "$comment" -j "$chain" >/dev/null 2>&1; do
        "$cmd" -t "$table" -D "$builtin" -m comment --comment "$comment" -j "$chain" || break
    done
    if fw_chain_exists "$cmd" "$table" "$chain"; then
        "$cmd" -t "$table" -F "$chain" >/dev/null 2>&1 || true
        "$cmd" -t "$table" -X "$chain" >/dev/null 2>&1 || true
    fi
}

fw_remove_instance_chains() {
    local instance="$1" family="$2"
    fw_remove_chain_hook_and_chain "$family" filter INPUT "$(firewall_chain_name "$instance" input)" "$instance" input
    fw_remove_chain_hook_and_chain "$family" filter FORWARD "$(firewall_chain_name "$instance" forward)" "$instance" forward
    fw_remove_chain_hook_and_chain "$family" filter OUTPUT "$(firewall_chain_name "$instance" output)" "$instance" output
    fw_remove_chain_hook_and_chain "$family" nat PREROUTING "$(firewall_chain_name "$instance" prerouting)" "$instance" prerouting
    fw_remove_chain_hook_and_chain "$family" nat POSTROUTING "$(firewall_chain_name "$instance" postrouting)" "$instance" postrouting
    fw_remove_chain_hook_and_chain "$family" mangle PREROUTING "$(firewall_chain_name "$instance" prerouting)" "$instance" mangle-prerouting
    fw_remove_chain_hook_and_chain "$family" mangle INPUT "$(firewall_chain_name "$instance" input)" "$instance" mangle-input
    fw_remove_chain_hook_and_chain "$family" mangle FORWARD "$(firewall_chain_name "$instance" forward)" "$instance" mangle-forward
    fw_remove_chain_hook_and_chain "$family" mangle OUTPUT "$(firewall_chain_name "$instance" output)" "$instance" mangle-output
    fw_remove_chain_hook_and_chain "$family" mangle POSTROUTING "$(firewall_chain_name "$instance" postrouting)" "$instance" mangle-postrouting
    fw_remove_chain_hook_and_chain "$family" raw PREROUTING "$(firewall_chain_name "$instance" prerouting)" "$instance" raw-prerouting
    fw_remove_chain_hook_and_chain "$family" raw OUTPUT "$(firewall_chain_name "$instance" output)" "$instance" raw-output
}

fw_remove_ufw_rules_by_prefix() {
    local instance="$1" prefix="ocserv-manager:$instance" nums n
    command -v ufw >/dev/null 2>&1 || return 0
    nums="$(ufw status numbered 2>/dev/null | grep -F "$prefix" | sed -nE 's/^\[[[:space:]]*([0-9]+)\].*/\1/p' | sort -rn || true)"
    for n in $nums; do yes | ufw delete "$n" >/dev/null 2>&1 || true; done
}

fw_remove_legacy_tun_rules_for_subnet() {
    local instance="$1" subnet="$2" base_comment="$3" ifaces="$4" tun comment
    [[ -n "$subnet" ]] || return 0
    ifaces="${ifaces//,/ }"
    for tun in $ifaces; do
        valid_interface_name "$tun" || continue
        comment="$base_comment:tun:$tun"
        while iptables -C FORWARD -s "$subnet" -o "$tun" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do iptables -D FORWARD -s "$subnet" -o "$tun" -m comment --comment "$comment" -j ACCEPT; done
        while iptables -C FORWARD -d "$subnet" -i "$tun" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do iptables -D FORWARD -d "$subnet" -i "$tun" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT; done
    done
    return 0
}

fw_remove_legacy_v29_rules() {
    local instance="$1" subnet iface comment ipv6 nat6 tcp udp tun vf vsub domain
    [[ "$(state_get "$instance" FIREWALL_V3_MIGRATED 2>/dev/null || true)" == 1 ]] && return 0
    subnet="$(state_get "$instance" SUBNET 2>/dev/null || true)"
    iface="$(state_get "$instance" OUT_IFACE 2>/dev/null || true)"
    [[ -n "$iface" ]] || iface="$(default_route_iface)"
    comment="$(fw_comment "$instance")"
    ipv6="$(state_get "$instance" IPV6_NETWORK 2>/dev/null || true)"
    nat6="$(state_get "$instance" IPV6_NAT 2>/dev/null || echo 0)"
    tcp="$(state_get "$instance" TCP_PORT 2>/dev/null || true)"
    udp="$(state_get "$instance" UDP_PORT 2>/dev/null || true)"
    tun="$(state_get "$instance" TUN_FORWARD_IFACES 2>/dev/null || true)"
    remove_iptables_ingress_values "$instance" "$tcp" "$udp" || true
    remove_ufw_managed_rules "$instance" "$tcp" "$udp" || true
    if [[ -n "$subnet" && -n "$iface" ]] && command -v iptables >/dev/null 2>&1; then
        while iptables -t nat -C POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$comment" -j MASQUERADE >/dev/null 2>&1; do iptables -t nat -D POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$comment" -j MASQUERADE; done
        while iptables -C FORWARD -s "$subnet" -o "$iface" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do iptables -D FORWARD -s "$subnet" -o "$iface" -m comment --comment "$comment" -j ACCEPT; done
        while iptables -C FORWARD -d "$subnet" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1; do iptables -D FORWARD -d "$subnet" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT; done
        fw_remove_legacy_tun_rules_for_subnet "$instance" "$subnet" "$comment" "$tun" || true
        if [[ -d "$(vhost_dir "$instance" 2>/dev/null || true)" ]]; then
            for vf in "$(vhost_dir "$instance")"/*.conf; do
                [[ -f "$vf" ]] || continue
                domain="$(basename "$vf" .conf)"; vsub="$(config_ipv4_cidr "$vf" 2>/dev/null || true)"
                [[ -n "$vsub" ]] && fw_remove_legacy_tun_rules_for_subnet "$instance" "$vsub" "$(vhost_fw_comment "$instance" "$domain")" "$tun" || true
            done
        fi
    fi
    [[ -n "$ipv6" && -n "$iface" ]] && remove_ipv6_firewall_values "$instance" "$ipv6" "$iface" "$nat6" || true
    state_set "$instance" FIREWALL_V3_MIGRATED 1
    return 0
}

fw_primary_out_iface() {
    local instance="$1" iface
    iface="$(state_get "$instance" OUT_IFACE 2>/dev/null || true)"
    if [[ -z "$iface" ]] || ! ip link show "$iface" >/dev/null 2>&1; then iface="$(default_route_iface)"; fi
    printf '%s\n' "$iface"
}

fw_resolve_token() {
    local instance="$1" value="$2" family="${3:-ipv4}"
    case "$value" in
        @vpn) state_get "$instance" SUBNET 2>/dev/null || true ;;
        @vpn6) state_get "$instance" IPV6_NETWORK 2>/dev/null || true ;;
        any|'') echo "" ;;
        *) echo "$value" ;;
    esac
}

fw_append_addr_match() {
    local -n arr="$1"; local flag="$2" value="$3"
    [[ -n "$value" && "$value" != any ]] && arr+=("$flag" "$value")
    return 0
}

fw_append_iface_match() {
    local -n arr="$1"; local flag="$2" value="$3"
    [[ -n "$value" && "$value" != any ]] && arr+=("$flag" "$value")
    return 0
}

fw_add_rule_to_chain() {
    local family="$1" table="$2" chain="$3" instance="$4" rid="$5"; shift 5
    local cmd comment i jump=-1
    local -a all=("$@") pre=() post=()
    cmd="$(fw_cmd_for_family "$family")" || return 0
    comment="$(firewall_rule_comment "$instance" "$rid")"
    for ((i=0;i<${#all[@]};i++)); do
        if [[ "${all[$i]}" == -j || "${all[$i]}" == --jump ]]; then jump=$i; break; fi
    done
    if (( jump >= 0 )); then
        pre=("${all[@]:0:jump}")
        post=("${all[@]:jump}")
    else
        pre=("${all[@]}")
    fi
    "$cmd" -t "$table" -A "$chain" "${pre[@]}" -m comment --comment "$comment" "${post[@]}"
}

fw_advanced_token_forbidden() {
    case "$1" in
        -A|--append|-C|--check|-D|--delete|-I|--insert|-R|--replace|-L|--list|-S|--list-rules|-F|--flush|-Z|--zero|-N|--new-chain|-X|--delete-chain|-P|--policy|-E|--rename-chain|-t|--table|-j|--jump) return 0 ;;
        *) return 1 ;;
    esac
}

fw_apply_structured_rule() {
    local instance="$1" rule="$2" kind family rid source dest inif outif action proto dport tosrc todst ret chain table cmd
    kind="$(jq -r '.kind' <<<"$rule")"
    family="$(jq -r '.family // "ipv4"' <<<"$rule")"
    rid="$(jq -r '.id' <<<"$rule")"
    source="$(fw_resolve_token "$instance" "$(jq -r '.source // "any"' <<<"$rule")" "$family")"
    dest="$(fw_resolve_token "$instance" "$(jq -r '.destination // "any"' <<<"$rule")" "$family")"
    inif="$(jq -r '.in_iface // ""' <<<"$rule")"
    outif="$(jq -r '.out_iface // ""' <<<"$rule")"
    action="$(jq -r '.action // "ACCEPT"' <<<"$rule")"
    proto="$(jq -r '.protocol // "all"' <<<"$rule")"
    dport="$(jq -r '.dport // ""' <<<"$rule")"
    tosrc="$(jq -r '.to_source // ""' <<<"$rule")"
    todst="$(jq -r '.to_destination // ""' <<<"$rule")"
    ret="$(jq -r '.return_established // false' <<<"$rule")"
    local -a args=()
    case "$kind" in
        forward_pair|forward)
            chain="$(firewall_chain_name "$instance" forward)"
            fw_append_addr_match args -s "$source"; fw_append_addr_match args -d "$dest"
            fw_append_iface_match args -i "$inif"; fw_append_iface_match args -o "$outif"
            args+=( -j "$action" )
            fw_add_rule_to_chain "$family" filter "$chain" "$instance" "$rid" "${args[@]}"
            if [[ "$kind" == forward_pair && "$ret" == true && "$action" == ACCEPT ]]; then
                args=()
                fw_append_addr_match args -s "$dest"; fw_append_addr_match args -d "$source"
                fw_append_iface_match args -i "$outif"; fw_append_iface_match args -o "$inif"
                args+=( -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT )
                fw_add_rule_to_chain "$family" filter "$chain" "$instance" "${rid}-return" "${args[@]}"
            fi
            ;;
        nat_masquerade)
            chain="$(firewall_chain_name "$instance" postrouting)"; args=()
            fw_append_addr_match args -s "$source"; fw_append_addr_match args -d "$dest"; fw_append_iface_match args -o "$outif"
            args+=( -j MASQUERADE )
            fw_add_rule_to_chain "$family" nat "$chain" "$instance" "$rid" "${args[@]}"
            ;;
        nat_snat)
            [[ -n "$tosrc" ]] || return 0
            chain="$(firewall_chain_name "$instance" postrouting)"; args=()
            fw_append_addr_match args -s "$source"; fw_append_addr_match args -d "$dest"; fw_append_iface_match args -o "$outif"
            args+=( -j SNAT --to-source "$tosrc" )
            fw_add_rule_to_chain "$family" nat "$chain" "$instance" "$rid" "${args[@]}"
            ;;
        mss_clamp)
            chain="$(firewall_chain_name "$instance" forward)"; args=()
            fw_append_addr_match args -s "$source"; fw_append_addr_match args -d "$dest"
            fw_append_iface_match args -i "$inif"; fw_append_iface_match args -o "$outif"
            args+=( -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu )
            fw_add_rule_to_chain "$family" mangle "$chain" "$instance" "$rid" "${args[@]}"
            ;;
        dnat)
            [[ -n "$todst" ]] || return 0
            chain="$(firewall_chain_name "$instance" prerouting)"; args=()
            fw_append_addr_match args -s "$source"; fw_append_addr_match args -d "$dest"; fw_append_iface_match args -i "$inif"
            [[ "$proto" != all ]] && args+=( -p "$proto" )
            [[ -n "$dport" ]] && args+=( --dport "$dport" )
            args+=( -j DNAT --to-destination "$todst" )
            fw_add_rule_to_chain "$family" nat "$chain" "$instance" "$rid" "${args[@]}"
            ;;
        input|output)
            # Custom INPUT/OUTPUT rules always use the isolated manager-owned
            # netfilter chains so address family and advanced matching stay exact.
            # In UFW backend only the base ocserv ingress ports are delegated to UFW.
            chain="$(firewall_chain_name "$instance" "$kind")"; args=()
            fw_append_addr_match args -s "$source"; fw_append_addr_match args -d "$dest"
            if [[ "$kind" == input ]]; then fw_append_iface_match args -i "$inif"; else fw_append_iface_match args -o "$outif"; fi
            [[ "$proto" != all ]] && args+=( -p "$proto" )
            [[ -n "$dport" ]] && args+=( --dport "$dport" )
            args+=( -j "$action" )
            fw_add_rule_to_chain "$family" filter "$chain" "$instance" "$rid" "${args[@]}"
            ;;
        advanced)
            table="$(jq -r '.table // "filter"' <<<"$rule")"
            local builtin="$(jq -r '.chain // "FORWARD"' <<<"$rule")" target="$(jq -r '.target // "ACCEPT"' <<<"$rule")"
            case "$table:$builtin" in
                filter:INPUT|mangle:INPUT) chain="$(firewall_chain_name "$instance" input)" ;;
                filter:FORWARD|mangle:FORWARD) chain="$(firewall_chain_name "$instance" forward)" ;;
                filter:OUTPUT|mangle:OUTPUT|raw:OUTPUT) chain="$(firewall_chain_name "$instance" output)" ;;
                nat:PREROUTING|mangle:PREROUTING|raw:PREROUTING) chain="$(firewall_chain_name "$instance" prerouting)" ;;
                nat:POSTROUTING|mangle:POSTROUTING) chain="$(firewall_chain_name "$instance" postrouting)" ;;
                *) print_warn "Skipping invalid advanced rule $rid ($table/$builtin)"; return 0 ;;
            esac
            args=()
            local enc a
            while IFS= read -r enc; do
                [[ -n "$enc" ]] || continue
                a="$(printf '%s' "$enc" | base64 -d)"
                if fw_advanced_token_forbidden "$a"; then
                    print_warn "Skipping forbidden command-level token in advanced rule $rid: $a"; return 0
                fi
                args+=("$a")
            done < <(jq -r '.match_args[]? | @base64' <<<"$rule")
            args+=( -j "$target" )
            while IFS= read -r enc; do
                [[ -n "$enc" ]] || continue
                a="$(printf '%s' "$enc" | base64 -d)"
                if fw_advanced_token_forbidden "$a"; then print_warn "Skipping forbidden command-level target token in advanced rule $rid: $a"; return 0; fi
                args+=("$a")
            done < <(jq -r '.target_args[]? | @base64' <<<"$rule")
            fw_add_rule_to_chain "$family" "$table" "$chain" "$instance" "$rid" "${args[@]}"
            ;;
    esac
}

fw_apply_ufw_custom_input() {
    local instance="$1" rule="$2" rid action proto dport source inif comment
    command -v ufw >/dev/null 2>&1 || return 0
    [[ "$(jq -r '.kind' <<<"$rule")" == input ]] || return 0
    [[ "$(jq -r '.family // "ipv4"' <<<"$rule")" == ipv4 ]] || return 0
    rid="$(jq -r '.id' <<<"$rule")"; action="$(jq -r '.action // "ACCEPT"' <<<"$rule")"
    proto="$(jq -r '.protocol // "all"' <<<"$rule")"; dport="$(jq -r '.dport // ""' <<<"$rule")"
    source="$(fw_resolve_token "$instance" "$(jq -r '.source // "any"' <<<"$rule")")"; inif="$(jq -r '.in_iface // ""' <<<"$rule")"
    comment="$(firewall_rule_comment "$instance" "$rid")"
    local verb=allow; [[ "$action" == DROP ]] && verb=deny; [[ "$action" == REJECT ]] && verb=reject
    local -a cmd=(ufw "$verb" in)
    [[ -n "$inif" ]] && cmd+=(on "$inif")
    [[ "$proto" != all ]] && cmd+=(proto "$proto")
    [[ -n "$source" ]] && cmd+=(from "$source") || cmd+=(from any)
    cmd+=(to any)
    [[ -n "$dport" ]] && cmd+=(port "$dport")
    cmd+=(comment "$comment")
    "${cmd[@]}" >/dev/null
}

fw_apply_base_rules() {
    local instance="$1" subnet iface ipv6 nat6 ingress forward natmode snat global_masq tcp udp mode inchain fwdchain postchain
    subnet="$(state_get "$instance" SUBNET 2>/dev/null || true)"; [[ -n "$subnet" ]] || return 0
    iface="$(fw_primary_out_iface "$instance")"; [[ -n "$iface" ]] || { print_err "Could not detect primary outbound interface."; return 1; }
    state_set "$instance" OUT_IFACE "$iface"
    ingress="$(state_get "$instance" FIREWALL_BASE_INGRESS 2>/dev/null || echo 1)"
    forward="$(state_get "$instance" FIREWALL_BASE_FORWARD 2>/dev/null || echo 1)"
    natmode="$(state_get "$instance" FIREWALL_BASE_NAT_MODE 2>/dev/null || echo masquerade)"
    snat="$(state_get "$instance" FIREWALL_BASE_SNAT_IP 2>/dev/null || true)"
    global_masq="$(state_get "$instance" FIREWALL_GLOBAL_MASQUERADE 2>/dev/null || echo 0)"
    tcp="$(state_get "$instance" TCP_PORT 2>/dev/null || echo 443)"; udp="$(state_get "$instance" UDP_PORT 2>/dev/null || echo "$tcp")"
    mode="$(firewall_mode_for_instance "$instance")"
    inchain="$(firewall_chain_name "$instance" input)"; fwdchain="$(firewall_chain_name "$instance" forward)"; postchain="$(firewall_chain_name "$instance" postrouting)"

    if [[ "$ingress" == 1 ]]; then
        if [[ "$mode" == ufw ]]; then
            if [[ "${OCSERV_MANAGER_BOOT_REAPPLY:-0}" == 1 ]]; then
                # UFW persists its own base ingress rules. Never call ufw from the
                # boot/UFW reapply hook, otherwise /etc/ufw/after.init could recurse.
                :
            elif command -v ufw >/dev/null 2>&1; then
                ufw allow "$tcp/tcp" comment "ocserv-manager:$instance:v3:base-tcp" >/dev/null || return 1
                ufw allow "$udp/udp" comment "ocserv-manager:$instance:v3:base-udp" >/dev/null || return 1
                ensure_ufw_reapply_hook || return 1
            else
                print_err "UFW backend selected but ufw is unavailable."; return 1
            fi
        else
            fw_add_rule_to_chain ipv4 filter "$inchain" "$instance" base-tcp -p tcp --dport "$tcp" -j ACCEPT
            fw_add_rule_to_chain ipv4 filter "$inchain" "$instance" base-udp -p udp --dport "$udp" -j ACCEPT
        fi
    fi
    if [[ "$forward" == 1 ]]; then
        fw_add_rule_to_chain ipv4 filter "$fwdchain" "$instance" base-forward-out -s "$subnet" -o "$iface" -j ACCEPT
        fw_add_rule_to_chain ipv4 filter "$fwdchain" "$instance" base-forward-return -d "$subnet" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    fi
    case "$natmode" in
        masquerade) fw_add_rule_to_chain ipv4 nat "$postchain" "$instance" base-nat -s "$subnet" -o "$iface" -j MASQUERADE ;;
        snat)
            if [[ -n "$snat" ]]; then fw_add_rule_to_chain ipv4 nat "$postchain" "$instance" base-nat -s "$subnet" -o "$iface" -j SNAT --to-source "$snat"; else print_warn "Base SNAT selected but no source IP is configured."; fi
            ;;
        none) : ;;
    esac
    if [[ "$global_masq" == 1 ]]; then
        # Intentionally broad compatibility mode. This is equivalent in effect to:
        #   iptables -t nat -A POSTROUTING -j MASQUERADE
        # It is opt-in because it affects unrelated host/container traffic too.
        fw_add_rule_to_chain ipv4 nat "$postchain" "$instance" base-global-masquerade -j MASQUERADE
    fi

    ipv6="$(state_get "$instance" IPV6_NETWORK 2>/dev/null || true)"; nat6="$(state_get "$instance" IPV6_NAT 2>/dev/null || echo 0)"
    if [[ -n "$ipv6" ]] && command -v ip6tables >/dev/null 2>&1; then
        inchain="$(firewall_chain_name "$instance" input)"; fwdchain="$(firewall_chain_name "$instance" forward)"; postchain="$(firewall_chain_name "$instance" postrouting)"
        if [[ "$mode" == iptables && "$ingress" == 1 ]]; then
            fw_add_rule_to_chain ipv6 filter "$inchain" "$instance" base6-tcp -p tcp --dport "$tcp" -j ACCEPT
            fw_add_rule_to_chain ipv6 filter "$inchain" "$instance" base6-udp -p udp --dport "$udp" -j ACCEPT
        fi
        if [[ "$forward" == 1 ]]; then
            fw_add_rule_to_chain ipv6 filter "$fwdchain" "$instance" base6-forward-out -s "$ipv6" -o "$iface" -j ACCEPT
            fw_add_rule_to_chain ipv6 filter "$fwdchain" "$instance" base6-forward-return -d "$ipv6" -i "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        fi
        if [[ "$nat6" == 1 ]]; then fw_add_rule_to_chain ipv6 nat "$postchain" "$instance" base6-nat -s "$ipv6" -o "$iface" -j MASQUERADE || true; fi
    fi
}

fw_apply_ufw_native_rule() {
    local instance="$1" rule="$2" rid action direction proto dport source dest inif outif comment
    [[ "$(firewall_mode_for_instance "$instance")" == ufw ]] || { print_warn "Skipping native UFW rule because backend is not UFW: $(jq -r '.id' <<<"$rule")"; return 0; }
    [[ "${OCSERV_MANAGER_BOOT_REAPPLY:-0}" == 1 ]] && return 0
    command -v ufw >/dev/null 2>&1 || { print_err "Native UFW rule exists but ufw is unavailable."; return 1; }
    rid="$(jq -r '.id' <<<"$rule")"; action="$(jq -r '.ufw_action // "allow"' <<<"$rule")"; direction="$(jq -r '.direction // "in"' <<<"$rule")"
    proto="$(jq -r '.protocol // "all"' <<<"$rule")"; dport="$(jq -r '.dport // ""' <<<"$rule")"
    source="$(fw_resolve_token "$instance" "$(jq -r '.source // "any"' <<<"$rule")")"; dest="$(fw_resolve_token "$instance" "$(jq -r '.destination // "any"' <<<"$rule")")"
    inif="$(jq -r '.in_iface // ""' <<<"$rule")"; outif="$(jq -r '.out_iface // ""' <<<"$rule")"; comment="$(firewall_rule_comment "$instance" "$rid")"
    local -a cmd=(ufw)
    [[ "$direction" == route ]] && cmd+=(route)
    cmd+=("$action")
    case "$direction" in
        in) cmd+=(in); [[ -n "$inif" ]] && cmd+=(on "$inif") ;;
        out) cmd+=(out); [[ -n "$outif" ]] && cmd+=(on "$outif") ;;
        route) [[ -n "$inif" ]] && cmd+=(in on "$inif"); [[ -n "$outif" ]] && cmd+=(out on "$outif") ;;
    esac
    [[ "$proto" != all ]] && cmd+=(proto "$proto")
    [[ -n "$source" ]] && cmd+=(from "$source") || cmd+=(from any)
    [[ -n "$dest" ]] && cmd+=(to "$dest") || cmd+=(to any)
    [[ -n "$dport" ]] && cmd+=(port "$dport")
    cmd+=(comment "$comment")
    "${cmd[@]}" >/dev/null
}

fw_apply_custom_rules() {
    local instance="$1" file rule
    file="$(firewall_policy_file "$instance")"
    [[ -f "$file" ]] || return 0
    while IFS= read -r rule; do
        [[ -n "$rule" ]] || continue
        if [[ "$(jq -r '.kind' <<<"$rule")" == ufw_native ]]; then
            fw_apply_ufw_native_rule "$instance" "$rule" || return 1
        else
            fw_apply_structured_rule "$instance" "$rule" || return 1
        fi
    done < <(jq -c '.rules[] | select(.enabled != false)' "$file")
}

# v3 override: all base/custom rules are rebuilt inside isolated per-instance chains.
apply_firewall_for_instance() {
    local instance="$1" mode subnet iface
    ensure_firewall_policy_file "$instance" || return 1
    fw_remove_legacy_v29_rules "$instance" || true
    enable_ip_forwarding
    [[ "${OCSERV_MANAGER_BOOT_REAPPLY:-0}" == 1 ]] || install_available_packages iptables
    mode="$(firewall_mode_for_instance "$instance")"
    if [[ "$mode" == ufw && ! -x "$(command -v ufw 2>/dev/null || true)" ]]; then
        print_err "UFW backend is selected for $instance, but ufw is not installed."; return 1
    fi
    fw_ensure_instance_chains "$instance" ipv4
    fw_flush_instance_chains "$instance" ipv4
    if command -v ip6tables >/dev/null 2>&1; then fw_ensure_instance_chains "$instance" ipv6; fw_flush_instance_chains "$instance" ipv6; fi
    if [[ "${OCSERV_MANAGER_BOOT_REAPPLY:-0}" != 1 || "$mode" != ufw ]]; then
        fw_remove_ufw_rules_by_prefix "$instance"
    fi
    fw_apply_base_rules "$instance" || return 1
    fw_apply_custom_rules "$instance" || return 1
    install_firewall_reapply_unit
    subnet="$(state_get "$instance" SUBNET 2>/dev/null || true)"; iface="$(fw_primary_out_iface "$instance")"
    audit "firewall-v3-applied instance=$instance backend=$mode subnet=$subnet primary_out=$iface custom_rules=$(jq '.rules|length' "$(firewall_policy_file "$instance")" 2>/dev/null || echo 0)"
    [[ "${OCSERV_MANAGER_BOOT_REAPPLY:-0}" == 1 ]] || print_ok "Firewall policy applied for $instance (backend=$mode, primary outbound=${iface:-none})."
}

remove_firewall_for_instance() {
    local instance="$1"
    remove_all_vhost_firewalls "$instance" 2>/dev/null || true
    fw_remove_ufw_rules_by_prefix "$instance" || true
    fw_remove_instance_chains "$instance" ipv4 || true
    fw_remove_instance_chains "$instance" ipv6 || true
    fw_remove_legacy_v29_rules "$instance" || true
    audit "firewall-v3-removed instance=$instance"
}

reapply_all_firewall_rules() {
    local instance f domain subnet
    command -v iptables >/dev/null 2>&1 || { print_err "iptables is unavailable; cannot reapply ocserv firewall rules."; return 1; }
    export OCSERV_MANAGER_BOOT_REAPPLY=1
    enable_ip_forwarding
    while read -r instance; do
        [[ -n "$instance" && -f "$(instance_state_file "$instance")" ]] || continue
        apply_firewall_for_instance "$instance" || print_warn "Could not reapply firewall policy for $instance"
        if [[ -d "$(vhost_dir "$instance")" ]]; then
            for f in "$(vhost_dir "$instance")"/*.conf; do
                [[ -f "$f" ]] || continue
                domain="$(basename "$f" .conf)"; subnet="$(config_ipv4_cidr "$f" 2>/dev/null || true)"
                [[ -n "$subnet" ]] && apply_firewall_for_vhost "$instance" "$domain" "$subnet" || true
            done
        fi
    done < <(list_instances | sort -u)
}

fw_show_detected_network() {
    echo "==== Detected interfaces ===="
    ip -o link show 2>/dev/null | awk -F': ' '{name=$2; sub(/@.*/,"",name); printf "- %s\n", name}' || true
    echo; echo "==== Local IPv4 addresses ===="
    ip -o -4 addr show 2>/dev/null | awk '{printf "- %s  %s  scope=%s\n", $2, $4, $6}' || true
    echo; echo "==== Local IPv6 addresses ===="
    ip -o -6 addr show 2>/dev/null | awk '{printf "- %s  %s  scope=%s\n", $2, $4, $6}' || true
    echo; echo "==== IPv4 routes / policy tables ===="
    ip -4 route show table all 2>/dev/null | sed 's/^/- /' || true
    echo; echo "==== IPv6 routes / policy tables ===="
    ip -6 route show table all 2>/dev/null | sed 's/^/- /' || true
    echo; echo "==== Policy rules ===="
    ip rule show 2>/dev/null | sed 's/^/- /' || true
}

fw_choose_interface() {
    local prompt="$1" default="${2:-}" allow_any="${3:-0}" line name state addr i choice
    local -a items=() states=() addrs=()
    while IFS= read -r line; do
        name="$(awk -F': ' '{print $2}' <<<"$line" | sed 's/@.*//')"; [[ -n "$name" ]] || continue
        state="$(awk '{for(i=1;i<=NF;i++) if($i=="state") print $(i+1)}' <<<"$line")"
        addr="$(ip -o -4 addr show dev "$name" 2>/dev/null | awk '{print $4}' | paste -sd, -)"
        items+=("$name"); states+=("${state:-?}"); addrs+=("${addr:-no-ipv4}")
    done < <(ip -o link show 2>/dev/null)
    echo "$prompt" >&2
    [[ "$allow_any" == 1 ]] && echo "0) Any interface" >&2
    for ((i=0;i<${#items[@]};i++)); do printf '%d) %s  state=%s  ipv4=%s\n' "$((i+1))" "${items[$i]}" "${states[$i]}" "${addrs[$i]}" >&2; done
    echo "m) Enter interface manually" >&2
    while true; do
        read -r -p "Select${default:+ [$default]}: " choice || true
        choice="${choice:-$default}"
        [[ "$allow_any" == 1 && "$choice" == 0 ]] && { echo ""; return 0; }
        if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice>=1 && choice<=${#items[@]})); then echo "${items[$((choice-1))]}"; return 0; fi
        if [[ "$choice" == m || "$choice" == M ]]; then
            name="$(ask_value "Interface name" "")"; valid_interface_name "$name" && { echo "$name"; return 0; }; print_warn "Invalid interface name." >&2
        else print_warn "Invalid selection." >&2; fi
    done
}

valid_ipv4() {
    python3 - "$1" <<'PYIP' >/dev/null 2>&1
import ipaddress, sys
try:
    ipaddress.IPv4Address(sys.argv[1])
except Exception:
    raise SystemExit(1)
PYIP
}

fw_choose_local_ipv4() {
    local prompt="$1" line iface cidr ip i choice
    local -a ips=() ifs=()
    while read -r iface cidr; do [[ -n "$iface" && -n "$cidr" ]] || continue; ip="${cidr%%/*}"; [[ "$ip" == 127.* ]] && continue; ips+=("$ip"); ifs+=("$iface"); done < <(ip -o -4 addr show 2>/dev/null | awk '{print $2, $4}')
    echo "$prompt" >&2
    for ((i=0;i<${#ips[@]};i++)); do printf '%d) %s on %s\n' "$((i+1))" "${ips[$i]}" "${ifs[$i]}" >&2; done
    echo "m) Enter IPv4 manually" >&2
    while true; do
        read -r -p "Select: " choice || true
        if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice>=1 && choice<=${#ips[@]})); then echo "${ips[$((choice-1))]}"; return 0; fi
        if [[ "$choice" == m || "$choice" == M ]]; then ip="$(ask_value "IPv4 address" "")"; valid_ipv4 "$ip" && { echo "$ip"; return 0; }; print_warn "Invalid IPv4." >&2; else print_warn "Invalid selection." >&2; fi
    done
}

fw_route_records() {
    local family="${1:-ipv4}"
    if [[ "$family" == ipv6 ]]; then
        ip -6 route show table all 2>/dev/null
    else
        ip -4 route show table all 2>/dev/null
    fi | awk '
    {
      dest=$1; dev=""; via=""; src=""; table="main";
      for(i=1;i<=NF;i++){if($i=="dev")dev=$(i+1); else if($i=="via")via=$(i+1); else if($i=="src")src=$(i+1); else if($i=="table")table=$(i+1)}
      if(dev!="") printf "%s|%s|%s|%s|%s|%s\n", dest,dev,via,src,table,$0;
    }' | awk '!seen[$0]++'
}

fw_choose_route() {
    local prompt="$1" family="${2:-ipv4}" r i choice
    local -a recs=()
    while IFS= read -r r; do [[ -n "$r" ]] && recs+=("$r"); done < <(fw_route_records "$family")
    echo "$prompt" >&2
    for ((i=0;i<${#recs[@]};i++)); do IFS='|' read -r d dev via src table raw <<<"${recs[$i]}"; printf '%d) dest=%s dev=%s via=%s src=%s table=%s\n' "$((i+1))" "$d" "$dev" "${via:--}" "${src:--}" "$table" >&2; done
    echo "0) Cancel" >&2
    while true; do read -r -p "Select route: " choice || true; [[ "$choice" == 0 ]] && return 1; if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice>=1 && choice<=${#recs[@]})); then echo "${recs[$((choice-1))]}"; return 0; fi; print_warn "Invalid selection." >&2; done
}

fw_choose_source() {
    local instance="$1" family="${2:-ipv4}" choice value
    echo "Source selector:" >&2
    if [[ "$family" == ipv6 ]]; then echo "1) Instance IPv6 VPN pool (@vpn6)" >&2; else echo "1) Instance IPv4 VPN pool (@vpn)" >&2; fi
    echo "2) Any source" >&2; echo "3) Custom IP/CIDR" >&2
    read -r -p "Select [1]: " choice || true; choice="${choice:-1}"
    case "$choice" in 1) [[ "$family" == ipv6 ]] && echo @vpn6 || echo @vpn ;; 2) echo any ;; 3) value="$(ask_value "Source IP/CIDR" "")"; echo "$value" ;; *) echo any ;; esac
}

fw_choose_destination() {
    local family="${1:-ipv4}" choice rec dest
    echo "Destination selector:" >&2; echo "1) Any destination" >&2; echo "2) Choose from detected routing table" >&2; echo "3) Custom IP/CIDR" >&2
    read -r -p "Select [1]: " choice || true; choice="${choice:-1}"
    case "$choice" in
        1) echo any ;;
        2)
            rec="$(fw_choose_route "Detected routes:" "$family" || true)"; [[ -n "$rec" ]] || { echo any; return; }
            dest="${rec%%|*}"; [[ "$dest" == default ]] && dest=any; echo "$dest"
            ;;
        3) ask_value "Destination IP/CIDR" "" ;;
        *) echo any ;;
    esac
}

fw_select_primary_outbound() {
    local instance="$1" choice iface rec dest dev via src table raw
    echo "Primary outbound selection:"; echo "1) Auto-detect current default route"; echo "2) Choose an interface"; echo "3) Choose from detected routes"
    read -r -p "Select [1]: " choice || true; choice="${choice:-1}"
    case "$choice" in
        1) iface="$(default_route_iface)"; state_set "$instance" OUT_IFACE "$iface"; state_set "$instance" FIREWALL_PRIMARY_ROUTE "default(auto)" ;;
        2) iface="$(fw_choose_interface "Choose primary outbound interface" "" 0)"; state_set "$instance" OUT_IFACE "$iface"; state_set "$instance" FIREWALL_PRIMARY_ROUTE "interface:$iface" ;;
        3) rec="$(fw_choose_route "Choose primary outbound route")" || return 0; IFS='|' read -r dest dev via src table raw <<<"$rec"; state_set "$instance" OUT_IFACE "$dev"; state_set "$instance" FIREWALL_PRIMARY_ROUTE "$raw" ;;
        *) return 0 ;;
    esac
    print_ok "Primary outbound set to $(state_get "$instance" OUT_IFACE)."
}

fw_policy_summary() {
    local instance="$1" file count enabled disabled
    ensure_firewall_policy_file "$instance" || return 1
    file="$(firewall_policy_file "$instance")"; count="$(jq '.rules|length' "$file")"; enabled="$(jq '[.rules[]|select(.enabled!=false)]|length' "$file")"; disabled=$((count-enabled))
    echo "Backend: $(firewall_mode_for_instance "$instance")"
    echo "Base ingress: $(state_get "$instance" FIREWALL_BASE_INGRESS 2>/dev/null || echo 1)"
    echo "Base forward: $(state_get "$instance" FIREWALL_BASE_FORWARD 2>/dev/null || echo 1)"
    echo "Base IPv4 NAT: $(state_get "$instance" FIREWALL_BASE_NAT_MODE 2>/dev/null || echo masquerade)"
    echo "Host-wide Global MASQUERADE: $(state_get "$instance" FIREWALL_GLOBAL_MASQUERADE 2>/dev/null || echo 0)"
    echo "Primary outbound: $(fw_primary_out_iface "$instance")"
    echo "Saved route hint: $(state_get "$instance" FIREWALL_PRIMARY_ROUTE 2>/dev/null || true)"
    echo "Custom rules: total=$count enabled=$enabled disabled=$disabled"
}

fw_list_rules() {
    local instance="$1" file
    ensure_firewall_policy_file "$instance" || return 1; file="$(firewall_policy_file "$instance")"
    if [[ "$(jq '.rules|length' "$file")" == 0 ]]; then print_info "No custom firewall rules for $instance."; return 0; fi
    jq -r '.rules | to_entries[] | "\(.key+1)) [\(if .value.enabled==false then "disabled" else "enabled" end)] id=\(.value.id) kind=\(.value.kind) family=\(.value.family // "ipv4")  \(.value.description // "")"' "$file"
}

fw_rule_json_by_index() {
    local instance="$1" idx="$2" file; file="$(firewall_policy_file "$instance")"; jq -c --argjson i "$((idx-1))" '.rules[$i] // empty' "$file"
}

fw_new_rule_id() { printf 'r%s-%04x\n' "$(date +%s)" "$((RANDOM & 65535))"; }

fw_validate_port_optional() { [[ -z "$1" || "$1" =~ ^[0-9]+$ && "$1" -ge 1 && "$1" -le 65535 ]]; }

fw_rule_wizard() {
    local instance="$1" replace_index="${2:-}" existing="${3:-}" type kind family source dest inif outif action proto dport tosrc todst desc ret id table chain target match targetargs rec rdest rdev rvia rsrc rtable rraw
    id="$(jq -r '.id // empty' <<<"${existing:-{}}" 2>/dev/null || true)"; [[ -n "$id" ]] || id="$(fw_new_rule_id)"
    echo "Rule type:" >&2
    echo "1) Stateful FORWARD pair (outbound + established return)" >&2
    echo "2) One-way FORWARD rule" >&2
    echo "3) NAT MASQUERADE" >&2
    echo "4) NAT SNAT to a local/source IP" >&2
    echo "5) DNAT / port forward" >&2
    echo "6) INPUT allow/deny/reject" >&2
    echo "7) OUTPUT allow/deny/reject" >&2
    echo "8) Advanced managed netfilter rule (filter/nat/mangle/raw; no flush/policy commands)" >&2
    echo "9) Native UFW rule (in / out / route; UFW backend only)" >&2
    echo "10) TCP MSS clamp to PMTU on a forwarded path" >&2
    echo "0) Cancel" >&2
    read -r -p "Select: " type || true
    [[ "$type" == 0 ]] && return 1
    case "$type" in 1) kind=forward_pair ;; 2) kind=forward ;; 3) kind=nat_masquerade ;; 4) kind=nat_snat ;; 5) kind=dnat ;; 6) kind=input ;; 7) kind=output ;; 8) kind=advanced ;; 9) kind=ufw_native ;; 10) kind=mss_clamp ;; *) print_warn "Invalid selection." >&2; return 1 ;; esac
    family="$(choose_menu "Address family:" "IPv4" "IPv6")"; [[ "$family" == 2 ]] && family=ipv6 || family=ipv4
    desc="$(ask_value "Description (optional)" "")"
    source=any; dest=any; inif=""; outif=""; action=ACCEPT; proto=all; dport=""; tosrc=""; todst=""; ret=false
    case "$kind" in
        forward_pair|forward)
            source="$(fw_choose_source "$instance" "$family")"; dest="$(fw_choose_destination "$family")"
            echo "Inbound interface is optional." >&2; inif="$(fw_choose_interface "Choose inbound interface" "" 1)"
            echo "Outbound interface can be selected directly or from a route." >&2; echo "1) Interface" >&2; echo "2) Detected route" >&2
            read -r -p "Select [1]: " type || true; type="${type:-1}"
            if [[ "$type" == 2 ]]; then rec="$(fw_choose_route "Choose route" "$family")" || return 1; IFS='|' read -r rdest rdev rvia rsrc rtable rraw <<<"$rec"; outif="$rdev"; [[ "$dest" == any && "$rdest" != default ]] && dest="$rdest"; else outif="$(fw_choose_interface "Choose outbound interface" "" 0)"; fi
            echo "Action: 1) ACCEPT  2) DROP  3) REJECT" >&2; read -r -p "Select [1]: " type || true; case "${type:-1}" in 2) action=DROP;;3) action=REJECT;;*) action=ACCEPT;; esac
            [[ "$kind" == forward_pair && "$action" == ACCEPT ]] && ret=true
            ;;
        nat_masquerade|nat_snat)
            source="$(fw_choose_source "$instance" "$family")"; dest="$(fw_choose_destination "$family")"
            echo "1) Select output interface" >&2; echo "2) Select detected route" >&2; read -r -p "Select [2]: " type || true; type="${type:-2}"
            if [[ "$type" == 2 ]]; then rec="$(fw_choose_route "Choose route used by this NAT rule" "$family")" || return 1; IFS='|' read -r rdest rdev rvia rsrc rtable rraw <<<"$rec"; outif="$rdev"; [[ "$dest" == any && "$rdest" != default ]] && dest="$rdest"; else outif="$(fw_choose_interface "Choose output interface" "" 0)"; fi
            if [[ "$kind" == nat_snat ]]; then [[ "$family" == ipv4 ]] && tosrc="$(fw_choose_local_ipv4 "Choose the local/source IPv4 used for SNAT")" || tosrc="$(ask_value "IPv6 source address for SNAT" "")"; fi
            ;;
        mss_clamp)
            source="$(fw_choose_source "$instance" "$family")"; dest="$(fw_choose_destination "$family")"
            outif="$(fw_choose_interface "Choose forwarded output interface/TUN" "" 0)"
            [[ -n "$outif" ]] || return 1
            ;;
        dnat)
            source="$(fw_choose_source "$instance" "$family")"; dest="$(fw_choose_destination "$family")"; inif="$(fw_choose_interface "Choose inbound interface (0=any)" "" 1)"
            echo "Protocol: 1) TCP  2) UDP  3) Any" >&2; read -r -p "Select [1]: " type || true; case "${type:-1}" in 2) proto=udp;;3) proto=all;;*) proto=tcp;; esac
            if [[ "$proto" != all ]]; then dport="$(ask_value "Destination port to match (blank=any)" "")"; fw_validate_port_optional "$dport" || { print_warn "Invalid port." >&2; return 1; }; fi
            todst="$(ask_nonempty "DNAT destination (IP or IP:port)")"
            ;;
        input|output)
            source="$(fw_choose_source "$instance" "$family")"; dest="$(fw_choose_destination "$family")"
            if [[ "$kind" == input ]]; then inif="$(fw_choose_interface "Choose inbound interface (0=any)" "" 1)"; else outif="$(fw_choose_interface "Choose outbound interface (0=any)" "" 1)"; fi
            echo "Protocol: 1) TCP  2) UDP  3) Any" >&2; read -r -p "Select [3]: " type || true; case "${type:-3}" in 1) proto=tcp;;2) proto=udp;;*) proto=all;; esac
            if [[ "$proto" != all ]]; then dport="$(ask_value "Destination port (blank=any)" "")"; fw_validate_port_optional "$dport" || { print_warn "Invalid port." >&2; return 1; }; fi
            echo "Action: 1) ACCEPT  2) DROP  3) REJECT" >&2; read -r -p "Select [1]: " type || true; case "${type:-1}" in 2) action=DROP;;3) action=REJECT;;*) action=ACCEPT;; esac
            ;;
        ufw_native)
            if [[ "$(firewall_mode_for_instance "$instance")" != ufw ]]; then
                print_warn "Native UFW rules require the instance backend to be UFW. Change backend first." >&2
                return 1
            fi
            local direction ufwaction
            echo "Direction: 1) in  2) out  3) route/forward" >&2; read -r -p "Select [1]: " type || true
            case "${type:-1}" in 2) direction=out;;3) direction=route;;*) direction=in;; esac
            echo "UFW action: 1) allow  2) deny  3) reject  4) limit" >&2; read -r -p "Select [1]: " type || true
            case "${type:-1}" in 2) ufwaction=deny;;3) ufwaction=reject;;4) ufwaction=limit;;*) ufwaction=allow;; esac
            source="$(fw_choose_source "$instance" "$family")"; dest="$(fw_choose_destination "$family")"
            case "$direction" in
                in) inif="$(fw_choose_interface "Choose inbound interface (0=any)" "" 1)" ;;
                out) outif="$(fw_choose_interface "Choose outbound interface (0=any)" "" 1)" ;;
                route) inif="$(fw_choose_interface "Choose inbound interface (0=any)" "" 1)"; outif="$(fw_choose_interface "Choose outbound interface (0=any)" "" 1)" ;;
            esac
            echo "Protocol: 1) TCP  2) UDP  3) Any" >&2; read -r -p "Select [3]: " type || true; case "${type:-3}" in 1) proto=tcp;;2) proto=udp;;*) proto=all;; esac
            if [[ "$proto" != all ]]; then dport="$(ask_value "Destination port (blank=any)" "")"; fw_validate_port_optional "$dport" || { print_warn "Invalid port." >&2; return 1; }; fi
            jq -n --arg id "$id" --arg family "$family" --arg desc "$desc" --arg direction "$direction" --arg action "$ufwaction" --arg source "$source" --arg destination "$dest" --arg in_iface "$inif" --arg out_iface "$outif" --arg protocol "$proto" --arg dport "$dport" '{id:$id,enabled:true,kind:"ufw_native",family:$family,description:$desc,direction:$direction,ufw_action:$action,source:$source,destination:$destination,in_iface:$in_iface,out_iface:$out_iface,protocol:$protocol,dport:$dport}'
            return 0
            ;;
        advanced)
            print_warn "Expert mode can still break this instance's traffic. Global flush/policy/chain-delete operations are blocked." >&2
            echo "Table: 1) filter  2) nat  3) mangle  4) raw" >&2; read -r -p "Select [1]: " type || true
            case "${type:-1}" in 2) table=nat;;3) table=mangle;;4) table=raw;;*) table=filter;; esac
            case "$table" in
                filter) echo "Chain: 1) INPUT 2) FORWARD 3) OUTPUT" >&2; read -r -p "Select [2]: " type || true; case "${type:-2}" in 1) chain=INPUT;;3) chain=OUTPUT;;*) chain=FORWARD;; esac ;;
                nat) echo "Chain: 1) PREROUTING 2) POSTROUTING" >&2; read -r -p "Select [2]: " type || true; [[ "${type:-2}" == 1 ]] && chain=PREROUTING || chain=POSTROUTING ;;
                mangle) echo "Chain: 1) PREROUTING 2) INPUT 3) FORWARD 4) OUTPUT 5) POSTROUTING" >&2; read -r -p "Select [3]: " type || true; case "${type:-3}" in 1) chain=PREROUTING;;2) chain=INPUT;;4) chain=OUTPUT;;5) chain=POSTROUTING;;*) chain=FORWARD;; esac ;;
                raw) echo "Chain: 1) PREROUTING 2) OUTPUT" >&2; read -r -p "Select [1]: " type || true; [[ "${type:-1}" == 2 ]] && chain=OUTPUT || chain=PREROUTING ;;
            esac
            match="$(ask_value "Match arguments, e.g. -s 10.10.0.0/16 -o eth1 -p tcp --dport 443" "")"
            target="$(ask_nonempty "Target, e.g. ACCEPT, DROP, REJECT, MASQUERADE, SNAT, DNAT")"
            targetargs="$(ask_value "Target arguments (optional), e.g. --to-source 1.2.3.4" "")"
            # Parse shell-like arguments without eval; store as JSON arrays.
            local match_json target_json
            match_json="$(python3 - "$match" <<'PY'
import json, shlex, sys
print(json.dumps(shlex.split(sys.argv[1])))
PY
)" || return 1
            target_json="$(python3 - "$targetargs" <<'PY'
import json, shlex, sys
print(json.dumps(shlex.split(sys.argv[1])))
PY
)" || return 1
            jq -n --arg id "$id" --arg family "$family" --arg desc "$desc" --arg table "$table" --arg chain "$chain" --arg target "$target" --argjson ma "$match_json" --argjson ta "$target_json" '{id:$id,enabled:true,kind:"advanced",family:$family,description:$desc,table:$table,chain:$chain,match_args:$ma,target:$target,target_args:$ta}'
            return 0
            ;;
    esac
    jq -n --arg id "$id" --arg kind "$kind" --arg family "$family" --arg source "$source" --arg destination "$dest" --arg in_iface "$inif" --arg out_iface "$outif" --arg action "$action" --arg protocol "$proto" --arg dport "$dport" --arg to_source "$tosrc" --arg to_destination "$todst" --arg description "$desc" --argjson ret "$ret" '{id:$id,enabled:true,kind:$kind,family:$family,source:$source,destination:$destination,in_iface:$in_iface,out_iface:$out_iface,action:$action,protocol:$protocol,dport:$dport,to_source:$to_source,to_destination:$to_destination,return_established:$ret,description:$description}'
}
fw_snapshot_dir_for_instance() { printf '%s/%s\n' "$FIREWALL_SNAPSHOT_ROOT" "$1"; }
fw_create_snapshot() {
    local instance="$1" label="${2:-manual}" dir root policy state
    if ! ask_yes_no "Create a persistent firewall snapshot for $instance now?" "y"; then print_info "Persistent firewall snapshot skipped by request."; return 1; fi
    ensure_backup_root; root="$(fw_snapshot_dir_for_instance "$instance")"; mkdir -p "$root"; chmod 700 "$root"
    dir="$root/$(date +%Y%m%d-%H%M%S)-${label//[^A-Za-z0-9_.-]/_}-$RANDOM"; mkdir -p "$dir"
    policy="$(firewall_policy_file "$instance")"; state="$(instance_state_file "$instance")"
    [[ -f "$policy" ]] && cp -a "$policy" "$dir/policy.json"; [[ -f "$state" ]] && cp -a "$state" "$dir/state.env"
    { echo "instance=$instance"; echo "created=$(date -Is)"; echo "label=$label"; } > "$dir/meta.env"
    fw_show_live_rules "$instance" > "$dir/live-rules.txt" 2>&1 || true
    print_ok "Firewall snapshot saved: $dir"
}

fw_temp_rollback_bundle() {
    local instance="$1" dir; dir="$(mktemp -d /tmp/ocserv-manager-firewall-rollback.XXXXXX)"
    [[ -f "$(firewall_policy_file "$instance")" ]] && cp -a "$(firewall_policy_file "$instance")" "$dir/policy.json"
    [[ -f "$(instance_state_file "$instance")" ]] && cp -a "$(instance_state_file "$instance")" "$dir/state.env"
    echo "$dir"
}

fw_restore_temp_bundle() {
    local instance="$1" dir="$2"
    [[ -f "$dir/policy.json" ]] && cp -a "$dir/policy.json" "$(firewall_policy_file "$instance")"
    [[ -f "$dir/state.env" ]] && cp -a "$dir/state.env" "$(instance_state_file "$instance")"
    apply_firewall_for_instance "$instance" >/dev/null 2>&1 || true
}

fw_prepare_change() {
    local instance="$1" label="$2" dir
    dir="$(fw_temp_rollback_bundle "$instance")"
    if ask_yes_no "Create a persistent firewall snapshot before '$label'?" "y"; then
        # The user already confirmed; create directly without a second prompt.
        ensure_backup_root; local root snap policy state; root="$(fw_snapshot_dir_for_instance "$instance")"; mkdir -p "$root"; chmod 700 "$root"
        snap="$root/$(date +%Y%m%d-%H%M%S)-before-${label//[^A-Za-z0-9_.-]/_}-$RANDOM"; mkdir -p "$snap"
        policy="$(firewall_policy_file "$instance")"; state="$(instance_state_file "$instance")"
        [[ -f "$policy" ]] && cp -a "$policy" "$snap/policy.json"; [[ -f "$state" ]] && cp -a "$state" "$snap/state.env"
        { echo "instance=$instance"; echo "created=$(date -Is)"; echo "label=before-$label"; } > "$snap/meta.env"
        fw_show_live_rules "$instance" > "$snap/live-rules.txt" 2>&1 || true
        print_ok "Firewall snapshot saved: $snap" >&2
    else
        print_info "No persistent snapshot will be kept; a temporary rollback copy exists only for this change." >&2
    fi
    echo "$dir"
}

fw_commit_or_rollback() {
    local instance="$1" rollback="$2"
    if apply_firewall_for_instance "$instance"; then rm -rf "$rollback"; return 0; fi
    print_err "Applying the new firewall policy failed; restoring the previous saved policy."
    fw_restore_temp_bundle "$instance" "$rollback"; rm -rf "$rollback"; return 1
}

fw_policy_add_rule() {
    local instance="$1" rollback rule file tmp
    ensure_firewall_policy_file "$instance" || return 1
    rollback="$(fw_prepare_change "$instance" add-rule)"
    rule="$(fw_rule_wizard "$instance" || true)"; [[ -n "$rule" ]] || { rm -rf "$rollback"; return 0; }
    file="$(firewall_policy_file "$instance")"; tmp="$(mktemp)"; jq --argjson r "$rule" '.rules += [$r]' "$file" > "$tmp" && mv "$tmp" "$file"
    fw_commit_or_rollback "$instance" "$rollback"
}

fw_choose_rule_index() {
    local instance="$1" count choice
    fw_list_rules "$instance" >&2; count="$(jq '.rules|length' "$(firewall_policy_file "$instance")")"; ((count>0)) || return 1
    while true; do read -r -p "Select rule number (0=cancel): " choice || true; [[ "$choice" == 0 ]] && return 1; [[ "$choice" =~ ^[0-9]+$ ]] && ((choice>=1 && choice<=count)) && { echo "$choice"; return 0; }; print_warn "Invalid selection." >&2; done
}

fw_policy_edit_rule() {
    local instance="$1" idx old rollback rule file tmp oldid
    ensure_firewall_policy_file "$instance" || return 1; idx="$(fw_choose_rule_index "$instance" || true)"; [[ -n "$idx" ]] || return 0
    old="$(fw_rule_json_by_index "$instance" "$idx")"; oldid="$(jq -r '.id' <<<"$old")"; rollback="$(fw_prepare_change "$instance" edit-rule)"
    print_info "Rebuild the selected rule. Its stable ID will be preserved: $oldid"
    rule="$(fw_rule_wizard "$instance" "$idx" "$old" || true)"; [[ -n "$rule" ]] || { rm -rf "$rollback"; return 0; }
    rule="$(jq --arg id "$oldid" '.id=$id' <<<"$rule")"; file="$(firewall_policy_file "$instance")"; tmp="$(mktemp)"
    jq --argjson i "$((idx-1))" --argjson r "$rule" '.rules[$i]=$r' "$file" > "$tmp" && mv "$tmp" "$file"
    fw_commit_or_rollback "$instance" "$rollback"
}

fw_policy_toggle_rule() {
    local instance="$1" idx rollback file tmp
    idx="$(fw_choose_rule_index "$instance" || true)"; [[ -n "$idx" ]] || return 0; rollback="$(fw_prepare_change "$instance" toggle-rule)"; file="$(firewall_policy_file "$instance")"; tmp="$(mktemp)"
    jq --argjson i "$((idx-1))" '.rules[$i].enabled = (if .rules[$i].enabled==false then true else false end)' "$file" > "$tmp" && mv "$tmp" "$file"
    fw_commit_or_rollback "$instance" "$rollback"
}

fw_policy_delete_rule() {
    local instance="$1" idx rollback file tmp id
    idx="$(fw_choose_rule_index "$instance" || true)"; [[ -n "$idx" ]] || return 0; id="$(jq -r --argjson i "$((idx-1))" '.rules[$i].id' "$(firewall_policy_file "$instance")")"
    ask_yes_no "Delete firewall rule $id?" "n" || return 0; rollback="$(fw_prepare_change "$instance" delete-rule)"; file="$(firewall_policy_file "$instance")"; tmp="$(mktemp)"
    jq --argjson i "$((idx-1))" 'del(.rules[$i])' "$file" > "$tmp" && mv "$tmp" "$file"
    fw_commit_or_rollback "$instance" "$rollback"
}

fw_policy_clone_rule() {
    local instance="$1" idx rollback file tmp rule newid
    idx="$(fw_choose_rule_index "$instance" || true)"; [[ -n "$idx" ]] || return 0; rollback="$(fw_prepare_change "$instance" clone-rule)"; file="$(firewall_policy_file "$instance")"; rule="$(fw_rule_json_by_index "$instance" "$idx")"; newid="$(fw_new_rule_id)"; rule="$(jq --arg id "$newid" '.id=$id | .description=((.description // "") + " (clone)")' <<<"$rule")"; tmp="$(mktemp)"; jq --argjson r "$rule" '.rules += [$r]' "$file" > "$tmp" && mv "$tmp" "$file"; fw_commit_or_rollback "$instance" "$rollback"
}

fw_base_policy_menu() {
    local instance="$1" choice rollback mode ip
    ensure_firewall_policy_file "$instance" || return 1
    while true; do
        echo; echo "==== Base ocserv firewall policy: $instance ===="
        echo "1) Toggle managed TCP/UDP ingress (current: $(state_get "$instance" FIREWALL_BASE_INGRESS 2>/dev/null || echo 1))"
        echo "2) Toggle base VPN FORWARD pair (current: $(state_get "$instance" FIREWALL_BASE_FORWARD 2>/dev/null || echo 1))"
        echo "3) IPv4 NAT mode (current: $(state_get "$instance" FIREWALL_BASE_NAT_MODE 2>/dev/null || echo masquerade))"
        echo "4) Primary outbound interface / detected route (current: $(fw_primary_out_iface "$instance"))"
        echo "5) IPv6 NAT66 toggle (current: $(state_get "$instance" IPV6_NAT 2>/dev/null || echo 0))"
        echo "6) Host-wide Global MASQUERADE compatibility mode (current: $(state_get "$instance" FIREWALL_GLOBAL_MASQUERADE 2>/dev/null || echo 0))"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) rollback="$(fw_prepare_change "$instance" base-ingress)"; [[ "$(state_get "$instance" FIREWALL_BASE_INGRESS 2>/dev/null || echo 1)" == 1 ]] && state_set "$instance" FIREWALL_BASE_INGRESS 0 || state_set "$instance" FIREWALL_BASE_INGRESS 1; fw_commit_or_rollback "$instance" "$rollback" ;;
            2) rollback="$(fw_prepare_change "$instance" base-forward)"; [[ "$(state_get "$instance" FIREWALL_BASE_FORWARD 2>/dev/null || echo 1)" == 1 ]] && state_set "$instance" FIREWALL_BASE_FORWARD 0 || state_set "$instance" FIREWALL_BASE_FORWARD 1; fw_commit_or_rollback "$instance" "$rollback" ;;
            3)
                echo "1) MASQUERADE (recommended for dynamic/default egress)"; echo "2) SNAT to a selected local IP"; echo "3) No base IPv4 NAT"
                read -r -p "Select: " mode || true; rollback="$(fw_prepare_change "$instance" base-nat)"
                case "$mode" in 1) state_set "$instance" FIREWALL_BASE_NAT_MODE masquerade; state_set "$instance" FIREWALL_BASE_SNAT_IP "" ;; 2) ip="$(fw_choose_local_ipv4 "Choose local IPv4 for base SNAT")"; state_set "$instance" FIREWALL_BASE_NAT_MODE snat; state_set "$instance" FIREWALL_BASE_SNAT_IP "$ip" ;; 3) state_set "$instance" FIREWALL_BASE_NAT_MODE none ;; *) rm -rf "$rollback"; continue ;; esac
                fw_commit_or_rollback "$instance" "$rollback"
                ;;
            4) rollback="$(fw_prepare_change "$instance" primary-outbound)"; fw_select_primary_outbound "$instance"; fw_commit_or_rollback "$instance" "$rollback" ;;
            5) rollback="$(fw_prepare_change "$instance" ipv6-nat)"; [[ "$(state_get "$instance" IPV6_NAT 2>/dev/null || echo 0)" == 1 ]] && state_set "$instance" IPV6_NAT 0 || state_set "$instance" IPV6_NAT 1; fw_commit_or_rollback "$instance" "$rollback" ;;
            6)
                echo
                print_warn "Global MASQUERADE is host-wide and intentionally broad."
                print_warn "It is equivalent in effect to: iptables -t nat -A POSTROUTING -j MASQUERADE"
                print_warn "It can affect containers, multi-IP source selection, FRP/proxies and unrelated services."
                if [[ "$(state_get "$instance" FIREWALL_GLOBAL_MASQUERADE 2>/dev/null || echo 0)" == 1 ]]; then
                    ask_yes_no "Disable host-wide Global MASQUERADE?" "y" || continue
                    rollback="$(fw_prepare_change "$instance" global-masquerade-off)"; state_set "$instance" FIREWALL_GLOBAL_MASQUERADE 0; fw_commit_or_rollback "$instance" "$rollback"
                else
                    ask_yes_no "Enable host-wide Global MASQUERADE anyway?" "n" || continue
                    rollback="$(fw_prepare_change "$instance" global-masquerade-on)"; state_set "$instance" FIREWALL_GLOBAL_MASQUERADE 1; fw_commit_or_rollback "$instance" "$rollback"
                fi
                ;;
            0) return 0 ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

fw_backend_menu() {
    local instance="$1" rollback old
    old="$(firewall_mode_for_instance "$instance")"; rollback="$(fw_prepare_change "$instance" backend-change)"
    configure_firewall_mode "$instance" || { rm -rf "$rollback"; return 0; }
    if [[ "$old" != "$(firewall_mode_for_instance "$instance")" ]]; then fw_commit_or_rollback "$instance" "$rollback"; else rm -rf "$rollback"; fi
}

fw_show_live_rules() {
    local instance="$1" family cmd role table chain
    for family in ipv4 ipv6; do
        cmd="$(fw_cmd_for_family "$family" 2>/dev/null || true)"; [[ -n "$cmd" ]] || continue
        echo "==== $family manager-owned chains: $instance ===="
        for role in input forward output; do chain="$(firewall_chain_name "$instance" "$role")"; echo "-- filter/$role ($chain)"; "$cmd" -t filter -S "$chain" 2>/dev/null || echo "(not present)"; done
        for role in prerouting postrouting; do chain="$(firewall_chain_name "$instance" "$role")"; echo "-- nat/$role ($chain)"; "$cmd" -t nat -S "$chain" 2>/dev/null || echo "(not present)"; done
        for role in prerouting input forward output postrouting; do chain="$(firewall_chain_name "$instance" "$role")"; echo "-- mangle/$role ($chain)"; "$cmd" -t mangle -S "$chain" 2>/dev/null || echo "(not present)"; done
        for role in prerouting output; do chain="$(firewall_chain_name "$instance" "$role")"; echo "-- raw/$role ($chain)"; "$cmd" -t raw -S "$chain" 2>/dev/null || echo "(not present)"; done
    done
    if command -v ufw >/dev/null 2>&1; then echo "==== UFW rules tagged for $instance ===="; ufw status numbered 2>/dev/null | grep -F "ocserv-manager:$instance" || echo "(none)"; fi
}

fw_restore_snapshot_menu() {
    local instance="$1" root d i choice rollback
    local -a snaps=()
    root="$(fw_snapshot_dir_for_instance "$instance")"; [[ -d "$root" ]] || { print_warn "No persistent firewall snapshots exist for $instance."; return 0; }
    while IFS= read -r d; do [[ -d "$d" ]] && snaps+=("$d"); done < <(find "$root" -mindepth 1 -maxdepth 1 -type d -printf '%p\n' | sort -r)
    ((${#snaps[@]})) || { print_warn "No snapshots found."; return 0; }
    echo "Firewall snapshots:"; for ((i=0;i<${#snaps[@]};i++)); do printf '%d) %s\n' "$((i+1))" "${snaps[$i]}"; done; echo "0) Cancel"
    read -r -p "Select: " choice || true; [[ "$choice" == 0 ]] && return 0; [[ "$choice" =~ ^[0-9]+$ ]] && ((choice>=1 && choice<=${#snaps[@]})) || { print_warn "Invalid selection."; return 0; }
    d="${snaps[$((choice-1))]}"; ask_yes_no "Restore firewall policy/state from $d?" "n" || return 0
    rollback="$(fw_prepare_change "$instance" restore-snapshot)"
    [[ -f "$d/policy.json" ]] && cp -a "$d/policy.json" "$(firewall_policy_file "$instance")"
    [[ -f "$d/state.env" ]] && cp -a "$d/state.env" "$(instance_state_file "$instance")"
    fw_commit_or_rollback "$instance" "$rollback"
}

fw_reset_defaults() {
    local instance="$1" rollback mode file tmp
    echo "Reset options:"; echo "1) Reset base/custom policy but keep current backend"; echo "2) Full Manager firewall defaults (iptables + base ingress/forward/MASQUERADE + no custom rules)"; echo "0) Cancel"
    read -r -p "Select: " mode || true; [[ "$mode" == 0 ]] && return 0
    ask_yes_no "Reset the saved firewall policy for $instance?" "n" || return 0; rollback="$(fw_prepare_change "$instance" reset-defaults)"
    state_set "$instance" FIREWALL_BASE_INGRESS 1; state_set "$instance" FIREWALL_BASE_FORWARD 1; state_set "$instance" FIREWALL_BASE_NAT_MODE masquerade; state_set "$instance" FIREWALL_BASE_SNAT_IP ""; state_set "$instance" FIREWALL_GLOBAL_MASQUERADE 0; state_set "$instance" OUT_IFACE "$(default_route_iface)"; state_set "$instance" FIREWALL_PRIMARY_ROUTE "default(auto)"
    [[ "$mode" == 2 ]] && state_set "$instance" FIREWALL_MODE iptables
    file="$(firewall_policy_file "$instance")"; tmp="$(mktemp)"; jq '.rules=[]' "$file" > "$tmp" && mv "$tmp" "$file"
    fw_commit_or_rollback "$instance" "$rollback"
}

fw_show_host_firewall_readonly() {
    echo "==== Full host firewall (read-only) ===="
    if command -v iptables-save >/dev/null 2>&1; then echo; echo "---- iptables-save ----"; iptables-save 2>/dev/null || true; fi
    if command -v ip6tables-save >/dev/null 2>&1; then echo; echo "---- ip6tables-save ----"; ip6tables-save 2>/dev/null || true; fi
    if command -v ufw >/dev/null 2>&1; then echo; echo "---- UFW status numbered ----"; ufw status numbered 2>/dev/null || true; fi
    if command -v nft >/dev/null 2>&1; then echo; echo "---- nftables ruleset ----"; nft list ruleset 2>/dev/null || true; fi
    print_info "This view is read-only. Firewall Manager edits only rules owned by the selected ocserv instance."
}


fw_choose_interface_simple() {
    local prompt="$1" allow_any="${2:-0}" line name state addr i choice
    local -a items=() states=() addrs=()
    while IFS= read -r line; do
        name="$(awk -F': ' '{print $2}' <<<"$line" | sed 's/@.*//')"
        [[ -n "$name" ]] || continue
        [[ "$name" == lo ]] && continue
        [[ "$name" =~ ^vpns[0-9]+$ ]] && continue
        state="$(awk '{for(i=1;i<=NF;i++) if($i=="state") print $(i+1)}' <<<"$line")"
        addr="$(ip -o -4 addr show dev "$name" 2>/dev/null | awk '{print $4}' | paste -sd, -)"
        items+=("$name"); states+=("${state:-?}"); addrs+=("${addr:-no-ipv4}")
    done < <(ip -o link show 2>/dev/null)
    echo "$prompt" >&2
    [[ "$allow_any" == 1 ]] && echo "0) Any interface" >&2
    for ((i=0;i<${#items[@]};i++)); do
        printf '%d) %s  state=%s  ipv4=%s\n' "$((i+1))" "${items[$i]}" "${states[$i]}" "${addrs[$i]}" >&2
    done
    echo "m) Enter interface manually" >&2
    while true; do
        read -r -p "Select: " choice || true
        [[ "$allow_any" == 1 && "$choice" == 0 ]] && { echo ""; return 0; }
        if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice>=1 && choice<=${#items[@]})); then
            echo "${items[$((choice-1))]}"; return 0
        fi
        if [[ "$choice" == m || "$choice" == M ]]; then
            name="$(ask_value "Interface name" "")"
            valid_interface_name "$name" && { echo "$name"; return 0; }
            print_warn "Invalid interface name." >&2
        else
            print_warn "Invalid selection." >&2
        fi
    done
}

fw_quick_add_forward() {
    local instance="$1" rollback outif desc id file tmp rule
    ensure_firewall_policy_file "$instance" || return 1
    echo
    print_info "Creates: VPN subnet -> selected interface/TUN, plus RELATED/ESTABLISHED return traffic."
    outif="$(fw_choose_interface_simple "Choose interface/TUN" 0)" || return 0
    [[ -n "$outif" ]] || return 0
    desc="$(ask_value "Description" "VPN through $outif")"
    rollback="$(fw_prepare_change "$instance" quick-forward)"
    id="$(fw_new_rule_id)"
    rule="$(jq -nc --arg id "$id" --arg out "$outif" --arg desc "$desc" '{id:$id,enabled:true,kind:"forward_pair",family:"ipv4",source:"@vpn",destination:"any",in_iface:"",out_iface:$out,action:"ACCEPT",return_established:true,description:$desc}')"
    file="$(firewall_policy_file "$instance")"; tmp="$(mktemp)"
    jq --argjson r "$rule" '.rules += [$r]' "$file" >"$tmp" && mv "$tmp" "$file"
    fw_commit_or_rollback "$instance" "$rollback"
}

fw_quick_add_masquerade() {
    local instance="$1" rollback outif desc id file tmp rule
    ensure_firewall_policy_file "$instance" || return 1
    echo
    print_info "Adds extra MASQUERADE for this VPN subnet on one selected egress interface."
    outif="$(fw_choose_interface_simple "Choose NAT egress interface" 0)" || return 0
    [[ -n "$outif" ]] || return 0
    desc="$(ask_value "Description" "VPN NAT via $outif")"
    rollback="$(fw_prepare_change "$instance" quick-masquerade)"
    id="$(fw_new_rule_id)"
    rule="$(jq -nc --arg id "$id" --arg out "$outif" --arg desc "$desc" '{id:$id,enabled:true,kind:"nat_masquerade",family:"ipv4",source:"@vpn",destination:"any",in_iface:"",out_iface:$out,action:"ACCEPT",return_established:false,description:$desc}')"
    file="$(firewall_policy_file "$instance")"; tmp="$(mktemp)"
    jq --argjson r "$rule" '.rules += [$r]' "$file" >"$tmp" && mv "$tmp" "$file"
    fw_commit_or_rollback "$instance" "$rollback"
}

fw_quick_optimize_tunnel() {
    local instance="$1" outif rollback file tmp subnet id rule existing added=0
    ensure_firewall_policy_file "$instance" || return 1
    echo
    print_info "Optimizes VPN -> selected interface/TUN with three scoped pieces:"
    echo "- Stateful FORWARD pair"
    echo "- MASQUERADE only for this instance VPN subnet on the selected interface"
    echo "- TCP MSS clamp to PMTU for SYN packets on this forwarded path"
    echo
    print_info "This reproduces the useful VPN->TUN NAT effect of a broad POSTROUTING MASQUERADE without NATing unrelated host traffic."
    outif="$(fw_choose_interface_simple "Choose interface/TUN to optimize" 0)" || return 0
    [[ -n "$outif" ]] || return 0
    subnet="$(state_get "$instance" SUBNET 2>/dev/null || true)"; [[ -n "$subnet" ]] || { print_err "VPN subnet is unknown for $instance."; return 1; }
    rollback="$(fw_prepare_change "$instance" optimize-tunnel)"
    file="$(firewall_policy_file "$instance")"; tmp="$(mktemp)"; cp -a "$file" "$tmp"

    existing="$(jq --arg o "$outif" '[.rules[] | select(.enabled!=false and .kind=="forward_pair" and .source=="@vpn" and (.destination//"any")=="any" and (.out_iface//"")==$o)] | length' "$tmp")"
    if [[ "$existing" == 0 ]]; then
        id="$(fw_new_rule_id)"; rule="$(jq -nc --arg id "$id" --arg out "$outif" '{id:$id,enabled:true,kind:"forward_pair",family:"ipv4",source:"@vpn",destination:"any",in_iface:"",out_iface:$out,action:"ACCEPT",return_established:true,description:("VPN forward via " + $out)}')"
        jq --argjson r "$rule" '.rules += [$r]' "$tmp" > "$tmp.new" && mv "$tmp.new" "$tmp"; added=$((added+1))
    fi
    existing="$(jq --arg o "$outif" '[.rules[] | select(.enabled!=false and .kind=="nat_masquerade" and .source=="@vpn" and (.destination//"any")=="any" and (.out_iface//"")==$o)] | length' "$tmp")"
    if [[ "$existing" == 0 ]]; then
        id="$(fw_new_rule_id)"; rule="$(jq -nc --arg id "$id" --arg out "$outif" '{id:$id,enabled:true,kind:"nat_masquerade",family:"ipv4",source:"@vpn",destination:"any",in_iface:"",out_iface:$out,action:"ACCEPT",return_established:false,description:("VPN scoped NAT via " + $out)}')"
        jq --argjson r "$rule" '.rules += [$r]' "$tmp" > "$tmp.new" && mv "$tmp.new" "$tmp"; added=$((added+1))
    fi
    existing="$(jq --arg o "$outif" '[.rules[] | select(.enabled!=false and .kind=="mss_clamp" and .source=="@vpn" and (.destination//"any")=="any" and (.out_iface//"")==$o)] | length' "$tmp")"
    if [[ "$existing" == 0 ]]; then
        id="$(fw_new_rule_id)"; rule="$(jq -nc --arg id "$id" --arg out "$outif" '{id:$id,enabled:true,kind:"mss_clamp",family:"ipv4",source:"@vpn",destination:"any",in_iface:"",out_iface:$out,action:"ACCEPT",return_established:false,description:("TCP MSS clamp via " + $out)}')"
        jq --argjson r "$rule" '.rules += [$r]' "$tmp" > "$tmp.new" && mv "$tmp.new" "$tmp"; added=$((added+1))
    fi
    mv "$tmp" "$file"
    if fw_commit_or_rollback "$instance" "$rollback"; then
        if (( added == 0 )); then print_ok "Tunnel optimization was already complete for $outif."; else print_ok "Tunnel optimization completed for $outif; added $added missing rule(s)."; fi
        echo "Expected effective path: $subnet -> $outif with scoped MASQUERADE and TCP MSS clamp."
    fi
}

fw_toggle_global_masquerade_quick() {
    local instance="$1" current rollback
    current="$(state_get "$instance" FIREWALL_GLOBAL_MASQUERADE 2>/dev/null || echo 0)"
    echo
    print_warn "Host-wide Global MASQUERADE affects ALL IPv4 traffic reaching POSTROUTING."
    echo "Equivalent in effect to: iptables -t nat -A POSTROUTING -j MASQUERADE"
    echo "Recommended only for compatibility/testing when scoped VPN NAT is insufficient."
    if [[ "$current" == 1 ]]; then
        ask_yes_no "Global MASQUERADE is ON. Disable it?" "y" || return 0
        rollback="$(fw_prepare_change "$instance" global-masquerade-off)"; state_set "$instance" FIREWALL_GLOBAL_MASQUERADE 0
    else
        ask_yes_no "Enable Global MASQUERADE despite the host-wide scope?" "n" || return 0
        rollback="$(fw_prepare_change "$instance" global-masquerade-on)"; state_set "$instance" FIREWALL_GLOBAL_MASQUERADE 1
    fi
    fw_commit_or_rollback "$instance" "$rollback"
}

fw_show_detected_network_simple() {
    local def line name state addr suffix
    def="$(default_route_iface 2>/dev/null || true)"
    echo "==== Useful interfaces ===="
    while IFS= read -r line; do
        name="$(awk -F': ' '{print $2}' <<<"$line" | sed 's/@.*//')"
        [[ -n "$name" && "$name" != lo ]] || continue
        [[ "$name" =~ ^vpns[0-9]+$ ]] && continue
        state="$(awk '{for(i=1;i<=NF;i++) if($i=="state") print $(i+1)}' <<<"$line")"
        addr="$(ip -o -4 addr show dev "$name" 2>/dev/null | awk '{print $4}' | paste -sd, -)"
        suffix=""; [[ "$name" == "$def" ]] && suffix="  [default Internet]"
        printf -- '- %s  state=%s  ipv4=%s%s\n' "$name" "${state:-?}" "${addr:-no-ipv4}" "$suffix"
    done < <(ip -o link show 2>/dev/null)
    echo; echo "==== Default route ===="
    ip -4 route show default 2>/dev/null | sed 's/^/- /' || true
    echo; echo "==== Policy rules ===="
    ip rule show 2>/dev/null | sed 's/^/- /' || true
    echo
    print_info "Ephemeral ocserv client interfaces (vpnsNNN) are hidden here. Advanced view shows everything."
}

fw_simple_rule_list() {
    local instance="$1" file
    ensure_firewall_policy_file "$instance" || return 1
    file="$(firewall_policy_file "$instance")"
    if [[ "$(jq '.rules|length' "$file")" == 0 ]]; then
        print_info "No extra managed firewall rules for $instance."
        return 0
    fi
    jq -r '.rules | to_entries[] | . as $e | (if $e.value.enabled==false then "OFF" else "ON " end) as $st | [$e.key+1,$st,($e.value.kind // "unknown"),($e.value.source // "any"),($e.value.destination // "any"),($e.value.out_iface // "any"),($e.value.description // "")] | @tsv' "$file" | awk -F '\t' '{printf "%s) %s  %s  src=%s  dst=%s  out=%s  %s\n",$1,$2,$3,$4,$5,$6,$7}'
}

fw_quick_setup_menu() {
    local instance="$1" choice
    while true; do
        echo; echo "==== Quick firewall setup: $instance ===="
        echo "1) Optimize VPN through an interface/TUN (FORWARD + scoped NAT + MSS clamp)"
        echo "2) Allow VPN through an interface/TUN only (FORWARD only)"
        echo "3) Add scoped VPN MASQUERADE on an interface"
        echo "4) Toggle host-wide Global MASQUERADE (old broad compatibility rule)"
        echo "5) Change normal Internet egress / base NAT"
        echo "6) Show useful interfaces/routes"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) fw_quick_optimize_tunnel "$instance"; pause ;;
            2) fw_quick_add_forward "$instance"; pause ;;
            3) fw_quick_add_masquerade "$instance"; pause ;;
            4) fw_toggle_global_masquerade_quick "$instance"; pause ;;
            5) fw_base_policy_menu "$instance" ;;
            6) fw_show_detected_network_simple; pause ;;
            0) return 0 ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

fw_rules_simple_menu() {
    local instance="$1" choice
    while true; do
        echo; echo "==== Extra firewall rules: $instance ===="
        fw_simple_rule_list "$instance"
        echo
        echo "1) Optimize VPN -> interface/TUN (FORWARD + NAT + MSS clamp)"
        echo "2) Add FORWARD-only VPN -> interface/TUN rule"
        echo "3) Enable/disable a rule"
        echo "4) Delete a rule"
        echo "5) Edit/rebuild a rule (detailed wizard)"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) fw_quick_optimize_tunnel "$instance"; pause ;;
            2) fw_quick_add_forward "$instance"; pause ;;
            3) fw_policy_toggle_rule "$instance"; pause ;;
            4) fw_policy_delete_rule "$instance"; pause ;;
            5) fw_policy_edit_rule "$instance"; pause ;;
            0) return 0 ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

fw_status_apply_menu() {
    local instance="$1" choice
    while true; do
        echo; echo "==== Firewall status: $instance ===="
        fw_policy_summary "$instance"
        echo
        echo "1) Show extra rules"
        echo "2) Apply/reapply saved firewall now"
        echo "3) Show useful interfaces/routes"
        echo "4) Show live Manager-owned chains"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) fw_simple_rule_list "$instance"; pause ;;
            2) apply_firewall_for_instance "$instance"; pause ;;
            3) fw_show_detected_network_simple; pause ;;
            4) fw_show_live_rules "$instance"; pause ;;
            0) return 0 ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

fw_backup_restore_menu() {
    local instance="$1" choice
    while true; do
        echo; echo "==== Firewall backup / restore: $instance ===="
        echo "1) Create snapshot"
        echo "2) Restore snapshot / previous saved state"
        echo "3) Reset to Manager firewall defaults"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) fw_create_snapshot "$instance" manual || true; pause ;;
            2) fw_restore_snapshot_menu "$instance"; pause ;;
            3) fw_reset_defaults "$instance"; pause ;;
            0) return 0 ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

fw_advanced_menu() {
    local instance="$1" choice rollback file tmp
    while true; do
        echo; echo "==== Advanced firewall: $instance ===="
        echo "1) Full rule wizard (FORWARD/NAT/SNAT/DNAT/INPUT/OUTPUT/UFW/mangle/raw)"
        echo "2) Clone a rule"
        echo "3) Full network detection (all vpnsNNN interfaces/tables)"
        echo "4) Show full host firewall read-only"
        echo "5) Remove all extra/custom rules (keep base policy)"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) fw_policy_add_rule "$instance"; pause ;;
            2) fw_policy_clone_rule "$instance"; pause ;;
            3) fw_show_detected_network; pause ;;
            4) fw_show_host_firewall_readonly; pause ;;
            5)
                ask_yes_no "Delete all custom firewall rules for $instance?" "n" || continue
                rollback="$(fw_prepare_change "$instance" clear-custom-rules)"
                file="$(firewall_policy_file "$instance")"; tmp="$(mktemp)"
                jq '.rules=[]' "$file" >"$tmp" && mv "$tmp" "$file"
                fw_commit_or_rollback "$instance" "$rollback"; pause ;;
            0) return 0 ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

firewall_manager_menu() {
    local instance="$1" choice
    ensure_firewall_policy_file "$instance" || return 1
    while true; do
        echo; echo "==== Firewall: $instance ===="
        echo "Backend: $(firewall_mode_for_instance "$instance")"
        echo "VPN subnet: $(state_get "$instance" SUBNET 2>/dev/null || echo unknown)"
        echo "Internet egress: $(fw_primary_out_iface "$instance")"
        echo "Base NAT: $(state_get "$instance" FIREWALL_BASE_NAT_MODE 2>/dev/null || echo masquerade)"
        echo "Global MASQUERADE: $(state_get "$instance" FIREWALL_GLOBAL_MASQUERADE 2>/dev/null || echo 0)"
        echo "Extra rules: $(jq '.rules|length' "$(firewall_policy_file "$instance")" 2>/dev/null || echo 0)"
        echo
        echo "1) Quick setup"
        echo "2) Extra routes / rules"
        echo "3) Base settings (iptables/UFW, ports, Internet FORWARD/NAT)"
        echo "4) Status / apply / detected network"
        echo "5) Backup / restore / reset"
        echo "6) Advanced"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) fw_quick_setup_menu "$instance" ;;
            2) fw_rules_simple_menu "$instance" ;;
            3)
                echo; echo "1) Change backend (iptables / UFW)"; echo "2) Base ocserv firewall policy"; echo "0) Back"
                read -r -p "Select: " choice || true
                case "$choice" in
                    1) fw_backend_menu "$instance"; pause ;;
                    2) fw_base_policy_menu "$instance" ;;
                    0) : ;;
                    *) print_warn "Invalid selection." ;;
                esac
                ;;
            4) fw_status_apply_menu "$instance" ;;
            5) fw_backup_restore_menu "$instance" ;;
            6) fw_advanced_menu "$instance" ;;
            0) return 0 ;;
            *) print_warn "Invalid selection." ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# Instance management menus
# -----------------------------------------------------------------------------
instance_detail_menu() {
    local instance="$1" choice
    while true; do
        echo; echo "==== Instance: $instance ===="
        echo "1) Status"; echo "2) Start"; echo "3) Stop"; echo "4) Restart"; echo "5) Reload"
        echo "6) Logs"; echo "7) Users"; echo "8) Groups"; echo "9) Configuration"
        echo "10) Virtual hosts (SNI)"; echo "11) Diagnostics"; echo "12) Repair"
        echo "13) Clone"; echo "14) Delete instance"; echo "15) Connection stability / mobile roaming / restore"
        echo "16) config-per-user / config-per-group settings"
        echo "17) Firewall (simple setup + advanced)"
        echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) show_instance_status "$instance"; pause;;
            2) start_instance "$instance"; pause;; 3) stop_instance "$instance"; pause;; 4) restart_instance "$instance"; pause;; 5) reload_instance "$instance"; pause;;
            6) show_instance_logs "$instance"; pause;; 7) user_management_menu "$instance";; 8) group_management_menu "$instance";; 9) configuration_menu "$instance";;
            10) vhost_menu "$instance";; 11) run_instance_diagnostics "$instance"; pause;; 12) repair_instance_menu "$instance";;
            13) clone_instance "$instance"; pause;;
            14) delete_instance "$instance"; return;;
            15) connection_stability_menu "$instance";;
            16) supplemental_config_menu "$instance";;
            17) firewall_manager_menu "$instance";;
            0) return;; *) print_warn "Invalid selection.";;
        esac
    done
}

instances_menu() {
    local choice instance
    while true; do
        echo; echo "==== Ocserv Instances ===="
        echo "1) List/status dashboard"; echo "2) Create new instance"; echo "3) Manage existing instance"; echo "4) Import existing ocserv installation"; echo "5) Migrate/copy default single instance to named multi-instance"; echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) status_dashboard || print_warn "Dashboard completed with one or more non-fatal errors."; pause;; 2) create_instance_wizard; pause;;
            3) instance="$(choose_instance)" && instance_detail_menu "$instance";;
            4) import_existing_menu; pause;; 5) migrate_default_to_named_instance; pause;; 0) return;; *) print_warn "Invalid selection.";; esac
    done
}

# -----------------------------------------------------------------------------
# Safe uninstall
# -----------------------------------------------------------------------------
remove_ocserv_software() {
    local method manifest
    if dpkg-query -W -f='${Status}' ocserv 2>/dev/null | grep -q 'install ok installed'; then
        if ask_yes_no "Purge the distribution ocserv package?" "y"; then DEBIAN_FRONTEND=noninteractive apt-get purge -y ocserv; fi
    fi
    manifest="$(source_install_manifest)"
    if [[ -f "$manifest" ]]; then
        if ask_yes_no "Remove the manager-tracked upstream source installation under /usr/local?" "y"; then remove_source_install_files; fi
    elif [[ -x /usr/local/sbin/ocserv || -x /usr/local/bin/occtl || -x /usr/local/bin/ocpasswd ]]; then
        print_warn "Legacy/untracked /usr/local ocserv binaries were detected (likely from the old source installer)."
        if ask_yes_no "Remove known legacy binaries /usr/local/sbin/ocserv, /usr/local/bin|sbin/occtl, ocpasswd?" "n"; then
            rm -f /usr/local/sbin/ocserv /usr/local/bin/ocserv /usr/local/sbin/occtl /usr/local/bin/occtl /usr/local/sbin/ocpasswd /usr/local/bin/ocpasswd
            ldconfig || true
        fi
    fi
}

uninstall_manager_ui_only() {
    local has_instances=0
    list_instances 2>/dev/null | grep -q . && has_instances=1 || true
    print_warn "This removes the read-only API/UI integrations while preserving VPN instance configs/state and runtime Central hooks."
    if (( has_instances == 1 )); then
        print_warn "The manager executable is also the minimal boot helper that reapplies only manager-owned iptables rules. It will be kept while managed instances exist so VPN networking survives reboot."
    fi
    ask_yes_no "Continue?" "n" || return 0
    disable_readonly_api || true
    if (( has_instances == 0 )); then
        systemctl disable --now ocserv-manager-firewall.service >/dev/null 2>&1 || true
        rm -f "$FIREWALL_REAPPLY_SERVICE" "$MANAGER_BIN"
        systemctl daemon-reload >/dev/null 2>&1 || true
        print_ok "Manager command/API removed; no managed instances required the boot firewall helper."
    else
        ensure_firewall_boot_persistence_for_existing_instances
        print_ok "API/UI integration removed. The manager executable was intentionally retained only as the firewall boot helper for the existing managed VPN instances."
    fi
}

uninstall_everything_menu() {
    local backup="" i
    print_warn "Full cleanup can remove all manager-owned ocserv instances and optionally ocserv software/configuration."
    ask_yes_no "Continue to full cleanup options?" "n" || return 0
    if ask_yes_no "Create a backup before cleanup?" "y"; then backup="$(create_backup_archive 1 1 before-full-uninstall)"; print_ok "Backup: $backup"; fi
    while read -r i; do
        [[ -n "$i" ]] || continue
        systemctl disable --now "$(instance_service "$i")" >/dev/null 2>&1 || true
        systemctl disable --now "$(central_agent_service "$i")" >/dev/null 2>&1 || true
        remove_firewall_for_instance "$i" || true
    done < <(list_instances | sort -u)
    systemctl disable --now ocserv-manager-api >/dev/null 2>&1 || true
    systemctl disable --now ocserv-manager-firewall.service >/dev/null 2>&1 || true
    rm -f "$SYSTEMD_DEFAULT" "$SYSTEMD_TEMPLATE" /etc/systemd/system/ocserv-manager-central@.service "$API_SERVICE" "$FIREWALL_REAPPLY_SERVICE"
    systemctl daemon-reload
    if ask_yes_no "Remove ocserv software binaries/packages too?" "y"; then remove_ocserv_software; fi
    if ask_yes_no "Delete /etc/ocserv configuration and user databases?" "n"; then rm -rf "$OCSERV_ETC"; fi
    if ask_yes_no "Delete Ocserv Manager state/config under $MANAGER_ETC?" "y"; then rm -rf "$MANAGER_ETC"; fi
    if ask_yes_no "Delete manager audit logs?" "n"; then rm -rf "$AUDIT_LOG_DIR"; fi
    rm -f /etc/logrotate.d/ocserv-manager "$MANAGER_BIN"
    rm -rf "$API_DIR"
    # Remove only our forwarding sysctl file. Do not force ip_forward=0 because another router/VPN may depend on it.
    rm -f "$SYSCTL_FILE"
    rmdir "$STABILITY_BACKUP_ROOT" 2>/dev/null || true
    rmdir "$BACKUP_ROOT" 2>/dev/null || true
    if [[ -x "$CENTRAL_MANAGER_BIN" || -f /etc/systemd/system/ocserv-central.service || -f /etc/systemd/system/ocserv-central-agent.service ]]; then
        if ask_yes_no "Remove integrated Central Master/Node components too?" "n"; then
            install_embedded_central_manager_code || true
            [[ -f /etc/systemd/system/ocserv-central-agent.service || -d /etc/ocserv-central-node ]] && "$CENTRAL_MANAGER_BIN" --uninstall-node || true
            [[ -f /etc/systemd/system/ocserv-central.service || -d /etc/ocserv-central || -d /var/lib/ocserv-central ]] && "$CENTRAL_MANAGER_BIN" --uninstall-master || true
        fi
        if ask_yes_no "Remove the extracted integrated Central Manager runtime command too?" "y"; then
            rm -f "$CENTRAL_MANAGER_BIN" "$CENTRAL_EMBED_STATE"
        fi
    fi
    print_ok "Full manager cleanup finished. Let's Encrypt was intentionally not deleted automatically because it may contain certificates used by other services."
    [[ -n "$backup" ]] && echo "Backup kept at: $backup"
}

uninstall_menu() {
    local choice instance
    while true; do
        echo; echo "==== Safe Uninstall ===="
        echo "1) Remove one instance"; echo "2) Remove manager UI/API only (preserve VPN runtime)"; echo "3) Full cleanup"; echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in 1) instance="$(choose_instance)" && delete_instance "$instance"; pause;; 2) uninstall_manager_ui_only; return;; 3) uninstall_everything_menu; return;; 0) return;; *) print_warn "Invalid selection.";; esac
    done
}

# -----------------------------------------------------------------------------
# Manager update/version and top-level menus
# -----------------------------------------------------------------------------
show_versions() {
    local latest installed binary
    latest="$(online_ocserv_tags 2>/dev/null | head -n1 || true)"
    echo "Ocserv Manager: $PROGRAM_VERSION"
    echo "Embedded Central Manager: $CENTRAL_EMBEDDED_VERSION"
    if [[ -x "$CENTRAL_MANAGER_BIN" ]]; then
        echo "Installed Central runtime: $($CENTRAL_MANAGER_BIN --version 2>/dev/null || echo unknown)"
    else
        echo "Installed Central runtime: not-installed (optional)"
    fi
    installed="$(installed_ocserv_version)"; binary="$(ocserv_bin)"
    echo "Installed ocserv: ${installed:-not-installed}"
    echo "Detected ocserv binary: ${binary:-not-found}"
    echo "Latest upstream tag found online: ${latest:-unavailable}"
    echo "Install method state:"
    [[ -f "$MANAGER_ETC/ocserv-install.env" ]] && cat "$MANAGER_ETC/ocserv-install.env" || echo "unknown/imported"
}

apply_manager_self_update() {
    local backup
    bash -n "$0" || { print_err "Current script syntax is invalid; refusing update."; return 1; }
    backup=""
    if ask_yes_no "Create a persistent backup before updating the Manager code?" "y"; then
        ensure_backup_root
        backup="$BACKUP_ROOT/manager-update-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$backup"
        [[ -f "$MANAGER_BIN" ]] && cp -a "$MANAGER_BIN" "$backup/ocserv-manager.previous"
        cp -a "$MANAGER_ETC" "$backup/manager-etc" 2>/dev/null || true
    fi
    install_manager_self
    refresh_manager_boot_units_without_reconfigure
    migrate_legacy_firewall_persistence_once
    ensure_firewall_boot_persistence_for_existing_instances
    migrate_central_multi_instance_v20_once
    print_ok "Manager code installed/updated without re-running ocserv configuration."
    [[ -n "$backup" ]] && print_info "Backup: $backup" || print_info "Backup: not created (declined)"
    if [[ -x "$CENTRAL_MANAGER_BIN" || -f /etc/systemd/system/ocserv-central.service || -f /etc/systemd/system/ocserv-central-agent.service ]]; then
        print_info "An integrated Central installation was detected. Updating its embedded code/components without reconfigure..."
        update_embedded_central_without_reconfigure || print_warn "Central update reported an error; existing Central configuration was not intentionally reconfigured."
    fi
}

backup_menu() {
    local choice
    while true; do
        echo; echo "==== Backup / Restore ===="
        echo "1) Create backup"; echo "2) Restore backup"; echo "3) List backups"; echo "0) Back"
        read -r -p "Select: " choice || true
        case "$choice" in 1) backup_interactive; pause;; 2) restore_backup_interactive; pause;; 3) ls -lh "$BACKUP_ROOT"/*.tar.gz 2>/dev/null || echo "No backups."; pause;; 0) return;; *) print_warn "Invalid selection.";; esac
    done
}

setup_optional_features_if_needed() {
    [[ -f "$AUDIT_ENV" ]] || configure_audit_logging
    if [[ ! -f "$API_ENV" ]]; then
        echo
        print_info "Optional JSON status is always available on the command line. A read-only HTTP API can also be enabled for a bot/web panel."
        if ask_yes_no "Enable the read-only HTTP API now?" "n"; then configure_readonly_api; fi
    fi
}

main_menu() {
    local choice instance
    need_root; ensure_dirs; os_preflight; install_manager_self
    refresh_manager_boot_units_without_reconfigure
    migrate_legacy_firewall_persistence_once
    ensure_firewall_boot_persistence_for_existing_instances
    migrate_central_multi_instance_v20_once
    # Central Manager is intentionally NOT prompted on initial startup.
    # It remains fully available on demand from main menu item 8 after ocserv setup.
    while true; do
        echo
        echo "=================================================="
        echo " $PROGRAM_NAME v$PROGRAM_VERSION"
        echo "=================================================="
        echo "1) Install / update ocserv (choose version, no reconfigure)"
        echo "2) Instances (default + multi-instance)"
        echo "3) Users"
        echo "4) Groups"
        echo "5) Certificates"
        echo "6) Backup / restore"
        echo "7) Diagnostics dashboard"
        echo "8) Open integrated Ocserv Central Manager"
        echo "9) JSON / read-only API"
        echo "10) Audit logging settings"
        echo "11) Version information"
        echo "12) Apply this Manager code update without reconfigure"
        echo "13) Safe uninstall"
        echo "0) Exit"
        read -r -p "Select: " choice || true
        case "$choice" in
            1) install_or_update_ocserv; pause;;
            2) setup_optional_features_if_needed; instances_menu;;
            3) instance="$(choose_instance)" && user_management_menu "$instance";;
            4) instance="$(choose_instance)" && group_management_menu "$instance";;
            5) certificate_manager;;
            6) backup_menu;;
            7) status_dashboard; if instance="$(choose_instance 2>/dev/null)"; then if ask_yes_no "Run detailed diagnostics for $instance?" "n"; then run_instance_diagnostics "$instance"; fi; fi; pause;;
            8) central_menu;;
            9) api_menu;;
            10) configure_audit_logging; pause;;
            11) show_versions; pause;;
            12) apply_manager_self_update; pause;;
            13) uninstall_menu;;
            0) exit 0;;
            *) print_warn "Invalid selection.";;
        esac
    done
}

# -----------------------------------------------------------------------------
# CLI entry points
# -----------------------------------------------------------------------------
case "${1:-}" in
    --version|-V)
        echo "$PROGRAM_NAME $PROGRAM_VERSION"
        exit 0
        ;;
    --reapply-firewall)
        need_root; ensure_dirs; reapply_all_firewall_rules
        exit $?
        ;;
    --json-status)
        need_root; ensure_dirs
        command -v jq >/dev/null 2>&1 || { print_err "jq is required for JSON status. Run the interactive manager once or install jq."; exit 1; }
        json_status "${2:-}"
        exit 0
        ;;
    --validate-all)
        need_root; validate_all_configs
        exit $?
        ;;
    --update-ocserv)
        need_root; install_or_update_ocserv
        exit $?
        ;;
    --apply-manager-update)
        need_root; apply_manager_self_update
        exit $?
        ;;
    --central-capability)
        echo "multi-instance-central-v20"
        exit 0
        ;;
    --central-instances)
        need_root; ensure_dirs; central_instances_menu
        exit $?
        ;;
    --central-instances-status)
        need_root; ensure_dirs; central_instances_status
        exit $?
        ;;
    --central-attach-all-local-master)
        need_root; ensure_dirs; central_attach_all_local_master
        exit $?
        ;;
    --central-sync-local-master-profile)
        need_root; ensure_dirs; central_sync_local_master_profile
        exit $?
        ;;
    --central-import-v19-node)
        need_root; ensure_dirs; central_import_v19_node_env "${2:-/etc/ocserv-central-node/node.env}"
        exit $?
        ;;
    --central-install)
        need_root; ensure_dirs; install_embedded_central_manager_code
        exit $?
        ;;
    --central-menu)
        need_root; ensure_dirs; central_menu
        exit 0
        ;;
    --central-update)
        need_root; ensure_dirs; update_embedded_central_without_reconfigure
        exit $?
        ;;
    --central-status)
        need_root; ensure_dirs; integrated_central_status
        exit $?
        ;;
    --help|-h)
        cat <<EOF
$PROGRAM_NAME $PROGRAM_VERSION
Usage: $0 [option]
  --version                 Show manager version
  --reapply-firewall        Reapply only manager-owned scoped firewall rules (normally used by systemd)
  --json-status [instance]  Print read-only JSON status
  --validate-all            Validate all registered ocserv configs
  --update-ocserv           Interactive ocserv version/install/update flow
  --apply-manager-update    Install this script as the persistent manager without reconfigure
  --central-install         Install/refresh embedded Central Manager code only
  --central-instances       Manage all local ocserv instances from Central (native multi-instance)
  --central-instances-status Show local Central attachment/source status
  --central-attach-all-local-master Attach all local instances to the local Master at 127.0.0.1:8088
  --central-sync-local-master-profile Sync current local Master token/profile to already attached local instances
  --central-import-v19-node [node.env] Import v19 Node API settings into the v20.4.4 source-aware shared instance profile
  --central-menu            Open the integrated Central Manager console
  --central-update          Update installed Central code/components without reconfigure
  --central-status          Show integrated Central status
  (no option)               Interactive menu
EOF
        exit 0
        ;;
    "") main_menu ;;
    *) print_err "Unknown option: $1"; exit 2 ;;
esac
