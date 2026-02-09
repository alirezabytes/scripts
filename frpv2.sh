#!/usr/bin/env bash
# FRP Menu Installer/Configurator (frps/frpc)
# - Server (frps): NO protocol selection (matches frpulse behavior when you press "n")
# - Client (frpc): protocol selection includes wss
# - Generates TOML configs + systemd services

set -euo pipefail

APP_NAME="frp-menu"
CONFIG_DIR="/etc/frp"
FRPS_TOML="${CONFIG_DIR}/frps.toml"
FRPC_TOML="${CONFIG_DIR}/frpc.toml"
BIN_FRPS="/usr/local/bin/frps"
BIN_FRPC="/usr/local/bin/frpc"
SYSTEMD_FRPS="/etc/systemd/system/frps.service"
SYSTEMD_FRPC="/etc/systemd/system/frpc.service"
INSTALL_WORKDIR="/tmp/frp_install.$$"

RED="$(printf '\033[31m')"
GRN="$(printf '\033[32m')"
YEL="$(printf '\033[33m')"
BLU="$(printf '\033[34m')"
RST="$(printf '\033[0m')"

cleanup() { rm -rf "$INSTALL_WORKDIR" >/dev/null 2>&1 || true; }
trap cleanup EXIT

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "${RED}ERROR:${RST} Run as root (sudo)."
    exit 1
  fi
}

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

ensure_deps() {
  local pkgs=()
  cmd_exists curl || pkgs+=("curl")
  cmd_exists tar  || pkgs+=("tar")
  cmd_exists systemctl || pkgs+=("systemd")

  if ((${#pkgs[@]}==0)); then return 0; fi

  echo "${YEL}Installing dependencies:${RST} ${pkgs[*]}"
  if cmd_exists apt-get; then
    apt-get update -y
    apt-get install -y "${pkgs[@]}"
  elif cmd_exists yum; then
    yum install -y "${pkgs[@]}"
  elif cmd_exists dnf; then
    dnf install -y "${pkgs[@]}"
  elif cmd_exists pacman; then
    pacman -Sy --noconfirm "${pkgs[@]}"
  else
    echo "${RED}ERROR:${RST} Unsupported package manager. Please install: ${pkgs[*]}"
    exit 1
  fi
}

get_arch() {
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7) echo "armv7" ;;
    i386|i686) echo "386" ;;
    *)
      echo "${RED}ERROR:${RST} Unsupported arch: $m"
      exit 1
      ;;
  esac
}

get_os() {
  local s
  s="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$s" in
    linux) echo "linux" ;;
    *)
      echo "${RED}ERROR:${RST} Unsupported OS: $s (script supports Linux only)"
      exit 1
      ;;
  esac
}

github_latest_tag() {
  # Uses GitHub API to get latest release tag
  # Example output: v0.66.0
  curl -fsSL "https://api.github.com/repos/fatedier/frp/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/'
}

download_and_install_frp() {
  mkdir -p "$INSTALL_WORKDIR"
  local os arch tag ver url tgz
  os="$(get_os)"
  arch="$(get_arch)"
  tag="$(github_latest_tag || true)"

  if [[ -z "$tag" ]]; then
    echo "${RED}ERROR:${RST} Could not detect latest FRP release tag from GitHub."
    exit 1
  fi

  ver="${tag#v}"
  tgz="frp_${ver}_${os}_${arch}.tar.gz"
  url="https://github.com/fatedier/frp/releases/download/${tag}/${tgz}"

  echo "${BLU}Downloading:${RST} $url"
  curl -fL "$url" -o "$INSTALL_WORKDIR/$tgz"

  echo "${BLU}Extracting...${RST}"
  tar -xzf "$INSTALL_WORKDIR/$tgz" -C "$INSTALL_WORKDIR"

  local dir="$INSTALL_WORKDIR/frp_${ver}_${os}_${arch}"
  if [[ ! -d "$dir" ]]; then
    echo "${RED}ERROR:${RST} Extracted directory not found: $dir"
    exit 1
  fi

  echo "${BLU}Installing binaries to /usr/local/bin ...${RST}"
  install -m 0755 "$dir/frps" "$BIN_FRPS"
  install -m 0755 "$dir/frpc" "$BIN_FRPC"

  mkdir -p "$CONFIG_DIR"
  echo "${GRN}Installed:${RST} frps + frpc (${tag})"
}

write_systemd_services() {
  echo "${BLU}Writing systemd services...${RST}"

  cat > "$SYSTEMD_FRPS" <<EOF
[Unit]
Description=frp server (frps)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_FRPS} -c ${FRPS_TOML}
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  cat > "$SYSTEMD_FRPC" <<EOF
[Unit]
Description=frp client (frpc)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_FRPC} -c ${FRPC_TOML}
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  echo "${GRN}OK:${RST} systemd services created."
}

read_yn() {
  local prompt="$1" default="${2:-y}" ans
  while true; do
    if [[ "$default" == "y" ]]; then
      read -r -p "$prompt [Y/n]: " ans || true
      ans="${ans:-Y}"
    else
      read -r -p "$prompt [y/N]: " ans || true
      ans="${ans:-N}"
    fi
    case "$(echo "$ans" | tr '[:upper:]' '[:lower:]')" in
      y|yes) echo "y"; return 0 ;;
      n|no)  echo "n"; return 0 ;;
      *) echo "Please answer y/n." ;;
    esac
  done
}

read_int() {
  local prompt="$1" default="$2" val
  while true; do
    read -r -p "$prompt [default: $default]: " val || true
    val="${val:-$default}"
    if [[ "$val" =~ ^[0-9]+$ ]] && ((val>=1 && val<=65535)); then
      echo "$val"
      return 0
    fi
    echo "Enter a valid port (1-65535)."
  done
}

read_str() {
  local prompt="$1" default="${2:-}" val
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [default: $default]: " val || true
    echo "${val:-$default}"
  else
    read -r -p "$prompt: " val || true
    echo "$val"
  fi
}

# ---------------------------
# FRPS CONFIG (SERVER) WIZARD
# IMPORTANT: NO protocol selection here (matches your frpulse behavior)
# ---------------------------
configure_frps() {
  mkdir -p "$CONFIG_DIR"

  echo
  echo "${BLU}FRPS (Server) config wizard${RST}"
  local bind_port token enable_auth
  bind_port="$(read_int "FRPS bindPort (server listen port)" "7000")"

  enable_auth="$(read_yn "Enable token authentication?" "y")"
  if [[ "$enable_auth" == "y" ]]; then
    token="$(read_str "Token (auth.token)" "")"
    if [[ -z "$token" ]]; then
      echo "${YEL}Warning:${RST} empty token selected. Auth will be disabled."
      enable_auth="n"
    fi
  fi

  # Optional: TLS force (needed for wss in many setups)
  local tls_force tls_cert tls_key
  tls_force="$(read_yn "Force TLS on server? (recommended if client uses wss)" "y")"
  if [[ "$tls_force" == "y" ]]; then
    tls_cert="$(read_str "TLS certFile path (e.g. /etc/letsencrypt/live/DOMAIN/fullchain.pem)" "/etc/letsencrypt/live/your-domain/fullchain.pem")"
    tls_key="$(read_str "TLS keyFile path (e.g. /etc/letsencrypt/live/DOMAIN/privkey.pem)" "/etc/letsencrypt/live/your-domain/privkey.pem")"
  fi

  # Optional: KCP / QUIC bind ports
  local enable_kcp enable_quic kcp_port quic_port
  enable_kcp="$(read_yn "Enable KCP bind port?" "n")"
  if [[ "$enable_kcp" == "y" ]]; then
    kcp_port="$(read_int "KCP bind port (kcpBindPort)" "7000")"
  fi

  enable_quic="$(read_yn "Enable QUIC bind port?" "n")"
  if [[ "$enable_quic" == "y" ]]; then
    quic_port="$(read_int "QUIC bind port (quicBindPort)" "7000")"
  fi

  # Optional: Dashboard (webServer)
  local enable_dash dash_port dash_user dash_pass dash_addr
  enable_dash="$(read_yn "Enable dashboard (webServer)?" "n")"
  if [[ "$enable_dash" == "y" ]]; then
    dash_addr="$(read_str "Dashboard listen addr" "0.0.0.0")"
    dash_port="$(read_int "Dashboard port" "7500")"
    dash_user="$(read_str "Dashboard user" "admin")"
    dash_pass="$(read_str "Dashboard password" "change_me")"
  fi

  cat > "$FRPS_TOML" <<EOF
# Auto-generated by ${APP_NAME}
bindPort = ${bind_port}
EOF

  if [[ "$enable_auth" == "y" ]]; then
    cat >> "$FRPS_TOML" <<EOF

[auth]
method = "token"
token = "${token}"
EOF
  fi

  # Transport section (server side)
  # NO protocol selection here on purpose.
  # TLS force enables WSS on the same bindPort in many deployments.
  if [[ "$tls_force" == "y" ]] || [[ "$enable_kcp" == "y" ]] || [[ "$enable_quic" == "y" ]]; then
    cat >> "$FRPS_TOML" <<'EOF'

[transport]
EOF
  fi

  if [[ "$enable_kcp" == "y" ]]; then
    echo "kcpBindPort = ${kcp_port}" >> "$FRPS_TOML"
  fi
  if [[ "$enable_quic" == "y" ]]; then
    echo "quicBindPort = ${quic_port}" >> "$FRPS_TOML"
  fi

  if [[ "$tls_force" == "y" ]]; then
    cat >> "$FRPS_TOML" <<EOF

[transport.tls]
force = true
certFile = "${tls_cert}"
keyFile  = "${tls_key}"
EOF
  fi

  if [[ "$enable_dash" == "y" ]]; then
    cat >> "$FRPS_TOML" <<EOF

[webServer]
addr = "${dash_addr}"
port = ${dash_port}
user = "${dash_user}"
password = "${dash_pass}"
EOF
  fi

  echo "${GRN}OK:${RST} wrote ${FRPS_TOML}"
}

# ---------------------------
# FRPC CONFIG (CLIENT) WIZARD
# Includes protocol selection (tcp/kcp/quic/websocket/wss)
# ---------------------------
select_frpc_protocol() {
  local choice
  echo
  echo "Select frpc transport.protocol:"
  echo "  1) tcp"
  echo "  2) kcp"
  echo "  3) quic"
  echo "  4) websocket"
  echo "  5) wss"
  while true; do
    read -r -p "Choice [1-5] (default 5=wss): " choice || true
    choice="${choice:-5}"
    case "$choice" in
      1) echo "tcp"; return 0 ;;
      2) echo "kcp"; return 0 ;;
      3) echo "quic"; return 0 ;;
      4) echo "websocket"; return 0 ;;
      5) echo "wss"; return 0 ;;
      *) echo "Invalid choice." ;;
    esac
  done
}

configure_frpc() {
  mkdir -p "$CONFIG_DIR"

  echo
  echo "${BLU}FRPC (Client) config wizard${RST}"

  local server_addr server_port proto enable_auth token
  server_addr="$(read_str "FRPS server address (domain or IP)" "example.com")"
  server_port="$(read_int "FRPS server port" "7000")"
  proto="$(select_frpc_protocol)"

  enable_auth="$(read_yn "Enable token authentication?" "y")"
  if [[ "$enable_auth" == "y" ]]; then
    token="$(read_str "Token (auth.token)" "")"
    if [[ -z "$token" ]]; then
      echo "${YEL}Warning:${RST} empty token selected. Auth will be disabled."
      enable_auth="n"
    fi
  fi

  # TLS behavior:
  # - wss: TLS must be enabled
  # - other protocols: ask user (TLS is enabled by default in docs, but we make it explicit)
  local tls_enable tls_server_name
  if [[ "$proto" == "wss" ]]; then
    tls_enable="y"
  else
    tls_enable="$(read_yn "Enable TLS? (recommended)" "y")"
  fi

  if [[ "$tls_enable" == "y" ]]; then
    tls_server_name="$(read_str "TLS serverName (SNI). Use domain if serverAddr is IP" "$server_addr")"
  fi

  # Proxies wizard
  echo
  echo "${BLU}Now add proxies (port forwards).${RST}"
  echo "You can add multiple proxies. Supported here: tcp/udp (simple, common)."
  echo "Press Enter to accept defaults."

  local proxy_blocks=""
  while true; do
    local add_more
    add_more="$(read_yn "Add a proxy?" "y")"
    if [[ "$add_more" != "y" ]]; then break; fi

    local pname ptype lip lport rport
    pname="$(read_str "Proxy name" "svc$(date +%s)")"
    echo "Proxy type:"
    echo "  1) tcp"
    echo "  2) udp"
    local tchoice
    while true; do
      read -r -p "Choice [1-2] (default 1=tcp): " tchoice || true
      tchoice="${tchoice:-1}"
      case "$tchoice" in
        1) ptype="tcp"; break ;;
        2) ptype="udp"; break ;;
        *) echo "Invalid choice." ;;
      esac
    done

    lip="$(read_str "Local IP" "127.0.0.1")"
    lport="$(read_int "Local Port" "22")"
    rport="$(read_int "Remote Port (opened on frps)" "6000")"

    proxy_blocks+=$'\n'"[[proxies]]"$'\n'
    proxy_blocks+="name = \"${pname}\""$'\n'
    proxy_blocks+="type = \"${ptype}\""$'\n'
    proxy_blocks+="localIP = \"${lip}\""$'\n'
    proxy_blocks+="localPort = ${lport}"$'\n'
    proxy_blocks+="remotePort = ${rport}"$'\n'
  done

  if [[ -z "$proxy_blocks" ]]; then
    echo "${YEL}No proxies added.${RST} frpc will run but do nothing until you add proxies."
  fi

  cat > "$FRPC_TOML" <<EOF
# Auto-generated by ${APP_NAME}
serverAddr = "${server_addr}"
serverPort = ${server_port}

[transport]
protocol = "${proto}"
EOF

  if [[ "$enable_auth" == "y" ]]; then
    cat >> "$FRPC_TOML" <<EOF

[auth]
method = "token"
token = "${token}"
EOF
  fi

  if [[ "$tls_enable" == "y" ]]; then
    cat >> "$FRPC_TOML" <<EOF

[transport.tls]
enable = true
serverName = "${tls_server_name}"
EOF
  else
    cat >> "$FRPC_TOML" <<EOF

[transport.tls]
enable = false
EOF
  fi

  if [[ -n "$proxy_blocks" ]]; then
    printf "\n%s\n" "$proxy_blocks" >> "$FRPC_TOML"
  fi

  echo "${GRN}OK:${RST} wrote ${FRPC_TOML}"
}

service_action() {
  local svc="$1" action="$2"
  systemctl "$action" "$svc"
  systemctl --no-pager --full status "$svc" || true
}

enable_autostart() {
  local svc="$1"
  systemctl enable "$svc"
  echo "${GRN}Enabled:${RST} $svc at boot."
}

disable_autostart() {
  local svc="$1"
  systemctl disable "$svc" || true
  echo "${YEL}Disabled:${RST} $svc at boot."
}

show_menu() {
  echo
  echo "${BLU}========== ${APP_NAME} ==========${RST}"
  echo "1) Install/Update FRP (download latest release)"
  echo "2) Configure frps (server)  - NO protocol selection"
  echo "3) Configure frpc (client)  - protocol selection includes wss"
  echo "4) Write/Refresh systemd services"
  echo "5) Start frps"
  echo "6) Start frpc"
  echo "7) Restart frps"
  echo "8) Restart frpc"
  echo "9) Stop frps"
  echo "10) Stop frpc"
  echo "11) Status (frps/frpc)"
  echo "12) Enable autostart (frps/frpc)"
  echo "13) Disable autostart (frps/frpc)"
  echo "14) Show configs (frps/frpc)"
  echo "0) Exit"
  echo
}

show_configs() {
  echo
  echo "${BLU}--- ${FRPS_TOML} ---${RST}"
  [[ -f "$FRPS_TOML" ]] && sed -n '1,240p' "$FRPS_TOML" || echo "(not found)"
  echo
  echo "${BLU}--- ${FRPC_TOML} ---${RST}"
  [[ -f "$FRPC_TOML" ]] && sed -n '1,260p' "$FRPC_TOML" || echo "(not found)"
}

main() {
  need_root
  ensure_deps
  mkdir -p "$CONFIG_DIR"

  while true; do
    show_menu
    local choice
    read -r -p "Select: " choice || true
    case "${choice:-}" in
      1)
        download_and_install_frp
        ;;
      2)
        configure_frps
        ;;
      3)
        configure_frpc
        ;;
      4)
        write_systemd_services
        ;;
      5)
        service_action "frps.service" "start"
        ;;
      6)
        service_action "frpc.service" "start"
        ;;
      7)
        service_action "frps.service" "restart"
        ;;
      8)
        service_action "frpc.service" "restart"
        ;;
      9)
        service_action "frps.service" "stop"
        ;;
      10)
        service_action "frpc.service" "stop"
        ;;
      11)
        echo
        systemctl --no-pager --full status frps.service || true
        echo
        systemctl --no-pager --full status frpc.service || true
        ;;
      12)
        enable_autostart "frps.service"
        enable_autostart "frpc.service"
        ;;
      13)
        disable_autostart "frps.service"
        disable_autostart "frpc.service"
        ;;
      14)
        show_configs
        ;;
      0)
        echo "Bye."
        exit 0
        ;;
      *)
        echo "Invalid choice."
        ;;
    esac
  done
}

main "$@"
