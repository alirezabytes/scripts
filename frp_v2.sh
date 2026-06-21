#!/usr/bin/env bash
# ============================================================================
#  FRP Unlimited Menu - multiversion / multi server / multi client
#  Persian-friendly workflow, English script text
#  Version: 2.5.0
#
#  Main changes compared to 2.4.x:
#  - Install latest, choose from recent GitHub releases, or enter a specific tag.
#  - Run multiple frps and frpc instances on the same machine with unique names.
#  - Client dashboard is optional to avoid port 7400 conflicts with many clients.
#  - Server can enable TCP, KCP, QUIC, WebSocket/WSS-ready TLS, HTTP/HTTPS vhost.
#  - HTTP/HTTPS proxy types now ask for required custom domain and server vhost ports.
#  - Compression/encryption are written per proxy, not as invalid global keys.
#  - KCP/QUIC ports are handled explicitly and separately.
# ============================================================================
set -Euo pipefail
: "${FRP_DEBUG:=0}"
trap 's=$?; if [[ "${FRP_DEBUG}" == 1 ]]; then echo "[ERROR] line $LINENO: $BASH_COMMAND -> exit $s"; fi' ERR

SCRIPT_VERSION="2.5.2-multiversion-multitunnel-awk-fix"
BASE_DIR="${FRP_BASE_DIR:-$(pwd)/frp}"
BIN_FRPS="/usr/local/bin/frps"
BIN_FRPC="/usr/local/bin/frpc"
SYSTEMD_DIR="/etc/systemd/system"
LETSCERT_DIR="/etc/letsencrypt/live"
GITHUB_REPO="fatedier/frp"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"

log(){ echo "$*"; }
ok(){ echo "[OK] $*"; }
warn(){ echo "[WARN] $*"; }
err(){ echo "[ERR] $*" >&2; }
pause(){ read -rp "Press Enter to continue..." _ || true; }

need_root(){
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    err "Run this script as root. Example: sudo bash $0"
    exit 1
  fi
}

ensure_base(){ mkdir -p "$BASE_DIR"; }
safe_user(){ echo "root"; }

validate_port(){ local p=${1:-}; [[ $p =~ ^[0-9]+$ ]] && (( p>=1 && p<=65535 )); }
validate_port_or_zero(){ local p=${1:-}; [[ $p =~ ^[0-9]+$ ]] && (( p>=0 && p<=65535 )); }
validate_num(){ local n=${1:-}; [[ $n =~ ^[0-9]+$ ]]; }
validate_bool(){ [[ ${1:-} == "true" || ${1:-} == "false" ]]; }

validate_host(){
  local h=${1:-}
  local ipv4='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
  local ipv6='^\[?([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\]?$'
  local domain='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
  [[ $h =~ $ipv4 || $h =~ $ipv6 || $h =~ $domain || $h == "localhost" ]]
}

sanitize_name(){ echo "${1:-}" | tr -cd '[:alnum:]_-'; }
rand_password(){ local p; p=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18 || true); echo "${p:-FRP$(date +%s)}"; }

ask_yes_no(){
  local prompt="$1" default="${2:-N}" ans
  local suffix="[y/N]"
  [[ ${default,,} == "y" ]] && suffix="[Y/n]"
  read -rp "$prompt $suffix: " ans || true
  ans=${ans:-$default}
  [[ ${ans,,} =~ ^y ]]
}

ask_port(){
  local prompt="$1" default="${2:-}" p
  while :; do
    if [[ -n $default ]]; then read -rp "$prompt [$default]: " p || true; p=${p:-$default}; else read -rp "$prompt: " p || true; fi
    validate_port "$p" && { echo "$p"; return 0; }
    echo "Invalid port. Use 1-65535." >&2
  done
}

ask_num(){
  local prompt="$1" default="${2:-0}" n
  while :; do
    read -rp "$prompt [$default]: " n || true; n=${n:-$default}
    validate_num "$n" && { echo "$n"; return 0; }
    echo "Invalid number." >&2
  done
}

ask_host(){
  local prompt="$1" h
  while :; do
    read -rp "$prompt: " h || true
    validate_host "$h" && { echo "$h"; return 0; }
    echo "Invalid IP/host." >&2
  done
}

arch_tag(){
  case "$(uname -m)" in
    x86_64|amd64) echo linux_amd64 ;;
    aarch64|arm64) echo linux_arm64 ;;
    armv7l|armv7*) echo linux_arm ;;
    armv6l|armv6*) echo linux_arm ;;
    *) err "Unsupported architecture: $(uname -m)"; return 1 ;;
  esac
}

normalize_tag(){
  local v="${1:-}"
  v="${v#frp_}"
  [[ $v == v* ]] || v="v$v"
  echo "$v"
}

current_frp_versions(){
  local sv="not installed" cv="not installed"
  [[ -x "$BIN_FRPS" ]] && sv=$($BIN_FRPS -v 2>/dev/null || echo "unknown")
  [[ -x "$BIN_FRPC" ]] && cv=$($BIN_FRPC -v 2>/dev/null || echo "unknown")
  echo "frps=$sv, frpc=$cv"
}

status_binaries(){
  if [[ -x "$BIN_FRPS" && -x "$BIN_FRPC" ]]; then
    echo "Installed ($(current_frp_versions))"
  else
    echo "Not installed"
  fi
}

require_binaries(){
  if [[ ! -x "$BIN_FRPS" || ! -x "$BIN_FRPC" ]]; then
    err "FRP binaries are not installed yet. Use menu option 1 first."
    pause
    return 1
  fi
}

fetch_release_json(){
  local tag="${1:-latest}" url
  if [[ $tag == "latest" ]]; then
    url="${GITHUB_API}/releases/latest"
  else
    url="${GITHUB_API}/releases/tags/$(normalize_tag "$tag")"
  fi
  curl -fsSL --connect-timeout 15 --retry 2 --retry-delay 1 "$url"
}

direct_release_download_url(){
  local tag="$1" arch ver
  arch=$(arch_tag) || return 1
  tag=$(normalize_tag "$tag")
  ver="${tag#v}"
  printf 'https://github.com/%s/releases/download/%s/frp_%s_%s.tar.gz\n' "$GITHUB_REPO" "$tag" "$ver" "$arch"
}

release_download_url(){
  local tag="$1" arch json url real_tag
  arch=$(arch_tag) || return 1
  json=$(fetch_release_json "$tag") || return 1

  url=$(printf '%s\n' "$json"     | grep 'browser_download_url'     | grep -E "${arch}\.tar\.gz"     | cut -d '"' -f 4     | head -n1 || true)

  if [[ -n "$url" ]]; then
    printf '%s\n' "$url"
    return 0
  fi

  # Fallback: construct the official release asset URL from the tag name.
  if [[ "$tag" == "latest" ]]; then
    real_tag=$(printf '%s\n' "$json" | grep '"tag_name"' | cut -d '"' -f 4 | head -n1 || true)
    [[ -n "$real_tag" ]] || return 1
    direct_release_download_url "$real_tag"
  else
    direct_release_download_url "$tag"
  fi
}

list_recent_tags(){
  curl -fsSL --connect-timeout 15 --retry 2 --retry-delay 1 "${GITHUB_API}/releases?per_page=20" \
    | grep '"tag_name"' \
    | cut -d '"' -f 4
}

choose_frp_version(){
  local c tag idx
  {
    echo "Install / Update FRP binaries"
    echo "1) Latest release (default)"
    echo "2) Choose from recent releases"
    echo "3) Enter version manually (example: 0.63.0 or v0.63.0)"
  } >&2
  read -rp "Choice [1]: " c || true
  case ${c:-1} in
    2)
      mapfile -t tags < <(list_recent_tags || true)
      if (( ${#tags[@]} == 0 )); then
        warn "Could not list releases. Falling back to latest." >&2
        printf 'latest\n'; return 0
      fi
      {
        echo "Recent releases:"
        local i=1
        for tag in "${tags[@]}"; do echo "  $i) $tag"; ((i++)); done
        echo "  0) Latest"
      } >&2
      read -rp "Choose release [0]: " idx || true
      idx=${idx:-0}
      if [[ $idx =~ ^[0-9]+$ ]] && (( idx>=1 && idx<=${#tags[@]} )); then
        printf '%s\n' "${tags[$((idx-1))]}"
      else
        printf 'latest\n'
      fi
      ;;
    3)
      while :; do
        read -rp "Version/tag: " tag || true
        if [[ -n ${tag:-} ]]; then normalize_tag "$tag"; return 0; fi
        echo "Version cannot be empty." >&2
      done
      ;;
    *) printf 'latest\n' ;;
  esac
}

install_frp(){
  local selected url pkg tmpdir extracted old
  selected=$(choose_frp_version | tail -n1 | tr -d '\r[:space:]')
  [[ -n "$selected" ]] || selected="latest"
  if [[ "$selected" != "latest" && ! "$selected" =~ ^v?[0-9]+(\.[0-9]+){1,3}([-_A-Za-z0-9.]*)?$ ]]; then
    err "Invalid release value generated: '$selected'"
    return 1
  fi
  old="$(current_frp_versions)"
  log "Selected release: $selected"
  log "Resolving download URL..."
  url=$(release_download_url "$selected" | tail -n1 | tr -d '\r') || { err "Could not resolve download URL from GitHub API."; return 1; }
  [[ -n $url && "$url" =~ ^https://github.com/.+\.tar\.gz$ ]] || { err "Invalid or empty download URL: ${url:-empty}"; return 1; }

  log "URL: $url"
  pkg="/tmp/$(basename "$url")"
  tmpdir="/tmp/frp-extract.$$"
  rm -rf "$tmpdir" "$pkg"
  mkdir -p "$tmpdir"
  curl -fL --connect-timeout 20 --retry 2 --retry-delay 1 -o "$pkg" "$url"
  tar -xzf "$pkg" -C "$tmpdir" --strip-components=1

  [[ -x "$tmpdir/frps" && -x "$tmpdir/frpc" ]] || { err "Archive does not contain executable frps/frpc."; rm -rf "$tmpdir" "$pkg"; return 1; }
  [[ -x "$BIN_FRPS" ]] && cp -f "$BIN_FRPS" "${BIN_FRPS}.bak.$(date +%Y%m%d%H%M%S)" || true
  [[ -x "$BIN_FRPC" ]] && cp -f "$BIN_FRPC" "${BIN_FRPC}.bak.$(date +%Y%m%d%H%M%S)" || true
  install -m0755 "$tmpdir/frps" "$BIN_FRPS"
  install -m0755 "$tmpdir/frpc" "$BIN_FRPC"
  rm -rf "$tmpdir" "$pkg"

  "$BIN_FRPS" -v >/dev/null 2>&1 || { err "frps failed to run after install."; return 1; }
  "$BIN_FRPC" -v >/dev/null 2>&1 || { err "frpc failed to run after install."; return 1; }
  ok "Installed FRP. Previous: $old | Current: $(current_frp_versions)"
}

select_cert(){
  [[ ! -d "$LETSCERT_DIR" ]] && { echo ""; return 0; }
  mapfile -t domains < <(find "$LETSCERT_DIR" -maxdepth 1 -mindepth 1 -type d ! -name README -printf '%f\n' 2>/dev/null | sort)
  (( ${#domains[@]} == 0 )) && { echo ""; return 0; }
  echo "Available Let's Encrypt certificates:" >&2
  local i=1
  for d in "${domains[@]}"; do echo "  $i) $d" >&2; ((i++)); done
  echo "  0) Skip" >&2
  local idx; read -rp "Choose certificate [0]: " idx || true
  idx=${idx:-0}
  if [[ ! $idx =~ ^[0-9]+$ ]] || (( idx<=0 || idx>${#domains[@]} )); then echo ""; return 0; fi
  local dom="${domains[$((idx-1))]}"
  local cert="$LETSCERT_DIR/$dom/fullchain.pem"
  local key="$LETSCERT_DIR/$dom/privkey.pem"
  if [[ -r "$cert" && -r "$key" ]]; then printf '%s|%s\n' "$cert" "$key"; else echo ""; fi
}

# ----------------------------- TOML writers --------------------------------
write_frps_toml(){
  local cfg="$1" name="$2" bind="$3" token="$4" tls_force="$5" cfile="${6:-}" kfile="${7:-}"
  local kcp_port="${8:-}" quic_port="${9:-}" udp_sz="${10:-1500}" qk="${11:-10}" qi="${12:-30}" qs="${13:-100000}"
  local allow_csv="${14:-}" dport="${15:-}" duser="${16:-admin}" dpwd="${17:-}" vhost_http="${18:-}" vhost_https="${19:-}"
  local heartbeat_enable="${20:-false}" ht="${21:-90}" max_pool="${22:-0}" tcp_mux="${23:-true}" proxy_bind="${24:-}"

  : >"$cfg"
  cat >>"$cfg" <<EOC
# frps-$name.toml (generated by FRP Unlimited Menu $SCRIPT_VERSION)
bindAddr = "0.0.0.0"
bindPort = $bind

# TLS: false means both TLS and non-TLS clients may connect. true means TLS-only.
transport.tls.force = $tls_force
EOC

  if [[ "$tls_force" == "true" && -n "$cfile" && -n "$kfile" ]]; then
    cat >>"$cfg" <<EOC
transport.tls.certFile = "$cfile"
transport.tls.keyFile = "$kfile"
EOC
  fi

  if [[ -n "$kcp_port" ]]; then
    echo "kcpBindPort = $kcp_port" >>"$cfg"
  fi

  if [[ -n "$quic_port" ]]; then
    cat >>"$cfg" <<EOC
quicBindPort = $quic_port
transport.quic.keepalivePeriod = $qk
transport.quic.maxIdleTimeout = $qi
transport.quic.maxIncomingStreams = $qs
EOC
  fi

  echo "udpPacketSize = $udp_sz" >>"$cfg"

  if [[ -n "$proxy_bind" ]]; then
    echo "proxyBindAddr = \"$proxy_bind\"" >>"$cfg"
  fi

  if [[ -n "$vhost_http" ]]; then
    echo "vhostHTTPPort = $vhost_http" >>"$cfg"
  fi
  if [[ -n "$vhost_https" ]]; then
    echo "vhostHTTPSPort = $vhost_https" >>"$cfg"
  fi

  cat >>"$cfg" <<EOC

auth.method = "token"
auth.token = "$token"
EOC

  if [[ -n "$allow_csv" ]]; then
    echo "allowPorts = [" >>"$cfg"
    local IFS=',' p start end
    for p in $allow_csv; do
      p=${p//[[:space:]]/}
      [[ -z "$p" ]] && continue
      if [[ $p == *"-"* ]]; then
        start="${p%-*}"; end="${p#*-}"
        if validate_port "$start" && validate_port "$end"; then
          printf '  { start = %s, end = %s },\n' "$start" "$end" >>"$cfg"
        fi
      elif validate_port "$p"; then
        printf '  { single = %s },\n' "$p" >>"$cfg"
      fi
    done
    echo "]" >>"$cfg"
  fi

  if [[ -n "$dport" ]]; then
    cat >>"$cfg" <<EOC

webServer.addr = "0.0.0.0"
webServer.port = $dport
webServer.user = "$duser"
webServer.password = "$dpwd"
enablePrometheus = true
EOC
  fi

  if [[ "$heartbeat_enable" == "true" ]]; then
    echo "transport.heartbeatTimeout = $ht" >>"$cfg"
  fi
  if (( max_pool > 0 )); then
    echo "transport.maxPoolCount = $max_pool" >>"$cfg"
  fi
  echo "transport.tcpMux = $tcp_mux" >>"$cfg"
}

write_frpc_toml(){
  local cfg="$1" name="$2" saddr="$3" sport="$4" token="$5" proto="$6" tls_enable="${7:-true}" sni="${8:-}"
  local udp_sz="${9:-1500}" heartbeat_enable="${10:-false}" hi="${11:-10}" ht="${12:-90}" pool_count="${13:-0}"
  local tcp_mux="${14:-true}" dport="${15:-}" duser="${16:-admin}" dpwd="${17:-}"

  : >"$cfg"
  cat >>"$cfg" <<EOC
# frpc-$name.toml (generated by FRP Unlimited Menu $SCRIPT_VERSION)
serverAddr = "$saddr"
serverPort = $sport
loginFailExit = false

auth.method = "token"
auth.token = "$token"

transport.protocol = "$proto"
transport.tcpMux = $tcp_mux
udpPacketSize = $udp_sz
EOC

  # Make TLS explicit. For websocket we default to plain WS. For wss/tcp+tls we enable TLS.
  echo "transport.tls.enable = $tls_enable" >>"$cfg"
  [[ -n "$sni" ]] && echo "transport.tls.serverName = \"$sni\"" >>"$cfg"

  if [[ "$heartbeat_enable" == "true" ]]; then
    echo "transport.heartbeatInterval = $hi" >>"$cfg"
    echo "transport.heartbeatTimeout = $ht" >>"$cfg"
  fi
  if (( pool_count > 0 )); then
    echo "transport.poolCount = $pool_count" >>"$cfg"
  fi

  if [[ -n "$dport" ]]; then
    cat >>"$cfg" <<EOC

webServer.addr = "127.0.0.1"
webServer.port = $dport
webServer.user = "$duser"
webServer.password = "$dpwd"
EOC
  fi
  echo >>"$cfg"
}

append_proxy_block(){
  local cfg="$1" ptype="$2" pname="$3" local_ip="$4" lport="$5" rport="${6:-}" cdom="${7:-}" enc="${8:-false}" comp="${9:-false}"
  {
    echo "[[proxies]]"
    echo "name = \"$pname\""
    echo "type = \"$ptype\""
    echo "localIP = \"$local_ip\""
    echo "localPort = $lport"
    echo "transport.useEncryption = $enc"
    echo "transport.useCompression = $comp"
    if [[ "$ptype" == "http" || "$ptype" == "https" ]]; then
      echo "customDomains = [\"$cdom\"]"
    else
      echo "remotePort = $rport"
    fi
    echo
  } >>"$cfg"
}

# ----------------------------- systemd helpers ------------------------------
create_service(){
  local unit="$1" exec_cmd="$2"
  cat >"$SYSTEMD_DIR/$unit.service" <<EOC
[Unit]
Description=$unit
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(safe_user)
WorkingDirectory=$BASE_DIR
ExecStartPre=/bin/sleep 2
ExecStart=$exec_cmd
Restart=always
RestartSec=5
LimitNOFILE=200000

NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOC
  systemctl daemon-reload
  systemctl enable --now "$unit.service"
}

service_exists(){ systemctl list-unit-files --type=service --no-pager 2>/dev/null | grep -q "^$1\.service"; }
list_services(){
  {
    systemctl list-units --type=service --all --no-pager 2>/dev/null | awk '{print $1}'
    systemctl list-unit-files --type=service --no-pager 2>/dev/null | awk '{print $1}'
  } | grep -E '^(frp-server|frp-client)-.*\.service$' | sed 's/\.service$//' | sort -u || true
}
list_server_services(){ list_services | grep '^frp-server-' || true; }
list_client_services(){ list_services | grep '^frp-client-' || true; }

remove_service(){
  local unit="$1"
  systemctl stop "$unit" >/dev/null 2>&1 || true
  systemctl disable "$unit" >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_DIR/$unit.service"
}

show_logs(){ local unit="$1"; journalctl -u "$unit" -n 100 --no-pager; pause; }

service_control_menu(){
  local kind="$1" units=() unit idx action
  if [[ $kind == server ]]; then mapfile -t units < <(list_server_services); else mapfile -t units < <(list_client_services); fi
  (( ${#units[@]} == 0 )) && { echo "No ${kind} services found."; pause; return; }
  local i=1
  for unit in "${units[@]}"; do echo "  $i) $unit"; ((i++)); done
  read -rp "Choose service: " idx || true
  [[ $idx =~ ^[0-9]+$ ]] && (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
  unit="${units[$((idx-1))]}"
  echo "1) start"
  echo "2) stop"
  echo "3) restart"
  echo "4) status"
  echo "5) logs"
  echo "6) back"
  read -rp "Action: " action || true
  case ${action:-6} in
    1) systemctl start "$unit"; ok "Started $unit"; pause ;;
    2) systemctl stop "$unit"; ok "Stopped $unit"; pause ;;
    3) systemctl restart "$unit"; ok "Restarted $unit"; pause ;;
    4) systemctl status "$unit" --no-pager || true; pause ;;
    5) show_logs "$unit" ;;
    *) : ;;
  esac
}

# ----------------------------- interactive flows ----------------------------
choose_transport_for_client(){
  local choice
  {
    echo "Transport protocol from frpc to frps:"
    echo "1) tcp        - TCP transport"
    echo "2) kcp        - UDP/KCP transport; frps must have kcpBindPort open"
    echo "3) quic       - UDP/QUIC transport; frps must have quicBindPort open"
    echo "4) websocket  - plain WebSocket over TCP"
    echo "5) wss        - WebSocket over TLS"
  } >&2
  read -rp "Choose [1]: " choice || true
  case ${choice:-1} in
    2) printf 'kcp\n' ;;
    3) printf 'quic\n' ;;
    4) printf 'websocket\n' ;;
    5) printf 'wss\n' ;;
    *) printf 'tcp\n' ;;
  esac
}

ask_proxy_block_interactive(){
  local cfg="$1" client_name="$2" idx="$3"
  local lport rport ptype cdom="" pname local_ip enc=false comp=false t

  echo "--- Proxy #$idx ---"
  while :; do
    read -rp "Local IP [127.0.0.1]: " local_ip || true
    local_ip=${local_ip:-127.0.0.1}
    [[ -n "$local_ip" ]] && break
  done
  lport=$(ask_port "Local port")

  echo "Proxy type:"
  echo "1) tcp   - exposes local TCP port on a remotePort"
  echo "2) udp   - exposes local UDP port on a remotePort"
  echo "3) http  - requires frps vhostHTTPPort and a domain"
  echo "4) https - requires frps vhostHTTPSPort and a domain"
  read -rp "Choose [1]: " t || true
  case ${t:-1} in
    2) ptype=udp ;;
    3) ptype=http ;;
    4) ptype=https ;;
    *) ptype=tcp ;;
  esac

  if [[ "$ptype" == "http" || "$ptype" == "https" ]]; then
    while :; do
      read -rp "Custom domain for this proxy (required): " cdom || true
      validate_host "$cdom" && break
      echo "Invalid domain. Example: app.example.com"
    done
    rport=""
  else
    rport=$(ask_port "Remote port on frps")
  fi

  ask_yes_no "Enable per-proxy encryption?" "N" && enc=true
  ask_yes_no "Enable per-proxy compression?" "N" && comp=true

  pname="${ptype}_${client_name}_${idx}"
  append_proxy_block "$cfg" "$ptype" "$pname" "$local_ip" "$lport" "$rport" "$cdom" "$enc" "$comp"
  ok "Added proxy $pname"
}

action_add_server(){
  ensure_base
  require_binaries || return
  echo "-- Add FRP Server instance --"
  local name raw service cfg bind token tls_force=false cert_pair="" cert_file="" key_file=""
  while :; do
    read -rp "Server instance name (alnum, hyphen, underscore): " raw || true
    name=$(sanitize_name "$raw")
    [[ -n "$name" ]] && break || echo "Name cannot be empty."
  done
  service="frp-server-$name"
  cfg="$BASE_DIR/frps-$name.toml"
  if service_exists "$service"; then err "Service already exists: $service"; pause; return; fi

  bind=$(ask_port "Main TCP bind port" "7000")
  while :; do read -rp "Auth token: " token || true; [[ -n "$token" ]] && break || echo "Token cannot be empty." >&2; done

  local kcp_port="" quic_port="" udp_sz=1500 qk=10 qi=30 qs=100000
  if ask_yes_no "Enable KCP transport on frps?" "N"; then
    kcp_port=$(ask_port "KCP UDP bind port" "$bind")
  fi
  if ask_yes_no "Enable QUIC transport on frps?" "N"; then
    local q_default="$bind"
    [[ -n "$kcp_port" && "$kcp_port" == "$bind" ]] && q_default=$((bind+1))
    quic_port=$(ask_port "QUIC UDP bind port" "$q_default")
    while [[ -n "$kcp_port" && "$quic_port" == "$kcp_port" ]]; do
      echo "KCP and QUIC cannot use the same UDP port in two different listeners."
      quic_port=$(ask_port "QUIC UDP bind port" "$((kcp_port+1))")
    done
    qk=$(ask_num "QUIC keepalivePeriod" "10")
    qi=$(ask_num "QUIC maxIdleTimeout" "30")
    qs=$(ask_num "QUIC maxIncomingStreams" "100000")
  fi
  if [[ -n "$kcp_port" || -n "$quic_port" ]]; then
    udp_sz=$(ask_num "udpPacketSize (must match client if changed)" "1500")
  fi

  if ask_yes_no "Force TLS-only clients? Use this only if all clients use tcp+TLS or wss" "N"; then
    tls_force=true
    cert_pair=$(select_cert)
    if [[ -n "$cert_pair" ]]; then cert_file="${cert_pair%%|*}"; key_file="${cert_pair##*|}"; fi
  fi

  local vhost_http="" vhost_https=""
  if ask_yes_no "Enable HTTP proxy support (vhostHTTPPort)?" "N"; then
    vhost_http=$(ask_port "vhostHTTPPort" "80")
  fi
  if ask_yes_no "Enable HTTPS proxy support (vhostHTTPSPort)?" "N"; then
    vhost_https=$(ask_port "vhostHTTPSPort" "443")
  fi

  local allow_csv=""
  read -rp "Restrict allowed remote ports? Comma list/ranges or empty: " allow_csv || true

  local dport="" duser="admin" dpwd=""
  if ask_yes_no "Enable frps dashboard?" "N"; then
    dport=$(ask_port "Dashboard port" "7500")
    read -rp "Dashboard username [admin]: " duser || true; duser=${duser:-admin}
    dpwd=$(rand_password); read -rp "Dashboard password (empty=random): " tmp || true; [[ -n ${tmp:-} ]] && dpwd="$tmp"
  fi

  local heartbeat_enable=false ht=90 max_pool=0 tcp_mux=true proxy_bind=""
  if ask_yes_no "Customize heartbeat timeout?" "N"; then
    heartbeat_enable=true
    ht=$(ask_num "Heartbeat timeout" "90")
  fi
  max_pool=$(ask_num "transport.maxPoolCount (0 disables pool cap)" "0")
  if ask_yes_no "Enable tcpMux? It must match clients" "Y"; then tcp_mux=true; else tcp_mux=false; fi
  read -rp "proxyBindAddr for exposed remote ports [empty = bindAddr]: " proxy_bind || true

  write_frps_toml "$cfg" "$name" "$bind" "$token" "$tls_force" "$cert_file" "$key_file" \
    "$kcp_port" "$quic_port" "$udp_sz" "$qk" "$qi" "$qs" "$allow_csv" "$dport" "$duser" "$dpwd" \
    "$vhost_http" "$vhost_https" "$heartbeat_enable" "$ht" "$max_pool" "$tcp_mux" "$proxy_bind"

  ok "Config written: $cfg"
  create_service "$service" "$BIN_FRPS -c $cfg"
  ok "Service started: $service"
  if [[ -n "$kcp_port" || -n "$quic_port" ]]; then
    warn "For KCP/QUIC, open the selected UDP port(s) on firewall/security group."
  fi
  if [[ -n "$vhost_http" || -n "$vhost_https" ]]; then
    warn "For HTTP/HTTPS proxy types, point the custom domain DNS to this frps server IP and use vhost port(s)."
  fi
  ask_yes_no "Show logs?" "N" && show_logs "$service"
}

action_add_client(){
  ensure_base
  require_binaries || return
  echo "-- Add FRP Client instance --"
  local name raw service cfg saddr sport token proto tls_enable=true sni="" udp_sz=1500
  while :; do
    read -rp "Client instance name (alnum, hyphen, underscore): " raw || true
    name=$(sanitize_name "$raw")
    [[ -n "$name" ]] && break || echo "Name cannot be empty."
  done
  service="frp-client-$name"
  cfg="$BASE_DIR/frpc-$name.toml"
  if service_exists "$service"; then err "Service already exists: $service"; pause; return; fi

  saddr=$(ask_host "Server address (IP/host)")
  while :; do read -rp "Auth token: " token || true; [[ -n "$token" ]] && break || echo "Token cannot be empty." >&2; done

  proto=$(choose_transport_for_client | tail -n1 | tr -d '\r[:space:]')
  case "$proto" in
    tcp)
      sport=$(ask_port "Server TCP bindPort" "7000")
      if ask_yes_no "Use TLS to server?" "Y"; then tls_enable=true; else tls_enable=false; fi
      ;;
    websocket)
      sport=$(ask_port "Server TCP bindPort for plain WebSocket" "7000")
      tls_enable=false
      warn "websocket = plain WS. For TLS WebSocket choose wss."
      ;;
    wss)
      sport=$(ask_port "Server TCP bindPort for WSS" "7000")
      tls_enable=true
      ;;
    kcp)
      sport=$(ask_port "Server KCP UDP bind port" "7000")
      tls_enable=false
      udp_sz=$(ask_num "udpPacketSize (must match server if changed)" "1500")
      warn "For kcp, open this UDP port on the server firewall/security group."
      ;;
    quic)
      sport=$(ask_port "Server QUIC UDP bind port" "7000")
      tls_enable=false
      udp_sz=$(ask_num "udpPacketSize (must match server if changed)" "1500")
      warn "For quic, open this UDP port on the server firewall/security group."
      ;;
    *)
      err "Invalid protocol generated: '$proto'"
      pause
      return
      ;;
  esac
  if [[ "$tls_enable" == "true" ]]; then
    read -rp "TLS serverName/SNI [optional]: " sni || true
  fi

  local heartbeat_enable=false hi=10 ht=90 pool_count=0 tcp_mux=true dport="" duser="admin" dpwd=""
  if ask_yes_no "Customize heartbeat?" "N"; then
    heartbeat_enable=true
    hi=$(ask_num "Heartbeat interval" "10")
    ht=$(ask_num "Heartbeat timeout" "90")
  fi
  pool_count=$(ask_num "transport.poolCount (0 disables pre-created connections)" "0")
  if ask_yes_no "Enable tcpMux? It must match frps" "Y"; then tcp_mux=true; else tcp_mux=false; fi

  if ask_yes_no "Enable local frpc admin dashboard? Usually keep disabled for multiple clients" "N"; then
    dport=$(ask_port "Local dashboard port" "7400")
    read -rp "Dashboard username [admin]: " duser || true; duser=${duser:-admin}
    dpwd=$(rand_password); read -rp "Dashboard password (empty=random): " tmp || true; [[ -n ${tmp:-} ]] && dpwd="$tmp"
  fi

  write_frpc_toml "$cfg" "$name" "$saddr" "$sport" "$token" "$proto" "$tls_enable" "$sni" "$udp_sz" \
    "$heartbeat_enable" "$hi" "$ht" "$pool_count" "$tcp_mux" "$dport" "$duser" "$dpwd"

  ok "Base client config written: $cfg"
  echo "Add one or more proxies. This is where you create multiple tunnels inside one client."
  local idx=1 ans
  while :; do
    ask_proxy_block_interactive "$cfg" "$name" "$idx"
    ((idx++))
    read -rp "Add another proxy to this client? [y/N or done]: " ans || true
    [[ ${ans,,} =~ ^y ]] || break
  done

  create_service "$service" "$BIN_FRPC -c $cfg"
  ok "Service started: $service"
  ask_yes_no "Show logs?" "N" && show_logs "$service"
}

# --------------------- client config parser / proxy manager -----------------
FRPC_HEAD=""
PROXIES=()
read_frpc_config(){
  local cfg="$1" line block=""
  FRPC_HEAD=""; PROXIES=()
  while IFS='' read -r line || [[ -n "$line" ]]; do
    line="${line%%$'\r'}"
    if [[ $line =~ ^\[\[proxies\]\] ]]; then
      [[ -n "$block" ]] && PROXIES+=("$block")
      block="[[proxies]]"
      continue
    fi
    if [[ -n "$block" ]]; then
      [[ -n ${line//[[:space:]]/} ]] && block+=$'\n'"$line"
    else
      FRPC_HEAD+="$line"$'\n'
    fi
  done <"$cfg"
  [[ -n "$block" ]] && PROXIES+=("$block")
}

write_frpc_with_blocks(){
  local cfg="$1" b
  : >"$cfg"
  printf '%s' "$FRPC_HEAD" >>"$cfg"
  for b in "${PROXIES[@]}"; do
    echo >>"$cfg"
    printf '%s\n' "$b" >>"$cfg"
  done
}

field_from_block(){
  local blk="$1" key="$2"
  # Parse simple TOML key/value lines without invalid awk regex escapes.
  # This removes awk warnings like: regexp escape sequence `\"` is not a known regexp operator.
  echo "$blk" | awk -F'=' -v k="$key" '
    {
      lhs = $1
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", lhs)
      if (lhs == k) {
        val = $0
        sub(/^[^=]*=/, "", val)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
        gsub(/^\[/, "", val)
        gsub(/\]$/, "", val)
        gsub(/^"/, "", val)
        gsub(/"$/, "", val)
        gsub(/"/, "", val)
        print val
        exit
      }
    }'
}

print_proxy_list(){
  local j=1 blk nm type lp lip rp dom
  for blk in "${PROXIES[@]}"; do
    nm=$(field_from_block "$blk" "name")
    type=$(field_from_block "$blk" "type")
    lip=$(field_from_block "$blk" "localIP")
    lp=$(field_from_block "$blk" "localPort")
    rp=$(field_from_block "$blk" "remotePort")
    dom=$(field_from_block "$blk" "customDomains")
    echo "$j) name=$nm type=$type local=${lip}:${lp} remotePort=${rp:-N/A} domain=${dom:-N/A}"
    ((j++))
  done
}

manage_client_ports(){
  echo "-- Manage Client Proxies --"
  local units=() idx unit name cfg c j
  mapfile -t units < <(list_client_services)
  (( ${#units[@]} == 0 )) && { echo "No client services found."; pause; return; }
  local i=1
  for unit in "${units[@]}"; do echo "  $i) $unit"; ((i++)); done
  read -rp "Choose client: " idx || true
  [[ $idx =~ ^[0-9]+$ ]] && (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
  unit="${units[$((idx-1))]}"
  name="${unit#frp-client-}"
  cfg="$BASE_DIR/frpc-$name.toml"
  [[ -f "$cfg" ]] || { err "Config not found: $cfg"; pause; return; }

  while :; do
    clear
    echo "Client: $name"
    echo "1) View proxies"
    echo "2) Add proxy"
    echo "3) Delete proxy"
    echo "4) Restart client"
    echo "5) Back"
    read -rp "Choice: " c || true
    case ${c:-5} in
      1)
        read_frpc_config "$cfg"
        if (( ${#PROXIES[@]} == 0 )); then echo "No proxies."; else print_proxy_list; fi
        pause ;;
      2)
        read_frpc_config "$cfg"
        local n=$(( ${#PROXIES[@]} + 1 ))
        ask_proxy_block_interactive "$cfg" "$name" "$n"
        systemctl restart "$unit" || true
        ok "Added and restarted $unit"
        pause ;;
      3)
        read_frpc_config "$cfg"
        (( ${#PROXIES[@]} == 0 )) && { echo "No proxies."; pause; continue; }
        print_proxy_list
        read -rp "Select proxy to delete: " j || true
        [[ $j =~ ^[0-9]+$ ]] && (( j>=1 && j<=${#PROXIES[@]} )) || { echo "Invalid"; pause; continue; }
        unset "PROXIES[$((j-1))]"
        PROXIES=("${PROXIES[@]}")
        write_frpc_with_blocks "$cfg"
        systemctl restart "$unit" || true
        ok "Deleted and restarted $unit"
        pause ;;
      4) systemctl restart "$unit"; ok "Restarted $unit"; pause ;;
      5) break ;;
      *) : ;;
    esac
  done
}

show_dashboard_info(){
  echo "-- Dashboard Info --"
  local units=() unit idx cfg name kind port user pwd
  echo "1) Server dashboard"
  echo "2) Client dashboard"
  echo "3) Back"
  read -rp "Choice: " kind || true
  case ${kind:-3} in
    1) mapfile -t units < <(list_server_services);;
    2) mapfile -t units < <(list_client_services);;
    *) return;;
  esac
  (( ${#units[@]} == 0 )) && { echo "No services found."; pause; return; }
  local i=1
  for unit in "${units[@]}"; do echo "  $i) $unit"; ((i++)); done
  read -rp "Choose: " idx || true
  [[ $idx =~ ^[0-9]+$ ]] && (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
  unit="${units[$((idx-1))]}"
  if [[ $unit == frp-server-* ]]; then name="${unit#frp-server-}"; cfg="$BASE_DIR/frps-$name.toml"; else name="${unit#frp-client-}"; cfg="$BASE_DIR/frpc-$name.toml"; fi
  [[ -f "$cfg" ]] || { err "Config not found: $cfg"; pause; return; }
  port=$(grep -E '^webServer\.port\s*=' "$cfg" | awk '{print $3}' | tr -d '\r') || true
  user=$(grep -E '^webServer\.user\s*=' "$cfg" | awk '{print $3}' | tr -d '"\r') || true
  pwd=$(grep -E '^webServer\.password\s*=' "$cfg" | awk '{print $3}' | tr -d '"\r') || true
  if [[ -n ${port:-} ]]; then
    echo "Dashboard for $unit:"
    echo "  Address: 127.0.0.1:$port (or server-ip:$port for frps if webServer.addr=0.0.0.0)"
    echo "  User   : $user"
    echo "  Pass   : $pwd"
  else
    echo "Dashboard is not enabled for $unit."
  fi
  pause
}

delete_unit_menu(){
  echo "1) Delete a server"
  echo "2) Delete a client"
  echo "3) Back"
  local c units=() idx unit name cfg
  read -rp "Choice: " c || true
  case ${c:-3} in
    1) mapfile -t units < <(list_server_services);;
    2) mapfile -t units < <(list_client_services);;
    *) return;;
  esac
  (( ${#units[@]} == 0 )) && { echo "No services found."; pause; return; }
  local i=1
  for unit in "${units[@]}"; do echo "  $i) $unit"; ((i++)); done
  read -rp "Choose: " idx || true
  [[ $idx =~ ^[0-9]+$ ]] && (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
  unit="${units[$((idx-1))]}"
  read -rp "Delete $unit and its config? [y/N]: " yn || true
  [[ ${yn,,} =~ ^y ]] || { echo "Cancelled"; pause; return; }
  if [[ $unit == frp-server-* ]]; then name="${unit#frp-server-}"; cfg="$BASE_DIR/frps-$name.toml"; else name="${unit#frp-client-}"; cfg="$BASE_DIR/frpc-$name.toml"; fi
  remove_service "$unit"
  systemctl daemon-reload
  [[ -f "$cfg" ]] && rm -f "$cfg"
  ok "Deleted $unit and $cfg"
  pause
}

view_logs_menu(){
  echo "1) Server logs"
  echo "2) Client logs"
  echo "3) Back"
  local c units=() idx unit
  read -rp "Choice: " c || true
  case ${c:-3} in
    1) mapfile -t units < <(list_server_services);;
    2) mapfile -t units < <(list_client_services);;
    *) return;;
  esac
  (( ${#units[@]} == 0 )) && { echo "No services found."; pause; return; }
  local i=1
  for unit in "${units[@]}"; do echo "  $i) $unit"; ((i++)); done
  read -rp "Choose: " idx || true
  [[ $idx =~ ^[0-9]+$ ]] && (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
  show_logs "${units[$((idx-1))]}"
}

list_all_instances(){
  echo "-- Servers --"
  local found=0 u
  while IFS= read -r u; do [[ -z "$u" ]] && continue; found=1; systemctl is-active --quiet "$u" && echo "  $u: active" || echo "  $u: inactive/failed"; done < <(list_server_services)
  (( found == 0 )) && echo "  none"
  echo "-- Clients --"
  found=0
  while IFS= read -r u; do [[ -z "$u" ]] && continue; found=1; systemctl is-active --quiet "$u" && echo "  $u: active" || echo "  $u: inactive/failed"; done < <(list_client_services)
  (( found == 0 )) && echo "  none"
  pause
}

remove_all(){
  echo "Searching for FRP services..."
  mapfile -t units < <(list_services)
  if (( ${#units[@]} > 0 )); then
    for u in "${units[@]}"; do echo "Removing $u"; remove_service "$u"; done
    systemctl daemon-reload
  fi
  if [[ -d "$BASE_DIR" ]]; then rm -rf "$BASE_DIR"; ok "Removed $BASE_DIR"; fi
  [[ -x "$BIN_FRPS" ]] && rm -f "$BIN_FRPS"
  [[ -x "$BIN_FRPC" ]] && rm -f "$BIN_FRPC"
  ok "Uninstall complete. Backup binaries, if any, were kept as /usr/local/bin/frp*.bak.TIMESTAMP"
}

server_management_menu(){
  while :; do
    clear
    echo "-- Server management --"
    echo "1) Add new server instance"
    echo "2) Control server service"
    echo "3) Show server dashboard info"
    echo "4) Back"
    read -rp "Choice: " s || true
    case ${s:-4} in
      1) action_add_server ;;
      2) service_control_menu server ;;
      3) show_dashboard_info ;;
      4) break ;;
      *) : ;;
    esac
  done
}

client_management_menu(){
  while :; do
    clear
    echo "-- Client management --"
    echo "1) Add new client instance"
    echo "2) Manage client proxies/tunnels"
    echo "3) Control client service"
    echo "4) Back"
    read -rp "Choice: " s || true
    case ${s:-4} in
      1) action_add_client ;;
      2) manage_client_ports ;;
      3) service_control_menu client ;;
      4) break ;;
      *) : ;;
    esac
  done
}

main_menu(){
  need_root
  ensure_base
  while :; do
    clear
    echo "FRP Unlimited Menu v$SCRIPT_VERSION"
    echo "Binaries : $(status_binaries)"
    echo "Config root: $BASE_DIR"
    echo
    echo "1) Install / Update FRP binaries"
    echo "2) Server management"
    echo "3) Client management"
    echo "4) List all instances"
    echo "5) Dashboard info"
    echo "6) View logs"
    echo "7) Delete a service"
    echo "8) Uninstall FRP (remove ALL services, configs, binaries)"
    echo "0) Exit"
    read -rp "Choice: " c || true
    case ${c:-0} in
      1) install_frp; pause ;;
      2) server_management_menu ;;
      3) client_management_menu ;;
      4) list_all_instances ;;
      5) show_dashboard_info ;;
      6) view_logs_menu ;;
      7) delete_unit_menu ;;
      8) read -rp "REMOVE ALL FRP services/configs/binaries? [y/N]: " a || true; [[ ${a,,} =~ ^y ]] && remove_all || echo "Cancelled"; pause ;;
      0) exit 0 ;;
      *) : ;;
    esac
  done
}

main_menu
