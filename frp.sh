#!/usr/bin/env bash
# ============================================================================
#  FRP Unlimited Menu (modern TOML for v0.63.x)
#  English‑only edition – updated July 2025
#  * Adds poolCount / maxPoolCount support (default 0)
#  * Correct udpPacketSize condition (KCP & QUIC only)
#  * Writes transport.tls.enable **only** when false
#  * Enables Prometheus automatically when dashboard enabled
#  * Supports proxyBindAddr for KCP/QUIC
#  * Avoids writing default keys via helper maybe_add()
# ============================================================================
set -Euo pipefail
: "${FRP_DEBUG:=0}"
trap 's=$?; if [[ "$FRP_DEBUG" == 1 ]]; then echo "[ERROR] line $LINENO: $BASH_COMMAND -> exit $s"; fi' ERR

SCRIPT_VERSION="2.4.0-pool-support"
BASE_DIR="$(pwd)/frp"                 # per‑user config root
BIN_FRPS="/usr/local/bin/frps"
BIN_FRPC="/usr/local/bin/frpc"
SYSTEMD_DIR="/etc/systemd/system"
LETSCERT_DIR="/etc/letsencrypt/live"

# Heartbeat defaults (keep default values out of TOML unless changed)
DEFAULT_FRPS_HEARTBEAT_TIMEOUT=90
DEFAULT_FRPC_HEARTBEAT_INTERVAL=10
DEFAULT_FRPC_HEARTBEAT_TIMEOUT=90

log(){ echo "$*"; }
ok(){ echo "[OK] $*"; }
err(){ echo "[ERR] $*" >&2; }
pause(){ read -rp "Press Enter to continue..." _ || true; }

# ─────────────────────────────────────────── helper ──────────────────────────
maybe_add(){ # $1 key  $2 value  $3 default  $4 cfg_path
  [[ -n ${2:-} && "$2" != "$3" ]] && printf '%s = %s\n' "$1" "$2" >>"$4"
}

# ─────────────────────────────────── arch / download ─────────────────────────
arch_tag(){
  case "$(uname -m)" in
    x86_64|amd64) echo linux_amd64 ;;
    aarch64|arm64) echo linux_arm64 ;;
    armv7l) echo linux_arm ;;
    *) err "Unsupported arch: $(uname -m)"; exit 1 ;;
  esac
}

latest_frp_url(){
  local arch; arch=$(arch_tag)
  curl -fsSL https://api.github.com/repos/fatedier/frp/releases/latest \
    | grep 'browser_download_url' | grep -E "${arch}\\.tar\\.gz" \
    | cut -d '"' -f 4 | head -n1
}

install_frp(){
  log "Downloading latest FRP via GitHub API..."
  local url pkg tmpdir
  url=$(latest_frp_url) || { err "Could not resolve download URL"; return 1; }
  [[ -z $url ]] && { err "Empty URL"; return 1; }
  log "URL: $url"
  pkg="/tmp/$(basename "$url")"
  curl -fL -o "$pkg" "$url"
  tmpdir="/tmp/frp-extract.$$"; rm -rf "$tmpdir"; mkdir -p "$tmpdir"
  tar -xzf "$pkg" -C "$tmpdir" --strip-components=1
  install -m0755 "$tmpdir/frps" "$BIN_FRPS"
  install -m0755 "$tmpdir/frpc" "$BIN_FRPC"
  rm -rf "$tmpdir" "$pkg"
  "$BIN_FRPS" -v >/dev/null 2>&1 || { err "frps failed to run. Wrong arch?"; return 1; }
  "$BIN_FRPC" -v >/dev/null 2>&1 || { err "frpc failed to run. Wrong arch?"; return 1; }
  ok "Installed: $BIN_FRPS , $BIN_FRPC"
}

is_installed(){ [[ -x "$BIN_FRPS" && -x "$BIN_FRPC" ]]; }
status_binaries(){ if is_installed; then echo "Installed"; else echo "Not installed"; fi; }
ensure_base(){ mkdir -p "$BASE_DIR"; }
safe_user(){ whoami; }

validate_port(){ local p=${1:-}; [[ $p =~ ^[0-9]+$ ]] && (( p>=1 && p<=65535 )); }
validate_host(){
  local h=${1:-}
  local ipv4='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
  local ipv6='^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$'
  local domain='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
  [[ $h =~ $ipv4 || $h =~ $ipv6 || $h =~ $domain ]]
}

rand_password(){ head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16; }

select_cert(){
  [[ ! -d "$LETSCERT_DIR" ]] && { echo ""; return 0; }
  mapfile -t domains < <(find "$LETSCERT_DIR" -maxdepth 1 -mindepth 1 -type d ! -name README -printf '%f\n')
  (( ${#domains[@]} == 0 )) && { echo ""; return 0; }
  echo "Available certificates:" >&2
  local i=1
  for d in "${domains[@]}"; do echo "  $i) $d" >&2; ((i++)); done
  echo "  0) Cancel" >&2
  local idx; read -rp "Choose certificate [0 to cancel]: " idx || true
  [[ -z ${idx:-} ]] && idx=0
  if (( idx<=0 || idx>${#domains[@]} )); then echo ""; return 0; fi
  local dom="${domains[$((idx-1))]}"
  local cert="$LETSCERT_DIR/$dom/fullchain.pem"
  local key="$LETSCERT_DIR/$dom/privkey.pem"
  if [[ -r "$cert" && -r "$key" ]]; then printf '%s|%s\n' "$cert" "$key"; else echo ""; fi
}

# ───────────────────────── TOML writers (0.63.x) ───────────────────────────
write_frps_toml(){
  # Args (positional)
  local cfg="$1" name="$2" bind="$3" token="$4" proto="$5" udp_sz="$6" tls_force="$7"
  local cfile="${8:-}" kfile="${9:-}" dport="${10:-}" duser="${11:-}" dpwd="${12:-}"
  local qk="${13:-10}" qi="${14:-30}" qs="${15:-100000}" allow_csv="${16:-}"

  : >"$cfg"
  cat >>"$cfg" <<EOF
# frps-$name.toml (generated)
bindAddr = "0.0.0.0"
bindPort = $bind
EOF
  # Heartbeat – only write if deviating from default
  maybe_add "transport.heartbeatTimeout" "$DEFAULT_FRPS_HEARTBEAT_TIMEOUT" "90" "$cfg"

  # KCP / QUIC specific
  if [[ "$proto" == "kcp" ]]; then echo "kcpBindPort = $bind" >>"$cfg"; fi
  if [[ "$proto" == "quic" ]]; then
    echo "quicBindPort = $bind" >>"$cfg"
    cat >>"$cfg" <<EOF
transport.quic.keepalivePeriod = $qk
transport.quic.maxIdleTimeout = $qi
transport.quic.maxIncomingStreams = $qs
EOF
  fi
  # TLS policy
  echo "transport.tls.force = $tls_force" >>"$cfg"
  if [[ "$tls_force" == "true" && -n "$cfile" && -n "$kfile" ]]; then
    echo "transport.tls.certFile = \"$cfile\"" >>"$cfg"
    echo "transport.tls.keyFile  = \"$kfile\"" >>"$cfg"
  fi
  # udpPacketSize only for kcp/quic
  if [[ "$proto" == "kcp" || "$proto" == "quic" ]]; then
    echo "udpPacketSize = $udp_sz" >>"$cfg"
  fi
  # Auth
  cat >>"$cfg" <<EOF

auth.method = "token"
auth.token  = "$token"
EOF
  # allowPorts
  if [[ -n "$allow_csv" ]]; then
    echo "allowPorts = [" >>"$cfg"
    local IFS=','; for p in $allow_csv; do p=${p//[[:space:]]/}; if [[ $p == *"-"* ]]; then
        printf '  { start = %s, end = %s },\n' "${p%-*}" "${p#*-}" >>"$cfg"
      else
        printf '  { single = %s },\n' "$p" >>"$cfg"
      fi; done
    echo "]" >>"$cfg"
  fi
  # Dashboard
  if [[ -n "$dport" ]]; then
    cat >>"$cfg" <<EOF

webServer.addr = "0.0.0.0"
webServer.port = $dport
webServer.user = "$duser"
webServer.password = "$dpwd"
enablePrometheus = true
EOF
  fi
}

write_frpc_toml(){
  local cfg="$1" name="$2" saddr="$3" sport="$4" token="$5" proto="$6" tls="$7" udp_sz="$8" sni="${9:-}"
  : >"$cfg"
  cat >>"$cfg" <<EOF
# frpc-$name.toml (generated)
serverAddr = "$saddr"
serverPort = $sport
loginFailExit = false

auth.method = "token"
auth.token  = "$token"

# Admin UI
webServer.addr = "127.0.0.1"
webServer.port = 7400
webServer.user = "admin"
webServer.password = "admin"

transport.protocol = "$proto"
EOF
  # TLS flag only when user turned it off
  maybe_add "transport.tls.enable" "$tls" "true" "$cfg"
  [[ -n "$sni" ]] && echo "transport.tls.serverName = \"$sni\"" >>"$cfg"
  # udp packet size for kcp/quic
  if [[ "$proto" == "kcp" || "$proto" == "quic" ]]; then
    echo "udpPacketSize = $udp_sz" >>"$cfg"
  fi
  echo >>"$cfg"
}

append_proxy_block(){
  local cfg="$1" ptype="$2" pname="$3" lport="$4" rport="$5" cdom="${6:-}"
  {
    echo "[[proxies]]"
    echo "name = \"$pname\""
    echo "type = \"$ptype\""
    if [[ "$ptype" == "tcp" || "$ptype" == "udp" ]]; then echo "localIP = \"127.0.0.1\""; fi
    echo "localPort = $lport"
    if [[ "$ptype" == "http" || "$ptype" == "https" ]]; then
      [[ -n "$cdom" ]] && echo "customDomains = [\"$cdom\"]"
    else
      echo "remotePort = $rport"
    fi
    echo
  } >>"$cfg"
}

# ────────────────────────── systemd helpers (unchanged) ─────────────────────
create_service(){
  local unit="$1" exec="$2"
  cat >"$SYSTEMD_DIR/$unit.service" <<EOF
[Unit]
Description=$unit
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(safe_user)
WorkingDirectory=$BASE_DIR
ExecStartPre=/bin/sleep 5
ExecStart=$exec
Restart=always
RestartSec=5
LimitNOFILE=200000

NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$unit.service" >/dev/null 2>&1 || true
}

show_logs(){ local unit="$1"; journalctl -u "$unit" -n 80 --no-pager; pause; }
service_exists(){ systemctl list-unit-files --type=service --no-pager | grep -q "^$1\.service"; }
list_services(){ systemctl list-units --type=service --all --no-pager | awk '{print $1}' | grep -E '^(frp-server|frp-client)-.*\.service$' | sed 's/\.service$//'; }
remove_service(){ local unit="$1"; systemctl stop "$unit" >/dev/null 2>&1 || true; systemctl disable "$unit" >/dev/null 2>&1 || true; rm -f "$SYSTEMD_DIR/$unit.service"; }

# ───────────────────────────── interactive flows ────────────────────────────
action_add_server(){
  ensure_base
  echo "-- Add FRP Server --"
  local name
  while :; do
    read -rp "Server name (alnum, hyphen, underscore): " name || true
    name=$(echo "$name" | tr -cd '[:alnum:]_-')
    [[ -n $name ]] && break || echo "Name cannot be empty"
  done
  local service="frp-server-$name" cfg="$BASE_DIR/frps-$name.toml"
  if service_exists "$service"; then err "Service already exists: $service"; pause; return; fi

  local bind token
  while :; do read -rp "Bind port (e.g. 7000): " bind || true; validate_port "$bind" && break || echo "Invalid port"; done
  while :; do read -rp "Auth token: " token || true; [[ -n $token ]] && break || echo "Token cannot be empty"; done

  echo "Transport protocol: 1) tcp  2) kcp  3) quic  4) websocket  5) wss"
  local choice proto; read -rp "Choose [1-5]: " choice || true
  case ${choice:-1} in
    1) proto=tcp ;;
    2) proto=kcp ;;
    3) proto=quic ;;
    4) proto=websocket ;;
    5) proto=wss ;;
    *) proto=tcp ;;
  esac

  local udp_sz=1500
  if [[ "$proto" == kcp || "$proto" == quic ]]; then
    read -rp "UDP packet size [1500]: " x || true; [[ -n ${x:-} ]] && udp_sz="$x"
  fi

  local tls_force=false cert_pair cert_file="" key_file=""
  if [[ "$proto" == tcp || "$proto" == websocket || "$proto" == wss ]]; then
    read -rp "Force TLS-only connections? (y/N): " a || true
    if [[ ${a,,} =~ ^y ]]; then
      tls_force=true
      cert_pair=$(select_cert)
      if [[ -n $cert_pair ]]; then cert_file="${cert_pair%%|*}"; key_file="${cert_pair##*|}"; fi
    fi
  fi

  local dport="" duser="admin" dpwd=""
  read -rp "Enable dashboard? (y/N): " d || true
  if [[ ${d,,} =~ ^y ]]; then
    while :; do read -rp "Dashboard port (e.g. 7500): " dport || true; validate_port "$dport" && break || echo "Invalid port"; done
    read -rp "Dashboard username [admin]: " duser || true; duser=${duser:-admin}
    dpwd=$(rand_password); read -rp "Dashboard password (empty=random): " t || true; [[ -n ${t:-} ]] && dpwd="$t"
  fi

  local qk=10 qi=30 qs=100000
  if [[ "$proto" == quic ]]; then
    read -rp "QUIC keepalivePeriod [10]: " t || true; [[ -n ${t:-} ]] && qk="$t"
    read -rp "QUIC maxIdleTimeout [30]: " t || true; [[ -n ${t:-} ]] && qi="$t"
    read -rp "QUIC maxIncomingStreams [100000]: " t || true; [[ -n ${t:-} ]] && qs="$t"
  fi

  local allow_csv=""
  read -rp "Restrict allowed ports? Comma‑separated list or empty: " allow_csv || true

  # --- connection pool ---
  local max_pool=0
  read -rp "TCP connection pool maxPoolCount [0]: " max_pool || true
  max_pool=${max_pool:-0}

  # --- proxyBindAddr for kcp/quic ---
  local proxy_bind=""
  if [[ "$proto" == kcp || "$proto" == quic ]]; then
    read -rp "UDP bind address [0.0.0.0]: " proxy_bind || true
    proxy_bind=${proxy_bind:-0.0.0.0}
  fi

  write_frps_toml "$cfg" "$name" "$bind" "$token" "$proto" "$udp_sz" "$tls_force" \
                   "$cert_file" "$key_file" "$dport" "$duser" "$dpwd" "$qk" "$qi" "$qs" "$allow_csv"

  if (( max_pool > 0 )); then echo "transport.maxPoolCount = $max_pool" >>"$cfg"; fi
  if [[ -n "$proxy_bind" ]]; then echo "proxyBindAddr = \"$proxy_bind\"" >>"$cfg"; fi

  ok "Config written: $cfg"
  create_service "$service" "$BIN_FRPS -c $cfg"
  ok "Service started: $service"
  read -rp "Show logs? (y/N): " v || true; [[ ${v,,} =~ ^y ]] && show_logs "$service"
}

action_add_client(){
  ensure_base
  echo "-- Add FRP Client --"
  local name
  while :; do
    read -rp "Client name (alnum, hyphen, underscore): " name || true
    name=$(echo "$name" | tr -cd '[:alnum:]_-')
    [[ -n $name ]] && break || echo "Name cannot be empty"
  done
  local service="frp-client-$name" cfg="$BASE_DIR/frpc-$name.toml"
  if service_exists "$service"; then err "Service exists: $service"; pause; return; fi

  local saddr sport token
  while :; do read -rp "Server address (IP/host): " saddr || true; validate_host "$saddr" && break || echo "Invalid"; done
  while :; do read -rp "Server port (e.g. 7000): " sport || true; validate_port "$sport" && break || echo "Invalid"; done
  while :; do read -rp "Auth token: " token || true; [[ -n $token ]] && break || echo "Token cannot be empty"; done

  echo "Transport protocol: 1) tcp  2) kcp  3) quic  4) websocket  5) wss"
  local choice proto; read -rp "Choose [1-5]: " choice || true
  case ${choice:-1} in
    1) proto=tcp ;;
    2) proto=kcp ;;
    3) proto=quic ;;
    4) proto=websocket ;;
    5) proto=wss ;;
    *) proto=tcp ;;
  esac

  local tls_enable=true sni=""
  if [[ "$proto" == tcp || "$proto" == websocket || "$proto" == wss ]]; then
    read -rp "Use TLS to server? (Y/n): " t || true
    [[ ${t,,} =~ ^n ]] && tls_enable=false
    if $tls_enable; then read -rp "TLS serverName (SNI) [optional]: " sni || true; fi
  fi

  local udp_sz=1500
  if [[ "$proto" == kcp || "$proto" == quic ]]; then
    read -rp "UDP packet size [1500]: " x || true; [[ -n ${x:-} ]] && udp_sz="$x"
  fi

  write_frpc_toml "$cfg" "$name" "$saddr" "$sport" "$token" "$proto" "$tls_enable" "$udp_sz" "$sni"

  # poolCount
  local pool_count=0
  read -rp "poolCount (0 = disabled) [0]: " pool_count || true
  pool_count=${pool_count:-0}
  if (( pool_count > 0 )); then echo "transport.poolCount = $pool_count" >>"$cfg"; fi

  ok "Base client config written: $cfg"
  # ... append proxy blocks (unchanged) ...
  echo "You can append multiple proxies. Type 'done' to finish."
  # (rest of original proxy‑adding loop remains unchanged)
  local idx=1
  while :; do
    echo "--- Proxy #$idx ---"
    local lport rport ptype cdom=""
    read -rp "Local port (or 'done'): " lport || true
    [[ ${lport,,} == done ]] && break
    validate_port "$lport" || { echo "Invalid"; continue; }
    echo "Type: 1) tcp  2) udp  3) http  4) https"
    read -rp "Choose [1-4]: " t || true
    case ${t:-1} in 1) ptype=tcp;;2) ptype=udp;;3) ptype=http;;4) ptype=https;; *) ptype=tcp;; esac
    if [[ "$ptype" == http || "$ptype" == https ]]; then
      read -rp "Custom domain (optional): " cdom || true
      rport=0
    else
      while :; do read -rp "Remote port: " rport || true; validate_port "$rport" && break || echo "Invalid"; done
    fi
    local pname="${ptype}_${name}_${idx}"
    append_proxy_block "$cfg" "$ptype" "$pname" "$lport" "$rport" "$cdom"
    ok "Added proxy $pname"
    ((idx++))
  done
  create_service "$service" "$BIN_FRPC -c $cfg"
  ok "Service started: $service"
  read -rp "Show logs? (y/N): " v || true; [[ ${v,,} =~ ^y ]] && show_logs "$service"
}

# ─────────────────────── rest of menus & functions (unchanged) ──────────────
#   ... (manage_client_ports, show_dashboard_info, delete_unit_menu, etc.) ...
#   They use the same helper maybe_add when they rewrite configs if needed.

main_menu(){
  while :; do
    clear
    echo "FRP Unlimited Menu v$SCRIPT_VERSION"
    echo "Binaries : $(status_binaries)   |   Config root : $BASE_DIR"
    echo
    echo "1) Install / Update FRP binaries"
    echo "2) Server management"
    echo "3) Client management"
    echo "4) Dashboard info"
    echo "5) View logs"
    echo "6) Delete a service"
    echo "7) Uninstall FRP (remove ALL services, configs, binaries)"
    echo "0) Exit"
    read -rp "Choice: " c || true
    case ${c:-0} in
      1) install_frp; pause ;;
      2)
        while :; do
          clear
          echo "-- Server management --"
          echo "1) Add new server"
          echo "2) Show server dashboard info"
          echo "3) Back"
          read -rp "Choice: " s || true
          case ${s:-3} in
            1) action_add_server ;;
            2) show_dashboard_info ;;
            3) break ;;
            *) : ;;
          esac
        done ;;
      3)
        while :; do
          clear
          echo "-- Client management --"
          echo "1) Add new client"
          echo "2) Manage client ports"
          echo "3) Back"
          read -rp "Choice: " s || true
          case ${s:-3} in
            1) action_add_client ;;
            2) manage_client_ports ;;
            3) break ;;
            *) : ;;
          esac
        done ;;
      4) show_dashboard_info ;;
      5) view_logs_menu ;;
      6) delete_unit_menu ;;
      7) read -rp "REMOVE ALL (y/N)? " a || true; [[ ${a,,} =~ ^y ]] && remove_all || echo "Cancelled"; pause ;;
      0) exit 0 ;;
      *) : ;;
    esac
  done
}

main_menu
