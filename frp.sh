#!/usr/bin/env bash
# ============================================================================
#  FRP Unlimited Menu (modern TOML for v0.63.x)
#  - Uses TOML (frps-<name>.toml / frpc-<name>.toml)
#  - Multi-service systemd units: frp-server-<name>.service / frp-client-<name>.service
#  - Fetches latest binaries from GitHub API (latest release)
#  - Protocols: tcp, kcp, quic, websocket, wss
#  - TLS: server uses transport.tls.force, client uses transport.tls.enable
#  - Dashboard via webServer.*
#  - Hardening & LimitNOFILE=200000 in systemd units
#  - **Pool options removed** (no transport.maxPoolCount / transport.poolCount)
#  - **Heartbeat tuned**: frps transport.heartbeatTimeout=90, frpc transport.heartbeatInterval=10 & heartbeatTimeout=90
#  - We DO NOT write transport.tcpMux at all (keep upstream default)
# ============================================================================
set -Euo pipefail
: "${FRP_DEBUG:=0}"
trap 's=$?; if [[ "$FRP_DEBUG" == 1 ]]; then echo "[ERROR] line $LINENO: $BASH_COMMAND -> exit $s"; fi' ERR

SCRIPT_VERSION="2.3.2-no-pool-fix-nounset"
BASE_DIR="$(pwd)/frp"                 # per-user config root (absolute at creation time)
BIN_FRPS="/usr/local/bin/frps"
BIN_FRPC="/usr/local/bin/frpc"
SYSTEMD_DIR="/etc/systemd/system"
LETSCERT_DIR="/etc/letsencrypt/live"

# Heartbeat defaults
FRPS_HEARTBEAT_TIMEOUT=90   # seconds
FRPC_HEARTBEAT_INTERVAL=10  # seconds
FRPC_HEARTBEAT_TIMEOUT=90   # seconds

log(){ echo "$*"; }
ok(){ echo "[OK] $*"; }
err(){ echo "[ERR] $*" >&2; }
pause(){ read -rp "Press Enter to continue..." _ || true; }

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

# --------------------------- TOML writers (0.63.x) ---------------------------

write_frps_toml(){
  # Args:
  #   $1 cfg_path
  #   $2 name
  #   $3 bind_port
  #   $4 token
  #   $5 protocol   (tcp|kcp|quic|websocket|wss)
  #   $6 udpPacketSize
  #   $7 tls_force  (true|false)
  #   $8 cert_file
  #   $9 key_file
  #  $10 dash_port (empty to disable)
  #  $11 dash_user
  #  $12 dash_pwd
  #  $13 quic_keepalive
  #  $14 quic_idle
  #  $15 quic_streams
  #  $16 allow_ports_csv
  local cfg="$1" name="$2" bind="$3" token="$4" proto="$5" udp_sz="$6" tls_force="$7"
  local cfile="${8:-}" kfile="${9:-}" dport="${10:-}" duser="${11:-}" dpwd="${12:-}"
  local qk="${13:-10}" qi="${14:-30}" qs="${15:-100000}" allow_csv="${16:-}"

  : >"$cfg"
  cat >>"$cfg" <<EOF
# frps-$name.toml (generated)
bindAddr = "0.0.0.0"
bindPort = $bind

# Heartbeat (server side)
transport.heartbeatTimeout = $FRPS_HEARTBEAT_TIMEOUT
EOF

  # KCP / QUIC UDP bind ports
  if [[ "$proto" == "kcp" ]]; then
    echo "kcpBindPort = $bind" >>"$cfg"
  fi
  if [[ "$proto" == "quic" ]]; then
    echo "quicBindPort = $bind" >>"$cfg"
    cat >>"$cfg" <<EOF
transport.quic.keepalivePeriod = $qk
transport.quic.maxIdleTimeout = $qi
transport.quic.maxIncomingStreams = $qs
EOF
  fi

  # TLS policy
  if [[ "$tls_force" == "true" ]]; then
    echo "transport.tls.force = true" >>"$cfg"
    [[ -n "$cfile" && -n "$kfile" ]] && {
      echo "transport.tls.certFile = \"$cfile\"" >>"$cfg"
      echo "transport.tls.keyFile  = \"$kfile\"" >>"$cfg"
    }
  else
    echo "transport.tls.force = false" >>"$cfg"
  fi

  # UDP size for non-TCP transports
  if [[ "$proto" != "tcp" ]]; then
    echo "udpPacketSize = $udp_sz" >>"$cfg"
  fi

  # Auth
  cat >>"$cfg" <<EOF

auth.method = "token"
auth.token  = "$token"
EOF

  # allowPorts list (optional)
  if [[ -n "$allow_csv" ]]; then
    echo "allowPorts = [" >>"$cfg"
    local IFS=','; for p in $allow_csv; do p=${p//[[:space:]]/}; [[ -n $p ]] && echo "  { single = $p }," >>"$cfg"; done
    echo "]" >>"$cfg"
  fi

  # Dashboard (optional)
  if [[ -n "$dport" ]]; then
    cat >>"$cfg" <<EOF

webServer.addr = "0.0.0.0"
webServer.port = $dport
webServer.user = "$duser"
webServer.password = "$dpwd"
# webServer.pprofEnable = false
# enablePrometheus = true
EOF
  fi
}

write_frpc_toml(){
  # Args:
  #   $1 cfg_path
  #   $2 name
  #   $3 server_addr
  #   $4 server_port
  #   $5 token
  #   $6 protocol (tcp|kcp|quic|websocket|wss)
  #   $7 tls_enable (true|false)
  #   $8 udpPacketSize
  #   $9 tls_server_name (optional)
  local cfg="$1" name="$2" saddr="$3" sport="$4" token="$5" proto="$6" tls="$7" udp_sz="$8" sni="${9:-}"

  : >"$cfg"
  cat >>"$cfg" <<EOF
# frpc-$name.toml (generated)
serverAddr = "$saddr"
serverPort = $sport
loginFailExit = false

auth.method = "token"
auth.token  = "$token"

# Admin (optional) for reload/logs via HTTP API
webServer.addr = "127.0.0.1"
webServer.port = 7400
webServer.user = "admin"
webServer.password = "admin"

# Transport
transport.protocol = "$proto"
# Heartbeat (client side)
transport.heartbeatInterval = $FRPC_HEARTBEAT_INTERVAL
transport.heartbeatTimeout  = $FRPC_HEARTBEAT_TIMEOUT
EOF

  if [[ "$proto" == "tcp" || "$proto" == "websocket" || "$proto" == "wss" ]]; then
    echo "transport.tls.enable = $tls" >>"$cfg"
    [[ -n "$sni" ]] && echo "transport.tls.serverName = \"$sni\"" >>"$cfg"
  fi

  if [[ "$proto" != "tcp" ]]; then
    echo "udpPacketSize = $udp_sz" >>"$cfg"
  fi

  echo >>"$cfg"
}

append_proxy_block(){
  # Args: cfg type name local_port remote_port [custom_domain]
  local cfg="$1" ptype="$2" pname="$3" lport="$4" rport="$5" cdom="${6:-}"
  {
    echo "[[proxies]]"
    echo "name = \"$pname\""
    echo "type = \"$ptype\""
    if [[ "$ptype" == "tcp" || "$ptype" == "udp" ]]; then
      echo "localIP = \"127.0.0.1\""
    fi
    echo "localPort = $lport"
    if [[ "$ptype" == "http" || "$ptype" == "https" ]]; then
      [[ -n "$cdom" ]] && echo "customDomains = [\"$cdom\"]"
    else
      echo "remotePort = $rport"
    fi
    echo
  } >>"$cfg"
}

# --------------------------- systemd helpers ---------------------------
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

remove_all(){
  echo "Searching for FRP services..."
  mapfile -t units < <(list_services)
  if (( ${#units[@]} > 0 )); then
    for u in "${units[@]}"; do echo "Removing $u"; remove_service "$u"; done
    systemctl daemon-reload
  fi
  [[ -d "$BASE_DIR" ]] && { rm -rf "$BASE_DIR"; ok "Removed $BASE_DIR"; }
  [[ -x "$BIN_FRPS" ]] && rm -f "$BIN_FRPS"
  [[ -x "$BIN_FRPC" ]] && rm -f "$BIN_FRPC"
  ok "Uninstall complete."
}

# --------------------------- Interactive flows ---------------------------

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
  if [[ "$proto" != tcp ]]; then
    read -rp "UDP packet size [1500]: " x || true; [[ -n ${x:-} ]] && udp_sz="$x"
  fi

  local tls_force=false cert_pair
  local cert_file="" key_file=""
  if [[ "$proto" == tcp || "$proto" == websocket || "$proto" == wss ]]; then
    read -rp "Force TLS-only connections? (y/N): " a || true
    if [[ ${a,,} =~ ^y ]]; then
      tls_force=true
      cert_pair=$(select_cert)
      if [[ -n $cert_pair ]]; then
        cert_file="${cert_pair%%|*}"; key_file="${cert_pair##*|}"
        echo "Using cert: $cert_file"
      else
        echo "No certificate selected; TLS will be required and frps must be able to load default certs."
      fi
    fi
  fi

  local dport="" duser="admin" dpwd=""
  read -rp "Enable dashboard? (y/N): " d || true
  if [[ ${d,,} =~ ^y ]]; then
    while :; do read -rp "Dashboard port (e.g. 7500): " dport || true; validate_port "$dport" && break || echo "Invalid port"; done
    read -rp "Dashboard username [admin]: " duser || true; duser=${duser:-admin}
    dpwd=$(rand_password); read -rp "Dashboard password (empty = random: $dpwd): " t || true; [[ -n ${t:-} ]] && dpwd="$t"
    echo "Dashboard creds -> user: $duser  pass: $dpwd"
  fi

  local qk=10 qi=30 qs=100000
  if [[ "$proto" == quic ]]; then
    read -rp "QUIC keepalivePeriod [10]: " t || true; [[ -n ${t:-} ]] && qk="$t"
    read -rp "QUIC maxIdleTimeout [30]: " t || true; [[ -n ${t:-} ]] && qi="$t"
    read -rp "QUIC maxIncomingStreams [100000]: " t || true; [[ -n ${t:-} ]] && qs="$t"
  fi

  local allow_csv=""
  read -rp "Restrict allowed ports? comma-separated list or empty for no limit: " allow_csv || true

  write_frps_toml "$cfg" "$name" "$bind" "$token" "$proto" "$udp_sz" "$tls_force" \
                   "$cert_file" "$key_file" "$dport" "$duser" "$dpwd" "$qk" "$qi" "$qs" "$allow_csv"
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
  if [[ "$proto" == tcp || "$proto" == websocket || "$proto" == "wss" ]]; then
    read -rp "Use TLS to server? (Y/n): " t || true
    [[ ${t,,} =~ ^n ]] && tls_enable=false || tls_enable=true
    if $tls_enable; then
      read -rp "TLS serverName (SNI). Hostname in server certificate (optional): " sni || true
    fi
  fi

  local udp_sz=1500
  if [[ "$proto" != tcp ]]; then
    read -rp "UDP packet size [1500]: " x || true; [[ -n ${x:-} ]] && udp_sz="$x"
  fi

  write_frpc_toml "$cfg" "$name" "$saddr" "$sport" "$token" "$proto" "$tls_enable" "$udp_sz" "$sni"
  ok "Base client config written: $cfg"

  echo "You can append multiple proxies. Type 'done' to finish."
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

# --------------------------- Client config parser (manage ports) ---------------------------

read_frpc_config(){
  local cfg="$1"; FRPC_HEAD=""; PROXIES=()
  local in_blocks=false in_block=false block=""
  while IFS='' read -r line || [[ -n "$line" ]]; do
    local t="${line%%$'\r'}"
    if [[ $t =~ ^\[\[proxies\]\] ]]; then
      in_blocks=true
      if [[ -n $block ]]; then PROXIES+=("$block"); fi
      block="[[proxies]]"
      in_block=true
      continue
    fi
    if ! $in_blocks; then
      FRPC_HEAD+="$t\n"
      continue
    fi
    if $in_block; then
      if [[ $t =~ ^\[\[proxies\]\] ]]; then
        PROXIES+=("$block"); block="[[proxies]]"; continue
      fi
      [[ -n ${t//[[:space:]]/} ]] && block+=$'\n'"$t"
    fi
  done <"$cfg"
  [[ -n $block ]] && PROXIES+=("$block")
}

write_frpc_with_blocks(){
  local cfg="$1"; shift
  : >"$cfg"
  [[ -n ${FRPC_HEAD:-} ]] && echo -ne "$FRPC_HEAD" >>"$cfg"
  for b in "${PROXIES[@]}"; do echo >>"$cfg"; echo "$b" >>"$cfg"; done
}

manage_client_ports(){
  echo "-- Manage Client Ports --"
  mapfile -t units < <(systemctl list-units --type=service --all --no-pager | awk '{print $1}' | sed -n 's/\.service$//p' | grep '^frp-client-')
  (( ${#units[@]} == 0 )) && { echo "No client services found"; pause; return; }
  local i=1; for u in "${units[@]}"; do echo "  $i) $u"; ((i++)); done
  local idx; read -rp "Choose client: " idx || true
  (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }

  # ---- FIX for nounset: split assignments
  local unit name cfg
  unit="${units[$((idx-1))]}"
  name="${unit#frp-client-}"
  cfg="$BASE_DIR/frpc-$name.toml"

  [[ -f "$cfg" ]] || { err "Config not found: $cfg"; pause; return; }

  while :; do
    printf "\nClient: %s\n" "$name"
    echo "1) View ports"
    echo "2) Add port"
    echo "3) Edit port"
    echo "4) Delete port"
    echo "5) Back"
    read -rp "Choice: " c || true
    case ${c:-1} in
      1)
        read_frpc_config "$cfg"
        if (( ${#PROXIES[@]} == 0 )); then
          echo "No proxies"
        else
          local j=1
          for blk in "${PROXIES[@]}"; do
            local nm type lp rp dom
            nm=$(echo "$blk" | grep -E '^name\s*=' | awk -F'=' '{print $2}' | tr -d ' "')
            type=$(echo "$blk" | grep -E '^type\s*=' | awk -F'=' '{print $2}' | tr -d ' "')
            lp=$(echo "$blk" | grep -E '^localPort\s*=' | awk -F'=' '{print $2}' | tr -d ' ')
            rp=$(echo "$blk" | grep -E '^remotePort\s*=' | awk -F'=' '{print $2}' | tr -d ' ')
            dom=$(echo "$blk" | grep -E '^customDomains\s*=' | sed -E 's/.*\[(.*)\].*/\1/' | tr -d ' "')
            echo "$j) $nm  type=$type  local=$lp  remote=$rp  domains=$dom"
            ((j++))
          done
        fi
        pause;;
      2)
        local l r pt dom=""
        while :; do read -rp "Local port: " l || true; validate_port "$l" && break || echo "Invalid"; done
        echo "Type 1) tcp 2) udp 3) http 4) https"; read -rp "Choose: " pt || true
        case ${pt:-1} in 1) pt=tcp;;2) pt=udp;;3) pt=http;;4) pt=https;; *) pt=tcp;; esac
        if [[ $pt == http || $pt == https ]]; then dom=""; r=0; else while :; do read -rp "Remote port: " r || true; validate_port "$r" && break || echo "Invalid"; done; fi
        read_frpc_config "$cfg"
        local n pname
        n=$(( ${#PROXIES[@]} + 1 ))
        pname="${pt}_${name}_$n"
        append_proxy_block "$cfg" "$pt" "$pname" "$l" "$r" "$dom"
        systemctl restart "$unit" || true; ok "Added & restarted"; pause;;
      3)
        read_frpc_config "$cfg"; (( ${#PROXIES[@]} == 0 )) && { echo "No proxies"; pause; continue; }
        local j=1; for _ in "${PROXIES[@]}"; do echo "  $j) block $j"; ((j++)); done
        read -rp "Select block: " j || true; (( j>=1 && j<=${#PROXIES[@]} )) || { echo "Invalid"; pause; continue; }
        local blk="${PROXIES[$((j-1))]}" nm type lp rp dom
        nm=$(echo "$blk" | grep -E '^name\s*=' | awk -F'=' '{print $2}' | tr -d ' "')
        type=$(echo "$blk" | grep -E '^type\s*=' | awk -F'=' '{print $2}' | tr -d ' "')
        lp=$(echo "$blk" | grep -E '^localPort\s*=' | awk -F'=' '{print $2}' | tr -d ' ')
        rp=$(echo "$blk" | grep -E '^remotePort\s*=' | awk -F'=' '{print $2}' | tr -d ' ')
        dom=$(echo "$blk" | grep -E '^customDomains\s*=' | sed -E 's/.*\[(.*)\].*/\1/' | tr -d ' "')
        read -rp "Local port [$lp]: " nl || true; nl=${nl:-$lp}; validate_port "$nl" || { echo "Invalid"; pause; continue; }
        if [[ $type == http || $type == https ]]; then
          r=0
        else
          read -rp "Remote port [$rp]: " nr || true; nr=${nr:-$rp}; validate_port "$nr" || { echo "Invalid"; pause; continue; }
        fi
        echo "Type 1) tcp 2) udp 3) http 4) https (current $type)"; read -rp "Choose: " nt || true
        case ${nt:-} in 1) type=tcp;;2) type=udp;;3) type=http;;4) type=https;; esac
        if [[ $type == http || $type == https ]]; then
          read -rp "Custom domain [$dom] (empty keep, 'none' remove): " nd || true
          if [[ ${nd,,} == none ]]; then dom=""; elif [[ -n ${nd:-} ]]; then dom="$nd"; fi
          nr=0
        else dom=""; nr=${nr:-$rp}; fi
        blk="[[proxies]]\nname = \"$nm\"\ntype = \"$type\"\n"
        if [[ $type == tcp || $type == udp ]]; then blk+="localIP = \"127.0.0.1\"\n"; fi
        blk+="localPort = $nl\n"; [[ $type == http || $type == https ]] || blk+="remotePort = $nr\n"
        [[ -n $dom ]] && blk+="customDomains = [\"$dom\"]\n"
        PROXIES[$((j-1))]="$blk"
        write_frpc_with_blocks "$cfg"
        systemctl restart "$unit" || true; ok "Updated & restarted"; pause;;
      4)
        read_frpc_config "$cfg"; (( ${#PROXIES[@]} == 0 )) && { echo "No proxies"; pause; continue; }
        local j=1; for _ in "${PROXIES[@]}"; do echo "  $j) block $j"; ((j++)); done
        read -rp "Select block to delete: " j || true
        (( j>=1 && j<=${#PROXIES[@]} )) || { echo "Invalid"; pause; continue; }
        unset 'PROXIES[$((j-1))]'; PROXIES=("${PROXIES[@]}")
        write_frpc_with_blocks "$cfg"
        systemctl restart "$unit" || true; ok "Deleted & restarted"; pause;;
      5) break;;
      *) :;;
    esac
  done
}

show_dashboard_info(){
  echo "-- Server Dashboard Info --"
  mapfile -t units < <(systemctl list-units --type=service --all --no-pager | awk '{print $1}' | sed -n 's/\.service$//p' | grep '^frp-server-')
  (( ${#units[@]} == 0 )) && { echo "No frp-server-* services"; pause; return; }
  local i=1; for u in "${units[@]}"; do echo "  $i) $u"; ((i++)); done
  local idx; read -rp "Choose: " idx || true; (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }

  # ---- FIX for nounset: split assignments
  local unit name cfg
  unit="${units[$((idx-1))]}"
  name="${unit#frp-server-}"
  cfg="$BASE_DIR/frps-$name.toml"

  [[ -f "$cfg" ]] || { err "Config not found: $cfg"; pause; return; }
  local port user pwd
  port=$(grep -E '^webServer\.port\s*=' "$cfg" | awk '{print $3}' | tr -d '\r') || true
  user=$(grep -E '^webServer\.user\s*=' "$cfg" | awk '{print $3}' | tr -d '"\r') || true
  pwd=$(grep -E '^webServer\.password\s*=' "$cfg" | awk '{print $3}' | tr -d '"\r') || true
  if [[ -n ${port:-} ]]; then
    echo "Dashboard:"
    echo "  Port : $port"
    echo "  User : $user"
    echo "  Pass : $pwd"
  else
    echo "Dashboard not enabled for this server."
  fi
  pause
}

delete_unit_menu(){
  echo "1) Delete a server"; echo "2) Delete a client"; echo "3) Back"
  read -rp "Choice: " c || true
  case ${c:-3} in
    1)
      mapfile -t units < <(systemctl list-units --type=service --all --no-pager | awk '{print $1}' | sed -n 's/\.service$//p' | grep '^frp-server-')
      (( ${#units[@]} == 0 )) && { echo "No server services"; pause; return; }
      local i=1; for u in "${units[@]}"; do echo "  $i) $u"; ((i++)); done
      local idx; read -rp "Choose: " idx || true; (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }

      # ---- FIX for nounset: split assignments
      local unit name cfg
      unit="${units[$((idx-1))]}"
      name="${unit#frp-server-}"
      cfg="$BASE_DIR/frps-$name.toml"

      remove_service "$unit"; systemctl daemon-reload; [[ -f "$cfg" ]] && rm -f "$cfg"
      ok "Deleted $unit and its config"; pause;;
    2)
      mapfile -t units < <(systemctl list-units --type=service --all --no-pager | awk '{print $1}' | sed -n 's/\.service$//p' | grep '^frp-client-')
      (( ${#units[@]} == 0 )) && { echo "No client services"; pause; return; }
      local i=1; for u in "${units[@]}"; do echo "  $i) $u"; ((i++)); done
      local idx; read -rp "Choose: " idx || true; (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }

      # ---- FIX for nounset: split assignments
      local unit name cfg
      unit="${units[$((idx-1))]}"
      name="${unit#frp-client-}"
      cfg="$BASE_DIR/frpc-$name.toml"

      remove_service "$unit"; systemctl daemon-reload; [[ -f "$cfg" ]] && rm -f "$cfg"
      ok "Deleted $unit and its config"; pause;;
    *) :;;
  esac
}

view_logs_menu(){
  echo "1) Server logs"; echo "2) Client logs"; echo "3) Back"
  read -rp "Choice: " c || true
  case ${c:-3} in
    1)
      mapfile -t units < <(systemctl list-units --type=service --all --no-pager | awk '{print $1}' | sed -n 's/\.service$//p' | grep '^frp-server-')
      (( ${#units[@]} == 0 )) && { echo "No server services"; pause; return; }
      local i=1; for u in "${units[@]}"; do echo "  $i) $u"; ((i++)); done
      local idx; read -rp "Choose: " idx || true; (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
      show_logs "${units[$((idx-1))]}";;
    2)
      mapfile -t units < <(systemctl list-units --type=service --all --no-pager | awk '{print $1}' | sed -n 's/\.service$//p' | grep '^frp-client-')
      (( ${#units[@]} == 0 )) && { echo "No client services"; pause; return; }
      local i=1; for u in "${units[@]}"; do echo "  $i) $u"; ((i++)); done
      local idx; read -rp "Choose: " idx || true; (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
      show_logs "${units[$((idx-1))]}";;
    *) :;;
  esac
}

main_menu(){
  while :; do
    clear
    echo "FRP Unlimited Menu (modern) v$SCRIPT_VERSION"
    echo "Repository: fatedier/frp"
    echo "Binary status: $(status_binaries)"
    echo "Config root: $BASE_DIR"
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
