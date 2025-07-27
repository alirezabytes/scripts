#!/usr/bin/env bash
# ============================================================================
#  FRP Unlimited Menu (Personalized)
#  - English messages & comments
#  - Uses TOML configs (frps-<name>.toml / frpc-<name>.toml)
#  - Multi-service layout: frp-server-<name>.service / frp-client-<name>.service
#  - No apt install, no certbot operations, no cron management
#  - Transport protocols: tcp, kcp, quic, websocket, wss
#  - Dashboard optional (port/user/password) like script #1
#  - Detect existing Let's Encrypt certs under /etc/letsencrypt/live
#  - Install binaries via GitHub API (latest), like script #1
# ============================================================================

set -Eeuo pipefail
trap 'status=$?; echo "[ERROR] Line $LINENO: exit $status"; exit $status' ERR

# --------- Paths & globals ---------
SCRIPT_VERSION="2.0.0"
BASE_DIR="$(pwd)/frp"                 # per-user config root (similar to script #1)
BIN_FRPS="/usr/local/bin/frps"
BIN_FRPC="/usr/local/bin/frpc"
SYSTEMD_DIR="/etc/systemd/system"
LETSCERT_DIR="/etc/letsencrypt/live"

# --------- Helpers ---------
log(){ echo "$*"; }
ok(){ echo "[OK] $*"; }
err(){ echo "[ERR] $*" >&2; }
pause(){ read -rp "Press Enter to continue..." _; }

arch_tag(){
  case "$(uname -m)" in
    x86_64|amd64) echo linux_amd64 ;;
    aarch64|arm64) echo linux_arm64 ;;
    armv7l) echo linux_arm ;;
    *) err "Unsupported architecture: $(uname -m)"; exit 1 ;;
  esac
}

latest_frp_url(){
  local tag arch; arch=$(arch_tag)
  tag=$(curl -fsSL https://api.github.com/repos/fatedier/frp/releases/latest | \
        grep '"tag_name"' | head -n1 | sed -E 's/.*"v?([0-9.]+)".*/\1/') || true
  [[ -z ${tag:-} ]] && { err "Failed to query latest FRP tag from GitHub"; return 1; }
  curl -fsSL https://api.github.com/repos/fatedier/frp/releases/latest \
    | grep 'browser_download_url' \
    | grep -E "${arch}\.tar\.gz" \
    | cut -d '"' -f 4 | head -n1
}

install_frp(){
  log "Downloading latest FRP via GitHub API..."
  local url; url=$(latest_frp_url) || { err "Could not resolve download URL"; return 1; }
  [[ -z $url ]] && { err "Download URL is empty"; return 1; }
  log "URL: $url"
  local tmp=/tmp frp_pkg; frp_pkg="$tmp/$(basename "$url")"
  curl -fL -o "$frp_pkg" "$url" || { err "Download failed"; return 1; }
  local extract_dir; extract_dir="$tmp/$(basename "$frp_pkg" .tar.gz)"
  rm -rf "$extract_dir" && mkdir -p "$extract_dir"
  tar -xzf "$frp_pkg" -C "$extract_dir" --strip-components=1
  install -m 0755 "$extract_dir/frps" "$BIN_FRPS"
  install -m 0755 "$extract_dir/frpc" "$BIN_FRPC"
  rm -rf "$extract_dir" "$frp_pkg"
  ok "FRP binaries installed: $BIN_FRPS , $BIN_FRPC"
}

is_installed(){ [[ -x "$BIN_FRPS" && -x "$BIN_FRPC" ]]; }

binary_status(){ if is_installed; then echo 'Installed'; else echo 'Not installed'; fi; }

service_exists(){ systemctl list-unit-files --type=service --no-pager | grep -q "^$1\.service"; }

list_services(){ systemctl list-units --type=service --all --no-pager | awk '{print $1}' | grep -E '^(frp-server|frp-client)-.*\.service$' | sed 's/\.service$//'; }

safe_user(){ whoami; }

ensure_base(){ mkdir -p "$BASE_DIR"; }

validate_port(){ local p=${1:-}; [[ $p =~ ^[0-9]+$ ]] && (( p>=1 && p<=65535 )); }

validate_email(){ [[ ${1:-} =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; }

validate_host(){
  local h=${1:-}
  local ipv4='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
  local ipv6='^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$'
  local domain='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
  [[ $h =~ $ipv4 || $h =~ $ipv6 || $h =~ $domain ]]
}

rand_password(){ head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16; }

select_cert(){
  # Print menu to stderr; output only the selected "cert|key" on stdout
  [[ ! -d "$LETSCERT_DIR" ]] && { echo ""; return 0; }
  mapfile -t domains < <(find "$LETSCERT_DIR" -maxdepth 1 -mindepth 1 -type d ! -name README -printf '%f
')
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
  if [[ -r "$cert" && -r "$key" ]]; then
    printf '%s|%s
' "$cert" "$key"
  else
    echo ""
  fi
}

write_frps_toml(){
  # Args: cfg_path server_name bind_port token transport udpPacketSize tls_enable cert_file key_file dashboard_port dashboard_user dashboard_pwd quic_keepalive quic_idle quic_streams
  local cfg="$1" name="$2" bind="$3" token="$4" proto="$5" udp_sz="$6" tls="$7"
  local cfile="${8:-}" kfile="${9:-}" dport="${10:-}" duser="${11:-}" dpwd="${12:-}"
  local q_keep="${13:-10}" q_idle="${14:-30}" q_streams="${15:-100000}"

  cat >"$cfg" <<EOF
# frps-$name.toml
[common]
bind_port = $bind
token = "$token"
EOF

  # tls_enable only meaningful for TCP/WS? Keep consistent with script #1
  if [[ "$proto" == "tcp" || "$proto" == "websocket" || "$proto" == "wss" ]]; then
    if [[ "$tls" == "true" ]]; then
      cat >>"$cfg" <<EOF
tls_enable = true
EOF
      if [[ -n "$cfile" && -n "$kfile" ]]; then
        cat >>"$cfg" <<EOF
cert_file = "$cfile"
key_file = "$kfile"
EOF
      fi
    else
      echo "tls_enable = false" >>"$cfg"
    fi
  else
    # For KCP/QUIC, FRP ignores tls_enable; don't write it.
    :
  fi

  # udpPacketSize: write only when protocol != tcp
  if [[ "$proto" != "tcp" ]]; then
    echo "udpPacketSize = $udp_sz" >>"$cfg"
  fi

  # Protocol specific
  if [[ "$proto" == "kcp" ]]; then
    echo "kcpBindPort = $bind" >>"$cfg"
  fi
  if [[ "$proto" == "quic" ]]; then
    cat >>"$cfg" <<EOF
quicBindPort = $bind
[transport.quic]
keepalivePeriod = $q_keep
maxIdleTimeout = $q_idle
maxIncomingStreams = $q_streams
EOF
  fi
  if [[ "$proto" == "websocket" || "$proto" == "wss" ]]; then
    cat >>"$cfg" <<EOF
[transport]
protocol = "$proto"
EOF
  fi

  # Dashboard
  if [[ -n "$dport" ]]; then
    cat >>"$cfg" <<EOF

dashboard_port = $dport
dashboard_user = "$duser"
dashboard_pwd = "$dpwd"
EOF
  fi
}

write_frpc_toml(){
  # Args: cfg_path client_name server_addr server_port token transport tls_enable udpPacketSize
  local cfg="$1" name="$2" saddr="$3" sport="$4" token="$5" proto="$6" tls="$7" udp_sz="$8"
  cat >"$cfg" <<EOF
# frpc-$name.toml
[common]
server_addr = "$saddr"
server_port = $sport
token = "$token"
transport.protocol = "$proto"
EOF
  if [[ "$proto" == "tcp" || "$proto" == "websocket" || "$proto" == "wss" ]]; then
    echo "tls_enable = $tls" >>"$cfg"
  fi
  if [[ "$proto" != "tcp" ]]; then
    echo "udpPacketSize = $udp_sz" >>"$cfg"
  fi
  echo >>"$cfg"
}

append_proxy_block(){
  # Args: cfg_path type name local_port remote_port [custom_domain]
  local cfg="$1" ptype="$2" pname="$3" lport="$4" rport="$5" cdom="${6:-}"
  {
    echo "[$pname]"
    echo "name = \"$pname\""
    echo "type = \"$ptype\""
    if [[ "$ptype" == "tcp" || "$ptype" == "udp" ]]; then
      echo "local_ip = \"127.0.0.1\""
    fi
    echo "local_port = $lport"
    echo "remote_port = $rport"
    if [[ "$ptype" == "http" || "$ptype" == "https" ]]; then
      if [[ -n "$cdom" ]]; then
        echo "custom_domains = [\"$cdom\"]"
      fi
    fi
    echo
  } >>"$cfg"
}

create_service(){
  # Args: unit_name ExecStart
  local unit="$1" exec="$2"
  cat >"$SYSTEMD_DIR/$unit.service" <<EOF
[Unit]
Description=$unit
After=network.target

[Service]
Type=simple
ExecStart=$exec
Restart=always
RestartSec=5
User=$(safe_user)

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$unit.service" >/dev/null 2>&1 || true
}

show_logs(){ local unit="$1"; journalctl -u "$unit" -n 50 --no-pager; pause; }

remove_service(){
  local unit="$1"
  systemctl stop "$unit" >/dev/null 2>&1 || true
  systemctl disable "$unit" >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_DIR/$unit.service"
}

remove_all(){
  echo "Searching for FRP services..."
  mapfile -t units < <(list_services)
  if (( ${#units[@]} > 0 )); then
    for u in "${units[@]}"; do
      echo "Removing service $u"
      remove_service "$u"
    done
    systemctl daemon-reload
  fi
  # Remove configs
  if [[ -d "$BASE_DIR" ]]; then
    rm -rf "$BASE_DIR"
    ok "Removed configs under $BASE_DIR"
  fi
  # Remove binaries
  if [[ -x "$BIN_FRPS" ]]; then rm -f "$BIN_FRPS"; fi
  if [[ -x "$BIN_FRPC" ]]; then rm -f "$BIN_FRPC"; fi
  ok "Uninstall complete."
}

# --------- Interactive flows ---------

action_add_server(){
  ensure_base
  echo "-- Add New FRP Server --"
  local name
  while :; do
    read -rp "Server name (alnum, hyphen, underscore): " name || true
    name=$(echo "$name" | tr -cd '[:alnum:]_-')
    [[ -n $name ]] && break || echo "Name cannot be empty"
  done
  local service="frp-server-$name"
  local cfg="$BASE_DIR/frps-$name.toml"
  if service_exists "$service"; then err "Service already exists: $service"; pause; return; fi

  local bind token
  while :; do read -rp "Bind port (e.g. 7000): " bind || true; validate_port "$bind" && break || echo "Invalid port"; done
  while :; do read -rp "Auth token: " token || true; [[ -n $token ]] && break || echo "Token cannot be empty"; done

  echo "Transport protocol options:"
  echo "  1) tcp"
  echo "  2) kcp"
  echo "  3) quic"
  echo "  4) websocket"
  echo "  5) wss"
  local choice proto; read -rp "Choose [1-5]: " choice || true
  case ${choice:-1} in
    1) proto="tcp";; 2) proto="kcp";; 3) proto="quic";; 4) proto="websocket";; 5) proto="wss";;
    *) proto="tcp";;
  esac

  local udp_sz=1500
  if [[ "$proto" != "tcp" ]]; then
    read -rp "UDP packet size (udpPacketSize) [1500]: " udp_in || true
    [[ -n ${udp_in:-} ]] && udp_sz="$udp_in"
  fi

  local tls_enable="false" cert_pair cert_file key_file
  if [[ "$proto" == "tcp" || "$proto" == "websocket" || "$proto" == "wss" ]]; then
    read -rp "Enable TLS? (y/N): " a || true
    if [[ ${a,,} =~ ^y ]]; then
      tls_enable="true"
      cert_pair=$(select_cert)
      if [[ -n $cert_pair ]]; then
        cert_file="${cert_pair%%|*}"; key_file="${cert_pair##*|}"
        echo "Using cert: $cert_file"
      else
        echo "No certificate selected/found. TLS will be enabled without explicit cert paths (if supported)."
      fi
    fi
  fi

  local enable_dash="n" dport="" duser="" dpwd=""
  read -rp "Enable dashboard? (y/N): " enable_dash || true
  if [[ ${enable_dash,,} =~ ^y ]]; then
    while :; do read -rp "Dashboard port (e.g. 7500): " dport || true; validate_port "$dport" && break || echo "Invalid port"; done
    read -rp "Dashboard username [admin]: " duser || true; duser=${duser:-admin}
    dpwd=$(rand_password)
    read -rp "Dashboard password (leave empty for random: $dpwd): " inpwd || true
    [[ -n ${inpwd:-} ]] && dpwd="$inpwd"
    echo "Dashboard credentials -> user: $duser  pass: $dpwd"
  fi

  local qk=10 qi=30 qs=100000
  if [[ "$proto" == "quic" ]]; then
    read -rp "QUIC keepalivePeriod [10]: " t || true; [[ -n ${t:-} ]] && qk="$t"
    read -rp "QUIC maxIdleTimeout [30]: " t || true; [[ -n ${t:-} ]] && qi="$t"
    read -rp "QUIC maxIncomingStreams [100000]: " t || true; [[ -n ${t:-} ]] && qs="$t"
  fi

  write_frps_toml "$cfg" "$name" "$bind" "$token" "$proto" "$udp_sz" "$tls_enable" "$cert_file" "$key_file" "$dport" "$duser" "$dpwd" "$qk" "$qi" "$qs"
  ok "Config written: $cfg"

  create_service "$service" "$BIN_FRPS -c $cfg"
  ok "Service started: $service"
  read -rp "View logs now? (y/N): " v || v=""
if [[ ${v,,} =~ ^y ]]; then
  show_logs "$service"
fi
}

action_add_client(){
  ensure_base
  echo "-- Add New FRP Client --"
  local name
  while :; do
    read -rp "Client name (alnum, hyphen, underscore): " name || true
    name=$(echo "$name" | tr -cd '[:alnum:]_-')
    [[ -n $name ]] && break || echo "Name cannot be empty"
  done
  local service="frp-client-$name"
  local cfg="$BASE_DIR/frpc-$name.toml"
  if service_exists "$service"; then err "Service already exists: $service"; pause; return; fi

  local saddr sport token
  while :; do read -rp "Server address (domain/IP): " saddr || true; validate_host "$saddr" && break || echo "Invalid address"; done
  while :; do read -rp "Server port (e.g. 7000): " sport || true; validate_port "$sport" && break || echo "Invalid port"; done
  while :; do read -rp "Auth token: " token || true; [[ -n $token ]] && break || echo "Token cannot be empty"; done

  echo "Transport protocol options:"
  echo "  1) tcp"
  echo "  2) kcp"
  echo "  3) quic"
  echo "  4) websocket"
  echo "  5) wss"
  local choice proto; read -rp "Choose [1-5]: " choice || true
  case ${choice:-1} in
    1) proto="tcp";; 2) proto="kcp";; 3) proto="quic";; 4) proto="websocket";; 5) proto="wss";;
    *) proto="tcp";;
  esac

  local tls_enable="true"
  if [[ "$proto" == "tcp" || "$proto" == "websocket" || "$proto" == "wss" ]]; then
    read -rp "Does server use TLS? (Y/n): " t || true
    [[ ${t,,} =~ ^n ]] && tls_enable="false" || tls_enable="true"
  fi

  local udp_sz=1500
  if [[ "$proto" != "tcp" ]]; then
    read -rp "UDP packet size (udpPacketSize) [1500]: " inp || true
    [[ -n ${inp:-} ]] && udp_sz="$inp"
  fi

  # Write base client TOML
  write_frpc_toml "$cfg" "$name" "$saddr" "$sport" "$token" "$proto" "$tls_enable" "$udp_sz"

  echo "You can create multiple proxies. Type 'done' when finished."
  local idx=1
  while :; do
    echo "--- Proxy #$idx ---"
    local lport rport ptype cdom=""
    read -rp "Local port (or 'done'): " lport || true
    [[ ${lport,,} == "done" ]] && break
    validate_port "$lport" || { echo "Invalid port"; continue; }
    while :; do read -rp "Remote port: " rport || true; validate_port "$rport" && break || echo "Invalid port"; done
    echo "Proxy type: 1) tcp  2) udp  3) http  4) https"
    read -rp "Choose [1-4]: " pt || true
    case ${pt:-1} in
      1) ptype="tcp";; 2) ptype="udp";; 3) ptype="http";; 4) ptype="https";; *) ptype="tcp";;
    esac
    if [[ "$ptype" == "http" || "$ptype" == "https" ]]; then
      read -rp "Custom domain (optional): " cdom || true
    fi
    local pname="${ptype}_${name}_${idx}"
    append_proxy_block "$cfg" "$ptype" "$pname" "$lport" "$rport" "$cdom"
    ok "Added proxy $pname"
    ((idx++))
  done

  create_service "$service" "$BIN_FRPC -c $cfg"
  ok "Service started: $service"
  read -rp "View logs now? (y/N): " v || v=""
if [[ ${v,,} =~ ^y ]]; then
  show_logs "$service"
fi
}

# --- Parse & manage client proxies ---
read_frpc_config(){
  # $1 cfg, outputs global COMMON and PROXIES array (each block string)
  local cfg="$1"; COMMON=""; PROXIES=()
  local in_common=false in_block=false block="" header
  while IFS='' read -r line || [[ -n "$line" ]]; do
    local t="${line%%$'\r'}" # strip CR
    if [[ $t =~ ^\[common\] ]]; then in_common=true; in_block=false; continue; fi
    if [[ $t =~ ^\[.*\] ]]; then
      # new block
      if [[ -n $block ]]; then PROXIES+=("$block"); fi
      block="$t"
      in_block=true; in_common=false; continue
    fi
    if $in_common; then
      [[ -n ${t//[[:space:]]/} ]] && COMMON+="$t\n"
    elif $in_block; then
      [[ -n ${t//[[:space:]]/} ]] && block+=$'\n'"$t"
    fi
  done <"$cfg"
  [[ -n $block ]] && PROXIES+=("$block")
}

write_frpc_with_blocks(){
  local cfg="$1"; shift
  : >"$cfg"
  echo "# regenerated by menu" >>"$cfg"
  echo "[common]" >>"$cfg"
  [[ -n ${COMMON:-} ]] && echo -e "$COMMON" >>"$cfg"
  for b in "${PROXIES[@]}"; do
    echo >>"$cfg"; echo "$b" >>"$cfg"
  done
}

extract_field(){ echo "$1" | grep -E "^$2\s*=\s*" | awk -F'=' '{print $2}' | tr -d ' "\r'; }

manage_client_ports(){
  echo "-- Manage Client Ports --"
  mapfile -t units < <(systemctl list-units --type=service --all --no-pager | awk '{print $1}' | sed -n 's/\.service$//p' | grep '^frp-client-')
  (( ${#units[@]} == 0 )) && { echo "No frp-client-* services found"; pause; return; }
  local i=1; for u in "${units[@]}"; do echo "  $i) $u"; ((i++)); done
  read -rp "Choose client: " idx || true
  (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
  local unit="${units[$((idx-1))]}" name="${unit#frp-client-}"
  local cfg="$BASE_DIR/frpc-$name.toml"
  [[ -f "$cfg" ]] || { err "Config not found: $cfg"; pause; return; }

  while :; do
    echo "\nClient: $name"
    echo "1) View ports"
    echo "2) Add port"
    echo "3) Edit port"
    echo "4) Delete port"
    echo "5) Back"
    read -rp "Choice: " c || true
    case ${c:-1} in
      1)
        read_frpc_config "$cfg"
        if (( ${#PROXIES[@]} == 0 )); then echo "No proxies"; else
          local idx=1
          for blk in "${PROXIES[@]}"; do
            local nm type lp rp dom
            nm=$(echo "$blk" | grep -E '^name\s*=' | awk -F'=' '{print $2}' | tr -d ' "')
            type=$(echo "$blk" | grep -E '^type\s*=' | awk -F'=' '{print $2}' | tr -d ' "')
            lp=$(echo "$blk" | grep -E '^local_port\s*=' | awk -F'=' '{print $2}' | tr -d ' ')
            rp=$(echo "$blk" | grep -E '^remote_port\s*=' | awk -F'=' '{print $2}' | tr -d ' ')
            dom=$(echo "$blk" | grep -E '^custom_domains\s*=' | sed -E 's/.*\[(.*)\].*/\1/' | tr -d ' "')
            echo "$idx) $nm  type=$type  local=$lp  remote=$rp  domains=$dom"
            ((idx++))
          done
        fi
        pause;;
      2)
        local l r pt dom=""; while :; do read -rp "Local port: " l || true; validate_port "$l" && break || echo "Invalid"; done
        while :; do read -rp "Remote port: " r || true; validate_port "$r" && break || echo "Invalid"; done
        echo "Type 1) tcp 2) udp 3) http 4) https"; read -rp "Choose: " pt || true
        case ${pt:-1} in 1) pt="tcp";;2) pt="udp";;3) pt="http";;4) pt="https";;*) pt="tcp";; esac
        if [[ $pt == http || $pt == https ]]; then read -rp "Custom domain (optional): " dom || true; fi
        read_frpc_config "$cfg"; local n=$(( ${#PROXIES[@]} + 1 )) pname="${pt}_${name}_${n}"
        append_proxy_block "$cfg" "$pt" "$pname" "$l" "$r" "$dom"
        systemctl restart "$unit" || true; ok "Added & restarted"; pause;;
      3)
        read_frpc_config "$cfg"; (( ${#PROXIES[@]} == 0 )) && { echo "No proxies"; pause; continue; }
        local j=1; for _ in "${PROXIES[@]}"; do echo "  $j) block $j"; ((j++)); done
        read -rp "Select block: " j || true; (( j>=1 && j<=${#PROXIES[@]} )) || { echo "Invalid"; pause; continue; }
        local blk="${PROXIES[$((j-1))]}"
        local nm type lp rp dom
        nm=$(echo "$blk" | grep -E '^name\s*=' | awk -F'=' '{print $2}' | tr -d ' "')
        type=$(echo "$blk" | grep -E '^type\s*=' | awk -F'=' '{print $2}' | tr -d ' "')
        lp=$(echo "$blk" | grep -E '^local_port\s*=' | awk -F'=' '{print $2}' | tr -d ' ')
        rp=$(echo "$blk" | grep -E '^remote_port\s*=' | awk -F'=' '{print $2}' | tr -d ' ')
        dom=$(echo "$blk" | grep -E '^custom_domains\s*=' | sed -E 's/.*\[(.*)\].*/\1/' | tr -d ' "')
        read -rp "Local port [$lp]: " nl || true; nl=${nl:-$lp}; validate_port "$nl" || { echo "Invalid"; pause; continue; }
        read -rp "Remote port [$rp]: " nr || true; nr=${nr:-$rp}; validate_port "$nr" || { echo "Invalid"; pause; continue; }
        echo "Type 1) tcp 2) udp 3) http 4) https (current $type)"; read -rp "Choose: " nt || true
        case ${nt:-} in 1) type="tcp";;2) type="udp";;3) type="http";;4) type="https";; esac
        if [[ $type == http || $type == https ]]; then
          read -rp "Custom domain [$dom] (empty to keep, 'none' to remove): " nd || true
          if [[ ${nd,,} == none ]]; then dom=""; elif [[ -n ${nd:-} ]]; then dom="$nd"; fi
        else dom=""; fi
        # rebuild block
        blk="[$nm]\nname = \"$nm\"\ntype = \"$type\"\n"
        if [[ $type == tcp || $type == udp ]]; then blk+="local_ip = \"127.0.0.1\"\n"; fi
        blk+="local_port = $nl\nremote_port = $nr\n"
        if [[ -n $dom ]]; then blk+="custom_domains = [\"$dom\"]"; fi
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
      *) echo "Invalid";;
    esac
  done
}

show_dashboard_info(){
  echo "-- Show FRP Dashboard Info --"
  mapfile -t units < <(systemctl list-units --type=service --all --no-pager | awk '{print $1}' | sed -n 's/\.service$//p' | grep '^frp-server-')
  (( ${#units[@]} == 0 )) && { echo "No frp-server-* services found"; pause; return; }
  local i=1; for u in "${units[@]}"; do echo "  $i) $u"; ((i++)); done
  read -rp "Choose server: " idx || true
  (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
  local unit="${units[$((idx-1))]}" name="${unit#frp-server-}"
  local cfg="$BASE_DIR/frps-$name.toml"
  [[ -f "$cfg" ]] || { err "Config not found: $cfg"; pause; return; }
  local port user pwd
  port=$(grep -E '^dashboard_port\s*=' "$cfg" | awk '{print $3}' | tr -d '\r') || true
  user=$(grep -E '^dashboard_user\s*=' "$cfg" | awk '{print $3}' | tr -d '"\r') || true
  pwd=$(grep -E '^dashboard_pwd\s*=' "$cfg" | awk '{print $3}' | tr -d '"\r') || true
  if [[ -n ${port:-} ]]; then
    echo "Dashboard:"; echo "  Port : $port"; echo "  User : $user"; echo "  Pass : $pwd"
  else
    echo "Dashboard not enabled for this server."
  fi
  pause
}

view_logs_menu(){
  echo "1) Server logs"; echo "2) Client logs"; echo "3) Back"
  read -rp "Choice: " c || true
  case ${c:-3} in
    1)
      mapfile -t units < <(systemctl list-units --type=service --all --no-pager | awk '{print $1}' | sed -n 's/\.service$//p' | grep '^frp-server-')
      (( ${#units[@]} == 0 )) && { echo "No server services"; pause; return; }
      local i=1; for u in "${units[@]}"; do echo "  $i) $u"; ((i++)); done
      read -rp "Choose: " idx || true; (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
      show_logs "${units[$((idx-1))]}";;
    2)
      mapfile -t units < <(systemctl list-units --type=service --all --no-pager | awk '{print $1}' | sed -n 's/\.service$//p' | grep '^frp-client-')
      (( ${#units[@]} == 0 )) && { echo "No client services"; pause; return; }
      local i=1; for u in "${units[@]}"; do echo "  $i) $u"; ((i++)); done
      read -rp "Choose: " idx || true; (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
      show_logs "${units[$((idx-1))]}";;
    *) :;;
  esac
}

delete_unit_menu(){
  echo "1) Delete a server"; echo "2) Delete a client"; echo "3) Back"
  read -rp "Choice: " c || true
  case ${c:-3} in
    1)
      mapfile -t units < <(systemctl list-units --type=service --all --no-pager | awk '{print $1}' | sed -n 's/\.service$//p' | grep '^frp-server-')
      (( ${#units[@]} == 0 )) && { echo "No server services"; pause; return; }
      local i=1; for u in "${units[@]}"; do echo "  $i) $u"; ((i++)); done
      read -rp "Choose: " idx || true; (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
      local unit="${units[$((idx-1))]}"
local name="${unit#frp-server-}"
local cfg="$BASE_DIR/frps-$name.toml"
      remove_service "$unit"; systemctl daemon-reload
      [[ -f "$cfg" ]] && rm -f "$cfg"
      ok "Deleted $unit and its config"
      pause;;
    2)
      mapfile -t units < <(systemctl list-units --type=service --all --no-pager | awk '{print $1}' | sed -n 's/\.service$//p' | grep '^frp-client-')
      (( ${#units[@]} == 0 )) && { echo "No client services"; pause; return; }
      local i=1; for u in "${units[@]}"; do echo "  $i) $u"; ((i++)); done
      read -rp "Choose: " idx || true; (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
      local unit="${units[$((idx-1))]}"
local name="${unit#frp-client-}"
local cfg="$BASE_DIR/frpc-$name.toml"
      remove_service "$unit"; systemctl daemon-reload
      [[ -f "$cfg" ]] && rm -f "$cfg"
      ok "Deleted $unit and its config"
      pause;;
    *) :;;
  esac
}

# --------- Main menu ---------
main_menu(){
  while :; do
    clear
    echo "FRP Unlimited Menu (personalized) v$SCRIPT_VERSION"
    echo "Repository: fatedier/frp"
    echo "Binary status: $(binary_status)"
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
      7)
        read -rp "Are you sure to REMOVE ALL (y/N)? " a || true
        [[ ${a,,} =~ ^y ]] && remove_all || echo "Cancelled"; pause ;;
      0) exit 0 ;;
      *) : ;;
    esac
  done
}

main_menu
