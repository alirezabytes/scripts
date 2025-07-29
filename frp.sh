#!/usr/bin/env bash
# ======================================================================
#  FRP Unlimited Menu (modern TOML, v0.63.x compatible)
#  Author: ChatGPT-Assistant (English only)
# ======================================================================

set -Euo pipefail
: "${FRP_DEBUG:=0}"
trap 's=$?; [[ "$FRP_DEBUG" == 1 ]] && echo "[ERROR] line $LINENO: $BASH_COMMAND -> exit $s"' ERR

SCRIPT_VERSION="2.4.0"
BASE_DIR="$(pwd)/frp"
BIN_FRPS="/usr/local/bin/frps"
BIN_FRPC="/usr/local/bin/frpc"
SYSTEMD_DIR="/etc/systemd/system"
LETSCERT_DIR="/etc/letsencrypt/live"

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
log(){ echo "$*"; }
ok(){ echo "[OK] $*"; }
err(){ echo "[ERR] $*" >&2; }
pause(){ read -rp "Press Enter to continue..." _ || true; }

maybe_add(){               # maybe_add <key> <value> <default> <cfg_path>
  local key=$1 val=$2 def=$3 cfg=$4
  [[ "$val" != "$def" ]] && printf '%s = %s\n' "$key" "$val" >>"$cfg"
}

arch_tag(){
  case "$(uname -m)" in
    x86_64|amd64) echo linux_amd64 ;;
    aarch64|arm64) echo linux_arm64 ;;
    armv7l)        echo linux_arm  ;;
    *) err "Unsupported arch: $(uname -m)"; exit 1 ;;
  esac
}

# ----------------------------------------------------------------------
# Un‑installer (must be defined early!)
# ----------------------------------------------------------------------
remove_all(){
  echo "Searching for FRP services..."
  mapfile -t units < <(systemctl list-units --type=service --all --no-pager \
                       | awk '{print $1}' | sed -n 's/\.service$//p' \
                       | grep -E '^(frp-server|frp-client)-')
  if (( ${#units[@]} > 0 )); then
    for u in "${units[@]}"; do
      echo "Removing $u"
      systemctl stop "$u"    >/dev/null 2>&1 || true
      systemctl disable "$u" >/dev/null 2>&1 || true
      rm -f "$SYSTEMD_DIR/$u.service"
    done
    systemctl daemon-reload
  fi
  [[ -d "$BASE_DIR" ]] && { rm -rf "$BASE_DIR"; ok "Removed $BASE_DIR"; }
  [[ -x "$BIN_FRPS" ]] && rm -f "$BIN_FRPS"
  [[ -x "$BIN_FRPC" ]] && rm -f "$BIN_FRPC"
  ok "Uninstall complete."
}

# ----------------------------------------------------------------------
# Download & install latest release
# ----------------------------------------------------------------------
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
  pkg="/tmp/$(basename "$url")"
  curl -fL -o "$pkg" "$url"
  tmpdir="/tmp/frp-extract.$$"; rm -rf "$tmpdir"; mkdir -p "$tmpdir"
  tar -xzf "$pkg" -C "$tmpdir" --strip-components=1
  install -m0755 "$tmpdir/frps" "$BIN_FRPS"
  install -m0755 "$tmpdir/frpc" "$BIN_FRPC"
  rm -rf "$tmpdir" "$pkg"
  ok "Installed: $BIN_FRPS , $BIN_FRPC"
}

# ----------------------------------------------------------------------
# TOML writers
# ----------------------------------------------------------------------
write_frps_toml(){
  local cfg="$1" name="$2" bind="$3" token="$4" proto="$5" udp_sz="$6" tls_force="$7"
  local cert="$8" key="$9" dport="${10}" duser="${11}" dpwd="${12}"
  local qk="${13:-10}" qi="${14:-30}" qs="${15:-100000}" allow_csv="${16:-}"
  local pba="${17:-}" pool_max="${18:-0}"

  : >"$cfg"
  cat >>"$cfg" <<EOF
# frps-$name.toml (generated)
bindAddr = "0.0.0.0"
bindPort = $bind
transport.heartbeatTimeout = 90
EOF

  [[ -n "$pba" ]] && echo "proxyBindAddr = \"$pba\"" >>"$cfg"

  [[ "$proto" == "kcp" ]]  && echo "kcpBindPort = $bind" >>"$cfg"
  [[ "$proto" == "quic" ]] && {
    echo "quicBindPort = $bind" >>"$cfg"
    cat >>"$cfg" <<EOF
transport.quic.keepalivePeriod = $qk
transport.quic.maxIdleTimeout = $qi
transport.quic.maxIncomingStreams = $qs
EOF
  }

  echo "transport.tls.force = $tls_force" >>"$cfg"
  if [[ "$tls_force" == true && -n "$cert" && -n "$key" ]]; then
    echo "transport.tls.certFile = \"$cert\"" >>"$cfg"
    echo "transport.tls.keyFile  = \"$key\""  >>"$cfg"
  fi

  [[ "$proto" =~ ^(kcp|quic)$ ]] && echo "udpPacketSize = $udp_sz" >>"$cfg"

  cat >>"$cfg" <<EOF

auth.method = "token"
auth.token  = "$token"
EOF

  maybe_add "transport.maxPoolCount" "$pool_max" "0" "$cfg"

  if [[ -n "$allow_csv" ]]; then
    echo "allowPorts = [" >>"$cfg"
    local IFS=','; for p in $allow_csv; do
      p=${p//[[:space:]]/}
      if [[ $p == *"-"* ]]; then
        echo "  { start = ${p%-*}, end = ${p#*-} }," >>"$cfg"
      else
        echo "  { single = $p }," >>"$cfg"
      fi
    done
    echo "]" >>"$cfg"
  fi

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
  local cfg="$1" name="$2" saddr="$3" sport="$4" token="$5" proto="$6"
  local tls="$7" udp_sz="$8" sni="${9:-}" pool="${10:-0}"

  : >"$cfg"
  cat >>"$cfg" <<EOF
# frpc-$name.toml (generated)
serverAddr = "$saddr"
serverPort = $sport
loginFailExit = false
auth.method = "token"
auth.token  = "$token"

webServer.addr = "127.0.0.1"
webServer.port = 7400
webServer.user = "admin"
webServer.password = "admin"

transport.protocol = "$proto"
transport.heartbeatInterval = 10
transport.heartbeatTimeout  = 90
EOF

  maybe_add "transport.tls.enable" "$tls" "true" "$cfg"
  maybe_add "transport.poolCount"   "$pool" "0"   "$cfg"
  [[ -n "$sni" ]] && echo "transport.tls.serverName = \"$sni\"" >>"$cfg"
  [[ "$proto" =~ ^(kcp|quic)$ ]] && echo "udpPacketSize = $udp_sz" >>"$cfg"
  echo >>"$cfg"
}

append_proxy_block(){
  local cfg="$1" ptype="$2" pname="$3" lport="$4" rport="$5" cdom="${6:-}"
  {
    echo "[[proxies]]"
    echo "name = \"$pname\""
    echo "type = \"$ptype\""
    [[ "$ptype" =~ ^(tcp|udp)$ ]] && echo "localIP = \"127.0.0.1\""
    echo "localPort = $lport"
    if [[ "$ptype" =~ ^https?$ ]]; then
      [[ -n "$cdom" ]] && echo "customDomains = [\"$cdom\"]"
    else
      echo "remotePort = $rport"
    fi
    echo
  } >>"$cfg"
}

# ----------------------------------------------------------------------
# Systemd helper
# ----------------------------------------------------------------------
create_service(){
  local unit="$1" exec="$2"
  cat >"$SYSTEMD_DIR/$unit.service" <<EOF
[Unit]
Description=$unit
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
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

# ----------------------------------------------------------------------
# Interactive flows
# ----------------------------------------------------------------------
ensure_base(){ mkdir -p "$BASE_DIR"; }

action_add_server(){
  ensure_base
  echo "-- Add FRP Server --"
  local name; while :; do
    read -rp "Server name: " name || true
    name=$(echo "$name" | tr -cd '[:alnum:]_-')
    [[ -n $name ]] && break
  done
  local service="frp-server-$name" cfg="$BASE_DIR/frps-$name.toml"
  systemctl list-unit-files | grep -q "^$service\.service" && { err "Service exists"; pause; return; }

  local bind; while :; do read -rp "Bind port (default 7000): " bind || true; bind=${bind:-7000}; [[ $bind =~ ^[0-9]+$ ]] && break; done
  local token; while :; do read -rp "Auth token: " token || true; [[ -n $token ]] && break; done

  echo "Transport: 1) tcp 2) kcp 3) quic 4) websocket 5) wss"
  local choice proto; read -rp "Choose [1-5]: " choice || true
  case ${choice:-1} in 1) proto=tcp;;2) proto=kcp;;3) proto=quic;;4) proto=websocket;;5) proto=wss;; *) proto=tcp;; esac

  local udp_sz=1500 pba=""
  if [[ "$proto" =~ ^(kcp|quic)$ ]]; then
    read -rp "UDP packet size [1500]: " t || true; [[ -n $t ]] && udp_sz="$t"
    read -rp "UDP bind address [0.0.0.0]: " pba || true; pba=${pba:-0.0.0.0}
  fi

  local tls_force=false
  if [[ "$proto" =~ ^(tcp|websocket
