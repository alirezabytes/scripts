#!/usr/bin/env bash
# ==============================================================
#  FRP UNLIMITED MENU  -  greatpr.pro  (TCP or QUIC control)
#  Author : <your-name> • 2025 • GPL‑3.0
# ==============================================================

[[ $EUID -ne 0 ]] && exec sudo "$0" "$@"

set -Eeuo pipefail
trap 'echo -e "\e[31m[ERROR]\e[0m Line $LINENO: Command exited with status $?"' ERR

FRP_VERSION="0.63.0"
INSTALL_DIR="/opt/frp"
CONF_DIR="/etc/frp"
SYSTEMD_DIR="/etc/systemd/system"

DOMAIN="greatpr.pro"
CERT_DIR=""; CERT_FILE=""; KEY_FILE=""
ENABLE_TLS="no"
CTRL_PROTO="tcp"           # tcp|quic
POOL_DEFAULT=0             # unlimited

GREEN='\e[32m'; RED='\e[31m'; YELLOW='\e[33m'; CYAN='\e[36m'; NC='\e[0m'

die(){ echo -e "${RED}ERROR: $*${NC}"; exit 1; }

arch(){ case $(uname -m) in x86_64) echo amd64;; aarch64|arm64) echo arm64;; armv7l) echo arm;; *) die "Unsupported arch";; esac; }

pkg(){ echo "frp_${FRP_VERSION}_linux_$(arch).tar.gz"; }

line(){ printf "${CYAN}%*s${NC}\n" 70 | tr ' ' '='; }

ask(){ local v=$1 p=$2 d=$3 i; read -rp "$(echo -e "${p} [${YELLOW}${d}${NC}] : ")" i || true
      [[ -z $i ]] && printf -v "$v" "%s" "$d" || printf -v "$v" "%s" "$i"; }

ask_tls(){ [[ $CTRL_PROTO == "quic" ]] && { ENABLE_TLS="no"; return; }
           local a; read -rp "$(echo -e "Enable TLS? [y/N] : ")" a || true
           [[ ${a,,} =~ ^y ]] && ENABLE_TLS="yes" || ENABLE_TLS="no"; }

check_tls_files(){ [[ -r $CERT_FILE && -r $KEY_FILE ]]; }

sysreload(){ systemctl daemon-reload; }

install_frp(){
  [[ -x $INSTALL_DIR/frps && -x $INSTALL_DIR/frpc ]] && return
  echo -e "${CYAN}Downloading FRP $FRP_VERSION…${NC}"
  curl -fsSL -o "/tmp/$(pkg)" "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/$(pkg)" || die "Download failed"
  mkdir -p "$INSTALL_DIR" "$CONF_DIR"
  tar -xzf "/tmp/$(pkg)" -C "$INSTALL_DIR" --strip-components=1
}

log_show(){ journalctl -u "$1" -n 50 --no-pager; read -rsp $'Press Enter…\n'; }

remove_unit(){ systemctl disable --now "$1" 2>/dev/null || true
               rm -f "${SYSTEMD_DIR}/$1.service" "${CONF_DIR}/$1.ini"
               sysreload; echo -e "${YELLOW}$1 removed${NC}"; }

# ---------- interactive ----------

collect_domain(){
  ask DOMAIN "Domain for certificate path (wildcard)" "$DOMAIN"
  CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
  CERT_FILE="${CERT_DIR}/fullchain.pem"
  KEY_FILE="${CERT_DIR}/privkey.pem"
}

collect_ctrl_proto(){
  local p; read -rp "Control protocol (tcp/quic) [tcp] : " p || true
  p=${p,,}; [[ $p == quic ]] && CTRL_PROTO="quic" || CTRL_PROTO="tcp"
}

collect_proxies(){  # arrays PROTO LOCAL REMOTE
  local n; ask n "How many ports to forward" 1
  declare -gA PROTO LOCAL REMOTE
  for ((i=1;i<=n;i++)); do
    local proto lp rp
    read -rp "Tunnel #$i protocol (tcp/udp) [tcp] : " proto || true
    proto=${proto,,}; [[ $proto == udp ]] || proto="tcp"
    ask lp "Local port to expose (#$i)" 443
    ask rp "Remote port on VPS Iran (#$i)" "$lp"
    PROTO[$i]=$proto; LOCAL[$i]=$lp; REMOTE[$i]=$rp
  done
}

# ---------- config writers ----------

write_frps_conf(){
  mkdir -p "$CONF_DIR"
  local ports=""; for p in "${REMOTE[@]}"; do ports+="$p,"; done; ports="${ports%,}"

cat >"${CONF_DIR}/frps.ini" <<EOF
[common]
bind_port      = ${BIND_PORT}
token          = ${TOKEN}
max_pool_count = 0
allow_ports    = ${ports}
EOF

if [[ $CTRL_PROTO == "quic" ]]; then
cat >>"${CONF_DIR}/frps.ini" <<EOF

[transport]
protocol       = quic
quic_bind_port = ${BIND_PORT}
EOF
elif [[ $ENABLE_TLS == "yes" ]]; then
cat >>"${CONF_DIR}/frps.ini" <<EOF
tls_enable    = true
tls_cert_file = ${CERT_FILE}
tls_key_file  = ${KEY_FILE}
EOF
else
  echo "tls_enable = false" >> "${CONF_DIR}/frps.ini"
fi
}

write_frpc_conf(){
  mkdir -p "$CONF_DIR"
cat >"${CONF_DIR}/frpc.ini" <<EOF
[common]
server_addr        = ${SERVER_IP}
server_port        = ${SERVER_PORT}
protocol           = ${CTRL_PROTO}
token              = ${TOKEN}
login_fail_exit    = false
heartbeat_interval = 15
EOF
if [[ $CTRL_PROTO == "tcp" ]]; then
  [[ $ENABLE_TLS == "yes" ]] && echo "tls_enable = true" >> "${CONF_DIR}/frpc.ini" \
                              || echo "tls_enable = false" >> "${CONF_DIR}/frpc.ini"
fi
echo >> "${CONF_DIR}/frpc.ini"

for i in "${!PROTO[@]}"; do
  local name="proxy${i}-${PROTO[$i]}-${REMOTE[$i]}"
cat >>"${CONF_DIR}/frpc.ini" <<EOF
[${name}]
type        = ${PROTO[$i]}
local_ip    = 127.0.0.1
local_port  = ${LOCAL[$i]}
remote_port = ${REMOTE[$i]}
pool_count  = 0

EOF
done
}

write_service(){
  local unit=$1 bin=$2 cfg=$3
cat >"${SYSTEMD_DIR}/${unit}.service" <<EOF
[Unit]
Description=${unit}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/sleep 10
ExecStart=${bin} -c ${cfg}
Restart=always
RestartSec=5
LimitNOFILE=200000

[Install]
WantedBy=multi-user.target
EOF
}

# ---------- workflows ----------

create_frps(){
  clear; line; echo -e "${GREEN}Configure frps (Iran) – Unlimited${NC}"
  collect_ctrl_proto
  ask_tls
  [[ $ENABLE_TLS == "yes" && $CTRL_PROTO == "tcp" ]] && collect_domain
  ask BIND_PORT "Control port (TCP or UDP for QUIC)" 8443
  ask TOKEN     "Auth token"                           greatpr
  collect_proxies

  if [[ $ENABLE_TLS == "yes" && ! check_tls_files ]]; then
    echo -e "${RED}TLS files not found in ${CERT_DIR}.${NC}"
    echo "1) Copy certs & exit   2) Continue WITHOUT TLS   0) Cancel"
    read -rp "Choice: " x
    case $x in 1) die "Copy the certs then rerun." ;; 2) ENABLE_TLS="no" ;; *) return ;; esac
  fi

  write_frps_conf
  write_service frps "${INSTALL_DIR}/frps" "${CONF_DIR}/frps.ini"
  sysreload && systemctl enable --now frps
  echo -e "${GREEN}frps running — protocol: ${CTRL_PROTO}, unlimited pools.${NC}"
  [[ $CTRL_PROTO == quic ]] && \
    echo -e "${YELLOW}Remember to open UDP ${BIND_PORT} on the Iran VPS firewall.${NC}"
  read -rsp $'Press Enter…\n'
}

create_frpc(){
  clear; line; echo -e "${GREEN}Configure frpc (Outside) – Unlimited${NC}"
  collect_ctrl_proto
  ask_tls
  ask SERVER_IP   "Iran VPS public IP/hostname" iran-vps-ip
  ask SERVER_PORT "Control channel port (${CTRL_PROTO^^})" 8443
  ask TOKEN       "Auth token"                  greatpr
  collect_proxies

  write_frpc_conf
  write_service frpc "${INSTALL_DIR}/frpc" "${CONF_DIR}/frpc.ini"
  sysreload && systemctl enable --now frpc
  echo -e "${GREEN}frpc running — protocol: ${CTRL_PROTO}, unlimited pools.${NC}"
  read -rsp $'Press Enter…\n'
}

menu(){
  install_frp
  while true; do
    clear; line; echo -e "${CYAN}FRP unlimited menu (v${FRP_VERSION})${NC}"; line
    cat <<EOF
1) (Re)install FRP binaries (update)
2) Setup & start frps  (Iran)
3) Setup & start frpc  (Outside)
4) Show frps log
5) Show frpc log
6) Remove frps
7) Remove frpc
0) Exit
EOF
    read -rp "Choice: " c
    case $c in
      1) rm -rf "$INSTALL_DIR"; install_frp;
         echo -e "${GREEN}Latest binaries installed.${NC}"; read -rsp $'Press Enter…\n';;
      2) create_frps ;;
      3) create_frpc ;;
      4) log_show frps ;;
      5) log_show frpc ;;
      6) remove_unit frps ;;
      7) remove_unit frpc ;;
      0) exit 0 ;;
      *) echo "Invalid choice"; sleep 1 ;;
    esac
  done
}

menu
