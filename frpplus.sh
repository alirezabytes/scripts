#!/usr/bin/env bash
# ============================================================================
#  FRP UNLIMITED MENU  (Enhanced Edition)
#  Based on the original script by <your-name> (2025 • GPL-3.0)
#  Add-ons inspired by ErfanXRay's FRPulse features
#  - Multiple server/client services
#  - TOML configuration support (recommended by new FRP versions)
#  - Certificate management via Certbot
#  - Cron-based restart scheduler
#  - Interactive port/proxy management (add/edit/delete)
#  - Dashboard info display
#  - Full uninstall/cleanup option
#  NOTE: All prompts, logs, and comments are in English as requested.
# ============================================================================

set -Eeuo pipefail
trap 'echo -e "\e[31m[ERROR]\e[0m Line $LINENO: Command exited with status $?"' ERR

# --------------------------- GLOBAL DEFAULTS ---------------------------------
FRP_VERSION="0.63.0"                  # default fallback version if GitHub query fails
INSTALL_DIR="/opt/frp"               # where FRP binaries live (frps, frpc)
CONF_BASE_DIR="/etc/frp"             # store config files here
SYSTEMD_DIR="/etc/systemd/system"    # systemd units
LOG_DIR="/var/log/frp"               # log destination for config files
TLS_CERT_BASE="/etc/letsencrypt/live"# default cert root
POOL_DEFAULT=0                        # unlimited
CTRL_PROTO_DEFAULT="tcp"             # tcp|quic|kcp|websocket|wss
TOKEN_DEFAULT="greatpr"              # default token
BIND_PORT_DEFAULT=8443                # default bind port
UDP_PACKET_SIZE_DEFAULT=1500          # recommended FRP advanced option

# Colors
GREEN='\e[32m'; RED='\e[31m'; YELLOW='\e[33m'; CYAN='\e[36m'; PURPLE='\e[35m'; NC='\e[0m'

# Marker for initial setup (package install etc.)
SETUP_MARKER="/var/lib/frp-menu/.setup_complete"

# --------------------------- UTILITY FUNCTIONS -------------------------------
arch(){
  case $(uname -m) in
    x86_64) echo amd64;;
    aarch64|arm64) echo arm64;;
    armv7l) echo arm;;
    *) echo "Unsupported arch"; exit 1;;
  esac
}

pkg(){ echo "frp_${FRP_VERSION}_linux_$(arch).tar.gz"; }

line(){ local c="${1:-${CYAN}}"; printf "${c}%*s${NC}\n" 80 | tr ' ' '='; }

prompt(){ local msg="$1" def="${2:-}" var="$3"; local input; read -rp "$(echo -e "${msg} [${YELLOW}${def}${NC}] : ")" input || true; if [[ -z "$input" ]]; then printf -v "$var" "%s" "$def"; else printf -v "$var" "%s" "$input"; fi; }

die(){ echo -e "${RED}ERROR:${NC} $*"; exit 1; }

validate_port(){ [[ $1 =~ ^[0-9]+$ ]] && (( $1>=1 && $1<=65535 )); }

validate_email(){ [[ $1 =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; }

validate_host(){
  local host="$1"
  local ipv4='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
  local ipv6='^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:([0-9a-fA-F]{1,4}){1,7}$'
  local domain='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
  [[ $host =~ $ipv4 || $host =~ $ipv6 || $host =~ $domain ]]
}

gen_pass(){ head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16; }

sysreload(){ systemctl daemon-reload; }

enter_to_continue(){ read -rsp $'Press Enter to continue...\n'; }

ensure_root(){ [[ $EUID -ne 0 ]] && exec sudo "$0" "$@"; }

ensure_dirs(){ mkdir -p "$INSTALL_DIR" "$CONF_BASE_DIR" "$LOG_DIR" "$(dirname "$SETUP_MARKER")"; }

# --------------------------- INSTALL / UPDATE FRP ----------------------------
install_frp(){
  # Try to fetch latest version tag from GitHub
  local latest_tag
  latest_tag=$(curl -fsSL https://api.github.com/repos/fatedier/frp/releases/latest 2>/dev/null | grep -m1 '"tag_name"' | cut -d '"' -f4 || true)
  if [[ -n "$latest_tag" ]]; then
    FRP_VERSION="${latest_tag#v}"
  fi
  echo -e "${CYAN}Downloading FRP ${FRP_VERSION}…${NC}"
  local tarball="/tmp/$(pkg)"
  curl -fsSL -o "$tarball" "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/$(pkg)" || die "Download failed"
  tar -xzf "$tarball" -C "$INSTALL_DIR" --strip-components=1
  rm -f "$tarball"
  chmod +x "$INSTALL_DIR/frps" "$INSTALL_DIR/frpc"
  echo -e "${GREEN}FRP binaries installed in $INSTALL_DIR${NC}"
}

# --------------------------- CERTIFICATE MANAGEMENT --------------------------
get_cert(){
  clear; line "$CYAN"; echo -e "${CYAN}Get New SSL Certificate (Certbot standalone)${NC}"; line "$CYAN"
  local domain email
  while true; do prompt "Domain" "example.com" domain; validate_host "$domain" && break || echo -e "${RED}Invalid domain${NC}"; done
  while true; do prompt "Email" "admin@example.com" email; validate_email "$email" && break || echo -e "${RED}Invalid email${NC}"; done
  echo -e "${YELLOW}Ensure port 80 is free before continuing...${NC}"
  certbot certonly --standalone -d "$domain" --non-interactive --agree-tos -m "$email" || die "Certbot failed"
  echo -e "${GREEN}Certificate installed under ${TLS_CERT_BASE}/${domain}${NC}"
  enter_to_continue
}

delete_cert(){
  clear; line "$CYAN"; echo -e "${CYAN}Delete SSL Certificate${NC}"; line "$CYAN"
  mapfile -t certs < <(find "$TLS_CERT_BASE" -maxdepth 1 -mindepth 1 -type d ! -name README -printf '%f\n' 2>/dev/null)
  if [[ ${#certs[@]} -eq 0 ]]; then echo -e "${YELLOW}No certificates found${NC}"; enter_to_continue; return; fi
  echo "Select cert to delete:"; select c in "${certs[@]}" "Back"; do
    [[ $REPLY -gt ${#certs[@]} ]] && break
    if [[ -n "$c" ]]; then certbot delete --cert-name "$c"; fi; break
  done
  enter_to_continue
}

# --------------------------- CRON MANAGEMENT ---------------------------------
schedule_restart(){
  local svc="$1"
  clear; line "$CYAN"; echo -e "${CYAN}Schedule restart for ${svc}${NC}"; line "$CYAN"
  echo "1) Every 30 minutes
2) Hourly
3) Every 2 hours
4) Every 4 hours
5) Every 6 hours
6) Every 12 hours
7) Daily at midnight"
  read -rp "Choice: " ch
  local cron_min="" cron_hr="" desc="" tag="FRPMenu"
  case $ch in
    1) cron_min="*/30"; cron_hr="*"; desc="every 30 minutes";;
    2) cron_min="0"; cron_hr="*/1"; desc="hourly";;
    3) cron_min="0"; cron_hr="*/2"; desc="every 2 hours";;
    4) cron_min="0"; cron_hr="*/4"; desc="every 4 hours";;
    5) cron_min="0"; cron_hr="*/6"; desc="every 6 hours";;
    6) cron_min="0"; cron_hr="*/12"; desc="every 12 hours";;
    7) cron_min="0"; cron_hr="0"; desc="daily";;
    *) echo "Invalid"; enter_to_continue; return;;
  esac
  local tmp=$(mktemp)
  sudo crontab -l 2>/dev/null > "$tmp" || true
  sed -i "/# ${tag} auto restart ${svc}$/d" "$tmp"
  echo "${cron_min} ${cron_hr} * * * /usr/bin/systemctl restart ${svc} >> /var/log/${tag}_cron.log 2>&1 # ${tag} auto restart ${svc}" >> "$tmp"
  sudo crontab "$tmp"
  rm -f "$tmp"
  echo -e "${GREEN}Cron job set (${desc}) for ${svc}${NC}"
  enter_to_continue
}

delete_restart(){
  clear; line "$CYAN"; echo -e "${CYAN}Delete Scheduled Restarts${NC}"; line "$CYAN"
  local tag="FRPMenu"
  local tmp=$(mktemp)
  sudo crontab -l 2>/dev/null > "$tmp" || true
  if ! grep -q "# ${tag} auto restart" "$tmp"; then
    echo -e "${YELLOW}No FRPMenu cron jobs found${NC}"; rm -f "$tmp"; enter_to_continue; return
  fi
  echo "Existing jobs:"; nl -ba "$tmp" | grep "${tag} auto restart" | cat
  read -rp "Delete ALL FRPMenu cron jobs? (y/N): " ans
  if [[ ${ans,,} =~ ^y ]]; then
    sed -i "/# ${tag} auto restart/d" "$tmp"
    sudo crontab "$tmp"
    echo -e "${GREEN}All FRPMenu cron jobs removed${NC}"
  else
    echo -e "${YELLOW}Cancelled${NC}"
  fi
  rm -f "$tmp"
  enter_to_continue
}

# --------------------------- LOG VIEWER --------------------------------------
view_logs(){
  local svc="$1"
  clear; line "$CYAN"; echo -e "${CYAN}Logs for ${svc}${NC}"; line "$CYAN"
  journalctl -u "$svc" -n 50 --no-pager || true
  enter_to_continue
}

# --------------------------- CONFIG WRITERS ----------------------------------
# We support TOML by default. You can force INI if needed.
# Helpers to build arrays of proxies.

declare -A PROTO_MAP LOCAL_MAP REMOTE_MAP CUSTOM_DOMAINS_MAP

collect_proxies(){
  local count i proto lp rp dom
  prompt "How many ports to forward" 1 count
  for ((i=1;i<=count;i++)); do
    read -rp "Proxy #$i protocol (tcp/udp/http/https) [tcp] : " proto || true
    proto=${proto,,}; [[ $proto =~ ^(udp|http|https)$ ]] || proto="tcp"
    while true; do prompt "Local port (#$i)" 443 lp; validate_port "$lp" && break || echo -e "${RED}Invalid port${NC}"; done
    while true; do prompt "Remote port on server (#$i)" "$lp" rp; validate_port "$rp" && break || echo -e "${RED}Invalid port${NC}"; end
    if [[ $proto == http || $proto == https ]]; then
      prompt "Custom domain for this proxy (optional)" "" dom
    else
      dom=""
    fi
    PROTO_MAP[$i]=$proto; LOCAL_MAP[$i]=$lp; REMOTE_MAP[$i]=$rp; CUSTOM_DOMAINS_MAP[$i]="$dom"
  done
}

write_frps_toml(){
  local file="$1" bind_port="$2" token="$3" proto="$4" tls_enable="$5" cert_file="$6" key_file="$7" udp_pkt="$8"
  local ports=""; for p in "${REMOTE_MAP[@]}"; do ports+="$p,"; done; ports="${ports%,}"
  cat >"$file" <<EOF
# Auto-generated by FRP Menu (Server)
[common]
bind_port = ${bind_port}
token = "${token}"
max_pool_count = 0
tcp_mux = false
allow_ports = "${ports}"
udpPacketSize = ${udp_pkt}
log_file = "${LOG_DIR}/frps-$(basename "${file%.*}").log"
log_level = "info"
log_max_days = 3
EOF
  if [[ $proto == quic ]]; then
cat >>"$file" <<EOF
[transport]
protocol = "quic"
quic_bind_port = ${bind_port}
EOF
  fi
  if [[ $tls_enable == yes && $proto == tcp ]]; then
cat >>"$file" <<EOF
tls_enable = true
cert_file = "${cert_file}"
key_file = "${key_file}"
EOF
  else
    echo "tls_enable = false" >> "$file"
  fi
}

write_frpc_toml(){
  local file="$1" server_addr="$2" server_port="$3" proto="$4" token="$5" tls_enable="$6" udp_pkt="$7"
  cat >"$file" <<EOF
# Auto-generated by FRP Menu (Client)
[common]
server_addr = "${server_addr}"
server_port = ${server_port}
protocol = "${proto}"
token = "${token}"
tcp_mux = false
login_fail_exit = false
heartbeat_interval = 15
tls_enable = ${tls_enable}
udpPacketSize = ${udp_pkt}
log_file = "${LOG_DIR}/frpc-$(basename "${file%.*}").log"
log_level = "info"
log_max_days = 3
EOF
  echo "" >> "$file"
  for i in "${!PROTO_MAP[@]}"; do
    local name="proxy${i}-${PROTO_MAP[$i]}-${REMOTE_MAP[$i]}"
    {
      echo "[${name}]"
      echo "type = \"${PROTO_MAP[$i]}\""
      if [[ ${PROTO_MAP[$i]} == tcp || ${PROTO_MAP[$i]} == udp ]]; then
        echo "local_ip = \"127.0.0.1\""
      fi
      echo "local_port = ${LOCAL_MAP[$i]}"
      echo "remote_port = ${REMOTE_MAP[$i]}"
      echo "pool_count = 0"
      if [[ ${PROTO_MAP[$i]} == http || ${PROTO_MAP[$i]} == https ]]; then
        if [[ -n ${CUSTOM_DOMAINS_MAP[$i]} ]]; then
          echo "custom_domains = [\"${CUSTOM_DOMAINS_MAP[$i]}\"]"
        fi
      fi
      echo
    } >> "$file"
  done
}

write_service(){
  local unit="$1" bin="$2" cfg="$3"
  cat >"${SYSTEMD_DIR}/${unit}.service" <<EOF
[Unit]
Description=$unit
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/sleep 5
ExecStart=${bin} -c ${cfg}
Restart=always
RestartSec=5
LimitNOFILE=200000
User=root

[Install]
WantedBy=multi-user.target
EOF
}

# --------------------------- SERVER WORKFLOW ---------------------------------
create_server(){
  clear; line "$CYAN"; echo -e "${GREEN}Configure FRP Server (Unlimited)${NC}"; line "$CYAN"
  local ctrl_proto tls_enable cert_file key_file bind_port token udp_pkt
  read -rp "Control protocol (tcp/quic) [tcp] : " ctrl_proto || true
  ctrl_proto=${ctrl_proto,,}; [[ $ctrl_proto == quic ]] || ctrl_proto="tcp"
  if [[ $ctrl_proto == tcp ]]; then
    read -rp "Enable TLS? [y/N] : " a || true
    [[ ${a,,} =~ ^y ]] && tls_enable="yes" || tls_enable="no"
  else
    tls_enable="no"
  fi
  if [[ $tls_enable == yes ]]; then
    local domain
    prompt "Domain for certificate (Let's Encrypt path)" "greatpr.pro" domain
    cert_file="${TLS_CERT_BASE}/${domain}/fullchain.pem"
    key_file="${TLS_CERT_BASE}/${domain}/privkey.pem"
    [[ -r $cert_file && -r $key_file ]] || { echo -e "${RED}Cert files not found${NC}"; tls_enable="no"; }
  fi
  prompt "Bind port (TCP or UDP for QUIC)" "$BIND_PORT_DEFAULT" bind_port
  while ! validate_port "$bind_port"; do echo -e "${RED}Invalid port${NC}"; prompt "Bind port" "$BIND_PORT_DEFAULT" bind_port; done
  prompt "Auth token" "$TOKEN_DEFAULT" token
  prompt "udpPacketSize" "$UDP_PACKET_SIZE_DEFAULT" udp_pkt

  collect_proxies
  mkdir -p "$CONF_BASE_DIR/servers" "$LOG_DIR"
  local name; prompt "Server name identifier" "main" name
  local cfg_file="$CONF_BASE_DIR/servers/frps-${name}.toml"
  write_frps_toml "$cfg_file" "$bind_port" "$token" "$ctrl_proto" "$tls_enable" "$cert_file" "$key_file" "$udp_pkt"
  write_service "frp-server-${name}" "$INSTALL_DIR/frps" "$cfg_file"
  sysreload; systemctl enable --now "frp-server-${name}"
  echo -e "${GREEN}frps running as frp-server-${name} (protocol: ${ctrl_proto})${NC}"
  [[ $ctrl_proto == quic ]] && echo -e "${YELLOW}Remember to open UDP ${bind_port} on firewall.${NC}"
  enter_to_continue
}

# --------------------------- CLIENT WORKFLOW ---------------------------------
create_client(){
  clear; line "$CYAN"; echo -e "${GREEN}Configure FRP Client (Unlimited)${NC}"; line "$CYAN"
  local ctrl_proto tls_enable server_addr server_port token udp_pkt
  read -rp "Control protocol (tcp/quic/kcp/websocket/wss) [tcp] : " ctrl_proto || true
  ctrl_proto=${ctrl_proto,,}; [[ $ctrl_proto =~ ^(quic|kcp|websocket|wss)$ ]] || ctrl_proto="tcp"
  read -rp "Enable TLS at client? (Y/n) [Y] : " a || true
  [[ ${a,,} =~ ^n ]] && tls_enable="false" || tls_enable="true"
  while true; do prompt "Server address (IP/domain)" "example.com" server_addr; validate_host "$server_addr" && break || echo -e "${RED}Invalid host${NC}"; done
  prompt "Server port" "$BIND_PORT_DEFAULT" server_port
  while ! validate_port "$server_port"; do echo -e "${RED}Invalid port${NC}"; prompt "Server port" "$BIND_PORT_DEFAULT" server_port; done
  prompt "Auth token" "$TOKEN_DEFAULT" token
  prompt "udpPacketSize" "$UDP_PACKET_SIZE_DEFAULT" udp_pkt

  collect_proxies
  mkdir -p "$CONF_BASE_DIR/clients" "$LOG_DIR"
  local name; prompt "Client name identifier" "client1" name
  local cfg_file="$CONF_BASE_DIR/clients/frpc-${name}.toml"
  write_frpc_toml "$cfg_file" "$server_addr" "$server_port" "$ctrl_proto" "$token" "$tls_enable" "$udp_pkt"
  write_service "frp-client-${name}" "$INSTALL_DIR/frpc" "$cfg_file"
  sysreload; systemctl enable --now "frp-client-${name}"
  echo -e "${GREEN}frpc running as frp-client-${name} (protocol: ${ctrl_proto})${NC}"
  enter_to_continue
}

# --------------------------- PROXY MANAGEMENT (CLIENT) -----------------------
# Utilities to read/write TOML blocks
read_frpc_config(){
  local file="$1"; local -n common_ref=$2; local -n blocks_ref=$3
  common_ref=""; blocks_ref=()
  local in_common=false proxy_block=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ $line =~ ^\[common\] ]]; then in_common=true; continue; fi
    if [[ $line =~ ^\[.*\] ]]; then
      if [[ -n $proxy_block ]]; then blocks_ref+=("$proxy_block"); fi
      proxy_block="$line"; in_common=false; continue
    fi
    if $in_common; then [[ -n $line ]] && common_ref+="$line"$'\n'
    else [[ -n $line ]] && proxy_block+=$'\n'"$line"
    fi
  done <"$file"
  [[ -n $proxy_block ]] && blocks_ref+=("$proxy_block")
}

write_frpc_config(){
  local file="$1" common="$2"; shift 2
  local -a blocks=("$@")
  {
    echo "# Rewritten by FRP Menu"
    echo "[common]"
    printf '%s\n' "$common"
    for b in "${blocks[@]}"; do
      echo
      printf '%s\n' "$b"
    done
  } >"$file"
}

select_client_cfg(){
  mapfile -t cfgs < <(find "$CONF_BASE_DIR/clients" -maxdepth 1 -type f -name 'frpc-*.toml' 2>/dev/null)
  [[ ${#cfgs[@]} -eq 0 ]] && { echo -e "${YELLOW}No client configs found${NC}"; enter_to_continue; return 1; }
  echo "Select client config:"; select f in "${cfgs[@]}" "Back"; do
    [[ $REPLY -gt ${#cfgs[@]} ]] && return 1
    [[ -n "$f" ]] && { echo "$f"; return 0; }
  done
  return 1
}

view_client_ports(){
  local cfg="$1" common blocks
  read_frpc_config "$cfg" common blocks
  clear; line "$CYAN"; echo -e "${CYAN}Tunneled Ports in $(basename "$cfg")${NC}"; line "$CYAN"
  if [[ ${#blocks[@]} -eq 0 ]]; then echo "No proxies"; enter_to_continue; return; fi
  local i=1
  for proxy in "${blocks[@]}"; do
    local name type lport rport domains
    name=$(echo "$proxy" | grep -E '^name' | awk -F'=' '{print $2}' | tr -d ' "')
    type=$(echo "$proxy" | grep -E '^type' | awk -F'=' '{print $2}' | tr -d ' "')
    lport=$(echo "$proxy" | grep -E '^local_port' | awk -F'=' '{print $2}' | tr -d ' ')
    rport=$(echo "$proxy" | grep -E '^remote_port' | awk -F'=' '{print $2}' | tr -d ' ')
    domains=$(echo "$proxy" | grep -E '^custom_domains' | sed -E 's/custom_domains = \[?"?([^]]*)"?\]?/\1/' | tr -d ' "')
    echo -e "${PURPLE}${i})${NC} Name: ${name:-N/A} | Type: ${type:-N/A} | Local: ${lport:-N/A} | Remote: ${rport:-N/A} ${domains:+| Domains: $domains}"
    ((i++))
  done
  enter_to_continue
}

add_client_port(){
  local cfg="$1" common blocks
  read_frpc_config "$cfg" common blocks
  local proto lp rp domains
  read -rp "Proxy type (tcp/udp/http/https) [tcp]: " proto || true
  proto=${proto,,}; [[ $proto =~ ^(udp|http|https)$ ]] || proto="tcp"
  while true; do prompt "Local port" 8080 lp; validate_port "$lp" && break || echo -e "${RED}Invalid port${NC}"; done
  while true; do prompt "Remote port" 80 rp; validate_port "$rp" && break || echo -e "${RED}Invalid port${NC}"; done
  if [[ $proto == http || $proto == https ]]; then prompt "Custom domain (optional)" "" domains; fi
  local idx=$(( ${#blocks[@]} + 1 ))
  local name="${proto}_$(basename "${cfg%.*}")_${idx}"
  local block="[${name}]\nname = \"${name}\"\ntype = \"${proto}\"\n"
  [[ $proto == tcp || $proto == udp ]] && block+="local_ip = \"127.0.0.1\"\n"
  block+="local_port = ${lp}\nremote_port = ${rp}\n"
  [[ -n $domains ]] && block+="custom_domains = [\"${domains}\"]\n"
  blocks+=("$block")
  write_frpc_config "$cfg" "$common" "${blocks[@]}"
  systemctl restart "frp-client-$(basename "${cfg%.toml}" | sed 's/frpc-//')" || true
  echo -e "${GREEN}Proxy added${NC}"; enter_to_continue
}

edit_client_port(){
  local cfg="$1" common blocks
  read_frpc_config "$cfg" common blocks
  [[ ${#blocks[@]} -eq 0 ]] && { echo "No proxies"; enter_to_continue; return; }
  view_client_ports "$cfg"
  read -rp "Select number to edit: " num
  (( num>=1 && num<=${#blocks[@]} )) || { echo "Invalid"; enter_to_continue; return; }
  local idx=$((num-1))
  local proxy="${blocks[$idx]}"
  local name type lport rport domains
  name=$(echo "$proxy" | grep -E '^name' | awk -F'=' '{print $2}' | tr -d ' "')
  type=$(echo "$proxy" | grep -E '^type' | awk -F'=' '{print $2}' | tr -d ' "')
  lport=$(echo "$proxy" | grep -E '^local_port' | awk -F'=' '{print $2}' | tr -d ' ')
  rport=$(echo "$proxy" | grep -E '^remote_port' | awk -F'=' '{print $2}' | tr -d ' ')
  domains=$(echo "$proxy" | grep -E '^custom_domains' | sed -E 's/custom_domains = \[?"?([^]]*)"?\]?/\1/' | tr -d ' "')

  local new_proto new_lp new_rp new_dom
  read -rp "New type (tcp/udp/http/https) [${type}] : " new_proto || true
  new_proto=${new_proto,,}; [[ -z $new_proto ]] && new_proto="$type"; [[ $new_proto =~ ^(tcp|udp|http|https)$ ]] || new_proto="$type"
  while true; do prompt "New local port" "$lport" new_lp; validate_port "$new_lp" && break || echo -e "${RED}Invalid port${NC}"; done
  while true; do prompt "New remote port" "$rport" new_rp; validate_port "$new_rp" && break || echo -e "${RED}Invalid port${NC}"; done
  if [[ $new_proto == http || $new_proto == https ]]; then
    prompt "New custom domain (empty to keep, 'none' to remove)" "$domains" new_dom
    [[ $new_dom == none ]] && new_dom=""
  else
    new_dom=""
  fi
  local block="[${name}]\nname = \"${name}\"\ntype = \"${new_proto}\"\n"
  [[ $new_proto == tcp || $new_proto == udp ]] && block+="local_ip = \"127.0.0.1\"\n"
  block+="local_port = ${new_lp}\nremote_port = ${new_rp}\n"
  [[ -n $new_dom ]] && block+="custom_domains = [\"${new_dom}\"]\n"
  blocks[$idx]="$block"
  write_frpc_config "$cfg" "$common" "${blocks[@]}"
  systemctl restart "frp-client-$(basename "${cfg%.toml}" | sed 's/frpc-//')" || true
  echo -e "${GREEN}Proxy updated${NC}"; enter_to_continue
}

delete_client_port(){
  local cfg="$1" common blocks
  read_frpc_config "$cfg" common blocks
  [[ ${#blocks[@]} -eq 0 ]] && { echo "No proxies"; enter_to_continue; return; }
  view_client_ports "$cfg"
  read -rp "Select number to delete: " num
  (( num>=1 && num<=${#blocks[@]} )) || { echo "Invalid"; enter_to_continue; return; }
  local idx=$((num-1))
  unset 'blocks[idx]'
  blocks=("${blocks[@]}")
  write_frpc_config "$cfg" "$common" "${blocks[@]}"
  systemctl restart "frp-client-$(basename "${cfg%.toml}" | sed 's/frpc-//')" || true
  echo -e "${GREEN}Proxy deleted${NC}"; enter_to_continue
}

manage_client_ports(){
  local cfg
  cfg=$(select_client_cfg) || return
  while true; do
    clear; line "$CYAN"; echo -e "${CYAN}Manage Client Ports: $(basename "$cfg")${NC}"; line "$CYAN"
    echo "1) View tunneled ports"
    echo "2) Add new tunneled port"
    echo "3) Edit tunneled port"
    echo "4) Delete tunneled port"
    echo "0) Back"
    read -rp "Choice: " c
    case $c in
      1) view_client_ports "$cfg";;
      2) add_client_port "$cfg";;
      3) edit_client_port "$cfg";;
      4) delete_client_port "$cfg";;
      0) break;;
      *) echo "Invalid"; sleep 1;;
    esac
  done
}

# --------------------------- DASHBOARD INFO (SERVER) -------------------------
show_dashboard_info(){
  clear; line "$CYAN"; echo -e "${CYAN}FRP Dashboard Info${NC}"; line "$CYAN"
  mapfile -t cfgs < <(find "$CONF_BASE_DIR/servers" -maxdepth 1 -type f -name 'frps-*.toml' 2>/dev/null)
  if [[ ${#cfgs[@]} -eq 0 ]]; then echo -e "${YELLOW}No server configs found${NC}"; enter_to_continue; return; fi
  echo "Select server config:"; select f in "${cfgs[@]}" "Back"; do
    [[ $REPLY -gt ${#cfgs[@]} ]] && return
    if [[ -n "$f" ]]; then cfg="$f"; break; fi
  done
  local port user pwd
  port=$(grep -E '^dashboard_port' "$cfg" | awk '{print $3}' | tr -d '\r')
  user=$(grep -E '^dashboard_user' "$cfg" | awk '{print $3}' | tr -d '"\r')
  pwd=$(grep -E '^dashboard_pwd' "$cfg" | awk '{print $3}' | tr -d '"\r')
  if [[ -n $port ]]; then
    echo -e "Port: ${port}\nUser: ${user}\nPassword: ${pwd}"
  else
    echo -e "${YELLOW}Dashboard is not enabled in this config${NC}"
  fi
  enter_to_continue
}

# --------------------------- REMOVE SERVICES ---------------------------------
remove_service(){
  local prefix="$1" # frp-server- or frp-client-
  clear; line "$CYAN"; echo -e "${CYAN}Remove ${prefix}* service${NC}"; line "$CYAN"
  mapfile -t svcs < <(systemctl list-unit-files --full --no-pager | grep "^${prefix}.*.service" | awk '{print $1}')
  if [[ ${#svcs[@]} -eq 0 ]]; then echo -e "${YELLOW}No ${prefix} services found${NC}"; enter_to_continue; return; fi
  echo "Select service to delete:"; select s in "${svcs[@]}" "Back"; do
    [[ $REPLY -gt ${#svcs[@]} ]] && return
    if [[ -n "$s" ]]; then svc="$s"; break; fi
  done
  local cfg_file
  if [[ $prefix == "frp-server-" ]]; then
    cfg_file="$CONF_BASE_DIR/servers/frps-$(echo "$svc" | sed 's/frp-server-//;s/.service//').toml"
  else
    cfg_file="$CONF_BASE_DIR/clients/frpc-$(echo "$svc" | sed 's/frp-client-//;s/.service//').toml"
  fi
  systemctl disable --now "$svc" || true
  rm -f "$SYSTEMD_DIR/$svc"
  sysreload
  [[ -f $cfg_file ]] && rm -f "$cfg_file"
  # remove cron job
  (sudo crontab -l 2>/dev/null | grep -v "# FRPMenu auto restart ${svc}$") | sudo crontab -
  echo -e "${GREEN}${svc} removed${NC}"
  enter_to_continue
}

# --------------------------- UNINSTALL / CLEANUP -----------------------------
uninstall_all(){
  clear; line "$RED"; echo -e "${RED}Uninstall FRP and cleanup all services/configs? (y/N)${NC}"; line "$RED"
  read -rp "Confirm: " ans
  [[ ${ans,,} =~ ^y$ ]] || { echo "Cancelled"; enter_to_continue; return; }
  echo "Stopping and removing services..."
  mapfile -t all < <(systemctl list-unit-files --full --no-pager | grep '^frp-' | awk '{print $1}')
  for s in "${all[@]}"; do
    systemctl disable --now "$s" 2>/dev/null || true
    rm -f "$SYSTEMD_DIR/$s" 2>/dev/null || true
  done
  sysreload
  rm -rf "$CONF_BASE_DIR" "$LOG_DIR"
  rm -rf "$INSTALL_DIR"
  (sudo crontab -l 2>/dev/null | grep -v "# FRPMenu auto restart") | sudo crontab -
  rm -f "$SETUP_MARKER"
  echo -e "${GREEN}Cleanup complete${NC}"
  enter_to_continue
}

# --------------------------- INITIAL SETUP -----------------------------------
initial_setup(){
  [[ -f $SETUP_MARKER ]] && return
  echo -e "${CYAN}Initial setup: installing dependencies...${NC}"
  apt update
  apt install -y curl tar certbot cron figlet || true
  touch "$SETUP_MARKER"
}

# --------------------------- MENUS ------------------------------------------
main_menu(){
  while true; do
    clear
    echo -e "${CYAN}"; figlet -f slant "FRP Menu" 2>/dev/null || echo "FRP MENU"; echo -e "${NC}"
    line "$CYAN"
    echo -e "FRP Version (detected/download): ${YELLOW}${FRP_VERSION}${NC}"
    echo -e "Install dir: ${INSTALL_DIR} | Config dir: ${CONF_BASE_DIR}"
    line "$CYAN"
    echo "1) Install/Update FRP binaries"
    echo "2) Server management"
    echo "3) Client management"
    echo "4) Certificate management"
    echo "5) Cron (restart) management"
    echo "6) View logs"
    echo "7) Uninstall & cleanup"
    echo "0) Exit"
    read -rp "Choice: " c
    case $c in
      1) install_frp;;
      2) server_menu;;
      3) client_menu;;
      4) cert_menu;;
      5) cron_menu;;
      6) log_menu;;
      7) uninstall_all;;
      0) exit 0;;
      *) echo "Invalid"; sleep 1;;
    esac
  done
}

server_menu(){
  while true; do
    clear; line "$CYAN"; echo -e "${CYAN}Server Management${NC}"; line "$CYAN"
    echo "1) Create & start new server"
    echo "2) Show dashboard info"
    echo "3) Remove a server"
    echo "0) Back"
    read -rp "Choice: " c
    case $c in
      1) create_server;;
      2) show_dashboard_info;;
      3) remove_service "frp-server-";;
      0) break;;
      *) echo "Invalid"; sleep 1;;
    esac
  done
}

client_menu(){
  while true; do
    clear; line "$CYAN"; echo -e "${CYAN}Client Management${NC}"; line "$CYAN"
    echo "1) Create & start new client"
    echo "2) Manage client ports"
    echo "3) Remove a client"
    echo "0) Back"
    read -rp "Choice: " c
    case $c in
      1) create_client;;
      2) manage_client_ports;;
      3) remove_service "frp-client-";;
      0) break;;
      *) echo "Invalid"; sleep 1;;
    esac
  done
}

cert_menu(){
  while true; do
    clear; line "$CYAN"; echo -e "${CYAN}Certificate Management${NC}"; line "$CYAN"
    echo "1) Get new certificate"
    echo "2) Delete certificate"
    echo "0) Back"
    read -rp "Choice: " c
    case $c in
      1) get_cert;;
      2) delete_cert;;
      0) break;;
      *) echo "Invalid"; sleep 1;;
    esac
  done
}

cron_menu(){
  while true; do
    clear; line "$CYAN"; echo -e "${CYAN}Cron (Restart) Management${NC}"; line "$CYAN"
    echo "1) Schedule restart for a service"
    echo "2) Delete all scheduled restarts (FRPMenu tag)"
    echo "0) Back"
    read -rp "Choice: " c
    case $c in
      1)
        read -rp "Service name (e.g., frp-server-main): " svc
        [[ -f "$SYSTEMD_DIR/${svc}.service" ]] || { echo -e "${RED}Service not found${NC}"; enter_to_continue; continue; }
        schedule_restart "$svc";;
      2) delete_restart;;
      0) break;;
      *) echo "Invalid"; sleep 1;;
    esac
  done
}

log_menu(){
  clear; line "$CYAN"; echo -e "${CYAN}View Logs${NC}"; line "$CYAN"
  read -rp "Enter systemd service name (frp-server-*/frp-client-*) : " svc
  view_logs "$svc"
}

# --------------------------- STARTUP -----------------------------------------
ensure_root "$@"
ensure_dirs
initial_setup
main_menu
