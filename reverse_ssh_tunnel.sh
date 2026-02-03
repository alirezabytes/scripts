#!/usr/bin/env bash
# ============================================================================
# Reverse SSH Tunnel Unlimited Menu
# English-only edition – updated February 2026
# * Supports multiple tunnels (services) with multiple port forwards
# * Manages SSH keys per-tunnel or global, with check and generate like original
# * Validates inputs, handles systemd services
# * Adds heartbeat/check-alive mechanism (optional ping/reconnect)
# * Allows custom SSH options (e.g., compression, multiplexing)
# * Uninstall removes all services, configs, binaries if applicable
# * Simplified port forward input: ask for remote and local ports separately
# * Adapted key handling, copy, and GatewayPorts like original script
# * Restored full .service content for better stability and security
# ============================================================================
set -Euo pipefail
: "${DEBUG:=0}"
trap 's=$?; if [[ "$DEBUG" == 1 ]]; then echo "[ERROR] line $LINENO: $BASH_COMMAND -> exit $s"; fi' ERR
SCRIPT_VERSION="1.3.0-full-service"
BASE_DIR="$(pwd)/reverse_ssh" # per-user config root
GLOBAL_KEY_FILE="/root/.ssh/id_rsa"
SYSTEMD_DIR="/etc/systemd/system"
log(){ echo "$*"; }
ok(){ echo "[OK] $*"; }
err(){ echo "[ERR] $*" >&2; }
pause(){ read -rp "Press Enter to continue..." _ || true; }
printc() {
    local text="$1"
    local color="$2"
    echo -e "\e[${color}m${text}\e[0m"
}
# ─────────────────────────────────────────── helper ──────────────────────────
validate_port(){ local p=${1:-}; [[ $p =~ ^[0-9]+$ ]] && (( p>=1 && p<=65535 )); }
validate_host(){
  local h=${1:-}
  local ipv4='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
  local ipv6='^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$'
  local domain='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
  [[ $h =~ $ipv4 || $h =~ $ipv6 || $h =~ $domain ]]
}
ensure_base(){ mkdir -p "$BASE_DIR"; }
# ────────────────────────────── SSH key helpers ─────────────────────────────
generate_key(){ local kf="$1"; ssh-keygen -t rsa -f "$kf" -q -N ""; printc "New SSH Key generated!" "32"; }
copy_key_to_server(){
  local kf="$1" sip="$2" sport="$3"
  printc "Enter tunnel vps password for installing ssh key" "32"
  ssh-copy-id -i "$kf.pub" -p "$sport" root@"$sip"
  ok "Key copied to $sip:$sport"
}
enable_gateway_ports(){
  local sip="$1" sport="$2"
  ssh -p "$sport" root@"$sip" "sed -i -E '/^\s*#?\s*GatewayPorts/ { s/^#//; s/\bno\b/yes/ }' /etc/ssh/sshd_config; service ssh restart;"
  ok "Enabled GatewayPorts on server"
}
check_and_generate_key(){
  local kf="$1"
  if [[ -e "$kf" ]]; then
    printc "SSH Key created already" "32"
  else
    generate_key "$kf"
  fi
}
# ────────────────────────────── Config writers ──────────────────────────────
write_tunnel_script(){
  local script="$1" sip="$2" sport="$3" key_file="$4" compression="$5" multiplexing="$6" heartbeat="$7"
  local forwards=("${@:8}")
  : >"$script"
  cat >>"$script" <<EOF
#!/bin/bash
# Generated reverse SSH tunnel script
TUNNEL_IP="$sip"
TUNNEL_SSH_PORT="$sport"
KEY_FILE="$key_file"
COMPRESSION="$compression"
MULTIPLEXING="$multiplexing"
HEARTBEAT="$heartbeat"
FORWARDS=()
EOF
  for fwd in "${forwards[@]}"; do
    echo "FORWARDS+=(\"$fwd\")" >>"$script"
  done
  cat >>"$script" <<'EOF'
SSH_OPTS="-N -o ServerAliveInterval=60 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=no"
[[ "$COMPRESSION" == "true" ]] && SSH_OPTS+=" -C"
if [[ "$MULTIPLEXING" == "true" ]]; then
  SSH_OPTS+=" -o ControlMaster=auto -o ControlPath=/tmp/ssh_mux_%h_%p_%r -o ControlPersist=2m"
fi
FWD_OPTS=""
for fwd in "${FORWARDS[@]}"; do
  FWD_OPTS+=" -R $fwd"
done
while true; do
  /usr/bin/ssh $SSH_OPTS $FWD_OPTS -i "$KEY_FILE" root@"$TUNNEL_IP" -p "$TUNNEL_SSH_PORT"
  if [[ "$HEARTBEAT" == "true" ]]; then
    sleep 10
  else
    exit 1
  fi
done
EOF
  chmod +x "$script"
}
# ────────────────────────── systemd helpers ─────────────────────
create_service(){
  local unit="$1" exec="$2"
  cat >"$SYSTEMD_DIR/$unit.service" <<EOF
[Unit]
Description=Reverse SSH Tunnel: $unit
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
ExecStartPre=/bin/sleep 5
ExecStart=$exec
Restart=always
RestartSec=10
LimitNOFILE=200000
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$unit.service" >/dev/null 2>&1 || true
  systemctl status "$unit.service"
}
show_logs(){ local unit="$1"; journalctl -u "$unit" -n 80 --no-pager; pause; }
service_exists(){ systemctl list-unit-files --type=service --no-pager | grep -q "^$1\.service"; }
list_services(){ systemctl list-units --type=service --all --no-pager | awk '{print $1}' | grep -E '^reverse-tunnel-.*\.service$' | sed 's/\.service$//'; }
remove_service(){ local unit="$1"; systemctl stop "$unit" >/dev/null 2>&1 || true; systemctl disable "$unit" >/dev/null 2>&1 || true; rm -f "$SYSTEMD_DIR/$unit.service"; }
remove_all(){
  echo "Searching for reverse SSH services..."
  mapfile -t units < <(list_services)
  if (( ${#units[@]} > 0 )); then
    for u in "${units[@]}"; do echo "Removing $u"; remove_service "$u"; done
    systemctl daemon-reload
  fi
  [[ -d "$BASE_DIR" ]] && { rm -rf "$BASE_DIR"; ok "Removed $BASE_DIR"; }
  [[ -f "$GLOBAL_KEY_FILE" ]] && rm -f "$GLOBAL_KEY_FILE" "$GLOBAL_KEY_FILE.pub"
  ok "Uninstall complete."
}
# ─────────────────────── tunnel config parser (manage forwards) ──────────────
read_tunnel_config(){
  local script="$1"; FORWARDS=()
  mapfile -t FORWARDS < <(grep '^FORWARDS+=' "$script" | sed 's/FORWARDS+=("//; s/")$//' | grep -v '^$')
  SIP=$(grep '^TUNNEL_IP=' "$script" | cut -d'"' -f2)
  SPORT=$(grep '^TUNNEL_SSH_PORT=' "$script" | cut -d'=' -f2)
  KEY_FILE=$(grep '^KEY_FILE=' "$script" | cut -d'"' -f2)
  COMPRESSION=$(grep '^COMPRESSION=' "$script" | cut -d'"' -f2)
  MULTIPLEXING=$(grep '^MULTIPLEXING=' "$script" | cut -d'"' -f2)
  HEARTBEAT=$(grep '^HEARTBEAT=' "$script" | cut -d'"' -f2)
}
write_tunnel_with_forwards(){
  local script="$1"
  write_tunnel_script "$script" "$SIP" "$SPORT" "$KEY_FILE" "$COMPRESSION" "$MULTIPLEXING" "$HEARTBEAT" "${FORWARDS[@]}"
}
# ───────────────────────────── interactive flows ────────────────────────────
action_add_tunnel(){
  ensure_base
  printc "-- Add Reverse SSH Tunnel --" "31"
  local name
  while :; do
    read -rp "Tunnel name (alnum, hyphen, underscore): " name || true
    name=$(echo "$name" | tr -cd '[:alnum:]_-')
    [[ -n $name ]] && break || echo "Name cannot be empty"
  done
  local service="reverse-tunnel-$name" script="$BASE_DIR/reverse-$name.sh"
  if service_exists "$service"; then err "Service already exists: $service"; pause; return; fi
  local sip sport key_file="$GLOBAL_KEY_FILE" use_global_key="true"
  while :; do read -rp "Server IP/host: " sip || true; validate_host "$sip" && break || echo "Invalid"; done
  printc "VPS Tunnel IP: $sip" "32"
  while :; do read -rp "Server SSH port [22]: " sport || true; sport=${sport:-22}; validate_port "$sport" && break || echo "Invalid"; done
  printc "VPS Tunnel SSH Port: $sport" "32"
  read -rp "Use global SSH key ($key_file)? (Y/n): " ug || true
  [[ ${ug,,} =~ ^n ]] && { use_global_key="false"; key_file="$BASE_DIR/id_rsa_$name"; }
  check_and_generate_key "$key_file"
  copy_key_to_server "$key_file" "$sip" "$sport"
  enable_gateway_ports "$sip" "$sport"
  local compression="false" multiplexing="false" heartbeat="true"
  read -rp "Enable compression? (y/N): " c || true; [[ ${c,,} =~ ^y ]] && compression="true"
  read -rp "Enable multiplexing? (y/N): " m || true; [[ ${m,,} =~ ^y ]] && multiplexing="true"
  read -rp "Enable heartbeat/reconnect? (Y/n): " h || true; [[ ${h,,} =~ ^n ]] && heartbeat="false"
  local forwards=()
  echo "Add port forwards. Type 'done' to finish."
  local idx=1
  while :; do
    echo "--- Forward #$idx ---"
    local remote_port local_port fwd
    read -rp "Remote port (on server, or 'done'): " remote_port || true
    [[ ${remote_port,,} == done ]] && break
    validate_port "$remote_port" || { echo "Invalid remote port"; continue; }
    printc "VPS Tunnel Listening Port: $remote_port" "32"
    read -rp "Local port (on this machine): " local_port || true
    validate_port "$local_port" || { echo "Invalid local port"; continue; }
    printc "Listen From $sip:$remote_port And Forward to Port: $local_port" "32"
    fwd="$remote_port:localhost:$local_port"
    forwards+=("$fwd")
    ok "Added forward: $fwd"
    ((idx++))
  done
  (( ${#forwards[@]} == 0 )) && { err "At least one forward required"; pause; return; }
  write_tunnel_script "$script" "$sip" "$sport" "$key_file" "$compression" "$multiplexing" "$heartbeat" "${forwards[@]}"
  ok "Script written: $script"
  create_service "$service" "$script"
  ok "Service started: $service"
  read -rp "Show logs? (y/N): " v || true; [[ ${v,,} =~ ^y ]] && show_logs "$service"
}
manage_tunnel_forwards(){
  echo "-- Manage Tunnel Forwards --"
  mapfile -t units < <(list_services)
  (( ${#units[@]} == 0 )) && { echo "No tunnel services found"; pause; return; }
  local i=1; for u in "${units[@]}"; do echo " $i) $u"; ((i++)); done
  local idx; read -rp "Choose tunnel: " idx || true
  (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
  local unit="${units[$((idx-1))]}"
  local name="${unit#reverse-tunnel-}"
  local script="$BASE_DIR/reverse-$name.sh"
  [[ -f "$script" ]] || { err "Script not found: $script"; pause; return; }
  while :; do
    printf "\nTunnel: %s\n" "$name"
    echo "1) View forwards"
    echo "2) Add forward"
    echo "3) Edit forward"
    echo "4) Delete forward"
    echo "5) Back"
    read -rp "Choice: " c || true
    case ${c:-1} in
      1)
        read_tunnel_config "$script"
        if (( ${#FORWARDS[@]} == 0 )); then
          echo "No forwards"
        else
          local j=1
          for fwd in "${FORWARDS[@]}"; do
            echo "$j) $fwd"
            ((j++))
          done
        fi
        pause;;
      2)
        local remote_port local_port fwd
        while :; do
          read -rp "Remote port (on server): " remote_port || true
          validate_port "$remote_port" || { echo "Invalid remote port"; continue; }
          break
        done
        while :; do
          read -rp "Local port (on this machine): " local_port || true
          validate_port "$local_port" || { echo "Invalid local port"; continue; }
          break
        done
        fwd="$remote_port:localhost:$local_port"
        read_tunnel_config "$script"
        FORWARDS+=("$fwd")
        write_tunnel_with_forwards "$script"
        systemctl restart "$unit" || true; ok "Added & restarted"; pause;;
      3)
        read_tunnel_config "$script"; (( ${#FORWARDS[@]} == 0 )) && { echo "No forwards"; pause; continue; }
        local j=1; for fwd in "${FORWARDS[@]}"; do echo " $j) $fwd"; ((j++)); done
        read -rp "Select forward: " j || true; (( j>=1 && j<=${#FORWARDS[@]} )) || { echo "Invalid"; pause; continue; }
        local old_fwd="${FORWARDS[$((j-1))]}" old_remote old_local
        old_remote="${old_fwd%%:*}"
        old_local="${old_fwd##*:}"
        local new_remote new_local nfwd
        read -rp "New remote port [$old_remote]: " new_remote || true; new_remote=${new_remote:-$old_remote}
        validate_port "$new_remote" || { echo "Invalid remote port"; pause; continue; }
        read -rp "New local port [$old_local]: " new_local || true; new_local=${new_local:-$old_local}
        validate_port "$new_local" || { echo "Invalid local port"; pause; continue; }
        nfwd="$new_remote:localhost:$new_local"
        FORWARDS[$((j-1))]="$nfwd"
        write_tunnel_with_forwards "$script"
        systemctl restart "$unit" || true; ok "Updated & restarted"; pause;;
      4)
        read_tunnel_config "$script"; (( ${#FORWARDS[@]} == 0 )) && { echo "No forwards"; pause; continue; }
        local j=1; for fwd in "${FORWARDS[@]}"; do echo " $j) $fwd"; ((j++)); done
        read -rp "Select to delete: " j || true
        (( j>=1 && j<=${#FORWARDS[@]} )) || { echo "Invalid"; pause; continue; }
        unset 'FORWARDS[$((j-1))]'; FORWARDS=("${FORWARDS[@]}")
        write_tunnel_with_forwards "$script"
        systemctl restart "$unit" || true; ok "Deleted & restarted"; pause;;
      5) break;;
      *) :;;
    esac
  done
}
delete_unit_menu(){
  mapfile -t units < <(list_services)
  (( ${#units[@]} == 0 )) && { echo "No tunnels"; pause; return; }
  local i=1; for u in "${units[@]}"; do echo " $i) $u"; ((i++)); done
  local idx; read -rp "Choose to delete: " idx || true; (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
  local unit="${units[$((idx-1))]}"
  local name="${unit#reverse-tunnel-}"
  local script="$BASE_DIR/reverse-$name.sh"
  remove_service "$unit"; systemctl daemon-reload; [[ -f "$script" ]] && rm -f "$script"
  local key_file="$BASE_DIR/id_rsa_$name"
  [[ -f "$key_file" ]] && rm -f "$key_file" "$key_file.pub"
  ok "Deleted $unit and its config"; pause
}
view_logs_menu(){
  mapfile -t units < <(list_services)
  (( ${#units[@]} == 0 )) && { echo "No tunnels"; pause; return; }
  local i=1; for u in "${units[@]}"; do echo " $i) $u"; ((i++)); done
  local idx; read -rp "Choose: " idx || true; (( idx>=1 && idx<=${#units[@]} )) || { echo "Invalid"; pause; return; }
  show_logs "${units[$((idx-1))]}"
}
main_menu(){
  while :; do
    clear
    printc "Reverse SSH Tunnel Unlimited Menu v$SCRIPT_VERSION" "31"
    echo "Config root : $BASE_DIR"
    echo
    echo "1) Add new tunnel"
    echo "2) Manage tunnel forwards"
    echo "3) View logs"
    echo "4) Delete a tunnel"
    echo "5) Uninstall (remove ALL tunnels, configs)"
    echo "0) Exit"
    read -rp "Choice: " c || true
    case ${c:-0} in
      1) action_add_tunnel ;;
      2) manage_tunnel_forwards ;;
      3) view_logs_menu ;;
      4) delete_unit_menu ;;
      5) read -rp "REMOVE ALL (y/N)? " a || true; [[ ${a,,} =~ ^y ]] && remove_all || echo "Cancelled"; pause ;;
      0) exit 0 ;;
      *) : ;;
    esac
  done
}
main_menu
