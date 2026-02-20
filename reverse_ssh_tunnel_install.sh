#!/usr/bin/env bash
set -euo pipefail

# Reverse SSH Tunnel Manager (Menu-driven)
# Features:
# - Create/Install reverse tunnel as a systemd service (autossh)
# - Remove one tunnel service (service only) + optional remote sshd_config reset (restore from .back)
# - Edit/Reconfigure existing service
# - Status / List / Logs
# - Uninstall everything (local) + optional remote sshd_config reset for one or multiple remote VPS
#
# Remote behavior:
# - On APPLY (harden), create one-time backup: /etc/ssh/sshd_config.back (no overwrite)
# - On RESET, restore sshd_config from /etc/ssh/sshd_config.back and restart ssh/sshd
#
# Requirements: autossh, openssh-client
# Run as root.

SERVICE_PREFIX="reverse_ssh_tunnel"
DEFAULT_SERVICE_NAME="${SERVICE_PREFIX}"
KEY_FILE="/root/.ssh/id_rsa"
KEY_PUB="/root/.ssh/id_rsa.pub"

printc() {
  local text="$1"
  local color="$2"
  echo -e "\e[${color}m${text}\e[0m"
}

pause() {
  read -rp "Press Enter to continue... " _
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "This script must be run as root."
  fi
}

ensure_deps() {
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y autossh openssh-client >/dev/null
}

ensure_key() {
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  if [[ -f "$KEY_FILE" ]]; then
    chmod 600 "$KEY_FILE" || true
    [[ -f "$KEY_PUB" ]] && chmod 644 "$KEY_PUB" || true
    return 0
  fi
  ssh-keygen -t rsa -b 4096 -f "$KEY_FILE" -q -N ""
  chmod 600 "$KEY_FILE"
  chmod 644 "$KEY_PUB"
}

unit_path() {
  local name="$1"
  echo "/etc/systemd/system/${name}.service"
}

service_exists() {
  local name="$1"
  systemctl list-unit-files --type=service | awk '{print $1}' | grep -qx "${name}.service"
}

list_services() {
  systemctl list-unit-files --type=service | awk '{print $1}' | grep -E "^${SERVICE_PREFIX}.*\.service$" || true
}

read_nonempty() {
  local prompt="$1"
  local var
  while true; do
    read -rp "$prompt" var
    if [[ -n "${var// }" ]]; then
      echo "$var"
      return 0
    fi
    echo "Value cannot be empty."
  done
}

ask_yes_no() {
  local prompt="$1"
  local default="${2:-N}"
  local ans
  while true; do
    read -rp "${prompt} (y/N): " ans
    ans="${ans:-$default}"
    case "$ans" in
      y|Y) return 0 ;;
      n|N) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

# --- Remote APPLY (harden) with one-time backup ---
remote_harden_sshd() {
  local ip="$1"
  local port="$2"

  ssh -p "$port" -o StrictHostKeyChecking=accept-new root@"$ip" << 'EOF'
set -e
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.back"

# Create a one-time backup (do not overwrite if exists)
if [ ! -f "$BACKUP" ]; then
  cp -a "$SSHD_CONFIG" "$BACKUP"
  echo "Backup created: $BACKUP"
else
  echo "Backup already exists: $BACKUP"
fi

ensure_param() {
  local key="$1"
  local value="$2"
  if grep -Eq "^\s*#?\s*${key}\b" "$SSHD_CONFIG"; then
    sed -i -E "s|^\s*#?\s*${key}\b.*|${key} ${value}|" "$SSHD_CONFIG"
  else
    echo "${key} ${value}" >> "$SSHD_CONFIG"
  fi
}

ensure_param "ClientAliveInterval" "30"
ensure_param "ClientAliveCountMax" "5"
ensure_param "TCPKeepAlive" "yes"
ensure_param "GatewayPorts" "yes"

systemctl daemon-reload
systemctl restart ssh.service 2>/dev/null || true
systemctl restart sshd.service 2>/dev/null || true
EOF
}

# --- Remote RESET (restore from backup) ---
remote_reset_sshd() {
  local ip="$1"
  local port="$2"

  ssh -p "$port" -o StrictHostKeyChecking=accept-new root@"$ip" << 'EOF'
set -e
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.back"

if [ ! -f "$BACKUP" ]; then
  echo "ERROR: Backup not found: $BACKUP"
  echo "Cannot restore. (Maybe the script never applied changes on this server.)"
  exit 1
fi

cp -a "$BACKUP" "$SSHD_CONFIG"
echo "Restored from backup: $BACKUP -> $SSHD_CONFIG"

systemctl daemon-reload
systemctl restart ssh.service 2>/dev/null || true
systemctl restart sshd.service 2>/dev/null || true
EOF
}

write_unit() {
  local name="$1"
  local tunnel_ip="$2"
  local tunnel_ssh_port="$3"
  local remote_listen_port="$4"
  local local_forward_port="$5"

  cat > "$(unit_path "$name")" <<EOT
[Unit]
Description=Reverse SSH Tunnel (${name})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/autossh -M 0 \\
  -o ServerAliveInterval=30 \\
  -o ServerAliveCountMax=3 \\
  -o ExitOnForwardFailure=yes \\
  -o StrictHostKeyChecking=accept-new \\
  -N -R ${remote_listen_port}:127.0.0.1:${local_forward_port} root@${tunnel_ip} -p ${tunnel_ssh_port}

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOT
}

pick_service_name() {
  echo
  printc "Enter service name (default: ${DEFAULT_SERVICE_NAME})" "36"
  read -rp "Service name: " name
  name="${name:-$DEFAULT_SERVICE_NAME}"

  # Enforce prefix to keep things organized
  if [[ "$name" != ${SERVICE_PREFIX}* ]]; then
    name="${SERVICE_PREFIX}_${name}"
  fi

  if ! [[ "$name" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    die "Invalid service name. Use only letters, numbers, dot, underscore, dash."
  fi

  echo "$name"
}

maybe_remote_reset_prompt() {
  echo
  if ask_yes_no "Reset remote sshd_config by restoring /etc/ssh/sshd_config.back ?" "N"; then
    local rip rport
    rip="$(read_nonempty "Enter remote VPS IP/Host: ")"
    rport="$(read_nonempty "Enter remote VPS SSH port: ")"
    printc "Restoring remote sshd_config from backup..." "33"
    if remote_reset_sshd "$rip" "$rport"; then
      printc "Remote restore done." "32"
    else
      printc "Remote restore failed (see errors above)." "31"
    fi
  else
    printc "Skipping remote restore." "33"
  fi
}

create_install_flow() {
  ensure_deps
  ensure_key

  local name
  name="$(pick_service_name)"

  if service_exists "$name"; then
    printc "Service already exists: ${name}.service" "33"
    printc "Use Edit option if you want to change its config." "33"
    pause
    return 0
  fi

  echo
  local tunnel_ip tunnel_ssh_port remote_listen_port local_forward_port
  tunnel_ip="$(read_nonempty "Enter tunnel VPS IP/Host: ")"
  tunnel_ssh_port="$(read_nonempty "Enter tunnel VPS SSH port: ")"

  printc "Copying SSH key to remote (ssh-copy-id)..." "32"
  ssh-copy-id -p "$tunnel_ssh_port" -o StrictHostKeyChecking=accept-new root@"$tunnel_ip"

  printc "Configuring remote sshd parameters (keepalive + GatewayPorts) + creating backup..." "32"
  remote_harden_sshd "$tunnel_ip" "$tunnel_ssh_port"

  remote_listen_port="$(read_nonempty "Enter tunnel VPS listening port (remote port): ")"
  local_forward_port="$(read_nonempty "Enter local port to forward to (this server): ")"

  write_unit "$name" "$tunnel_ip" "$tunnel_ssh_port" "$remote_listen_port" "$local_forward_port"

  systemctl daemon-reload
  systemctl enable --now "${name}.service" >/dev/null

  printc "Installed & started: ${name}.service" "32"
  systemctl --no-pager status "${name}.service" || true
  pause
}

remove_flow() {
  local name
  name="$(pick_service_name)"

  if ! service_exists "$name"; then
    printc "Service not found: ${name}.service" "31"
    pause
    return 0
  fi

  echo
  if ! ask_yes_no "Are you sure you want to remove '${name}.service' (local unit only)?" "N"; then
    printc "Canceled." "33"
    pause
    return 0
  fi

  systemctl stop "${name}.service" >/dev/null 2>&1 || true
  systemctl disable "${name}.service" >/dev/null 2>&1 || true
  rm -f "$(unit_path "$name")"
  systemctl daemon-reload
  systemctl reset-failed "${name}.service" >/dev/null 2>&1 || true

  printc "Removed: ${name}.service" "32"
  printc "Note: SSH key is NOT deleted: ${KEY_FILE}" "36"

  # Step-by-step optional remote restore
  maybe_remote_reset_prompt

  pause
}

status_flow() {
  local name
  name="$(pick_service_name)"

  if ! service_exists "$name"; then
    printc "Service not found: ${name}.service" "31"
    pause
    return 0
  fi

  systemctl --no-pager status "${name}.service" || true
  pause
}

list_flow() {
  echo
  printc "Managed services:" "36"
  list_services || true
  pause
}

logs_flow() {
  local name
  name="$(pick_service_name)"

  if ! service_exists "$name"; then
    printc "Service not found: ${name}.service" "31"
    pause
    return 0
  fi

  echo
  printc "Showing logs (last 200 lines). Press q to exit." "36"
  journalctl -u "${name}.service" -n 200 --no-pager || true

  echo
  if ask_yes_no "Follow logs live?" "N"; then
    journalctl -u "${name}.service" -f
  fi
  pause
}

edit_flow() {
  ensure_deps
  ensure_key

  local name
  name="$(pick_service_name)"

  if ! service_exists "$name"; then
    printc "Service not found: ${name}.service" "31"
    pause
    return 0
  fi

  echo
  printc "Reconfigure existing service: ${name}.service" "36"
  printc "This will overwrite the unit file and restart the service." "33"
  echo

  local tunnel_ip tunnel_ssh_port remote_listen_port local_forward_port
  tunnel_ip="$(read_nonempty "Enter NEW tunnel VPS IP/Host: ")"
  tunnel_ssh_port="$(read_nonempty "Enter NEW tunnel VPS SSH port: ")"

  printc "Copying SSH key to remote (ssh-copy-id)..." "32"
  ssh-copy-id -p "$tunnel_ssh_port" -o StrictHostKeyChecking=accept-new root@"$tunnel_ip"

  printc "Configuring remote sshd parameters (keepalive + GatewayPorts) + creating backup..." "32"
  remote_harden_sshd "$tunnel_ip" "$tunnel_ssh_port"

  remote_listen_port="$(read_nonempty "Enter NEW tunnel VPS listening port (remote port): ")"
  local_forward_port="$(read_nonempty "Enter NEW local port to forward to (this server): ")"

  write_unit "$name" "$tunnel_ip" "$tunnel_ssh_port" "$remote_listen_port" "$local_forward_port"

  systemctl daemon-reload
  systemctl restart "${name}.service" >/dev/null 2>&1 || true

  printc "Updated & restarted: ${name}.service" "32"
  systemctl --no-pager status "${name}.service" || true
  pause
}

uninstall_everything_flow() {
  echo
  printc "UNINSTALL EVERYTHING (local machine)" "31"
  printc "This will remove services created by this script and optionally uninstall packages and SSH keys." "33"
  echo

  local services
  services="$(list_services || true)"

  if [[ -z "${services// }" ]]; then
    printc "No managed services found to remove." "33"
  else
    printc "Found these managed services:" "36"
    echo "$services"
    echo

    if ask_yes_no "Remove ALL above services (stop/disable/delete unit)?" "N"; then
      while read -r svc; do
        [[ -z "$svc" ]] && continue
        local name="${svc%.service}"
        systemctl stop "${name}.service" >/dev/null 2>&1 || true
        systemctl disable "${name}.service" >/dev/null 2>&1 || true
        rm -f "$(unit_path "$name")"
        systemctl reset-failed "${name}.service" >/dev/null 2>&1 || true
      done <<< "$services"

      systemctl daemon-reload
      printc "All managed services removed." "32"
    else
      printc "Skipping service removal." "33"
    fi
  fi

  echo
  printc "Remote restore is OPTIONAL. You can do it for one or multiple tunnel VPS servers." "36"
  while true; do
    if ask_yes_no "Do you want to restore remote sshd_config from /etc/ssh/sshd_config.back now?" "N"; then
      maybe_remote_reset_prompt
    else
      break
    fi
  done

  echo
  if ask_yes_no "Purge autossh package?" "N"; then
    apt-get purge -y autossh >/dev/null 2>&1 || true
    apt-get autoremove -y >/dev/null 2>&1 || true
    printc "autossh purged." "32"
  else
    printc "Keeping autossh installed." "33"
  fi

  echo
  if ask_yes_no "Purge openssh-client package? (WARNING: you may need SSH later)" "N"; then
    apt-get purge -y openssh-client >/dev/null 2>&1 || true
    apt-get autoremove -y >/dev/null 2>&1 || true
    printc "openssh-client purged." "32"
  else
    printc "Keeping openssh-client installed." "33"
  fi

  echo
  printc "SSH Key removal is OPTIONAL and risky if you use this key for other SSH access." "33"
  if [[ -f "$KEY_FILE" || -f "$KEY_PUB" ]]; then
    if ask_yes_no "Delete SSH key files (${KEY_FILE}, ${KEY_PUB})?" "N"; then
      rm -f "$KEY_FILE" "$KEY_PUB"
      printc "SSH key files deleted." "32"
    else
      printc "Keeping SSH key files." "33"
    fi
  else
    printc "No SSH key files found at default path." "33"
  fi

  echo
  printc "Uninstall completed (local)." "32"
  pause
}

main_menu() {
  while true; do
    clear || true
    printc "Reverse SSH Tunnel Manager (Menu)" "31"
    echo
    echo "1) Create/Install new tunnel"
    echo "2) Remove tunnel (service only + optional remote restore)"
    echo "3) Status"
    echo "4) List tunnels"
    echo "5) View logs"
    echo "6) Edit/Reconfigure existing tunnel"
    echo "7) Uninstall everything (local + optional remote restore)"
    echo "0) Exit"
    echo
    read -rp "Choose an option: " choice

    case "${choice:-}" in
      1) create_install_flow ;;
      2) remove_flow ;;
      3) status_flow ;;
      4) list_flow ;;
      5) logs_flow ;;
      6) edit_flow ;;
      7) uninstall_everything_flow ;;
      0) exit 0 ;;
      *) echo "Invalid option."; pause ;;
    esac
  done
}

require_root
main_menu
