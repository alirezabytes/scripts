#!/usr/bin/env bash
set -euo pipefail

# Reverse SSH Tunnel Manager (AutoSSH + systemd)
# Features:
#   - install: create a new reverse tunnel service
#   - remove : stop/disable and delete the service unit
#   - status : show service status
#   - list   : list managed services
#
# Notes:
#   - Script must be run as root.
#   - Uses /etc/systemd/system/<service>.service for systemd unit.
#   - Keeps SSH key as-is (does not delete /root/.ssh/id_rsa).

SERVICE_PREFIX="reverse_ssh_tunnel"
DEFAULT_SERVICE_NAME="${SERVICE_PREFIX}"
KEY_FILE="/root/.ssh/id_rsa"

printc() {
  local text="$1"
  local color="$2"
  echo -e "\e[${color}m${text}\e[0m"
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
  # Install required packages
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y autossh openssh-client >/dev/null
}

generate_key() {
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  ssh-keygen -t rsa -b 4096 -f "$KEY_FILE" -q -N ""
  chmod 600 "$KEY_FILE"
  chmod 644 "${KEY_FILE}.pub"
  printc "New SSH key generated at: $KEY_FILE" "32"
}

ensure_key() {
  if [[ -f "$KEY_FILE" ]]; then
    printc "SSH key already exists: $KEY_FILE" "33"
  else
    generate_key
  fi
}

unit_path() {
  local name="$1"
  echo "/etc/systemd/system/${name}.service"
}

service_exists() {
  local name="$1"
  systemctl list-unit-files --type=service | awk '{print $1}' | grep -qx "${name}.service"
}

remote_harden_sshd() {
  local ip="$1"
  local port="$2"

  # Configure sshd on the remote VPS for stable reverse tunnels + allow binding on 0.0.0.0 (GatewayPorts)
  ssh -p "$port" -o StrictHostKeyChecking=accept-new root@"$ip" << 'EOF'
set -e

SSHD_CONFIG="/etc/ssh/sshd_config"

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

install_tunnel() {
  local name="${1:-$DEFAULT_SERVICE_NAME}"

  if service_exists "$name"; then
    die "Service '${name}' already exists. Use another name or remove it first."
  fi

  ensure_deps
  ensure_key

  printc "\nReverse SSH Tunnel Manager" "31"
  printc "Service name: $name" "36"
  echo

  read -rp "Enter tunnel VPS IP/Host: " TUNNEL_VPS_IP
  [[ -n "${TUNNEL_VPS_IP}" ]] || die "Tunnel VPS IP/Host cannot be empty."

  read -rp "Enter tunnel VPS SSH port: " TUNNEL_VPS_SSH_PORT
  [[ -n "${TUNNEL_VPS_SSH_PORT}" ]] || die "SSH port cannot be empty."

  printc "Copying SSH key to remote (ssh-copy-id)..." "32"
  ssh-copy-id -p "$TUNNEL_VPS_SSH_PORT" -o StrictHostKeyChecking=accept-new root@"$TUNNEL_VPS_IP"

  printc "Configuring remote sshd parameters (keepalive + GatewayPorts)..." "32"
  remote_harden_sshd "$TUNNEL_VPS_IP" "$TUNNEL_VPS_SSH_PORT"

  read -rp "Enter tunnel VPS listening port (remote port): " TUNNEL_VPS_LISTENING_PORT
  [[ -n "${TUNNEL_VPS_LISTENING_PORT}" ]] || die "Remote listening port cannot be empty."

  read -rp "Enter local port to forward to (this server): " LOCAL_FORWARD_PORT
  [[ -n "${LOCAL_FORWARD_PORT}" ]] || die "Local forward port cannot be empty."

  printc "\nCreating systemd service unit..." "32"

  cat > "$(unit_path "$name")" <<EOT
[Unit]
Description=Reverse SSH Tunnel (${name})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple

# AutoSSH (no monitoring port) + keepalives + fail fast if forward fails
ExecStart=/usr/bin/autossh -M 0 \\
  -o ServerAliveInterval=30 \\
  -o ServerAliveCountMax=3 \\
  -o ExitOnForwardFailure=yes \\
  -o StrictHostKeyChecking=accept-new \\
  -N -R ${TUNNEL_VPS_LISTENING_PORT}:127.0.0.1:${LOCAL_FORWARD_PORT} root@${TUNNEL_VPS_IP} -p ${TUNNEL_VPS_SSH_PORT}

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOT

  systemctl daemon-reload
  systemctl enable --now "${name}.service" >/dev/null

  printc "\nService installed and started successfully." "32"
  printc "Check status with: systemctl status ${name}.service" "36"
  echo
  systemctl --no-pager status "${name}.service" || true
}

remove_tunnel() {
  local name="${1:-$DEFAULT_SERVICE_NAME}"

  if ! service_exists "$name"; then
    die "Service '${name}' not found."
  fi

  printc "Stopping service..." "33"
  systemctl stop "${name}.service" >/dev/null 2>&1 || true

  printc "Disabling service..." "33"
  systemctl disable "${name}.service" >/dev/null 2>&1 || true

  local path
  path="$(unit_path "$name")"

  printc "Removing unit file: $path" "33"
  rm -f "$path"

  systemctl daemon-reload
  systemctl reset-failed "${name}.service" >/dev/null 2>&1 || true

  printc "Service '${name}' removed successfully." "32"
  printc "Note: SSH key is NOT deleted: $KEY_FILE" "36"
}

status_tunnel() {
  local name="${1:-$DEFAULT_SERVICE_NAME}"
  if ! service_exists "$name"; then
    die "Service '${name}' not found."
  fi
  systemctl --no-pager status "${name}.service"
}

list_tunnels() {
  printc "Managed services (matching prefix: ${SERVICE_PREFIX}):" "36"
  systemctl list-unit-files --type=service | awk '{print $1}' | grep -E "^${SERVICE_PREFIX}.*\.service$" || true
}

usage() {
  cat <<EOF
Usage:
  $0 install [service_name]
  $0 remove  [service_name]
  $0 status  [service_name]
  $0 list

Examples:
  $0 install ocserv_443_tunnel
  $0 remove  ocserv_443_tunnel
  $0 status  ocserv_443_tunnel
  $0 list
EOF
}

main() {
  require_root

  local cmd="${1:-}"
  local name="${2:-$DEFAULT_SERVICE_NAME}"

  case "$cmd" in
    install|add)
      install_tunnel "$name"
      ;;
    remove|delete|uninstall)
      remove_tunnel "$name"
      ;;
    status)
      status_tunnel "$name"
      ;;
    list|ls)
      list_tunnels
      ;;
    ""|-h|--help|help)
      usage
      ;;
    *)
      die "Unknown command: $cmd (use --help)"
      ;;
  esac
}

main "$@"