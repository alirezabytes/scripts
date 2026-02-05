#!/usr/bin/env bash

# ============================================================================
# Reverse SSH Tunnel Manager with autossh
# Interactive menu only - no command-line arguments needed
# All messages in English
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_info()    { echo -e "${YELLOW}[INFO]${NC} $1"; }

# Paths
SERVICE_NAME="reverse-ssh-tunnel"
TUNNEL_SCRIPT="/usr/local/bin/${SERVICE_NAME}.sh"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
KEY_FILE="/root/.ssh/id_rsa"

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root."
        exit 1
    fi
}

show_menu() {
    clear
    echo -e "${YELLOW}============================================================${NC}"
    echo "          Reverse SSH Tunnel Manager (autossh)"
    echo -e "${YELLOW}============================================================${NC}"
    echo "  1) Install / Setup new reverse tunnel"
    echo "  2) Uninstall / Remove tunnel completely"
    echo "  3) Start the tunnel service"
    echo "  4) Stop the tunnel service"
    echo "  5) Restart the tunnel service"
    echo "  6) Show service status"
    echo "  7) Show recent logs (last 50 lines)"
    echo "  0) Exit"
    echo -e "${YELLOW}============================================================${NC}"
    read -r -p "Enter choice (0-7): " choice
}

install_autossh() {
    if ! command -v autossh >/dev/null 2>&1; then
        print_info "Installing autossh..."
        apt-get update -qq >/dev/null
        apt-get install -y autossh >/dev/null
        print_success "autossh installed successfully"
    fi
}

generate_ssh_key() {
    if [ ! -f "$KEY_FILE" ]; then
        print_info "Generating new SSH key pair..."
        ssh-keygen -t rsa -b 4096 -f "$KEY_FILE" -q -N ""
        print_success "SSH key generated at $KEY_FILE"
    fi
}

copy_public_key() {
    local ip="$1"
    local port="${2:-22}"
    print_info "Copying public key to remote server (may ask for password)..."
    ssh-copy-id -i "${KEY_FILE}.pub" -p "$port" root@"$ip" || {
        print_error "Failed to copy public key. Check IP, port, password or firewall."
        exit 1
    }
    print_success "Public key copied"
}

configure_remote_sshd() {
    local ip="$1"
    local port="${2:-22}"
    print_info "Enabling GatewayPorts on remote server..."
    ssh -p "$port" root@"$ip" "
        sed -i 's/^#*GatewayPorts.*/GatewayPorts yes/' /etc/ssh/sshd_config
        systemctl restart ssh || service ssh restart || /etc/init.d/ssh restart
    " 2>/dev/null
    print_success "Remote sshd configured"
}

create_tunnel_script() {
    local ip="$1"
    local ssh_port="${2:-22}"
    local remote_port="$3"
    local local_port="$4"

    cat > "$TUNNEL_SCRIPT" << EOF
#!/usr/bin/env bash
# Persistent reverse tunnel - auto-generated

autossh -M 0 \\
    -o ServerAliveInterval=10 \\
    -o ServerAliveCountMax=3 \\
    -o ExitOnForwardFailure=yes \\
    -o TCPKeepAlive=yes \\
    -o IPQoS=throughput \\
    -N -R ${remote_port}:localhost:${local_port} \\
    -p ${ssh_port} root@${ip}
EOF

    chmod +x "$TUNNEL_SCRIPT"
    print_success "Tunnel script created"
}

create_systemd_service() {
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Persistent Reverse SSH Tunnel (autossh)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$TUNNEL_SCRIPT
Restart=always
RestartSec=7
StartLimitIntervalSec=60
StartLimitBurst=10
Environment=AUTOSSH_GATETIME=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_success "Systemd service file created"
}

do_install() {
    check_root
    install_autossh
    generate_ssh_key

    read -r -p "Enter remote VPS IP (Iran server): " VPS_IP
    read -r -p "Enter remote VPS SSH port [22]: " VPS_SSH_PORT
    VPS_SSH_PORT=${VPS_SSH_PORT:-22}
    read -r -p "Enter listening port on remote VPS (e.g. 443): " REMOTE_PORT
    read -r -p "Enter local port to forward (e.g. 443): " LOCAL_PORT

    echo
    print_info "Summary:"
    echo "  Remote IP       : $VPS_IP"
    echo "  Remote SSH port : $VPS_SSH_PORT"
    echo "  Remote listen   : $REMOTE_PORT"
    echo "  Local forward   : $LOCAL_PORT"
    echo
    read -r -p "Continue? (y/N): " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return

    copy_public_key "$VPS_IP" "$VPS_SSH_PORT"
    configure_remote_sshd "$VPS_IP" "$VPS_SSH_PORT"
    create_tunnel_script "$VPS_IP" "$VPS_SSH_PORT" "$REMOTE_PORT" "$LOCAL_PORT"
    create_systemd_service

    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
    systemctl restart "$SERVICE_NAME"
    print_success "Installation finished. Service started."
    sleep 2
    systemctl --no-pager status "$SERVICE_NAME" --lines=12
}

do_uninstall() {
    check_root
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_FILE" "$TUNNEL_SCRIPT"
    systemctl daemon-reload
    print_success "Tunnel service and files removed."
    print_info "SSH keys are not deleted. Remove manually if needed."
}

# Main loop - always show menu
check_root

while true; do
    show_menu

    case $choice in
        1) do_install ;;
        2) do_uninstall ;;
        3) systemctl start  "$SERVICE_NAME" && systemctl --no-pager status "$SERVICE_NAME" --lines=10 ;;
        4) systemctl stop   "$SERVICE_NAME" && print_success "Service stopped" ;;
        5) systemctl restart "$SERVICE_NAME" && systemctl --no-pager status "$SERVICE_NAME" --lines=10 ;;
        6) systemctl status "$SERVICE_NAME" --no-pager --lines=15 ;;
        7) journalctl -u "$SERVICE_NAME" -n 50 --no-pager ;;
        0) echo "Exiting..."; exit 0 ;;
        *) print_error "Invalid choice. Please try again."; sleep 1 ;;
    esac

    echo
    read -r -p "Press Enter to return to menu..." || true
done
