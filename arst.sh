#!/usr/bin/env bash
# =============================================================================
# Auto-Reconnecting Reverse SSH Tunnel Manager (with autossh)
# English-only script – Persistent connection with auto-reconnect
# Features:
# - Uses autossh for automatic reconnect
# - Checks if remote port is bindable before starting
# - Aggressive keepalive to detect drops early
# - Retries if port is in TIME_WAIT
# - Full uninstall & remove packages option
# - Interactive menu after initial setup
# =============================================================================

set -euo pipefail

# ──────────────────────────────────────────── Colors ──────────────────────────
RED='\033[0;31m'    GREEN='\033[0;32m'    YELLOW='\033[1;33m'
BLUE='\033[0;34m'   NC='\033[0m'

# ──────────────────────────────────────────── Config ──────────────────────────
SERVICE_NAME="reverse-ssh-tunnel"
SCRIPT_PATH="/usr/local/bin/${SERVICE_NAME}.sh"
SYSTEMD_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

# ──────────────────────────────────────────── Functions ───────────────────────
print() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }

check_root() {
    [[ $EUID -ne 0 ]] && error "This script must be run as root (use sudo)."
}

install_dependencies() {
    print "Installing required packages: autossh and netcat-openbsd..."
    apt update -qq && apt install -y autossh netcat-openbsd
    success "Dependencies installed."
}

generate_key_if_needed() {
    KEY_FILE="/root/.ssh/id_rsa"
    if [[ ! -f "$KEY_FILE" ]]; then
        print "Generating new SSH key pair..."
        ssh-keygen -t rsa -b 4096 -f "$KEY_FILE" -N "" -q
        success "SSH key generated at $KEY_FILE"
    else
        print "SSH key already exists."
    fi
}

copy_key_to_remote() {
    print "Copying public key to remote server (you will be asked for password once)..."
    ssh-copy-id -i "${KEY_FILE}.pub" "root@${TUNNEL_VPS_IP}" -p "${TUNNEL_VPS_SSH_PORT}"
    success "Public key copied."
}

enable_gateway_ports_on_remote() {
    print "Enabling GatewayPorts on remote server..."
    ssh -p "${TUNNEL_VPS_SSH_PORT}" "root@${TUNNEL_VPS_IP}" \
        "sed -i 's/^#*GatewayPorts.*/GatewayPorts yes/' /etc/ssh/sshd_config && systemctl restart ssh"
    success "GatewayPorts enabled."
}

create_tunnel_script() {
    print "Creating persistent tunnel script at $SCRIPT_PATH..."

    cat > "$SCRIPT_PATH" << 'EOF'
#!/usr/bin/env bash
# Auto-reconnecting reverse SSH tunnel using autossh

TUNNEL_IP="${TUNNEL_VPS_IP}"
TUNNEL_PORT="${TUNNEL_VPS_SSH_PORT}"
REMOTE_LISTEN_PORT="${TUNNEL_VPS_LISTENING_PORT}"
LOCAL_PORT="${CURRENT_VPS_LISTENING_PORT}"
KEY_FILE="/root/.ssh/id_rsa"

MAX_RETRIES=20
RETRY_DELAY=8

for attempt in $(seq 1 $MAX_RETRIES); do
    echo "[Attempt $attempt/$MAX_RETRIES] Checking if port $REMOTE_LISTEN_PORT is bindable..."

    nc -l -p "$REMOTE_LISTEN_PORT" -w 3 >/dev/null 2>&1 &
    NC_PID=$!
    sleep 1.5

    if kill -0 $NC_PID 2>/dev/null; then
        kill $NC_PID 2>/dev/null
        echo "Port is free. Starting autossh..."

        exec autossh -M 0 \
            -o "ExitOnForwardFailure=yes" \
            -o "ServerAliveInterval=20" \
            -o "ServerAliveCountMax=5" \
            -o "TCPKeepAlive=yes" \
            -o "StrictHostKeyChecking=no" \
            -i "$KEY_FILE" \
            -N -R "$REMOTE_LISTEN_PORT:localhost:$LOCAL_PORT" \
            "root@$TUNNEL_IP" -p "$TUNNEL_PORT"
    else
        echo "Port still in use (TIME_WAIT?). Waiting ${RETRY_DELAY}s..."
        sleep $RETRY_DELAY
    fi
done

echo "Failed after $MAX_RETRIES attempts. Giving up."
exit 1
EOF

    chmod +x "$SCRIPT_PATH"
    success "Tunnel script created."
}

create_systemd_service() {
    print "Creating systemd service..."

    cat > "$SYSTEMD_PATH" <<EOF
[Unit]
Description=Persistent Reverse SSH Tunnel (autossh)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$SCRIPT_PATH
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=30
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME" >/dev/null 2>&1
    success "Systemd service created and started."
}

show_status() {
    print "Tunnel Service Status:"
    systemctl status "$SERVICE_NAME" --no-pager
    echo
    print "Recent Logs:"
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager
}

uninstall_tunnel() {
    warn "Uninstalling tunnel and service..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SYSTEMD_PATH"
    rm -f "$SCRIPT_PATH"
    systemctl daemon-reload
    success "Tunnel and service removed."
}

remove_packages() {
    warn "Removing installed packages: autossh and netcat-openbsd"
    apt remove -y autossh netcat-openbsd
    apt autoremove -y
    success "Packages removed."
}

main_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== Reverse SSH Tunnel Manager ===${NC}"
        echo "1) Install / Reconfigure Tunnel"
        echo "2) Show Status & Logs"
        echo "3) Uninstall Tunnel & Service"
        echo "4) Remove Installed Packages"
        echo "5) Exit"
        echo
        read -rp "Choose an option [1-5]: " choice

        case $choice in
            1) install_tunnel ;;
            2) show_status; read -rp "Press Enter to continue..." ;;
            3) uninstall_tunnel; read -rp "Press Enter to continue..." ;;
            4) remove_packages; read -rp "Press Enter to continue..." ;;
            5) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
            *) warn "Invalid choice. Try again." ;;
        esac
    done
}

install_tunnel() {
    install_dependencies
    generate_key_if_needed

    read -rp "Enter VPS (remote) IP: " TUNNEL_VPS_IP
    read -rp "Enter VPS SSH port [22]: " TUNNEL_VPS_SSH_PORT
    TUNNEL_VPS_SSH_PORT=${TUNNEL_VPS_SSH_PORT:-22}

    copy_key_to_remote
    enable_gateway_ports_on_remote

    read -rp "Enter listening port on VPS (remote port): " TUNNEL_VPS_LISTENING_PORT
    read -rp "Enter local port to forward to: " CURRENT_VPS_LISTENING_PORT

    create_tunnel_script
    create_systemd_service

    success "Setup complete!"
    echo "Service name: $SERVICE_NAME"
    echo "Check logs: journalctl -u $SERVICE_NAME -f"
    echo "Status: systemctl status $SERVICE_NAME"
}

# ──────────────────────────────────────────── Start ────────────────────────────
check_root

if [[ -f "$SYSTEMD_PATH" ]]; then
    print "Tunnel already installed. Showing menu..."
    main_menu
else
    print "No tunnel found. Starting installation..."
    install_tunnel
    main_menu
fi