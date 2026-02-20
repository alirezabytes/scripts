#!/bin/bash

# FRP Pure TCP Tunnel Setup Script (Menu-Driven) - No TLS / Raw TCP
# With Uninstall Option
# Designed for Iran server -> Germany OCserv tunnel
# Works on Ubuntu 24.04+

set -e

FRP_VERSION="0.67.0"  # Latest as of now - update if needed (check https://github.com/fatedier/frp/releases)
FRP_URL="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_amd64.tar.gz"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/frp"
TMP_FILE="/tmp/frp_${FRP_VERSION}_linux_amd64.tar.gz"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}FRP Pure TCP (No TLS) Setup Script - Menu Driven with Uninstall${NC}"
echo "This will install FRP in raw TCP mode (transport.tls.enable = false)"
echo ""

download_frp() {
    if [ ! -f "$TMP_FILE" ]; then
        echo "Downloading FRP v${FRP_VERSION}..."
        wget -q --show-progress "${FRP_URL}" -O "$TMP_FILE"
    fi
    tar -xzf "$TMP_FILE" -C /tmp
}

install_binaries() {
    download_frp
    cd "/tmp/frp_${FRP_VERSION}_linux_amd64"
    sudo mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}"
    sudo cp frps frpc "${INSTALL_DIR}/"
    echo -e "${GREEN}FRP binaries installed.${NC}"
}

create_server_config() {
    local bind_port="$1"
    local token="$2"

    cat <<EOL | sudo tee "${CONFIG_DIR}/frps.toml"
# FRP Server - Pure TCP, No TLS
[common]
bindPort = ${bind_port}
auth.method = "token"
auth.token = "${token}"

transport.tls.enable = false
transport.maxPoolCount = 100
EOL

    echo -e "${GREEN}Server config created: ${CONFIG_DIR}/frps.toml${NC}"
}

create_client_config() {
    local server_ip="$1"
    local server_port="$2"
    local token="$3"
    local remote_port="$4"
    local local_ocserv_port="${5:-443}"

    cat <<EOL | sudo tee "${CONFIG_DIR}/frpc.toml"
# FRP Client - Pure TCP, No TLS
[common]
serverAddr = "${server_ip}"
serverPort = ${server_port}
auth.method = "token"
auth.token = "${token}"

transport.tls.enable = false
transport.maxPoolCount = 50

[ocserv]
type = tcp
localIP = 127.0.0.1
localPort = ${local_ocserv_port}
remotePort = ${remote_port}
EOL

    echo -e "${GREEN}Client config created: ${CONFIG_DIR}/frpc.toml${NC}"
}

setup_systemd_service() {
    local service_name="$1"
    local exec_bin="$2"
    local config_file="$3"

    cat <<EOL | sudo tee "/etc/systemd/system/${service_name}.service"
[Unit]
Description=FRP ${service_name^} - Pure TCP Tunnel
After=network.target

[Service]
ExecStart=${exec_bin} -c ${config_file}
Restart=always
RestartSec=5
User=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOL

    sudo systemctl daemon-reload
    sudo systemctl enable --now "${service_name}"
    echo -e "${GREEN}${service_name^} service enabled and started.${NC}"
    echo "Check status: sudo systemctl status ${service_name}"
}

uninstall_frp() {
    echo -e "${YELLOW}Uninstalling FRP Completely...${NC}"
    echo -e "${RED}This will STOP and REMOVE frps/frpc services, binaries, configs, and temp files.${NC}"
    echo -n "Are you sure? (y/N): "
    read confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Uninstall cancelled."
        return
    fi

    # Stop and disable services if exist
    for svc in frps frpc; do
        if systemctl is-active --quiet "$svc"; then
            sudo systemctl stop "$svc"
        fi
        if systemctl is-enabled --quiet "$svc"; then
            sudo systemctl disable "$svc"
        fi
        if [ -f "/etc/systemd/system/${svc}.service" ]; then
            sudo rm -f "/etc/systemd/system/${svc}.service"
        fi
    done

    sudo systemctl daemon-reload
    sudo systemctl reset-failed

    # Remove binaries
    sudo rm -f "${INSTALL_DIR}/frps" "${INSTALL_DIR}/frpc"

    # Remove config dir
    sudo rm -rf "${CONFIG_DIR}"

    # Remove temp download
    rm -f "$TMP_FILE"
    rm -rf "/tmp/frp_${FRP_VERSION}_linux_amd64"

    echo -e "${GREEN}Uninstall complete!${NC}"
    echo "FRP binaries, configs, services removed."
    echo "You may need to manually close any open ports if needed (ufw delete allow ...)"
}

show_menu() {
    echo ""
    echo "Select mode:"
    echo "1) Setup FRP Server (Iran side)"
    echo "2) Setup FRP Client (Germany side)"
    echo "3) Exit"
    echo "4) Uninstall FRP Completely"
    echo -n "Enter choice [1-4]: "
    read choice
}

main() {
    while true; do
        show_menu

        case $choice in
            1)
                echo -e "${YELLOW}Setting up FRP Server (Iran)${NC}"
                install_binaries

                echo -n "Enter bind port for frps (default 7000): "
                read bind_port
                bind_port=${bind_port:-7000}

                echo -n "Enter auth token (make it strong): "
                read token
                if [ -z "$token" ]; then
                    echo -e "${RED}Token is required!${NC}"
                    continue
                fi

                create_server_config "$bind_port" "$token"
                setup_systemd_service "frps" "${INSTALL_DIR}/frps" "${CONFIG_DIR}/frps.toml"

                echo -e "${GREEN}Server setup complete!${NC}"
                echo "Clients connect to your Iran IP:${bind_port}"
                echo "Remember: sudo ufw allow ${bind_port}/tcp if firewall active"
                ;;
            2)
                echo -e "${YELLOW}Setting up FRP Client (Germany)${NC}"
                install_binaries

                echo -n "Enter Iran server IP: "
                read server_ip
                if [ -z "$server_ip" ]; then
                    echo -e "${RED}IP is required!${NC}"
                    continue
                fi

                echo -n "Enter Iran bind port (default 7000): "
                read server_port
                server_port=${server_port:-7000}

                echo -n "Enter auth token (same as server): "
                read token
                if [ -z "$token" ]; then
                    echo -e "${RED}Token is required!${NC}"
                    continue
                fi

                echo -n "Enter remote port on Iran side (e.g. 8443): "
                read remote_port
                if [ -z "$remote_port" ]; then
                    echo -e "${RED}Remote port required!${NC}"
                    continue
                fi

                echo -n "Enter local OCserv port (default 443): "
                read local_port
                local_port=${local_port:-443}

                create_client_config "$server_ip" "$server_port" "$token" "$remote_port" "$local_port"
                setup_systemd_service "frpc" "${INSTALL_DIR}/frpc" "${CONFIG_DIR}/frpc.toml"

                echo -e "${GREEN}Client setup complete!${NC}"
                echo "Users in Iran connect to: ${server_ip}:${remote_port}"
                ;;
            3)
                echo -e "${GREEN}Exiting...${NC}"
                exit 0
                ;;
            4)
                uninstall_frp
                ;;
            *)
                echo -e "${RED}Invalid choice!${NC}"
                ;;
        esac

        echo ""
        echo -n "Press Enter to continue or Ctrl+C to exit..."
        read dummy
    done
}

# Start the script
main