#!/usr/bin/env bash

if [ $EUID != 0 ]; then
        echo "The script must be run by root previlage"
	exit
fi

# Function for generating new ssh key
generate_key(){
	ssh-keygen -t rsa -f $KEY_FILE -q -N ""
	echo -e "New SSH Key generated!\n"
}

# Function for print colored text
printc() {
    local text="$1"
    local color="$2"
    echo -e "\e[${color}m${text}\e[0m\n"
}

SERVICE_NAME="reverse_ssh_tunnel"

if [ -n "$1" ]; then
        SERVICE_NAME="$1"
fi

KEY_FILE="/root/.ssh/id_rsa"
REVERSE_TUNNEL_BASHFILE_PATH="/usr/local/bin/$SERVICE_NAME.sh"

printc "\n\nReverse SSH Tunnel\nby: milad ebrahimi" "31"

if [ -e $KEY_FILE ]; then
	echo -e "SSH Key created already\n"
else
	generate_key
fi

read -p "Enter tunnel vps ip: " TUNNEL_VPS_IP
printc "VPS Tunnel IP: $TUNNEL_VPS_IP" "32"

read -p "Enter tunnel vps ssh port: " TUNNEL_VPS_SSH_PORT
printc "VPS Tunnel SSH Port: $TUNNEL_VPS_SSH_PORT" "32"

#read -p "Enter tunnel vps password: " TUNNEL_VPS_PASSWORD
#printc "VPS Tunnel Password: $TUNNEL_VPS_PASSWORD" "32"
printc "Enter tunnel vps password for installing ssh key" "32"

ssh-copy-id -p $TUNNEL_VPS_SSH_PORT root@$TUNNEL_VPS_IP

ssh -p $TUNNEL_VPS_SSH_PORT root@$TUNNEL_VPS_IP "sed -i -E '/^\s*#?\s*GatewayPorts/ { s/^#//; s/\bno\b/yes/ }' /etc/ssh/sshd_config; service ssh restart;"

read -p "Enter tunnel vps listening port: " TUNNEL_VPS_LISTENING_PORT
printc "VPS Tunnel Listening Port: $TUNNEL_VPS_LISTENING_PORT" "32"

read -p "Enter which port should be forward: " CURRENT_VPS_LISTENING_PORT
printc "Listen From $TUNNEL_VPS_IP:$TUNNEL_VPS_LISTENING_PORT And Forward to Port: $CURRENT_VPS_LISTENING_PORT" "32"

echo "#!/bin/bash

# Variables
TUNNEL_SSH_PORT=$TUNNEL_VPS_SSH_PORT
TUNNEL_IP=$TUNNEL_VPS_IP
TUNNEL_LISTEN_PORT=$TUNNEL_VPS_LISTENING_PORT
CURRENT_LISTEN_PORT=$CURRENT_VPS_LISTENING_PORT

# Establish reverse SSH tunnel
/usr/bin/ssh -N -R \$TUNNEL_LISTEN_PORT:localhost:\$CURRENT_LISTEN_PORT root@\$TUNNEL_IP -p \$TUNNEL_SSH_PORT" > "$REVERSE_TUNNEL_BASHFILE_PATH"

chmod +x $REVERSE_TUNNEL_BASHFILE_PATH

echo "[Unit]
Description=Reverse SSH Tunnel.
After=network.target

[Service]
#Restart=on-failure
Restart=always
RestartSec=10
ExecStart="$REVERSE_TUNNEL_BASHFILE_PATH"

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/${SERVICE_NAME}.service

systemctl daemon-reload

systemctl enable ${SERVICE_NAME}

systemctl start ${SERVICE_NAME}

systemctl status ${SERVICE_NAME}

#printc "Operation Successfully!" "32"
