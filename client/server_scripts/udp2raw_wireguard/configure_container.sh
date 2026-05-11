mkdir -p /opt/amnezia/wireguard
cd /opt/amnezia/wireguard
WIREGUARD_SERVER_PRIVATE_KEY=$(wg genkey)
echo $WIREGUARD_SERVER_PRIVATE_KEY > /opt/amnezia/wireguard/wireguard_server_private_key.key

WIREGUARD_SERVER_PUBLIC_KEY=$(echo $WIREGUARD_SERVER_PRIVATE_KEY | wg pubkey)
echo $WIREGUARD_SERVER_PUBLIC_KEY > /opt/amnezia/wireguard/wireguard_server_public_key.key

WIREGUARD_PSK=$(wg genpsk)
echo $WIREGUARD_PSK > /opt/amnezia/wireguard/wireguard_psk.key

cat > /opt/amnezia/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = $WIREGUARD_SUBNET_IP/$WIREGUARD_SUBNET_CIDR
ListenPort = $UDP2RAW_INTERNAL_PORT
EOF

cat > /opt/amnezia/udp2raw.env <<EOF
UDP2RAW_PUBLIC_PORT=$UDP2RAW_PUBLIC_PORT
UDP2RAW_INTERNAL_PORT=$UDP2RAW_INTERNAL_PORT
UDP2RAW_PASSWORD=$UDP2RAW_PASSWORD
UDP2RAW_RAW_MODE=$UDP2RAW_RAW_MODE
EOF
