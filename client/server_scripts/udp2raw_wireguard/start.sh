#!/bin/bash

echo "Container startup"

wg-quick down /opt/amnezia/wireguard/wg0.conf
pkill udp2raw || true

if [ -f /opt/amnezia/wireguard/wg0.conf ]; then (wg-quick up /opt/amnezia/wireguard/wg0.conf); fi

iptables -A INPUT -i wg0 -j ACCEPT
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A OUTPUT -o wg0 -j ACCEPT

iptables -A FORWARD -i wg0 -o eth0 -s $WIREGUARD_SUBNET_IP/$WIREGUARD_SUBNET_CIDR -j ACCEPT
iptables -A FORWARD -i wg0 -o eth1 -s $WIREGUARD_SUBNET_IP/$WIREGUARD_SUBNET_CIDR -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s $WIREGUARD_SUBNET_IP/$WIREGUARD_SUBNET_CIDR -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s $WIREGUARD_SUBNET_IP/$WIREGUARD_SUBNET_CIDR -o eth1 -j MASQUERADE

iptables -A INPUT -p udp --dport $UDP2RAW_INTERNAL_PORT ! -s 127.0.0.1 -j DROP

udp2raw -s -l 0.0.0.0:$UDP2RAW_PUBLIC_PORT -r 127.0.0.1:$UDP2RAW_INTERNAL_PORT -k "$UDP2RAW_PASSWORD" --raw-mode $UDP2RAW_RAW_MODE -a &

tail -f /dev/null
