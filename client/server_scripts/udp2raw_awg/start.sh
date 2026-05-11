#!/bin/bash

echo "Container startup"

awg-quick down /opt/amnezia/awg/awg0.conf
pkill udp2raw || true

if [ -f /opt/amnezia/awg/awg0.conf ]; then (awg-quick up /opt/amnezia/awg/awg0.conf); fi

iptables -A INPUT -i awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -j ACCEPT
iptables -A OUTPUT -o awg0 -j ACCEPT

iptables -A FORWARD -i awg0 -o eth0 -s $AWG_SUBNET_IP/$WIREGUARD_SUBNET_CIDR -j ACCEPT
iptables -A FORWARD -i awg0 -o eth1 -s $AWG_SUBNET_IP/$WIREGUARD_SUBNET_CIDR -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s $AWG_SUBNET_IP/$WIREGUARD_SUBNET_CIDR -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s $AWG_SUBNET_IP/$WIREGUARD_SUBNET_CIDR -o eth1 -j MASQUERADE

iptables -A INPUT -p udp --dport $UDP2RAW_INTERNAL_PORT ! -s 127.0.0.1 -j DROP

udp2raw -s -l 0.0.0.0:$UDP2RAW_PUBLIC_PORT -r 127.0.0.1:$UDP2RAW_INTERNAL_PORT -k "$UDP2RAW_PASSWORD" --raw-mode $UDP2RAW_RAW_MODE -a &

tail -f /dev/null
