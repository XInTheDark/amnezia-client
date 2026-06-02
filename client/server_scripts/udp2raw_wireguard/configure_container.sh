#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="$CONTAINER_NAME"
BASE_DIR="/opt/amnezia/$CONTAINER_NAME"
WG_DIR="$BASE_DIR/wireguard"
ENV_FILE="$BASE_DIR/udp2raw.env"
IFACE="amnwg0"
SERVICE_NAME="$CONTAINER_NAME.service"
WG_QUICK_CONFIG_FILE="/etc/wireguard/$IFACE.conf"
CONFIG_FILE="$WG_DIR/$IFACE.conf"

PUBLIC_PORT="$UDP2RAW_PUBLIC_PORT"
INTERNAL_PORT="$UDP2RAW_INTERNAL_PORT"
PASSWORD="$UDP2RAW_PASSWORD"
RAW_MODE="$UDP2RAW_RAW_MODE"
SUBNET_IP="$WIREGUARD_SUBNET_IP"
SUBNET_CIDR="$WIREGUARD_SUBNET_CIDR"
SERVER_HOST="$SERVER_IP_ADDRESS"
IMPL_VERSION="$UDP2RAW_IMPL_VERSION"

default_interface() {
  ip -4 route list default 2>/dev/null | awk '{print $5; exit}'
}

first_host() {
  local ip="$1"
  local a b c d
  IFS=. read -r a b c d <<EOF_IP
$ip
EOF_IP
  echo "$a.$b.$c.$((d + 1))"
}

install_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -yq
    apt-get install -yq curl tar iptables iproute2 wireguard-tools
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl tar iptables iproute wireguard-tools
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl tar iptables iproute wireguard-tools
  elif command -v zypper >/dev/null 2>&1; then
    zypper -n install curl tar iptables iproute2 wireguard-tools
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm --noprogressbar curl tar iptables iproute2 wireguard-tools
  else
    echo "Packet manager not found"
    exit 1
  fi
}

install_udp2raw() {
  if command -v udp2raw >/dev/null 2>&1; then
    return
  fi

  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "Unsupported udp2raw server architecture: $(uname -m)"; exit 1 ;;
  esac

  local tmp
  tmp="$(mktemp -d)"
  curl -fsSL "https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz" -o "$tmp/udp2raw.tar.gz"
  tar -xzf "$tmp/udp2raw.tar.gz" -C "$tmp"
  local bin
  bin="$(find "$tmp" -type f \( -name "udp2raw_$arch" -o -name "udp2raw_${arch}_*" \) | head -n 1)"
  if [ -z "$bin" ]; then
    echo "udp2raw binary for $arch not found in release archive"
    exit 1
  fi
  install -m 0755 "$bin" /usr/local/bin/udp2raw
  rm -rf "$tmp"
}

install_packages
install_udp2raw
modprobe wireguard >/dev/null 2>&1 || true

mkdir -p "$WG_DIR" /etc/wireguard
chmod 700 "$BASE_DIR"

if [ ! -f "$WG_DIR/wireguard_server_private_key.key" ]; then
  wg genkey > "$WG_DIR/wireguard_server_private_key.key"
fi
WIREGUARD_SERVER_PRIVATE_KEY="$(cat "$WG_DIR/wireguard_server_private_key.key")"
echo "$WIREGUARD_SERVER_PRIVATE_KEY" | wg pubkey > "$WG_DIR/wireguard_server_public_key.key"

if [ ! -f "$WG_DIR/wireguard_psk.key" ]; then
  wg genpsk > "$WG_DIR/wireguard_psk.key"
fi

SERVER_INTERFACE_IP="$(first_host "$SUBNET_IP")"
SERVER_PUB_NIC="$(default_interface)"
if [ -z "$SERVER_PUB_NIC" ]; then
  echo "Default network interface not found"
  exit 1
fi

cat > "$WG_QUICK_CONFIG_FILE" <<EOF_CONF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = $SERVER_INTERFACE_IP/$SUBNET_CIDR
ListenPort = $INTERNAL_PORT
PostUp = iptables -A INPUT -p tcp --dport $PUBLIC_PORT -j ACCEPT; iptables -A INPUT -i lo -p udp --dport $INTERNAL_PORT -j ACCEPT; iptables -A INPUT ! -i lo -p udp --dport $INTERNAL_PORT -j DROP; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s $SUBNET_IP/$SUBNET_CIDR -o $SERVER_PUB_NIC -j MASQUERADE
PostDown = iptables -D INPUT -p tcp --dport $PUBLIC_PORT -j ACCEPT; iptables -D INPUT -i lo -p udp --dport $INTERNAL_PORT -j ACCEPT; iptables -D INPUT ! -i lo -p udp --dport $INTERNAL_PORT -j DROP; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s $SUBNET_IP/$SUBNET_CIDR -o $SERVER_PUB_NIC -j MASQUERADE
EOF_CONF
ln -sfn "$WG_QUICK_CONFIG_FILE" "$CONFIG_FILE"

cat > "$ENV_FILE" <<EOF_ENV
UDP2RAW_IMPL_VERSION=$IMPL_VERSION
UDP2RAW_NATIVE_KIND=wireguard
UDP2RAW_INTERFACE=$IFACE
SERVER_HOST=$SERVER_HOST
SERVER_INTERFACE_IP=$SERVER_INTERFACE_IP
SERVER_PUB_NIC=$SERVER_PUB_NIC
WIREGUARD_SUBNET_IP=$SUBNET_IP
WIREGUARD_SUBNET_CIDR=$SUBNET_CIDR
UDP2RAW_PUBLIC_PORT=$PUBLIC_PORT
UDP2RAW_INTERNAL_PORT=$INTERNAL_PORT
UDP2RAW_PASSWORD=$PASSWORD
UDP2RAW_RAW_MODE=$RAW_MODE
EOF_ENV
chmod 600 "$ENV_FILE"

cat > "$BASE_DIR/run-service.sh" <<'EOF_RUN'
#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$BASE_DIR/udp2raw.env"

stop_children() {
  if [ -f "$BASE_DIR/udp2raw.pid" ]; then
    kill "$(cat "$BASE_DIR/udp2raw.pid")" >/dev/null 2>&1 || true
    rm -f "$BASE_DIR/udp2raw.pid"
  fi
  pkill -f "udp2raw .*${UDP2RAW_PUBLIC_PORT}.*${UDP2RAW_INTERNAL_PORT}" >/dev/null 2>&1 || true
}

cleanup_all() {
  stop_children
}

trap cleanup_all EXIT INT TERM

cleanup_all

udp2raw -s \
  -l "0.0.0.0:$UDP2RAW_PUBLIC_PORT" \
  -r "127.0.0.1:$UDP2RAW_INTERNAL_PORT" \
  -k "$UDP2RAW_PASSWORD" \
  --raw-mode "$UDP2RAW_RAW_MODE" \
  --cipher-mode xor \
  -a &
echo "$!" > "$BASE_DIR/udp2raw.pid"
wait "$(cat "$BASE_DIR/udp2raw.pid")"
EOF_RUN

cat > "$BASE_DIR/start.sh" <<'EOF_START'
#!/usr/bin/env bash
set -euo pipefail
SERVICE_NAME="$(basename "$0")"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_FILE="/etc/systemd/system/$(basename "$BASE_DIR").service"

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required for native UDP2Raw lifecycle"
  exit 1
fi

. "$BASE_DIR/udp2raw.env"
WG_QUICK_SERVICE="wg-quick@$UDP2RAW_INTERFACE.service"

cat > /etc/sysctl.d/99-amnezia-udp2raw-wireguard.conf <<EOF_SYSCTL
net.ipv4.ip_forward=1
net.ipv4.conf.all.src_valid_mark=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF_SYSCTL
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null || true

cat > "$SERVICE_FILE" <<EOF_UNIT
[Unit]
Description=Amnezia UDP2Raw WireGuard native host service
After=network-online.target $WG_QUICK_SERVICE
Wants=network-online.target $WG_QUICK_SERVICE
Requires=$WG_QUICK_SERVICE

[Service]
Type=simple
ExecStart=$BASE_DIR/run-service.sh
ExecStop=$BASE_DIR/stop.sh --no-systemctl
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF_UNIT

systemctl daemon-reload
systemctl enable --now "$WG_QUICK_SERVICE"
systemctl restart "$WG_QUICK_SERVICE"
sysctl -w "net.ipv4.conf.$UDP2RAW_INTERFACE.rp_filter=0" >/dev/null || true
systemctl enable --now "$(basename "$BASE_DIR").service"
systemctl restart "$(basename "$BASE_DIR").service"
EOF_START

cat > "$BASE_DIR/stop.sh" <<'EOF_STOP'
#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$BASE_DIR/udp2raw.env"
SERVICE="$(basename "$BASE_DIR").service"
WG_QUICK_SERVICE="wg-quick@$UDP2RAW_INTERFACE.service"

if [ "${1:-}" != "--no-systemctl" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  systemctl stop "$WG_QUICK_SERVICE" >/dev/null 2>&1 || true
fi

if [ -f "$BASE_DIR/udp2raw.pid" ]; then
  kill "$(cat "$BASE_DIR/udp2raw.pid")" >/dev/null 2>&1 || true
  rm -f "$BASE_DIR/udp2raw.pid"
fi
pkill -f "udp2raw .*${UDP2RAW_PUBLIC_PORT}.*${UDP2RAW_INTERNAL_PORT}" >/dev/null 2>&1 || true

if [ "${1:-}" != "--no-systemctl" ]; then
  wg-quick down "$UDP2RAW_INTERFACE" >/dev/null 2>&1 || true
  ip link delete "$UDP2RAW_INTERFACE" >/dev/null 2>&1 || true
fi
EOF_STOP

cat > "$BASE_DIR/remove.sh" <<'EOF_REMOVE'
#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE="$(basename "$BASE_DIR").service"
"$BASE_DIR/stop.sh" || true
. "$BASE_DIR/udp2raw.env"
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable "$SERVICE" >/dev/null 2>&1 || true
  systemctl disable "wg-quick@$UDP2RAW_INTERFACE.service" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$SERVICE"
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
rm -f "/etc/wireguard/$UDP2RAW_INTERFACE.conf"
rm -f /etc/sysctl.d/99-amnezia-udp2raw-wireguard.conf
rm -rf "$BASE_DIR"
EOF_REMOVE

cat > "$BASE_DIR/server_diagnostics.sh" <<'EOF_DIAG'
#!/usr/bin/env bash
set +e
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$BASE_DIR/udp2raw.env"
echo "== udp2raw env =="
sed 's/UDP2RAW_PASSWORD=.*/UDP2RAW_PASSWORD=<redacted>/' "$BASE_DIR/udp2raw.env"
echo "== systemd =="
systemctl --no-pager status "$(basename "$BASE_DIR").service"
systemctl --no-pager status "wg-quick@$UDP2RAW_INTERFACE.service"
echo "== processes =="
ps -ef | grep -E 'udp2raw|wg-quick|amnwg0' | grep -v grep
echo "== listeners =="
ss -lntup
ss -lnup
echo "== routes =="
ip addr show
ip route show table all
echo "== wg =="
wg show all
echo "== sysctl =="
sysctl net.ipv4.ip_forward net.ipv4.conf.all.src_valid_mark net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter "net.ipv4.conf.$UDP2RAW_INTERFACE.rp_filter"
echo "== iptables =="
iptables -S
iptables -t nat -S
iptables -t mangle -S
iptables -L -v -n
iptables -t nat -L -v -n
iptables -t mangle -L -v -n
EOF_DIAG

chown -R root:root "$BASE_DIR"
chmod 700 "$BASE_DIR" "$WG_DIR" "$BASE_DIR"/*.sh
chmod 600 "$WG_DIR"/*.key "$WG_QUICK_CONFIG_FILE" "$ENV_FILE"
