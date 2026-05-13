#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="$CONTAINER_NAME"
BASE_DIR="/opt/amnezia/$CONTAINER_NAME"
WG_DIR="$BASE_DIR/wireguard"
ENV_FILE="$BASE_DIR/udp2raw.env"
IFACE="amnwg0"
SERVICE_NAME="$CONTAINER_NAME.service"
CONFIG_FILE="$WG_DIR/$IFACE.conf"

PUBLIC_PORT="$UDP2RAW_PUBLIC_PORT"
INTERNAL_PORT="$UDP2RAW_INTERNAL_PORT"
PASSWORD="$UDP2RAW_PASSWORD"
RAW_MODE="$UDP2RAW_RAW_MODE"
SUBNET_IP="$WIREGUARD_SUBNET_IP"
SUBNET_CIDR="$WIREGUARD_SUBNET_CIDR"
SERVER_HOST="$SERVER_IP_ADDRESS"
IMPL_VERSION="$UDP2RAW_IMPL_VERSION"

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

mkdir -p "$WG_DIR"
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

cat > "$CONFIG_FILE" <<EOF_CONF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = $SERVER_INTERFACE_IP/$SUBNET_CIDR
ListenPort = $INTERNAL_PORT
EOF_CONF

cat > "$ENV_FILE" <<EOF_ENV
UDP2RAW_IMPL_VERSION=$IMPL_VERSION
UDP2RAW_NATIVE_KIND=wireguard
UDP2RAW_INTERFACE=$IFACE
SERVER_HOST=$SERVER_HOST
SERVER_INTERFACE_IP=$SERVER_INTERFACE_IP
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
CONFIG_FILE="$BASE_DIR/wireguard/$UDP2RAW_INTERFACE.conf"
CHAIN_IN="AMN_U2R_WG_IN"
CHAIN_FWD="AMN_U2R_WG_FWD"
CHAIN_NAT="AMN_U2R_WG_NAT"

delete_jump() {
  local table="$1"
  local chain="$2"
  local target="$3"
  if [ -n "$table" ]; then
    while iptables -t "$table" -C "$chain" -j "$target" >/dev/null 2>&1; do
      iptables -t "$table" -D "$chain" -j "$target" || true
    done
  else
    while iptables -C "$chain" -j "$target" >/dev/null 2>&1; do
      iptables -D "$chain" -j "$target" || true
    done
  fi
}

cleanup_rules() {
  delete_jump "" INPUT "$CHAIN_IN"
  delete_jump "" FORWARD "$CHAIN_FWD"
  delete_jump nat POSTROUTING "$CHAIN_NAT"
  iptables -F "$CHAIN_IN" >/dev/null 2>&1 || true
  iptables -X "$CHAIN_IN" >/dev/null 2>&1 || true
  iptables -F "$CHAIN_FWD" >/dev/null 2>&1 || true
  iptables -X "$CHAIN_FWD" >/dev/null 2>&1 || true
  iptables -t nat -F "$CHAIN_NAT" >/dev/null 2>&1 || true
  iptables -t nat -X "$CHAIN_NAT" >/dev/null 2>&1 || true
}

setup_rules() {
  cleanup_rules
  iptables -N "$CHAIN_IN"
  iptables -N "$CHAIN_FWD"
  iptables -t nat -N "$CHAIN_NAT"
  iptables -A "$CHAIN_IN" -i lo -p udp --dport "$UDP2RAW_INTERNAL_PORT" -j ACCEPT
  iptables -A "$CHAIN_IN" -p tcp --dport "$UDP2RAW_PUBLIC_PORT" -j ACCEPT
  iptables -A "$CHAIN_IN" -p udp --dport "$UDP2RAW_INTERNAL_PORT" -j DROP
  iptables -A "$CHAIN_IN" -i "$UDP2RAW_INTERFACE" -j ACCEPT
  iptables -A "$CHAIN_FWD" -i "$UDP2RAW_INTERFACE" -j ACCEPT
  iptables -A "$CHAIN_FWD" -o "$UDP2RAW_INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -t nat -A "$CHAIN_NAT" -s "$WIREGUARD_SUBNET_IP/$WIREGUARD_SUBNET_CIDR" ! -o "$UDP2RAW_INTERFACE" -j MASQUERADE
  iptables -I INPUT 1 -j "$CHAIN_IN"
  iptables -I FORWARD 1 -j "$CHAIN_FWD"
  iptables -t nat -I POSTROUTING 1 -j "$CHAIN_NAT"
}

cleanup_interface() {
  wg-quick down "$CONFIG_FILE" >/dev/null 2>&1 || true
  ip link delete "$UDP2RAW_INTERFACE" >/dev/null 2>&1 || true
}

stop_children() {
  if [ -f "$BASE_DIR/udp2raw.pid" ]; then
    kill "$(cat "$BASE_DIR/udp2raw.pid")" >/dev/null 2>&1 || true
    rm -f "$BASE_DIR/udp2raw.pid"
  fi
  pkill -f "udp2raw .*${UDP2RAW_PUBLIC_PORT}.*${UDP2RAW_INTERNAL_PORT}" >/dev/null 2>&1 || true
}

cleanup_all() {
  stop_children
  cleanup_interface
  cleanup_rules
}

trap cleanup_all EXIT INT TERM

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null
cleanup_all
setup_rules
wg-quick up "$CONFIG_FILE"

udp2raw -s \
  -l "0.0.0.0:$UDP2RAW_PUBLIC_PORT" \
  -r "127.0.0.1:$UDP2RAW_INTERNAL_PORT" \
  -k "$UDP2RAW_PASSWORD" \
  --raw-mode "$UDP2RAW_RAW_MODE" \
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

cat > "$SERVICE_FILE" <<EOF_UNIT
[Unit]
Description=Amnezia UDP2Raw WireGuard native host service
After=network-online.target
Wants=network-online.target

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
systemctl enable --now "$(basename "$BASE_DIR").service"
systemctl restart "$(basename "$BASE_DIR").service"
EOF_START

cat > "$BASE_DIR/stop.sh" <<'EOF_STOP'
#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$BASE_DIR/udp2raw.env"
SERVICE="$(basename "$BASE_DIR").service"
CHAIN_IN="AMN_U2R_WG_IN"
CHAIN_FWD="AMN_U2R_WG_FWD"
CHAIN_NAT="AMN_U2R_WG_NAT"
CONFIG_FILE="$BASE_DIR/wireguard/$UDP2RAW_INTERFACE.conf"

if [ "${1:-}" != "--no-systemctl" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
fi

if [ -f "$BASE_DIR/udp2raw.pid" ]; then
  kill "$(cat "$BASE_DIR/udp2raw.pid")" >/dev/null 2>&1 || true
  rm -f "$BASE_DIR/udp2raw.pid"
fi
pkill -f "udp2raw .*${UDP2RAW_PUBLIC_PORT}.*${UDP2RAW_INTERNAL_PORT}" >/dev/null 2>&1 || true
wg-quick down "$CONFIG_FILE" >/dev/null 2>&1 || true
ip link delete "$UDP2RAW_INTERFACE" >/dev/null 2>&1 || true

for spec in " INPUT $CHAIN_IN" " FORWARD $CHAIN_FWD"; do
  set -- $spec
  while iptables -C "$1" -j "$2" >/dev/null 2>&1; do iptables -D "$1" -j "$2" || true; done
  iptables -F "$2" >/dev/null 2>&1 || true
  iptables -X "$2" >/dev/null 2>&1 || true
done
while iptables -t nat -C POSTROUTING -j "$CHAIN_NAT" >/dev/null 2>&1; do iptables -t nat -D POSTROUTING -j "$CHAIN_NAT" || true; done
iptables -t nat -F "$CHAIN_NAT" >/dev/null 2>&1 || true
iptables -t nat -X "$CHAIN_NAT" >/dev/null 2>&1 || true
EOF_STOP

cat > "$BASE_DIR/remove.sh" <<'EOF_REMOVE'
#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE="$(basename "$BASE_DIR").service"
"$BASE_DIR/stop.sh" || true
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable "$SERVICE" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$SERVICE"
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
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
sysctl net.ipv4.ip_forward net.ipv4.conf.all.src_valid_mark
echo "== iptables =="
iptables -S
iptables -t nat -S
iptables -L -v -n
iptables -t nat -L -v -n
EOF_DIAG

chown -R root:root "$BASE_DIR"
chmod 700 "$BASE_DIR" "$WG_DIR" "$BASE_DIR"/*.sh
chmod 600 "$WG_DIR"/*.key "$CONFIG_FILE" "$ENV_FILE"
