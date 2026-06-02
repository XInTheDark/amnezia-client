#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="$CONTAINER_NAME"
BASE_DIR="/opt/amnezia/$CONTAINER_NAME"
AWG_DIR="$BASE_DIR/awg"
ENV_FILE="$BASE_DIR/udp2raw.env"
IFACE="amnawg0"
SERVICE_NAME="$CONTAINER_NAME.service"
CONFIG_FILE="$AWG_DIR/$IFACE.conf"

PUBLIC_PORT="$UDP2RAW_PUBLIC_PORT"
INTERNAL_PORT="$UDP2RAW_INTERNAL_PORT"
PASSWORD="$UDP2RAW_PASSWORD"
RAW_MODE="$UDP2RAW_RAW_MODE"
SUBNET_IP="$AWG_SUBNET_IP"
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
    apt-get install -yq curl tar iptables iproute2 software-properties-common gnupg
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl tar iptables iproute
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl tar iptables iproute
  elif command -v zypper >/dev/null 2>&1; then
    zypper -n install curl tar iptables iproute2
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm --noprogressbar curl tar iptables iproute2
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

install_awg_tools() {
  if command -v awg >/dev/null 2>&1 && command -v awg-quick >/dev/null 2>&1; then
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    if command -v add-apt-repository >/dev/null 2>&1; then
      add-apt-repository -y ppa:amnezia/ppa || true
      apt-get update -yq || true
      apt-get install -yq amneziawg amneziawg-tools || true
    fi
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y amneziawg-tools || true
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm --noprogressbar amneziawg-tools || true
  fi

  if ! command -v awg >/dev/null 2>&1 || ! command -v awg-quick >/dev/null 2>&1; then
    echo "AmneziaWG host tools are missing. Install awg and awg-quick on the server, then retry."
    exit 1
  fi
}

install_packages
install_udp2raw
install_awg_tools
modprobe amneziawg >/dev/null 2>&1 || true

mkdir -p "$AWG_DIR"
chmod 700 "$BASE_DIR"

if [ ! -f "$AWG_DIR/wireguard_server_private_key.key" ]; then
  awg genkey > "$AWG_DIR/wireguard_server_private_key.key"
fi
WIREGUARD_SERVER_PRIVATE_KEY="$(cat "$AWG_DIR/wireguard_server_private_key.key")"
echo "$WIREGUARD_SERVER_PRIVATE_KEY" | awg pubkey > "$AWG_DIR/wireguard_server_public_key.key"

if [ ! -f "$AWG_DIR/wireguard_psk.key" ]; then
  awg genpsk > "$AWG_DIR/wireguard_psk.key"
fi

SERVER_INTERFACE_IP="$(first_host "$SUBNET_IP")"

cat > "$CONFIG_FILE" <<EOF_CONF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = $SERVER_INTERFACE_IP/$SUBNET_CIDR
ListenPort = $INTERNAL_PORT
Jc = $JUNK_PACKET_COUNT
Jmin = $JUNK_PACKET_MIN_SIZE
Jmax = $JUNK_PACKET_MAX_SIZE
S1 = $INIT_PACKET_JUNK_SIZE
S2 = $RESPONSE_PACKET_JUNK_SIZE
S3 = $COOKIE_REPLY_PACKET_JUNK_SIZE
S4 = $TRANSPORT_PACKET_JUNK_SIZE
H1 = $INIT_PACKET_MAGIC_HEADER
H2 = $RESPONSE_PACKET_MAGIC_HEADER
H3 = $UNDERLOAD_PACKET_MAGIC_HEADER
H4 = $TRANSPORT_PACKET_MAGIC_HEADER
# I1 = $SPECIAL_JUNK_1
# I2 = $SPECIAL_JUNK_2
# I3 = $SPECIAL_JUNK_3
# I4 = $SPECIAL_JUNK_4
# I5 = $SPECIAL_JUNK_5
EOF_CONF

cat > "$ENV_FILE" <<EOF_ENV
UDP2RAW_IMPL_VERSION=$IMPL_VERSION
UDP2RAW_NATIVE_KIND=awg
UDP2RAW_INTERFACE=$IFACE
SERVER_HOST=$SERVER_HOST
SERVER_INTERFACE_IP=$SERVER_INTERFACE_IP
AWG_SUBNET_IP=$SUBNET_IP
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
CONFIG_FILE="$BASE_DIR/awg/$UDP2RAW_INTERFACE.conf"

iptables_delete() {
  local table="$1"
  shift
  if [ "$table" = "filter" ]; then
    while iptables -C "$@" >/dev/null 2>&1; do
      iptables -D "$@" || true
    done
  else
    while iptables -t "$table" -C "$@" >/dev/null 2>&1; do
      iptables -t "$table" -D "$@" || true
    done
  fi
}

cleanup_rules() {
  iptables_delete filter INPUT -i lo -p udp --dport "$UDP2RAW_INTERNAL_PORT" -j ACCEPT
  iptables_delete filter INPUT -p tcp --dport "$UDP2RAW_PUBLIC_PORT" -j ACCEPT
  iptables_delete filter INPUT -p udp --dport "$UDP2RAW_INTERNAL_PORT" -j DROP
  iptables_delete filter FORWARD -i "$UDP2RAW_INTERFACE" -j ACCEPT
  iptables_delete filter FORWARD -o "$UDP2RAW_INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables_delete nat POSTROUTING -s "$AWG_SUBNET_IP/$WIREGUARD_SUBNET_CIDR" -j MASQUERADE
}

setup_rules() {
  cleanup_rules
  iptables -I INPUT 1 -p udp --dport "$UDP2RAW_INTERNAL_PORT" -j DROP
  iptables -I INPUT 1 -p tcp --dport "$UDP2RAW_PUBLIC_PORT" -j ACCEPT
  iptables -I INPUT 1 -i lo -p udp --dport "$UDP2RAW_INTERNAL_PORT" -j ACCEPT
  iptables -I FORWARD 1 -o "$UDP2RAW_INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -I FORWARD 1 -i "$UDP2RAW_INTERFACE" -j ACCEPT
  iptables -t nat -I POSTROUTING 1 -s "$AWG_SUBNET_IP/$WIREGUARD_SUBNET_CIDR" -j MASQUERADE
}

cleanup_interface() {
  awg-quick down "$CONFIG_FILE" >/dev/null 2>&1 || true
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
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null || true
cleanup_all
setup_rules
awg-quick up "$CONFIG_FILE"
sysctl -w "net.ipv4.conf.$UDP2RAW_INTERFACE.rp_filter=0" >/dev/null || true

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
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_FILE="/etc/systemd/system/$(basename "$BASE_DIR").service"

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required for native UDP2Raw lifecycle"
  exit 1
fi

cat > "$SERVICE_FILE" <<EOF_UNIT
[Unit]
Description=Amnezia UDP2Raw AmneziaWG native host service
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
CONFIG_FILE="$BASE_DIR/awg/$UDP2RAW_INTERFACE.conf"

iptables_delete() {
  local table="$1"
  shift
  if [ "$table" = "filter" ]; then
    while iptables -C "$@" >/dev/null 2>&1; do iptables -D "$@" || true; done
  else
    while iptables -t "$table" -C "$@" >/dev/null 2>&1; do iptables -t "$table" -D "$@" || true; done
  fi
}

if [ "${1:-}" != "--no-systemctl" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
fi

if [ -f "$BASE_DIR/udp2raw.pid" ]; then
  kill "$(cat "$BASE_DIR/udp2raw.pid")" >/dev/null 2>&1 || true
  rm -f "$BASE_DIR/udp2raw.pid"
fi
pkill -f "udp2raw .*${UDP2RAW_PUBLIC_PORT}.*${UDP2RAW_INTERNAL_PORT}" >/dev/null 2>&1 || true
awg-quick down "$CONFIG_FILE" >/dev/null 2>&1 || true
ip link delete "$UDP2RAW_INTERFACE" >/dev/null 2>&1 || true

iptables_delete filter INPUT -i lo -p udp --dport "$UDP2RAW_INTERNAL_PORT" -j ACCEPT
iptables_delete filter INPUT -p tcp --dport "$UDP2RAW_PUBLIC_PORT" -j ACCEPT
iptables_delete filter INPUT -p udp --dport "$UDP2RAW_INTERNAL_PORT" -j DROP
iptables_delete filter FORWARD -i "$UDP2RAW_INTERFACE" -j ACCEPT
iptables_delete filter FORWARD -o "$UDP2RAW_INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables_delete nat POSTROUTING -s "$AWG_SUBNET_IP/$WIREGUARD_SUBNET_CIDR" -j MASQUERADE
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
ps -ef | grep -E 'udp2raw|awg-quick|amnawg0' | grep -v grep
echo "== listeners =="
ss -lntup
ss -lnup
echo "== routes =="
ip addr show
ip route show table all
echo "== awg =="
awg show all
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
chmod 700 "$BASE_DIR" "$AWG_DIR" "$BASE_DIR"/*.sh
chmod 600 "$AWG_DIR"/*.key "$CONFIG_FILE" "$ENV_FILE"
