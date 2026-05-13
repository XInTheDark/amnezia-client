#!/usr/bin/env bash
set -euo pipefail

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="/tmp/amnezia-server-udp2raw-diag-$STAMP"
ARCHIVE="$OUT_DIR.tar.gz"

mkdir -p "$OUT_DIR"

run() {
  local name="$1"
  shift
  {
    echo "$ $*"
    "$@" 2>&1 || true
  } > "$OUT_DIR/$name.txt"
}

run "host" sh -c 'uname -a; id; date; command -v udp2raw || true; udp2raw --help 2>&1 | head -40 || true'
run "native_dirs" sh -c 'find /opt/amnezia -maxdepth 3 -type f \( -name "udp2raw.env" -o -name "*.conf" -o -name "server_diagnostics.sh" \) -print 2>/dev/null'
run "env" sh -c 'for f in /opt/amnezia/amnezia-udp2raw-*/udp2raw.env; do [ -f "$f" ] || continue; echo "## $f"; sed "s/UDP2RAW_PASSWORD=.*/UDP2RAW_PASSWORD=<redacted>/" "$f"; done'
run "systemd" sh -c 'systemctl --no-pager status amnezia-udp2raw-wireguard.service amnezia-udp2raw-awg.service'
run "processes" ps -ef
run "listeners" sh -c 'ss -lntup; ss -lnup'
run "ip_addr" ip addr show
run "ip_route" ip route show table all
run "sysctl" sysctl net.ipv4.ip_forward net.ipv4.conf.all.src_valid_mark
run "wg" sh -c 'wg show all 2>&1 || true'
run "awg" sh -c 'awg show all 2>&1 || true'
run "iptables_rules" sh -c 'iptables -S; iptables -t nat -S'
run "iptables_counters" sh -c 'iptables -L -v -n; iptables -t nat -L -v -n'
run "docker_leftovers" sh -c 'docker ps -a --format "{{.Names}} {{.Image}} {{.Ports}} {{.Networks}}" 2>/dev/null | grep amnezia || true'

for d in /opt/amnezia/amnezia-udp2raw-wireguard /opt/amnezia/amnezia-udp2raw-awg; do
  if [ -x "$d/server_diagnostics.sh" ]; then
    "$d/server_diagnostics.sh" > "$OUT_DIR/$(basename "$d")_installed_diagnostics.txt" 2>&1 || true
  fi
done

tar -czf "$ARCHIVE" -C "$(dirname "$OUT_DIR")" "$(basename "$OUT_DIR")"
echo "$ARCHIVE"
