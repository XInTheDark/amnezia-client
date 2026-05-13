#!/usr/bin/env bash
set -euo pipefail

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${TMPDIR:-/tmp}/amnezia-udp2raw-diag-$STAMP"
ARCHIVE="$OUT_DIR.tar.gz"
APP_PATH="${AMNEZIA_APP_PATH:-/Applications/AmneziaVPN.app}"
SERVICE_BIN="$APP_PATH/Contents/MacOS/AmneziaVPN-service"
APP_BIN="$APP_PATH/Contents/MacOS/AmneziaVPN"

mkdir -p "$OUT_DIR"

run() {
  local name="$1"
  shift
  {
    echo "$ $*"
    "$@" 2>&1 || true
  } > "$OUT_DIR/$name.txt"
}

capture_uuid() {
  local name="$1"
  local path="$2"
  {
    echo "path=$path"
    if [ -e "$path" ]; then
      dwarfdump --uuid "$path" 2>/dev/null || true
      shasum -a 256 "$path" 2>/dev/null || true
    else
      echo "missing"
    fi
  } > "$OUT_DIR/$name.txt"
}

capture_uuid "app_uuid" "$APP_BIN"
capture_uuid "service_uuid" "$SERVICE_BIN"
run "processes" ps axww -o pid,ppid,user,stat,command
run "udp2raw_process" pgrep -af "udp2raw_mp|udp2raw"
run "wg_process" pgrep -af "wireguard-go|amneziawg-go"
run "daemon_status" sh -c 'printf "{\"type\":\"status\"}\n" | nc -U /var/run/amneziavpn/daemon.socket'
run "routes_v4" netstat -rn -f inet
run "routes_v6" netstat -rn -f inet6
run "route_default" route -n get default
run "route_google" route -n get google.com
run "dns" scutil --dns
run "networksetup_dns" sh -c 'networksetup -listallnetworkservices | sed "s/^\\*//" | while read -r svc; do [ -n "$svc" ] && { echo "## $svc"; networksetup -getdnsservers "$svc"; }; done'
run "runtime_amneziavpn" sh -c 'ls -la /var/run/amneziavpn 2>/dev/null; find /var/run/amneziavpn -maxdepth 1 -type f -print -exec sh -c "echo --- {}; sed -n '\''1,80p'\'' {} 2>/dev/null" \;'
run "runtime_amneziawg" sh -c 'ls -la /var/run/amneziawg 2>/dev/null; find /var/run/amneziawg -maxdepth 1 -type f -print'
run "sockets" lsof -nP -iTCP -iUDP
run "crash_reports" sh -c 'ls -lt /Library/Logs/DiagnosticReports/*Amnezia* ~/Library/Logs/DiagnosticReports/*Amnezia* 2>/dev/null | head -40'

mkdir -p "$OUT_DIR/crash_reports"
find /Library/Logs/DiagnosticReports "$HOME/Library/Logs/DiagnosticReports" -maxdepth 1 -type f -name '*Amnezia*' -mtime -2 -exec cp {} "$OUT_DIR/crash_reports/" \; 2>/dev/null || true

log show --last 30m --style syslog --predicate 'process CONTAINS "Amnezia" OR eventMessage CONTAINS "udp2raw" OR eventMessage CONTAINS "amneziawg" OR eventMessage CONTAINS "wireguard"' > "$OUT_DIR/unified_logs.txt" 2>&1 || true

tar -czf "$ARCHIVE" -C "$(dirname "$OUT_DIR")" "$(basename "$OUT_DIR")"
echo "$ARCHIVE"
