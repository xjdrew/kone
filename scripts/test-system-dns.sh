#!/usr/bin/env bash
# Run only inside the CI-created mount AND network namespaces.
set -euo pipefail
if [ "${KONE_SYSTEM_DNS_TEST:-}" != 1 ] || [ "$EUID" -ne 0 ]; then
  echo 'Requires the isolated system-DNS CI harness.' >&2
  exit 1
fi
if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net)" ] || [ "$(readlink /proc/self/ns/mnt)" = "$(readlink /proc/1/ns/mnt)" ]; then
  echo 'Refusing to operate in the runner host namespaces.' >&2
  exit 1
fi
KONE_FIXTURE=$(mktemp -d)
cleanup() {
  [ -z "${KONE_RESOLVED_PID:-}" ] || kill "$KONE_RESOLVED_PID" 2>/dev/null || true
  [ -z "${KONE_BUS_PID:-}" ] || kill "$KONE_BUS_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  cat "$KONE_FIXTURE/resolved.log" 2>/dev/null || true
}
trap cleanup EXIT

# A private /run also hides the host system-bus socket even if a tool ignores
# DBUS_SYSTEM_BUS_ADDRESS. All resolver state and the local stub stay private.
mount -t tmpfs -o mode=755 tmpfs /run
mount -t sysfs sysfs /sys
mkdir -p /run/dbus /run/systemd/resolve /run/systemd/netif/links
mount -t tmpfs -o mode=755 tmpfs /etc/systemd
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/zzzzzz-kone-test.conf <<'EOF'
[Resolve]
DNSSEC=no
DNSOverTLS=no
LLMNR=no
MulticastDNS=no
Cache=no
FallbackDNS=
DNSStubListener=yes
EOF
cp /etc/passwd "$KONE_FIXTURE/passwd"
cp /etc/group "$KONE_FIXTURE/group"
if ! grep -q '^systemd-resolve:' "$KONE_FIXTURE/passwd"; then
  printf 'systemd-resolve:x:61111:61111:Private resolver:/run/systemd/resolve:/usr/sbin/nologin\n' >> "$KONE_FIXTURE/passwd"
  printf 'systemd-resolve:x:61111:\n' >> "$KONE_FIXTURE/group"
fi
mount --bind "$KONE_FIXTURE/passwd" /etc/passwd
mount --bind "$KONE_FIXTURE/group" /etc/group
chown systemd-resolve:systemd-resolve /run/systemd/resolve
printf 'nameserver 127.0.0.53\noptions timeout:1 attempts:1\n' > "$KONE_FIXTURE/resolv.conf"
KONE_RESOLV_TARGET=$(readlink -m /etc/resolv.conf)
case "$KONE_RESOLV_TARGET" in
  /run/*) mkdir -p "$(dirname "$KONE_RESOLV_TARGET")"; cp "$KONE_FIXTURE/resolv.conf" "$KONE_RESOLV_TARGET"; chown systemd-resolve:systemd-resolve "$KONE_RESOLV_TARGET" ;;
  /etc/resolv.conf) mount --bind "$KONE_FIXTURE/resolv.conf" /etc/resolv.conf ;;
  *) echo 'Unexpected resolver file location; refusing bind mount.' >&2; exit 1 ;;
esac
cat > "$KONE_FIXTURE/bus.conf" <<'EOF'
<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>
EOF
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket
dbus-daemon --nofork --nopidfile --config-file="$KONE_FIXTURE/bus.conf" > "$KONE_FIXTURE/bus.log" 2>&1 &
KONE_BUS_PID=$!
ip link set lo up
ip link add upstream-test type dummy
ip address add 192.0.2.53/24 dev upstream-test
ip link set upstream-test up
export SYSTEMD_LOG_TARGET=console
export SYSTEMD_LOG_LEVEL=debug
export SYSTEMD_RESOLVED_FALLBACK_DNS=''
"${KONE_RESOLVED_BINARY:-/usr/lib/systemd/systemd-resolved}" > "$KONE_FIXTURE/resolved.log" 2>&1 &
KONE_RESOLVED_PID=$!
for attempt in $(seq 1 100); do
  if busctl --system --no-pager call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetNameOwner s org.freedesktop.resolve1 >/dev/null 2>&1; then break; fi
  sleep 0.1
done
for stack in system mixed; do
  export KONE_SYSTEM_TEST=1 KONE_TEST_STACK="$stack"
  "$1" -test.run '^TestSystemDNSOwnedLink' -test.v -test.timeout 180s
done
