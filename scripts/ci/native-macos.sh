#!/usr/bin/env bash
# CI only. Keep the caller's source checkout and existing runner environment.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'Usage: native-macos.sh build|tun|session' >&2
  exit 2
fi
case "$1" in
  build|tun|session) ;;
  *) echo 'Unknown native macOS action.' >&2; exit 2 ;;
esac
if [[ "${GITHUB_ACTIONS:-}" != true ]]; then
  echo 'Native macOS acceptance is restricted to disposable GitHub Actions runners.' >&2
  exit 1
fi
if [[ "$(uname -s)" != Darwin || "${RUNNER_TEMP:-}" != /* || ! -d "${RUNNER_TEMP:-}" ]]; then
  echo 'Requires a macOS runner and an existing absolute RUNNER_TEMP.' >&2
  exit 1
fi

case "$1" in
  build)
    go test -tags with_gvisor -race -c -o "$RUNNER_TEMP/kone-darwin-system.test" ./test/integration
    go test -tags with_gvisor -race -c -o "$RUNNER_TEMP/kone-darwin-dns-session.test" ./pkg/kone
    "$RUNNER_TEMP/kone-darwin-system.test" -test.list '^TestSystemDarwinUTUN$' | grep -qx TestSystemDarwinUTUN
    "$RUNNER_TEMP/kone-darwin-system.test" -test.list '^TestSystemDarwinDNSGuidance$' | grep -qx TestSystemDarwinDNSGuidance
    if [[ -f test/integration/ipv6_darwin_test.go ]]; then
      "$RUNNER_TEMP/kone-darwin-system.test" -test.list '^TestSystemDarwinIPv6$' | grep -qx TestSystemDarwinIPv6
    fi
    "$RUNNER_TEMP/kone-darwin-dns-session.test" -test.list '^TestDarwinOwnedSystemDNSSessionDeath$' | grep -qx TestDarwinOwnedSystemDNSSessionDeath
    ;;
  tun)
    output="$RUNNER_TEMP/native-macos.log"
    sudo -n env KONE_DARWIN_SYSTEM_TEST=1 KONE_DARWIN_DNS_SYSTEM_TEST=1 "$RUNNER_TEMP/kone-darwin-system.test" -test.run '^TestSystemDarwin(UTUN|DNSGuidance|IPv6)$' -test.v -test.timeout 8m 2>&1 | tee "$output"
    stacks=(system mixed)
    if [[ -f pkg/kone/stack_modes.go ]]; then stacks=(system gvisor mixed); fi
    for stack in "${stacks[@]}"; do
      for case in fake-ip-tcp-udp occupied-dns occupied-dns-tcp route-failure-preserves-owner; do
        grep -Fq -- "--- PASS: TestSystemDarwinUTUN/$stack/$case (" "$output"
      done
      for failure in false true; do
        grep -Fq -- "--- PASS: TestSystemDarwinDNSGuidance/$stack/late-failure=$failure (" "$output"
      done
      if [[ -f test/integration/ipv6_darwin_test.go ]]; then
        for case in proxy-tcp-udp direct-tcp-udp udp6-rollback tcp6-rollback route-rollback owned-routes-restore; do
          grep -Fq -- "--- PASS: TestSystemDarwinIPv6/$stack/$case (" "$output"
        done
      fi
    done
    ;;
  session)
    sudo -n env KONE_DARWIN_DNS_SYSTEM_TEST=1 "$RUNNER_TEMP/kone-darwin-dns-session.test" -test.run '^TestDarwinOwnedSystemDNSSessionDeath$' -test.v -test.timeout 1m 2>&1 | tee "$RUNNER_TEMP/native-macos-session.log"
    grep -Fq -- '--- PASS: TestDarwinOwnedSystemDNSSessionDeath (' "$RUNNER_TEMP/native-macos-session.log"
    ;;
esac
