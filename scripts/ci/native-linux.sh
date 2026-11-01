#!/usr/bin/env bash
# CI only. Run from the source checkout under test, which may be a historical ref.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'Usage: native-linux.sh build|tun|dns-tools|dns' >&2
  exit 2
fi
case "$1" in
  build|tun|dns-tools|dns) ;;
  *) echo 'Unknown native Linux action.' >&2; exit 2 ;;
esac
if [[ "${GITHUB_ACTIONS:-}" != true ]]; then
  echo 'Native Linux acceptance is restricted to disposable GitHub Actions runners.' >&2
  exit 1
fi
if [[ "$(uname -s)" != Linux || "${RUNNER_TEMP:-}" != /* || ! -d "${RUNNER_TEMP:-}" ]]; then
  echo 'Requires a Linux runner and an existing absolute RUNNER_TEMP.' >&2
  exit 1
fi

case "$1" in
  build)
    entry=./cmd/kone
    if [[ -d cmd/kone-cli ]]; then entry=./cmd/kone-cli; fi
    go build -tags with_gvisor -race -o "$RUNNER_TEMP/kone-system-cli" "$entry"
    go test -tags with_gvisor -race -c -o "$RUNNER_TEMP/kone-system.test" ./test/integration
    ;;
  tun)
    baseline="$RUNNER_TEMP/native-data-plane-baseline"
    mkdir -p "$baseline"
    {
      git rev-parse HEAD
      go version
      uname -a
      getconf _NPROCESSORS_ONLN
      lscpu
      head -n 5 /proc/meminfo
      printf 'build flags: with_gvisor -race; namespaces: isolated per stack\n'
    } > "$baseline/environment.txt"
    stacks=(system mixed)
    if [[ -f pkg/kone/stack_modes.go ]]; then stacks=(system gvisor mixed); fi
    for stack in "${stacks[@]}"; do
      sudo unshare --net -- bash -c '
        set -e
        ip link set lo up
        export KONE_SYSTEM_TEST=1
        export KONE_SYSTEM_CLI="$1"
        export KONE_TEST_STACK="$3"
        "$2" -test.run "^TestSystem(Lifecycle|Gateway|DNS|IPv6|Performance)" -test.v -test.timeout 180s
      ' -- "$RUNNER_TEMP/kone-system-cli" "$RUNNER_TEMP/kone-system.test" "$stack" | tee "$baseline/$stack.log"
      for test in TestSystemLifecyclePortFailure TestSystemLifecycleRouteFailure TestSystemLifecycleExclusiveDevice TestSystemLifecycleConcurrentClose TestSystemLifecycleTrafficAndReload TestSystemLifecycleCLISignal TestSystemGatewayLANFullCapture TestSystemIPv6FakeAAAAProxyTCPAndUDP TestSystemIPv6FakeAAAADirectUsesRealAAAAAndUDP6 TestSystemIPv6ListenerAndRouteFailureRestore TestSystemPerformanceBaseline; do
        grep -Fq -- "--- PASS: $test (" "$baseline/$stack.log"
      done
    done
    ;;
  dns-tools)
    command -v busctl
    command -v resolvectl
    command -v dbus-daemon
    test -x /usr/lib/systemd/systemd-resolved
    ;;
  dns)
    # Resolve the isolated fixture from the tested checkout, not this wrapper.
    sudo env KONE_SYSTEM_DNS_TEST=1 unshare --mount --net --propagation private --fork -- bash scripts/test-system-dns.sh "$RUNNER_TEMP/kone-system.test"
    ;;
esac
