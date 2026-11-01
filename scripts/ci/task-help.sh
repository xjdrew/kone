#!/usr/bin/env bash
# Sourced by script recipes so help/argument checks precede every task action.
# Bash-only: container builds do not require Node just to use the task runner.
task_arguments() {
  local task="$1"; shift
  local usage="just ci $task" defaults='No positional arguments.' options='-h, --help' maximum=0 minimum=0
  local description example="just ci $task"
  case "$task" in
    fmt) description='Format Go source files in place.' ;;
    check-config) description='Validate a TOML configuration through the CLI without enabling capture.'; example='just ci check-config configs/kone.example.toml' ;;
    geoip-convert) description='Convert a local DB-IP CSV using explicit trusted provenance; never download data.'; example='just ci geoip-convert --input dbip-country-lite-2026-10.csv.gz --sha256 "$DBIP_SHA256" --release 2026-10 --retrieved-at 2026-11-01T00:00:00Z --output-dir dist/geoip' ;;
    web-deps) description='Install locked frontend dependencies with npm ci.' ;;
    web-dev) description='Start the frontend development server.' ;;
    web-preview) description='Serve the built frontend for local review.' ;;
    test-web) description='Run frontend unit tests.' ;;
    test-release) description='Run task contracts and release safety regression tests.' ;;
    test-tasks) description='Run task argument, help and build orchestration regressions.' ;;
    test-data) description='Test GeoIP conversion boundaries and provenance validation.' ;;
    web-build) description='Build the frontend assets embedded in the application.' ;;
    web-check) description='Reject differences between committed and rebuilt frontend assets.' ;;
    web-browsers) description='Install Playwright browsers and their required system dependencies.' ;;
    test-web-e2e) description='Run complete browser journeys, including the paused real-manager fixture and execution gate.' ;;
    test-web-e2e-mock) description='Run browser journeys against mock APIs; exclude real-manager tests and never start KONE.' ;;
    icons) description='Generate or verify canonical image assets and both Windows resource copies using pinned tools.'; example='just ci icons check' ;;
    ci-web-fixture) description='CI only: compile a console management fixture; requires RUNNER_TEMP and GITHUB_ENV.' ;;
    go-deps) description='Download Go modules declared by the project.' ;;
    go-verify) description='Verify downloaded Go modules against their checksums.' ;;
    vet) description='Run go vet across all application packages.' ;;
    test) description='Run all Go tests with the race detector and no result cache.' ;;
    test-coverage) description='Measure all-package statement coverage with the race detector.'; example='just ci test-coverage .coverage-base ../coverage-base.out' ;;
    test-mixed) description='Run Go race tests with optional gVisor mixed-stack support.' ;;
    test-pe) description='Run Windows PE-loader pointer-boundary regressions.' ;;
    test-windows-package) description='Windows only: zip, extract and copy inert fixtures using system PowerShell; never run KONE.' ;;
    test-macos-desktop) description='Run macOS menu and private-helper boundary regressions.' ;;
    coverage-check) description='Reject a full-module coverage percentage below the measured base.'; example='just ci coverage-check coverage-base.out coverage.out' ;;
    quality-check) description='Check Go formatting and module-file consistency without applying source formatting.' ;;
    fuzz) description='Fuzz strict TOML configuration parsing for a bounded duration.'; example='just ci fuzz 30s' ;;
    vuln) description='Check reachable Go dependencies with the pinned vulnerability scanner.' ;;
    benchmark-metadata) description='Record source, hardware and toolchain details for the performance baseline.' ;;
    benchmark) description='Record repeated core/GeoIP benchmarks and matching CPU/memory profiles.' ;;
    profile) description='Open a captured Go performance profile with its matching test binary.'; example='just ci profile baseline/cpu.out baseline/kone.test' ;;
    build-all) description='Cross-compile the complete release matrix and record binary roles and hashes.' ;;
    source-bundle) description='Bundle the exact source, vendored dependencies and build identity for distribution.' ;;
    package) description='CI only: package host-platform targets and validate CLI versions and temporary installation.' ;;
    build-container) description='Container-builder stage only: compile the Linux CLI into /out/kone.' ;;
    ci-macos-build) description='CI only: compile native macOS acceptance binaries in RUNNER_TEMP.' ;;
    ci-macos-tun) description='Privileged disposable macOS CI only: exercise owned utun and system DNS lifecycle.' ;;
    ci-macos-session) description='Privileged disposable macOS CI only: verify cleanup after an owned DNS session dies.' ;;
    ci-linux-build) description='CI only: compile Linux system acceptance binaries in RUNNER_TEMP.' ;;
    ci-linux-tun) description='Disposable Linux CI with sudo/unshare only: test both stacks in isolated network namespaces.' ;;
    ci-linux-dns-tools) description='CI only: verify tools needed by the private system-DNS acceptance harness.' ;;
    ci-linux-dns) description='Disposable Linux CI with sudo/unshare only: test DNS in private mount/network/D-Bus contexts.' ;;
    ci-ss) description='Disposable CI only: test Shadowsocks against a digest-pinned isolated official server container.' ;;
    ci-windows-tun) description='Administrator Windows CI only: require KONE_WINDOWS_SYSTEM_TEST=1 and a system/mixed KONE_TEST_STACK.' ;;
    docker-build) description='Build the container image from source; requires a running Docker daemon.' ;;
    docker-check) description='Validate the container configuration without enabling capture; requires the built image and Docker.' ;;
    windows-firewall-check) description='Windows only: inspect existing KONE firewall entries without changing them.' ;;
    windows-firewall-update) description='Administrator Windows only: explicitly update optional LAN firewall rules for the chosen executable.'; example='just ci windows-firewall-update -Program ./dist/kone.exe' ;;
    release-plan) description='Master release CI only: enumerate exact source SHAs using the GitHub event and repository context.' ;;
    release-marker) description='Release CI only: record successful exact RELEASE_SHA/VERSION and GitHub run/attempt evidence.' ;;
    release-publish) description='Master release CI only: verify evidence/checksums before publishing; never use for local packaging.' ;;
    release-withdraw) description='Master workflow_dispatch only: withdraw a release using the reviewed tag/reason and GitHub token.' ;;
    release-skipped) description='Print why no release was published for a failed or unavailable qualification.' ;;
    *) printf 'Unknown CI task: %s\n' "$task" >&2; exit 2 ;;
  esac
  TASK_HELP=false
  TASK_ARGS=("$@")
  TASK_ARG_COUNT=$#
  case "$task" in
    check-config) usage+=' [config]'; defaults='configs/kone.example.toml'; maximum=1; TASK_ARGS=("${1-configs/kone.example.toml}"); TASK_ARG_COUNT=1 ;;
    test-coverage) usage+=' [directory] [output]'; defaults='. coverage.out (output relative to directory)'; maximum=2; TASK_ARGS=("${1-.}" "${2-coverage.out}"); TASK_ARG_COUNT=2 ;;
    coverage-check) usage+=' [base] [head]'; defaults='coverage-base.out coverage.out'; maximum=2; TASK_ARGS=("${1-coverage-base.out}" "${2-coverage.out}"); TASK_ARG_COUNT=2 ;;
    fuzz) usage+=' [duration]'; defaults='15s'; maximum=1; TASK_ARGS=("${1-15s}"); TASK_ARG_COUNT=1 ;;
    profile) usage+=' [profile] [binary]'; defaults='baseline/cpu.out baseline/kone.test'; maximum=2; TASK_ARGS=("${1-baseline/cpu.out}" "${2-baseline/kone.test}"); TASK_ARG_COUNT=2 ;;
    geoip-convert) usage+=' <converter arguments>'; defaults='No conversion without explicit inputs; see docs/geoip.md.'; options+='; --input, --sha256, --release, --retrieved-at, --output-dir, --json'; minimum=1; maximum=100 ;;
    windows-firewall-update) usage+=' <PowerShell script arguments>'; defaults='Explicit administrator action; see docs/windows/README.md.'; options+='; -Program <path>'; minimum=1; maximum=100 ;;
    icons) usage+=' [mode]'; defaults='check'; options+='; generate | check'; maximum=1; TASK_ARGS=("${1-check}"); TASK_ARG_COUNT=1 ;;
  esac
  if [[ $# == 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    printf 'Usage: %s\n%s\nDefault: %s\nOptions: %s\nExamples:\n  %s\n  just ci %s --help\n' "$usage" "$description" "$defaults" "$options" "$example" "$task"
    TASK_HELP=true
    return
  fi
  local argument
  for argument in "$@"; do
    if [[ "$argument" == -h || "$argument" == --help ]]; then
      printf 'Help takes no other arguments. Run just ci %s --help.\n' "$task" >&2
      exit 2
    fi
  done
  if (( $# < minimum || $# > maximum )); then
    printf 'Invalid arguments. Usage: %s\nRun just ci %s --help for options.\n' "$usage" "$task" >&2
    exit 2
  fi
  if [[ "$task" == icons && "${1-check}" != check && "${1-check}" != generate ]]; then
    printf 'Icon mode must be generate or check. Run just ci icons --help.\n' >&2
    exit 2
  fi
  case "$task" in
    windows-firewall-*|test-windows-package)
      case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) ;; *) echo 'This task requires Windows. Use --help to view its usage.' >&2; exit 2 ;; esac ;;
  esac
}
