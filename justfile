# Windows: run with Git Bash on PATH. CI uses just 1.59.0.
set minimum-version := '1.59.0'
set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

# Keep orchestration at the entrypoint revision; commands operate on the selected source.
export KONE_TASK_ROOT := justfile_directory()
export KONE_TASK_BINARY := if os() == 'windows' { 'dist/kone.exe' } else { 'dist/kone' }

# List available tasks without building or changing system networking.
default:
    @just --justfile "$KONE_TASK_ROOT/justfile" --list

# Build the default system-stack CLI.
[group('development')]
build output=KONE_TASK_BINARY:
    bash "$KONE_TASK_ROOT/scripts/ci/build.sh" system "$1"

# Build with the optional mixed stack.
[group('development')]
build-mixed output=KONE_TASK_BINARY:
    bash "$KONE_TASK_ROOT/scripts/ci/build.sh" mixed "$1"

# Build and explicitly open local management with capture paused.
[group('development')]
desktop: web-build build
    "./$KONE_TASK_BINARY"

# Format Go sources.
[group('development')]
fmt:
    gofmt -w cmd pkg test web/embed.go

# Validate TOML configuration without enabling capture.
[group('development')]
check-config config='configs/kone.example.toml':
    go run ./cmd/kone -check -config "$1"

# Convert a local DB-IP CSV and record provenance; see docs/geoip.md for arguments.
[group('development')]
geoip-convert +args:
    node scripts/data/convert-dbip.mjs "$@"

[group('web')]
web-deps:
    cd web && npm ci

[group('web')]
web-dev:
    cd web && npm run dev

[group('web')]
web-preview:
    cd web && npm run preview

[group('web')]
test-web:
    cd web && npm test

[group('web')]
test-release: test-tasks
    node --test test/release/*.test.mjs

# Task contracts belong to the orchestration revision, including historical replay.
[group('web')]
test-tasks:
    node --test "$KONE_TASK_ROOT"/test/tasks/*.test.mjs

[group('web')]
test-data:
    node --test scripts/data/*.test.mjs

[group('web')]
web-build:
    cd web && npm run build

[group('web')]
web-check:
    git diff --exit-code -- web/dist

[group('web')]
web-browsers:
    cd web && npx playwright install --with-deps chromium webkit firefox

[group('web')]
test-web-e2e:
    bash "$KONE_TASK_ROOT/scripts/ci/web-e2e.sh"

[group('web')]
ci-web-fixture:
    bash "$KONE_TASK_ROOT/scripts/ci/web-fixture.sh"

[group('go')]
go-deps:
    go mod download

[group('go')]
go-verify:
    go mod verify

[group('go')]
vet:
    go vet ./...

[group('go')]
test:
    go test -race -count=1 ./...

# Measure all-package statement coverage, including an exact base checkout.
[group('go')]
test-coverage directory='.' output='coverage.out':
    bash "$KONE_TASK_ROOT/scripts/ci/go-coverage.sh" "$1" "$2"

[group('go')]
test-mixed:
    go test -tags with_gvisor -race -count=1 ./...

[group('go')]
test-pe:
    go test -race -count=1 github.com/sagernet/sing-tun/internal/wintun github.com/sagernet/sing-tun/internal/wintun/memmod

# Exercise ZIP, extraction and temporary installation with Windows PowerShell 5.1.
[group('windows maintenance')]
[windows]
test-windows-package:
    node --test "$KONE_TASK_ROOT/test/integration/windows-package.test.mjs"

[group('go')]
test-macos-desktop:
    go test -v -count=1 ./pkg/desktop -run '^TestDarwin(NativeTray(Selectors|PipeEOF)|AuthenticatedPrivateHelperLifecycleWithoutNetworkChanges)$'

[group('go')]
coverage-check base='coverage-base.out' head='coverage.out':
    go run ./cmd/covercheck -base "$1" -head "$2"

[group('quality')]
quality-check:
    bash "$KONE_TASK_ROOT/scripts/ci/go-quality.sh"

[group('quality')]
fuzz duration='15s':
    go test ./pkg/kone -run '^$' -fuzz '^FuzzParseConfig$' -fuzztime "$1"

[group('quality')]
vuln:
    go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

[group('quality')]
benchmark-metadata:
    node "$KONE_TASK_ROOT/scripts/ci/benchmark-metadata.mjs"

# Three core/GeoIP samples and one matching CPU/memory profile.
[group('quality')]
benchmark:
    bash "$KONE_TASK_ROOT/scripts/ci/benchmark.sh"

# Inspect a retained CPU or memory profile with its matching test program.
[group('quality')]
profile file='baseline/cpu.out' binary='baseline/kone.test':
    go tool pprof "$2" "$1"

# Seven release targets; two concurrent compilers, ARMv7 uses system stack.
[group('build')]
build-all:
    bash "$KONE_TASK_ROOT/scripts/ci/build-all.sh"

[group('build')]
source-bundle:
    bash "$KONE_TASK_ROOT/scripts/ci/source-bundle.sh"

[group('build')]
package:
    node scripts/release/package.mjs

# Build all targets and create this host's unsigned packages without publishing.
[group('build')]
package-local: web-build
    bash "$KONE_TASK_ROOT/scripts/ci/package-local.sh"

# Container builder stage only; does not run KONE.
[group('build')]
build-container:
    CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" go build -tags with_gvisor -trimpath -ldflags='-s -w' -o /out/kone ./cmd/kone

[group('native CI')]
ci-macos-build:
    bash "$KONE_TASK_ROOT/scripts/ci/native-macos.sh" build

[group('native CI')]
ci-macos-tun:
    bash "$KONE_TASK_ROOT/scripts/ci/native-macos.sh" tun

[group('native CI')]
ci-macos-session:
    bash "$KONE_TASK_ROOT/scripts/ci/native-macos.sh" session

[group('native CI')]
ci-linux-build:
    bash "$KONE_TASK_ROOT/scripts/ci/native-linux.sh" build

[group('native CI')]
ci-linux-tun:
    bash "$KONE_TASK_ROOT/scripts/ci/native-linux.sh" tun

[group('native CI')]
ci-linux-dns-tools:
    bash "$KONE_TASK_ROOT/scripts/ci/native-linux.sh" dns-tools

[group('native CI')]
ci-linux-dns:
    bash "$KONE_TASK_ROOT/scripts/ci/native-linux.sh" dns

[group('native CI')]
ci-ss:
    bash scripts/test-shadowsocks-interop.sh

[group('native CI')]
ci-windows-tun:
    pwsh -NoLogo -NoProfile -File "$KONE_TASK_ROOT/scripts/ci/native-windows.ps1" tun

[group('container')]
docker-build:
    docker build -f deploy/docker/Dockerfile -t kone:ci .

[group('container')]
docker-check:
    docker run --rm kone:ci -check -config /etc/kone/config.toml

# Inspect the optional LAN firewall rules; requires the Windows NetSecurity module.
[group('windows maintenance')]
[windows]
windows-firewall-check:
    powershell.exe -NoLogo -NoProfile -File scripts/windows/check-firewall-rules.ps1

# Explicitly update optional LAN firewall rules; run from an elevated terminal.
[group('windows maintenance')]
[windows]
windows-firewall-update +args:
    powershell.exe -NoLogo -NoProfile -File scripts/windows/update-firewall-rules.ps1 "$@"

[group('release')]
release-plan:
    node scripts/release/plan.mjs

[group('release')]
release-marker:
    node scripts/release/marker.mjs

[group('release')]
release-publish:
    node scripts/release/publish.mjs

[group('release')]
release-withdraw:
    node scripts/release/withdraw.mjs

[group('release')]
release-skipped:
    @printf '%s\n' 'Required gates failed or evidence is unavailable for this SHA; no tag or release was created.'
