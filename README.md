# KONE

[![Master CI](https://github.com/xjdrew/kone/actions/workflows/release.yml/badge.svg?branch=master&event=push)](https://github.com/xjdrew/kone/actions/workflows/release.yml)

KONE is a TUN proxy for individual computers and Linux gateways. DNS virtual addresses (Fake-IP), routing rules and upstream proxies let applications and LAN clients use a proxy without configuring every application.

Run it on Linux, macOS or Windows, or on a Raspberry Pi serving a home or small-business network. Windows uses Wintun bundled through SagerNet/sing-tun; no separate TAP installation is needed. Creating the tunnel and changing routes require elevated privileges.

## Features

These capabilities form the compatibility baseline for future refactoring. New features should extend this list and their acceptance tests.

| ID | Capability | Current behavior |
| --- | --- | --- |
| F01 | Desktop and gateway deployment | Linux, macOS and Windows; Linux amd64, arm64 and ARMv7 builds, including Raspberry Pi gateways |
| F02 | LAN traffic takeover | Selective Fake-IP/CIDR routing or optional full IPv4 capture; clients use the gateway and KONE DNS, with forwarding and firewall rules configured by the operator |
| F03 | DNS and routing policy | Stable Fake-IP addresses; ordered domain, suffix, keyword, IPv4/IPv6 CIDR, GeoIP, DIRECT, REJECT and final rules, with protocol/port selectors and expiring domain rules |
| F04 | Outbound policy | HTTP/HTTPS CONNECT TCP, SOCKS5 TCP/UDP and Shadowsocks AEAD2017 TCP/UDP; built-in direct/reject; unsupported proxy UDP is denied unless an explicit direct fallback is configured |
| F05 | Safe rule reload | Atomic rule/proxy snapshots; virtual addresses and established connections survive reload |
| F06 | Predictable lifecycle | Startup rollback, signal/context shutdown, owned route/device cleanup and failed TUN opens without panics |
| F07 | Gateway outbound isolation | Bind proxy transports and upstream DNS to the physical interface to avoid recapture by full-tunnel routes |
| F08 | Operation and diagnostics | Persistent authenticated management, strict TOML import/validation, live business-flow observation, DNS history and independent diagnostics |
| F09 | Optional IPv6 on Linux and Windows | ULA virtual network, DNS AAAA and IPv6 capture/rules; disabled by default, with unsupported macOS activation rejected before changes |
| F10 | Owned DNS guidance | Optional Linux systemd-resolved link or macOS temporary resolver integration after listeners are ready, restored before DNS shutdown |
| F11 | Desktop lifecycle | Start with capture paused, preserve settings across restarts, and authorize a separate Windows/macOS network helper; manage capture from the native tray/menu |
| F12 | Mobile management | Responsive offline console, explicit HTTPS LAN access, expiring pairing codes, read-only defaults and revocable sessions |
| F13 | Country data updates | Bundled DB-IP Country Lite October 2026 IPv4 data, verified local imports and previous-version recovery |
| F14 | Traceable delivery | Test-gated development releases for master commits, installable packages, matching source, versions and checksums |

## Build and run

Source development uses [just](https://github.com/casey/just) 1.59.0 and Go 1.27.3. Run tasks from the repository root; Windows developers use Git Bash. Running `just` alone lists tasks without building or changing networking. See [development tasks](docs/development.md).

```sh
just build
./dist/kone
```

Starting without a configuration file opens the local management console with capture **paused**. Configure the TUN inbound, named proxy outbounds, ordered rules and DNS in the console, save the settings, then run preflight and explicitly enable capture. The profile is stored in your user configuration directory and survives restarts; no shell proxy settings are imported. Creating a TUN device and changing routes still require the appropriate host privileges. A failed proxy or preflight does not close the management console.

The eight pages provide a live traffic Sankey, connection and failure details, inbound/outbound/rule/DNS settings, independent diagnostics and network recovery. Only traffic entering KONE is observable; DNS, diagnostic and business traffic are counted separately. Saving and applying are separate actions, established connections retain their original policy, and configuration conflicts preserve the local draft.

`-manage` explicitly selects the managed profile; `-data-dir` selects its directory. `-listen` controls the managed loopback listener and `-no-browser` prints its one-time local authorization URL. The bootstrap token is removed from the browser address after exchange for an HttpOnly session cookie. Keep that initial URL private.

For a phone or tablet, enable HTTPS LAN access **on the KONE host**, choose one of its private interface addresses, download its local CA certificate and explicitly trust it on your device after checking the fingerprint. Open the displayed address and enter a short-lived pairing code. Read-only is the default; an owner can explicitly grant management access or revoke a session. KONE does not install certificates, change firewall rules or open router ports automatically. The phone displays the connected host's observations; opening the console does not route the phone's other traffic through KONE.

For a Linux gateway or an explicitly configured headless run:

```sh
cp configs/kone.example.toml config.toml
# Edit config.toml to configure your upstream proxy.
./dist/kone -check -config config.toml
sudo ./dist/kone -config config.toml
```

On Windows, use `just build dist/kone.exe` and launch it without arguments for desktop management. After `just web-deps`, `just desktop` builds the current pages and executable, then opens management with capture paused. The managed console stays at ordinary user privileges and requests a separate UAC network helper when capture needs elevation. Explicit file mode hands off to a visible administrator window when needed; services/headless callers can use `-no-elevate`. Read-only flags do not request elevation. Smart App Control trust is separate from UAC. See [desktop builds and packages](docs/development.md#桌面构建与运行) and [Windows setup](docs/windows/README.md).

On macOS, the managed console and menu bar run as the ordinary desktop user. Enabling capture requests administrator authorization for a separate network helper. See [macOS permissions](docs/macos-helper.md) and [menu bar behavior](docs/macos-tray.md).

`-check` validates configuration without creating a TUN device or changing routes. `-version` prints the version and exits successfully. `-debug` overrides the configured log level. Logs are structured text or JSON on stderr; CLI results go to stdout.

## Configuration and compatibility

Configuration is **TOML**. Declare named proxies with `[[outbounds]]`, `name` and `url`; the URL selects the proxy protocol. Rules reference a proxy name or the built-in `direct` / `reject` targets using `outbound`; these built-ins need no configuration and their names are reserved. Select `system` or `mixed` using `core.stack`. The optional `[dns]` section uses system DNS upstreams by default. Start with [the complete annotated example](configs/kone.example.toml) and [the migration guide](docs/configuration.md). For LAN traffic, follow [Raspberry Pi / Linux gateway setup](docs/guides/how-to-use-with-raspberry-pi.md).

An explicit `-config` uses headless file mode. Its legacy manager defaults to `http://127.0.0.1:9200/`; set `general.manager-addr = ""` to disable it. This listener is independent of the authenticated managed console and must remain loopback or be protected by the operator. Headless rule reload uses:

```sh
curl -X POST http://127.0.0.1:9200/reload/
```

Reload atomically publishes domain/GeoIP/default rules and outbound definitions, preserving virtual addresses. Established flows retain their original outbound. Changes to core/DNS settings, logging, manager address or CIDR routes require a restart and are rejected without modifying the active configuration.

## Current boundaries

- IPv4 DNS virtual-address routing, explicit CIDR routes and optional full IPv4 capture; Linux and Windows may explicitly opt into ULA IPv6 virtual addresses, IPv6 rules and optional full IPv6 capture. IPv6 is disabled by default and macOS activation is rejected. Full capture follows routing rules and existing more-specific system routes. LAN clients must use KONE DNS and the gateway; DHCP and firewall setup remain operator-owned.
- TCP uses the selected outbound. UDP uses direct for direct rules and always denies reject rules. SOCKS5 and supported Shadowsocks AEAD2017 outbounds carry native UDP; HTTP/HTTPS CONNECT do not. Unsupported proxy UDP is denied by default; set `udp-fallback = "direct"` only when direct UDP is intended. Shadowsocks plugins, legacy stream ciphers and AEAD-2022 are outside the supported range.
- The default `system` stack uses `just build`. Optional `mixed` (system TCP and gVisor UDP) uses `just build-mixed`, which enables `with_gvisor`; see [stack selection](docs/configuration.md#tun-backend-and-stack). Packet/fragment behavior depends on the selected stack; arbitrary fragmentation is not a compatibility guarantee yet.
- Startup failures roll back owned network changes; normal signal/context shutdown closes active flows and restores adapter settings. Forced termination cannot run cleanup. See [runtime reliability](docs/runtime.md).
- Full IPv4 capture requires `core.outbound-interface` so proxy transports and DNS leave through the physical interface. Network changes pause capture for a new preflight; the recovery journal detects leftovers and only restores resources whose ownership can be verified.
- GeoIP uses bundled DB-IP Country Lite October 2026 IPv4 data, with verified local imports and previous-version recovery. IPv6 country lookup remains outside this dataset. See [GeoIP data and attribution](docs/geoip.md).
- The explicit file mode's legacy manager has no authentication. The managed console authenticates local and mobile sessions; legacy bindings still require loopback isolation or an authenticated management layer.

## Development

Read [the architecture and core traffic paths](docs/architecture.md) for DNS/Fake-IP, TUN interception, gateway forwarding, sing-tun and gVisor's roles.

The root [justfile](justfile) is the shared development and CI entrypoint. Build, test, coverage, frontend, data conversion and release tasks are listed in [the development guide](docs/development.md). Installed KONE binaries and package installers run directly; end users do not need just.

Frontend sources build to the embedded, offline assets; building the existing assets needs no Node installation. After a frontend change, use Node 26.13.0 and run these tasks from the repository root:

```sh
just web-deps
just test-web
just web-build
just web-browsers
```

Use `just test-web-e2e` to build the local management fixture and run browser journeys, as described in [the development guide](docs/development.md#browser-journeys). They use isolated loopback API fixtures and a genuine management service with capture paused, checking real cookie authorization, credential and rule saves, reload, and persistence across process restarts. Browser tests never enable capture; real TUN acceptance runs separately in isolated/native CI. They cover all eight pages at 320px, path aggregation and fixed-window drilldown, configuration conflicts, credential preservation, read-only authorization and offline/error states. iOS Safari and Android Chrome device/network trust still need real-device acceptance.

The frontend build targets Safari/iOS 16.4, Chrome/Android 110 and Firefox 115 or later. Browser automation exercises Chromium and key touch, permission and recovery journeys in WebKit/Firefox, with engine and viewport in the report; it does not replace real iOS/Android device testing. Assets, icons and fonts do not require a public CDN. [Verified releases](docs/releases.md) describes per-commit qualification, three-platform packages, checksums, stable promotion, withdrawal and rollback; packages are currently unsigned and macOS packages are not notarized.

[System DNS guidance](docs/system-dns.md) describes the Linux/macOS integration and platform boundaries. [The acceptance index](docs/acceptance.md) links each feature to tests and remaining hardware checks; [performance baselines](docs/performance.md) distinguish synthetic counters, finite TUN samples and hardware measurements.

```sh
just test # race checks require CGO and a platform C compiler
just vet
just test-mixed
just fuzz 15s
```

CI covers native race tests, non-decreasing PR coverage, cross-platform builds, dependency checks and container smoke tests. Privileged acceptance exercises TUN lifecycle, route ownership, reload, shutdown, Windows Wintun and traffic from a separate LAN client. [CI grouping and measurements](docs/ci.md) explains the parallelism, shared build work and per-commit master qualification. Real Raspberry Pi throughput, suspend/resume and multi-VPN coexistence still need deployment-specific testing.

See [product requirements and roadmap](docs/features.md), [management UI requirements](docs/management-ui-requirements.md), [dependency decisions and remaining work](docs/engineering.md), [Raspberry Pi deployment](docs/guides/how-to-use-with-raspberry-pi.md), and [Docker deployment](deploy/docker/README.md). Older network recipes are retained under `docs/guides` as historical references.

## License

**GPL-3.0-or-later**. See [LICENSE](LICENSE). Earlier MIT notices remain in [LICENSE-MIT](LICENSE-MIT); copied components retain their own notices. Embedded Wintun binaries use the [Wintun Prebuilt Binaries License](licenses/WINTUN.txt).
