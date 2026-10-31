# KONE

[![Go](https://github.com/xjdrew/kone/actions/workflows/go.yml/badge.svg)](https://github.com/xjdrew/kone/actions/workflows/go.yml)

KONE is a TUN proxy for individual computers and Linux gateways. DNS virtual addresses (Fake-IP), routing rules and upstream proxies let applications and LAN clients use a proxy without configuring every application.

Run it on Linux, macOS or Windows, or on a Raspberry Pi serving a home or small-business network. Windows uses Wintun bundled through SagerNet/sing-tun; no separate TAP installation is needed. Creating the tunnel and changing routes require elevated privileges.

## Features

These capabilities form the compatibility baseline for future refactoring. New features should extend this list and their acceptance tests.

| ID | Capability | Current behavior |
| --- | --- | --- |
| F01 | Desktop and gateway deployment | Linux, macOS and Windows; Linux amd64, arm64 and ARMv7 builds, including Raspberry Pi gateways |
| F02 | LAN traffic takeover | Selective Fake-IP/CIDR routing or optional full IPv4 capture; clients use the gateway and KONE DNS, with forwarding and firewall rules configured by the operator |
| F03 | DNS and routing policy | Stable Fake-IP addresses; ordered domain, suffix, keyword, IPv4 CIDR, GeoIP, DIRECT, REJECT and final rules |
| F04 | Outbound policy | HTTP/HTTPS CONNECT TCP, SOCKS5 TCP/UDP and Shadowsocks AEAD2017 TCP/UDP; built-in direct/reject; unsupported proxy UDP is denied unless an explicit direct fallback is configured |
| F05 | Safe rule reload | Atomic rule/proxy snapshots; virtual addresses and established connections survive reload |
| F06 | Predictable lifecycle | Startup rollback, signal/context shutdown, owned route/device cleanup and failed TUN opens without panics |
| F07 | Gateway outbound isolation | Bind proxy transports and upstream DNS to the physical interface to avoid recapture by full-tunnel routes |
| F08 | Operation and diagnostics | Persistent authenticated management, strict TOML import/validation, live business-flow observation, DNS history and independent diagnostics |
| F09 | Optional IPv6 on Linux and Windows | ULA virtual network, DNS AAAA and IPv6 capture/rules; disabled by default, with unsupported macOS activation rejected before changes |
| F10 | Owned DNS guidance | Optional Linux systemd-resolved link integration after listeners are ready, with verified ownership and restoration before DNS shutdown |

## Build and run

Use the Go toolchain declared in [go.mod](go.mod). Run these commands from the repository root:

```sh
go build -o dist/kone ./cmd/kone
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

On Windows, build `dist/kone.exe`. Normal startup validates the configuration and requests UAC elevation when needed, handing off to a visible administrator window. Read-only flags do not request elevation; services/headless callers can use `-no-elevate`. Smart App Control trust is separate from UAC. See [Windows setup](docs/windows/README.md).

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
- The default `system` stack works with an ordinary Go build. Optional `mixed` (system TCP and gVisor UDP) requires `-tags with_gvisor`; see [stack selection](docs/configuration.md#tun-backend-and-stack). Packet/fragment behavior depends on the selected stack; arbitrary fragmentation is not a compatibility guarantee yet.
- Startup failures roll back owned network changes; normal signal/context shutdown closes active flows and restores adapter settings. Forced termination cannot run cleanup. See [runtime reliability](docs/runtime.md).
- Full IPv4 capture requires `core.outbound-interface` so proxy transports and DNS leave through the physical interface. Changing that interface requires a restart; automatic network switching and crash recovery remain future work.
- GeoIP rules currently use a bundled legacy database; database updates remain future work.
- The explicit file mode's legacy manager has no authentication. The managed console authenticates local and mobile sessions; legacy bindings still require loopback isolation or an authenticated management layer.

## Development

Read [the architecture and core traffic paths](docs/architecture.md) for DNS/Fake-IP, TUN interception, gateway forwarding, sing-tun and gVisor's roles.

Frontend sources live in `web/` and build to the embedded, offline `web/dist/` assets; an ordinary Go build needs no Node installation. After a frontend change, use Node 26.13.0 and npm to update the checked-in assets:

```sh
cd web
npm ci
npm test
npm run build
npx playwright install chromium
npm run test:e2e
```

Browser journeys run against an isolated loopback mock API and never start KONE or change host networking. They cover all eight pages at 320px, real-path aggregation and fixed-window drilldown, configuration conflicts, credential preservation, read-only authorization and offline/error states. Phone browser layouts are covered by automated browser tests; iOS Safari and Android Chrome device/network trust still need real-device acceptance.

The frontend build targets Safari/iOS 16.4, Chrome/Android 110 and Firefox 115 or later. Browser automation exercises Chromium and key touch, permission and recovery journeys in WebKit/Firefox, with engine and viewport in the report; it does not replace real iOS/Android device testing. Assets, icons and fonts do not require a public CDN. [Verified releases](docs/releases.md) describes per-commit qualification, three-platform packages, checksums, stable promotion, withdrawal and rollback; packages are currently unsigned and macOS packages are not notarized.

[System DNS guidance](docs/system-dns.md) describes the Linux opt-in and platform boundaries. [The acceptance index](docs/acceptance.md) links each feature to tests and remaining hardware checks; [performance baselines](docs/performance.md) keep synthetic recorder throughput separate from measured network performance.

```sh
go test ./...
go vet ./...
go test -race ./... # requires CGO and a platform C compiler
go test ./pkg/kone -run '^$' -fuzz '^FuzzParseConfig$' -fuzztime 15s
```

CI runs native race tests, non-decreasing PR coverage, cross-platform builds, dependency checks and container smoke tests. Privileged acceptance exercises TUN lifecycle, route ownership, reload, shutdown, Windows Wintun and traffic from a separate LAN client. Real Raspberry Pi throughput, suspend/resume and multi-VPN coexistence still need deployment-specific testing.

See [product requirements and roadmap](docs/features.md), [management UI requirements](docs/management-ui-requirements.md), [dependency decisions and remaining work](docs/engineering.md), [Raspberry Pi deployment](docs/guides/how-to-use-with-raspberry-pi.md), and [Docker deployment](deploy/docker/README.md). Older network recipes are retained under `docs/guides` as historical references.

## License

**GPL-3.0-or-later**. See [LICENSE](LICENSE). Earlier MIT notices remain in [LICENSE-MIT](LICENSE-MIT); copied components retain their own notices. Embedded Wintun binaries use the [Wintun Prebuilt Binaries License](licenses/WINTUN.txt).
