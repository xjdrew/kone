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
| F04 | Outbound policy | HTTP/HTTPS CONNECT and SOCKS5 TCP; built-in direct/reject; unsupported proxy UDP is denied unless an explicit direct fallback is configured |
| F05 | Safe rule reload | Atomic rule/proxy snapshots; virtual addresses and established connections survive reload |
| F06 | Predictable lifecycle | Startup rollback, signal/context shutdown, owned route/device cleanup and failed TUN opens without panics |
| F07 | Gateway outbound isolation | Bind proxy transports and upstream DNS to the physical interface to avoid recapture by full-tunnel routes |
| F08 | Operation and diagnostics | Strict TOML validation, checks without network changes, structured logs and local management |

## Build and run

Use the Go toolchain declared in [go.mod](go.mod). Run these commands from the repository root:

```sh
go build -o dist/kone ./cmd/kone
cp configs/kone.example.toml config.toml
# Edit config.toml to configure your upstream proxy.
./dist/kone -check -config config.toml
sudo ./dist/kone -config config.toml
```

On Windows, build `dist/kone.exe`. Normal startup validates the configuration and requests UAC elevation when needed, handing off to a visible administrator window. Read-only flags do not request elevation; services/headless callers can use `-no-elevate`. Smart App Control trust is separate from UAC. See [Windows setup](docs/windows/README.md).

`-check` validates configuration without creating a TUN device or changing routes. `-version` prints the version and exits successfully. `-debug` overrides the configured log level. Logs are structured text or JSON on stderr; CLI results go to stdout.

## Configuration and compatibility

Configuration is **TOML**. Declare named proxies with `[[outbounds]]`, `name` and `url`; the URL selects the proxy protocol. Rules reference a proxy name or the built-in `direct` / `reject` targets using `outbound`; these built-ins need no configuration and their names are reserved. Select `system` or `mixed` using `core.stack`. The optional `[dns]` section uses system DNS upstreams by default. Start with [the complete annotated example](configs/kone.example.toml) and [the migration guide](docs/configuration.md). For LAN traffic, follow [Raspberry Pi / Linux gateway setup](docs/guides/how-to-use-with-raspberry-pi.md).

The manager defaults to `http://127.0.0.1:9200/`. Set `general.manager-addr = ""` to disable it. Configuration pages redact proxy credentials. Rule reload uses:

```sh
curl -X POST http://127.0.0.1:9200/reload/
```

Reload atomically publishes domain/GeoIP/default rules and outbound definitions, preserving virtual addresses. Established flows retain their original outbound. Changes to core/DNS settings, logging, manager address or CIDR routes require a restart and are rejected without modifying the active configuration.

## Current boundaries

- IPv4 DNS virtual-address routing, explicit CIDR routes and optional full IPv4 route capture. Full capture still follows DIRECT/REJECT/proxy rules and existing more-specific system routes. LAN clients must use KONE DNS and the gateway; DHCP and firewall setup remain operator-owned.
- TCP uses the selected outbound. UDP uses direct for direct rules and always denies reject rules. Current proxies have no UDP support, so proxy UDP is denied by default; set the proxy's optional `udp-fallback = "direct"` only when direct UDP is intended. SOCKS5 UDP ASSOCIATE and IPv6 interception are not implemented.
- The default `system` stack works with an ordinary Go build. Optional `mixed` (system TCP and gVisor UDP) requires `-tags with_gvisor`; see [stack selection](docs/configuration.md#tun-backend-and-stack). Packet/fragment behavior depends on the selected stack; arbitrary fragmentation is not a compatibility guarantee yet.
- Startup failures roll back owned network changes; normal signal/context shutdown closes active flows and restores adapter settings. Forced termination cannot run cleanup. See [runtime reliability](docs/runtime.md).
- Full IPv4 capture requires `core.outbound-interface` so proxy transports and DNS leave through the physical interface. Changing that interface requires a restart; automatic network switching and crash recovery remain future work.
- GeoIP rules currently use a bundled legacy database; database updates remain future work.
- The manager has no authentication. Keep its default loopback binding or isolate it with an authenticated management layer.

## Development

Read [the architecture and core traffic paths](docs/architecture.md) for DNS/Fake-IP, TUN interception, gateway forwarding, sing-tun and gVisor's roles.

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
