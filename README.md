# KONE

[![Go](https://github.com/xjdrew/kone/actions/workflows/go.yml/badge.svg)](https://github.com/xjdrew/kone/actions/workflows/go.yml)

KONE routes selected traffic through HTTP, HTTPS CONNECT or SOCKS5 proxies using DNS virtual addresses and a TUN interface. It supports Linux, macOS and Windows (Windows requires an existing TAP-Windows adapter).

## Build and run

Use **Go 1.27.3**. Run these commands from the repository root:

```sh
go build -o dist/kone ./cmd/kone
cp configs/kone.example.toml config.toml
# Edit config.toml to configure your upstream proxy.
./dist/kone -check -config config.toml
sudo ./dist/kone -config config.toml
```

On Windows, build `dist/kone.exe` and run it from an administrator terminal. See [Windows setup](docs/windows/README.md).

`-check` validates configuration without creating a TUN device or changing routes. `-version` prints the version and exits successfully. `-debug` overrides the configured log level. Logs are structured text or JSON on stderr; CLI results go to stdout.

## Configuration and compatibility

Configuration is now **TOML**; INI is no longer supported. Start with [the annotated example](configs/kone.example.toml) and [the migration guide](docs/configuration.md). Go imports moved from the module root to `github.com/xjdrew/kone/pkg/kone` (and `pkg/proxy`, `pkg/tcpip`, `pkg/geoip`).

The manager defaults to `http://127.0.0.1:9200/`. Set `general.manager-addr = ""` to disable it. Configuration pages redact proxy credentials. Rule reload uses:

```sh
curl -X POST http://127.0.0.1:9200/reload/
```

Reload supports domain/GeoIP/default policy changes, preserving virtual addresses while updating cached policy. Changes to core settings, proxy definitions, logging, manager address or CIDR routes require a restart and are rejected without modifying the active configuration.

## Current boundaries

- IPv4 DNS virtual-address routing and explicitly configured CIDR routes; automatic full-system DNS/route takeover is future work. Linux/macOS clients must be configured to query KONE's DNS address.
- TCP uses the configured proxy. UDP currently connects directly to the resolved destination; SOCKS5 UDP ASSOCIATE is not implemented. IPv6 interception is not supported and `IP-CIDR6` rules are rejected.
- IPv4 fragments are dropped because reassembly is not implemented.
- System-network rollback and coordinated component shutdown remain the next engineering milestone. Upstream proxy IPs must not be captured by configured CIDR routes; complete outbound bypass is still pending.
- The manager has no authentication. Keep its default loopback binding or isolate it with an authenticated management layer.

## Development

```sh
go test ./...
go vet ./...
go test -race ./... # requires CGO and a platform C compiler
go test ./pkg/tcpip -run '^$' -fuzz '^FuzzParseIPv4$' -fuzztime 15s
```

CI runs native tests and the race detector on Linux, macOS and Windows, builds amd64/arm64 binaries, scans dependencies and smoke-tests the container. It does not replace privileged TUN/route tests on real machines.

```text
cmd/kone/          CLI
pkg/kone/          engine, configuration, DNS, NAT and management
pkg/proxy/         upstream proxy adapters
pkg/tcpip/         validated IPv4 packet views
pkg/geoip/         GeoIP lookup and legacy generated database
configs/           example TOML
test/integration/  CLI tests without network administration privileges
docs/              configuration, dependency decisions and deployment guides
scripts/windows/  firewall helpers
deploy/docker/    container build and Compose configuration
```

Unit tests live beside the packages they test; cross-package CLI tests live under `test/integration`.

See [dependency decisions and remaining work](docs/engineering.md), [Raspberry Pi deployment](docs/guides/how-to-use-with-raspberry-pi.md), and [Docker deployment](deploy/docker/README.md). Older network recipes are retained under `docs/guides` as historical references.

## License

MIT. Copyright (c) 2016 xjdrew.
