# 2026/10/31 — runtime reliability
- Add context-owned startup, cancellation, idempotent close and reverse-order network rollback; propagate component and cleanup failures.
- Restore Windows adapter DNS/DHCP/MTU/metric and remove only owned addresses/routes; isolate newly created Linux/macOS devices.
- Publish immutable, versioned rule/proxy/config snapshots; cancel DNS and proxy handshakes and drain active TCP/UDP flows on exit.
- Bound management statistics and direct DNS caches; add fault injection, concurrent state tests and isolated real Linux TUN/signal end-to-end checks.
- Ensure half-closed TCP requests can receive responses; bound active TLS shutdown and verify UDP worker drainage.
- Move dnsconfig sources, fixtures and tests into pkg/dnsconfig; preserve upstream/Go license notices and remove the external module dependency.
- Remove goodbye in favor of standard signal/context lifecycle; verify testify is already at latest stable release v1.12.1.

# 2026/10/31 — engineering foundation
- Simplify development rules; require CHANGELOG updates, unit/end-to-end tests and non-decreasing coverage.
- Add a PR coverage gate against the exact target commit using full-project statement counts, duplicate-block merging and exact fraction comparison.
- Go 1.27.3 across module, CI and Docker; native Windows/macOS/Linux CI and six build targets.
- Move implementation to pkg/, examples to configs/, deployment assets to deploy/ and docs/.
- Replace INI with strict TOML (breaking configuration change) and go-logging with structured slog.
- Upgrade maintained dependencies and replace custom SOCKS5 handshake with x/net/proxy.
- Validate configuration before system changes; add non-privileged -check and successful -version.
- Fix missing proxy map panic, NAT flow collisions, malformed packet crashes, reload bypass loss and stale DNS policy.
- Add regression, race, fuzz, CLI and container checks; preserve virtual addresses during rule reload.
- Bound domain suffix matching, preserve DIRECT CIDR priority, redact configuration credentials and require POST reload.

# 2023/12/26
- [x] feat: upgrade to surge like config
- [x] feat: support windows 10
- [x] tech: merge proxy code
- [x] feat: reload rule by manager: curl http://127.0.0.1:9200/reload
- [x] tech: use system dns config as default

# plan
- [ ] feat: default hijack dns query
- [ ] feat: show process name of network
- [ ] bug: traffic will be endless loop if proxy's ip use proxy by rule
- [ ] feat: support ss protocol
- [ ] feat: support IPv6
- [ ] feat: update GEOIP database
- [ ] feat: record all dns query
- [ ] feat: support for internal domain name resolution
