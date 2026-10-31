# 2026/10/31 — sing-tun migration and gateway compatibility
- Replace water with pinned SagerNet/sing-tun; use embedded Wintun on Windows without a preinstalled TAP adapter.
- Move production transparent TCP/UDP handling to system/mixed stacks while retaining rule/proxy snapshots, Fake-IP stability and connection shutdown behavior.
- Fix typed-nil device cleanup panics, preserve original startup errors, supervise terminal TUN I/O failures and reserve the stack forwarder address.
- Preserve Raspberry Pi/LAN gateway routing; add optional full IPv4 capture and physical-interface binding for proxy, direct and DNS transports, including proxy hostname resolution.
- Track owned Windows firewall rules and on-link routes; extend failure, flow, gateway and Wintun acceptance tests, mixed-stack race checks and ARMv7 builds.
- Adopt GPL-3.0-or-later with original MIT/component notices preserved; reorganize README around stable product capabilities and refresh configuration/deployment documentation.
- Add a developer architecture guide explaining DNS/Fake-IP, transparent TCP/UDP, gateway capture, sing-tun/gVisor boundaries, lifecycle and future optimization points.
- Retain the pinned sing-tun source with bounded PE section slices for Windows race/checkptr and immediate adapter cleanup on session failure; record patch provenance and add the upstream regression to CI.
- Accept newly created Wintun adapters with no IPv4 address when taking the initial snapshot; preserve other snapshot errors and validate the exact occupied-listener failure in acceptance tests.
- Enforce exclusive native device creation on Linux/Windows so a concurrent name-check race cannot attach an existing interface; verify the original engine remains usable after duplicate creation fails.
- Enumerate all KONE module packages explicitly for head/base coverage so the in-tree third-party module keeps the same dependency treatment; verify local upstream patches separately with race tests.
- Inject Windows DNS port conflicts on the exact new TUN address rather than relying on wildcard UDP binding behavior.
- Configure owned Wintun L3 forwarding/DAD prerequisites and restore automatic metric mode without applying an invalid manual metric value; cover rollback only for stages actually attempted.
- Add payload-free TUN header/checksum diagnostics and document the current TCP-only management traffic accounting boundary; retain owned-interface/firewall diagnostics on native acceptance failures.
- Extend the full-capture LAN scenario with an explicit DIRECT TCP exception alongside proxy, UDP and REJECT traffic.
- Create the required Windows inbound TCP exception explicitly, scoped to this executable and owned TUN address, instead of relying on upstream's silently failing COM helper; roll it back on startup failure and exit.
- Use a unique Windows firewall rule ID and remove that exact ID, retaining the upstream display name; normalize DOS 8.3 executable paths for the application filter and make absent-rule rollback idempotent.

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
