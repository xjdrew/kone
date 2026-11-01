# Using KONE

KONE routes traffic through a virtual network interface. It can run on an individual computer or on a Linux gateway serving LAN clients. Start with desktop management for interactive use, or use a TOML file for an explicitly configured gateway/headless deployment.

## Download and install

Download a platform package from [Releases](https://github.com/xjdrew/kone/releases) and verify its checksum before installation. Installed binaries and package installers run directly; end users do not need Go, Node or just.

| Platform | Available packages |
| --- | --- |
| Linux amd64, arm64 | `.deb` |
| macOS amd64, arm64 | Unsigned `.pkg` |
| Windows amd64, arm64 | Portable ZIP with a per-user `install.ps1` |

Packages are unsigned, and macOS packages are not notarized. The macOS package includes `Kone.app` and the `kone-cli` console entrypoint. Platform security and application-control policies still apply. An architecture being cross-compiled does not prove its driver, desktop or installation behavior on real hardware. See [release verification and native coverage](releases.md).

Published releases contain these six platform/architecture targets. A 64-bit Raspberry Pi can use Linux arm64; 32-bit gateways remain supported through an explicit source build with `just build-all --include-armv7` or local packaging with `just package-all --include-armv7`. Local `package-all` also retains portable archives for review; those extra archives are not the published package set.

Locally generated packages are experimental and unverified: packaging only creates files and does not run or temporarily install the executable. Published release evidence separately records the checks actually performed in CI.

Installation does not enable capture, create services, configure autostart or change system networking. User settings are stored separately and survive application upgrades. Before replacing or uninstalling a running version, pause capture and exit normally; see [upgrade and rollback](releases.md#withdrawal-and-rollback).

## Desktop management

Double-click `kone.exe` on Windows or open `Kone.app` on macOS. These desktop entrypoints show a tray/menu icon without a console or automatic browser window; choose **Open management**. On Linux, run `kone` without arguments. Set a management password on first use. Capture starts **paused**, with a prepared TUN inbound, direct policy and system DNS discovery. Configure the needed outbounds/rules and select **Start capture**; initial direct-only operation requires one short confirmation. Preflight and safe cleanup happen automatically, with details in runtime logs. See the [desktop guide](desktop.md). A failed proxy or preflight keeps management available.

Settings persist in an independent profile in your user configuration directory. Managed mode does not read the working directory's `config.toml` or import terminal proxy settings. With the console entrypoint (`kone-cli.exe` on Windows, `kone-cli` on macOS, `kone` on Linux), `-manage` explicitly selects managed mode, `-data-dir` selects its profile and `-listen` selects the loopback listener. Console `-no-browser` prints the local entry URL. On first use it includes a one-time password-setup proof: keep it private. Once a password is set, local links require password authentication; the browser uses an HttpOnly cookie. Desktop entrypoints discard bootstrap output and use the tray's explicit browser action instead.

Windows keeps management at ordinary user privileges and requests a separate UAC network helper when capture needs elevation. Wintun is included; no separate TAP installation is required. Use an explicit `kone.exe` path when working beside an older extensionless binary. See [Windows setup and application trust](windows/README.md).

On macOS, management and the native menu bar run as the ordinary desktop user. Enabling capture requests authorization for a separate network helper. See [macOS permissions](macos-helper.md) and [menu bar behavior](macos-tray.md).

Use the tray/menu or management interface to pause capture or exit. Normal shutdown releases owned resources. Forced process termination cannot run cleanup; recovery only restores resources whose ownership can be verified. See [runtime reliability](runtime.md).

Console pages update automatically. Login and session checking hide management navigation and controls until authentication completes. **Settings** uses grouped menu lists with About first, dedicated configuration subpages, and reset/logout at the bottom. Unsaved edits require confirmation before leaving a subpage. Password changes require the current password and revoke other sessions and pairing codes. A full reset is available only locally while capture is paused, and cleans up safe leftovers automatically; it restores capture settings, GeoIP and LAN access defaults, preserves the management password and local login, and leaves capture paused. Historical backups are retained; undo can restore previously confirmed capture settings, but cannot guarantee recovery of never-started edits. Exported TOML omits proxy credentials.

Editors use compact forms with **Save** and **Cancel**, automatic validation on save, and expandable advanced options. The outbound editor provides protocol, server, port and authentication fields, with an editable generated name. Existing credentials remain private: leave both fields blank to preserve them, enter both to replace them, or explicitly clear authentication. Changing an authenticated endpoint requires replacing or clearing its credentials. An explicit test can check a draft without saving it. After saving, a suggestion offers a connection test; saving alone sends no probe.

The outbound list keeps built-in direct and reject targets at the top with read-only details. Each outbound shows its saved-rule reference count, including explicit FINAL and expired rules; an implicit default fallback is not counted as a saved rule.

**Add rule** defaults to matching a domain across TCP/UDP and all ports; advanced conditions narrow that scope. Each matcher has its own input guidance, including country choices for GeoIP and address/prefix inputs for CIDR. **FINAL** has a fixed group below ordinary rules and only its fallback outbound is edited; an omitted FINAL appears as built-in direct until explicitly saved. Simulations identify the matched rule or FINAL without resolving DNS or testing connectivity. Legacy conditional FINAL rules require confirmation before their scope is expanded.

When IPv6 capture is enabled, intercepted domains use Fake-AAAA as well as IPv4 Fake-IP. With IPv6 capture disabled, their client AAAA queries return an empty successful response instead of real addresses that could bypass domain policy; direct domains and protected proxy endpoints retain real resolution. This applies to DNS queries through KONE and does not clear client caches or existing connections.

Connection tests expand an inline panel with live stages and separate endpoint, proxy protocol and target TLS results. Connection latency measures the actual TCP endpoint connection, including endpoint name resolution. UDP remains unverified without a UDP round trip. A UDP fallback selector appears after an explicit test establishes a protocol limitation. New Web-managed outbounds explicitly default to direct fallback; existing policies remain unchanged. File-mode outbounds with no fallback still reject unsupported UDP.

## Traffic and diagnostics

Management shows business connections, traffic paths, DNS history, routing decisions and connection failures. Only traffic entering KONE is observable. DNS queries, diagnostic probes and business flows are different measurements; opening management does not make KONE observe all host traffic.

Independent diagnostics support TCP/optional TLS and UDP DNS-response checks through direct, SOCKS5 or Shadowsocks. UDP requires an explicitly chosen DNS server and a matching response; DNS response codes and truncation do not imply application success. HTTP proxy UDP tests never fall back to direct. See [diagnostic scope and limits](diagnostics.md).

Diagnostics also shows bounded, redacted recent runtime logs with level/source filters. Management startup produces logs before capture starts; preflight, automatic cleanup, helper progress, capture readiness and shutdown appear at the default INFO level. Operational lifecycle events are retained independently of the engine diagnostic level; a display filter cannot recover debug records that were never collected. Capture telemetry can be unavailable while management stays reachable; the page identifies stale snapshots without disabling management as if the connection had been lost. Tray capture failures open diagnostics and show a desktop notice without terminating management.

The compact log table also supports time ranges and 50/100/200-record pages. Automatic updates preserve filters, expanded fields and the reading position; historical pages stay fixed and offer a return to the latest records. Real outbound connection failures are recorded at ERROR and remain visible at the default INFO level. Log history is bounded and is not a persistent audit archive. See [diagnostics and log query parameters](diagnostics.md).

Saving persists settings. While capture is running, compatible rule/outbound updates are also applied to new connections; virtual addresses and established connections retain their current policy. The interface identifies saved and running versions separately and preserves the running configuration if application fails. Restart-required changes are checked before application, and a configuration conflict preserves the local draft.

The offline frontend supports Safari/iOS 16.4, Chrome/Android 110 and Firefox 115 or later. Assets, icons and fonts do not require a public CDN. Browser automation covers desktop and touch layouts; it does not replace testing on actual phones, tablets and desktop permission dialogs.

## Phone and tablet management

Enable HTTPS LAN access **on the KONE host**, select one of its private interface addresses, then download its local CA certificate. Check the fingerprint before explicitly trusting it on the phone or tablet. Open the displayed address and enter a short-lived pairing code.

Read-only access is the default. An owner can grant management access or revoke a session. KONE does not install certificate trust, change LAN firewall rules or open router ports automatically. The phone displays the connected host's observations; opening management does not route the phone's other traffic through KONE.

## TOML and file mode

Use the [complete annotated example](../configs/kone.example.toml) and [configuration guide](configuration.md). Declare named proxies with `[[outbounds]]`, `name` and `url`; the URL selects the proxy protocol. Rules reference a proxy name or the built-in `direct` and `reject` targets. These built-ins need no outbound declaration. The optional `[dns]` section uses current system DNS upstreams by default.

Save your configuration as `config.toml`, validate it, then start file mode with the privileges required by the host:

```sh
kone -check -config config.toml
sudo kone -config config.toml
```

On Windows use `kone-cli.exe -config config.toml`; on macOS use `kone-cli -config config.toml`. Windows console file mode requests a visible administrator window when necessary. Services/headless callers can use `-no-elevate` when the calling process already has the required privileges. This option does not grant permissions. See the platform instructions before enabling capture.

`-check` validates without creating a TUN device or changing routes. `-version` prints the version and exits. `-debug` overrides the configured log level. Logs use structured text or JSON on stderr; CLI results go to stdout.

File mode runs capture without an HTTP management listener. Remove the retired `general.manager-addr` option from file-mode configurations; old HTML pages and `/reload/` are no longer available. Restart file mode after editing its configuration, or use the password-protected managed console (`kone-cli -manage`) for configuration and supported hot updates. The console maintains its own profile rather than editing a running file-mode process.

Existing managed profiles automatically retire this obsolete option while preserving their rules, credentials and confirmation settings. Before a subsequent explicit save, the original profile is retained in a private `*.legacy-manager` backup beside its settings file. This backup contains credentials; keep it private with the profile.

## Gateway and protocol scope

- Linux gateways, including Raspberry Pi, can serve LAN clients through Fake-IP/CIDR routes or optional full IPv4 capture. Clients must use the gateway and KONE DNS. Forwarding, DHCP, firewall policy and return routing remain operator-owned. Follow [gateway setup](guides/how-to-use-with-raspberry-pi.md).
- Full capture follows routing rules and existing more-specific system routes. Set `core.outbound-interface` to the real physical exit so proxy transports, direct traffic and upstream DNS avoid recapture. Network changes pause capture for a new preflight.
- IPv6 is optional and disabled by default. Linux, Windows and macOS support explicit ULA virtual addresses, AAAA, IPv6 rules and capture. See [IPv6 configuration](ipv6.md). Gateway IPv4 support does not imply LAN IPv6 is automatically configured.
- HTTP/HTTPS CONNECT support TCP. SOCKS5 and supported Shadowsocks AEAD2017 outbounds support TCP and native UDP. UDP follows direct/reject rules; unsupported proxy UDP is denied unless an explicit fallback is configured. Shadowsocks plugins, legacy stream ciphers and AEAD-2022 are outside the supported range.
- Every package includes `system`, `gvisor` and `mixed`; `core.stack` selects the mode at runtime and defaults to `system`. Changing the stack requires pausing and restarting capture and does not add proxy protocol capabilities. Arbitrary fragmentation is not a compatibility guarantee. See [stack selection](configuration.md#tun-backend-and-stack).
- Country rules use offline DB-IP IPv4 data by default; import DB-IP, IPinfo Lite or MaxMind Country MMDB for newer data and IPv6 country lookup, with checksum validation and previous-version recovery. See [GeoIP sources and attribution](geoip.md).
- Optional system DNS guidance uses a Linux systemd-resolved link, a macOS temporary resolver or an owned Windows NRPT rule. Conflicts stop startup, normal exit restores owned settings, and interrupted Windows leases require explicit local recovery. See [system DNS setup](system-dns.md) and [private resolver context](dns-context.md).

Native CI verifies traffic and recovery on its runner hardware. Raspberry Pi throughput, long-duration deployment load, suspend/resume, multi-VPN coexistence, real-device certificate trust and clean-machine desktop installation need deployment-specific acceptance. [The acceptance index](acceptance.md) distinguishes automated evidence from those checks; [performance measurements](performance.md) state their load and hardware limits.

## Source development and licensing

Source builds and development tasks are described in [development](development.md); building is separate from enabling capture. Docker deployment is covered in [the Docker guide](../deploy/docker/README.md). Older recipes under `guides/` are retained as historical references.

KONE uses [GPL-3.0-or-later](../LICENSE). Earlier MIT notices remain in [LICENSE-MIT](../LICENSE-MIT); copied components retain their own notices. Embedded Wintun binaries use the [Wintun Prebuilt Binaries License](../licenses/WINTUN.txt). Source packages include the corresponding sources and component licenses.
