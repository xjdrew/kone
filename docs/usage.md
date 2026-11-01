# Using KONE

KONE routes traffic through a virtual network interface. It can run on an individual computer or on a Linux gateway serving LAN clients. Start with desktop management for interactive use, or use a TOML file for an explicitly configured gateway/headless deployment.

## Download and install

Download a platform package from [Releases](https://github.com/xjdrew/kone/releases) and verify its checksum before installation. Installed binaries and package installers run directly; end users do not need Go, Node or just.

| Platform | Available packages |
| --- | --- |
| Linux amd64, arm64, ARMv7 | Portable archive and `.deb` |
| macOS amd64, arm64 | Portable archive and unsigned `.pkg` |
| Windows amd64, arm64 | Portable ZIP with a per-user `install.ps1` |

Packages are unsigned, and macOS packages are not notarized. The macOS package includes `Kone.app` and the `kone-cli` console entrypoint. Platform security and application-control policies still apply. An architecture being cross-compiled does not prove its driver, desktop or installation behavior on real hardware. See [release verification and native coverage](releases.md).

Locally generated packages are experimental and unverified: packaging only creates files and does not run or temporarily install the executable. Published release evidence separately records the checks actually performed in CI.

Installation does not enable capture, create services, configure autostart or change system networking. User settings are stored separately and survive application upgrades. Before replacing or uninstalling a running version, pause capture and exit normally; see [upgrade and rollback](releases.md#withdrawal-and-rollback).

## Desktop management

Double-click `kone.exe` on Windows or open `Kone.app` on macOS. These desktop entrypoints show a tray/menu icon without a console or automatic browser window; choose **Open management**. On Linux, run `kone` without arguments. Capture starts **paused**. Enable and save the TUN inbound, configure outbounds/rules, then run preflight and explicitly start capture. See the [three-step desktop guide](desktop.md). A failed proxy or preflight keeps management available.

Settings persist in an independent profile in your user configuration directory. Managed mode does not read the working directory's `config.toml` or import terminal proxy settings. With the console entrypoint (`kone-cli.exe` on Windows, `kone-cli` on macOS, `kone` on Linux), `-manage` explicitly selects managed mode, `-data-dir` selects its profile and `-listen` selects the loopback listener. Console `-no-browser` prints a one-time local authorization URL; keep it private. After authorization, the browser uses an HttpOnly session cookie and removes the bootstrap token from its address. Desktop entrypoints discard bootstrap output and use the tray's explicit browser action instead.

Windows keeps management at ordinary user privileges and requests a separate UAC network helper when capture needs elevation. Wintun is included; no separate TAP installation is required. Use an explicit `kone.exe` path when working beside an older extensionless binary. See [Windows setup and application trust](windows/README.md).

On macOS, management and the native menu bar run as the ordinary desktop user. Enabling capture requests authorization for a separate network helper. See [macOS permissions](macos-helper.md) and [menu bar behavior](macos-tray.md).

Use the tray/menu or management interface to pause capture or exit. Normal shutdown releases owned resources. Forced process termination cannot run cleanup; recovery only restores resources whose ownership can be verified. See [runtime reliability](runtime.md).

## Traffic and diagnostics

Management shows business connections, traffic paths, DNS history, routing decisions and connection failures. Only traffic entering KONE is observable. DNS queries, diagnostic probes and business flows are different measurements; opening management does not make KONE observe all host traffic.

Diagnostics also shows bounded, redacted recent runtime logs with level/source filters. Configured logging levels still control collection; a display filter cannot recover debug records that were never collected. Capture telemetry can be unavailable while management stays reachable; the page identifies stale snapshots without disabling management as if the connection had been lost. Tray capture failures open diagnostics and show a desktop notice without terminating management.

Saving and applying settings are separate actions. Rule/outbound updates preserve virtual addresses and established connections; existing flows retain their original policy. Changes that require restarting capture are checked before application, and a configuration conflict preserves the local draft.

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

File mode has a legacy manager that defaults to `http://127.0.0.1:9200/`; set `general.manager-addr = ""` to disable it. This listener has no authentication and is separate from the authenticated managed console. Keep it on loopback or behind operator-provided protection. Its rule reload endpoint is:

```sh
curl -X POST http://127.0.0.1:9200/reload/
```

File-mode reload atomically publishes domain/GeoIP/default rules and outbound definitions while preserving virtual addresses and established flows. Core/DNS settings, logging, manager address and changes to captured CIDR routes require a restart; an unsupported update leaves the active configuration unchanged.

## Gateway and protocol scope

- Linux gateways, including Raspberry Pi, can serve LAN clients through Fake-IP/CIDR routes or optional full IPv4 capture. Clients must use the gateway and KONE DNS. Forwarding, DHCP, firewall policy and return routing remain operator-owned. Follow [gateway setup](guides/how-to-use-with-raspberry-pi.md).
- Full capture follows routing rules and existing more-specific system routes. Set `core.outbound-interface` to the real physical exit so proxy transports, direct traffic and upstream DNS avoid recapture. Network changes pause capture for a new preflight.
- IPv6 is optional and disabled by default. Linux and Windows support explicit ULA virtual addresses, AAAA, IPv6 rules and capture; macOS activation is rejected. See [IPv6 configuration](ipv6.md). Gateway IPv4 support does not imply LAN IPv6 is automatically configured.
- HTTP/HTTPS CONNECT support TCP. SOCKS5 and supported Shadowsocks AEAD2017 outbounds support TCP and native UDP. UDP follows direct/reject rules; unsupported proxy UDP is denied unless an explicit fallback is configured. Shadowsocks plugins, legacy stream ciphers and AEAD-2022 are outside the supported range.
- `core.stack` selects `system` or `mixed`. Mixed requires a build that includes `with_gvisor`; changing the stack does not add proxy protocol capabilities. Arbitrary fragmentation is not a compatibility guarantee. See [stack selection](configuration.md#tun-backend-and-stack).
- Built-in country data is DB-IP Country Lite October 2026 IPv4, with verified local imports and previous-version recovery. IPv6 country lookup is outside this dataset. See [GeoIP data and attribution](geoip.md).
- Optional system DNS guidance uses a Linux systemd-resolved link or a macOS temporary resolver. Windows system DNS guidance is not enabled by this option. See [system DNS setup](system-dns.md) and [private resolver context](dns-context.md).

Native CI verifies traffic and recovery on its runner hardware. Raspberry Pi throughput, long-duration deployment load, suspend/resume, multi-VPN coexistence, real-device certificate trust and clean-machine desktop installation need deployment-specific acceptance. [The acceptance index](acceptance.md) distinguishes automated evidence from those checks; [performance measurements](performance.md) state their load and hardware limits.

## Source development and licensing

Source builds and development tasks are described in [development](development.md); building is separate from enabling capture. Docker deployment is covered in [the Docker guide](../deploy/docker/README.md). Older recipes under `guides/` are retained as historical references.

KONE uses [GPL-3.0-or-later](../LICENSE). Earlier MIT notices remain in [LICENSE-MIT](../LICENSE-MIT); copied components retain their own notices. Embedded Wintun binaries use the [Wintun Prebuilt Binaries License](../licenses/WINTUN.txt). Source packages include the corresponding sources and component licenses.
