# 2026/11/01

## Features

- Include system, gVisor and mixed stacks in every build, selected at runtime with system as the default.
- Require a management password on first use and password authentication on later logins.
- Guide first-time capture setup with ready-to-use defaults and explicit direct-only confirmation.
- Show configuration as status lists with focused editors, outbound connection tests and live rule/outbound updates.
- Protect TUN and other restart-required settings while capture is running.
- Add application and tray icons, terminal-free Windows/macOS desktop launch, and a separate console CLI.
- View filtered, redacted recent runtime logs in Diagnostics.
- Show defaults, options and examples with `-h` or `--help` on every daily just command.
- Open a local management interface without preparing a configuration file.
- Manage capture, outbounds, rules and DNS through a responsive desktop and mobile interface.
- Inspect live TCP/UDP traffic, failed connections and Sankey paths.
- Compare connectivity, simulate routing and save precise rules without replaying application requests.
- Save, import, export and restore settings with version conflict checks and credential redaction.
- Enable authenticated HTTPS LAN access with expiring pairing codes and revocable sessions.
- Support SOCKS5 UDP and Shadowsocks AEAD TCP/UDP outbounds.
- Support DNS over TCP, truncated-response retry, private suffix resolvers and bounded query history.
- Import verified GeoIP datasets and restore the previous version.
- Update built-in IPv4 country data to DB-IP Country Lite October 2026.
- Show verified local process ownership where the operating system allows it.
- Support optional IPv6 capture on Linux and Windows.
- Request a separate Windows/macOS network helper when capture needs administrator permission.
- Control capture and open diagnostics from the Windows system tray or macOS menu bar.
- Support expiring domain rules and disabled proxy outbounds.
- Guide system DNS through KONE on supported Linux and macOS systems.
- Preserve discovered private DNS scopes and show resolver context.
- Build installable packages and verified development releases for successful master commits.

## Bugfixes

- Keep gateway capture stable when using the gVisor stack.
- Keep signed-out sessions closed and resume first-time password setup after refreshing the page.
- Show capture failures from the tray and open diagnostics without closing management.
- Keep management usable when capture telemetry is temporarily unavailable instead of reporting a lost connection.
- Build Windows installation packages without installing PowerShell 7.
- Keep management available while capture is paused or fails to start.
- Preserve active Fake-IP mappings and prevent private DNS fallback to public resolvers.
- Pause capture when the physical network context changes.
- Refresh expired DNS addresses and CNAME routing decisions without changing active connections.
- Offer the last valid settings for repair when the saved profile is damaged.
- Honor explicit direct domain rules before later default policies.
- Preserve existing macOS routes when capture startup fails.
- Mark retained traffic as historical after capture stops.
- Preserve the observed protocol and port when drafting a precise rule.
- Preserve both proxy username and password when editing credentials.

## Changes

- Derive versions from cumulative feature and bugfix changes, with master prereleases and tag-triggered stable releases.
- Publish Windows ZIP, macOS PKG and Linux DEB for amd64/arm64; keep ARMv7 gateway builds as an explicit option.
- Remove legacy HTTP management and `general.manager-addr`; use the password-protected Web console.
- Speed up CI while preserving platform and release validation.
- Simplify setup, development, checks, builds and packaging into a few just commands.
- Keep local packaging limited to creating files without running or installing the program.

# 2026/10/31

## Features

- Support Windows UAC elevation on startup.
- Use Wintun on Windows without a separate TAP installation.
- Support optional full IPv4 traffic takeover on Linux and Raspberry Pi gateways.
- Add system and mixed network-stack options.
- Add named proxy outbounds and built-in direct/reject policies.
- Use system DNS by default, with optional settings in `[dns]`.
- Reject unsupported proxy UDP by default and allow explicitly configured fallback.
- Add configuration checks, structured logs and clearer startup errors.

## Bugfixes

- Fix crashes when TUN initialization fails.
- Fix occasional failures during concurrent shutdown.
- Fix incomplete network cleanup after startup failures or shutdown.
- Fix stale routing policies after rule reload.

## Changes

- Switch configuration to TOML; migrate INI files and remove obsolete relay settings.
- Improve configuration, Windows and gateway documentation.
- Change the project license to GPL-3.0-or-later.

# 2023/12/26

## Features

- Support Windows 10.
- Support rule reload through the management interface.
- Use system DNS by default.
- Adopt Surge-style configuration.
