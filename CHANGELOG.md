# 2026/11/01

## Features

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
- Control capture from the Windows system tray or macOS menu bar.
- Support expiring domain rules and disabled proxy outbounds.
- Guide system DNS through KONE on supported Linux systems.
- Preserve discovered private DNS scopes and show resolver context.
- Build installable packages and verified development releases for successful master commits.

## Bugfixes

- Keep management available while capture is paused or fails to start.
- Preserve active Fake-IP mappings and prevent private DNS fallback to public resolvers.
- Pause capture when the physical network context changes.
- Refresh expired DNS addresses and CNAME routing decisions without changing active connections.
- Offer the last valid settings for repair when the saved profile is damaged.
- Honor explicit direct domain rules before later default policies.
- Preserve existing macOS routes when capture startup fails.
- Mark retained traffic as historical after capture stops.
- Preserve the observed protocol and port when drafting a precise rule.

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
