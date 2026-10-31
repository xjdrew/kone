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

## Bugfixes

- Keep management available while capture is paused or fails to start.
- Preserve active Fake-IP mappings and prevent private DNS fallback to public resolvers.

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
