# KONE

[![Master CI](https://github.com/xjdrew/kone/actions/workflows/release.yml/badge.svg?branch=master&event=push)](https://github.com/xjdrew/kone/actions/workflows/release.yml)

KONE is a TUN proxy with desktop management and Linux gateway support.

## Features

- Route application and LAN traffic through proxies without configuring every application.
- Use HTTP/HTTPS, SOCKS5 and Shadowsocks outbounds, with direct and reject policies.
- Run on Linux, macOS and Windows, including Raspberry Pi home and small-business gateways.
- Inspect traffic, DNS history and routing decisions, and diagnose connection failures.
- Control capture from the desktop tray or menu, and manage it from a paired phone or tablet.
- Preserve established connections during rule updates, roll back failed startup,
  and restore owned network settings on normal exit.

## Use

**Prebuilt packages**

Download the package for your platform from [Releases](https://github.com/xjdrew/kone/releases).
See [installation and platform notes](docs/usage.md) for checksums, permissions and package trust.
Start `kone` or `kone.exe` without arguments to open management with capture **paused**.
Configure your proxies and rules, save the settings, then explicitly enable capture.

**From source**

Install the [development tools](docs/development.md), then run from the repository root:

```sh
just init
just build
```

Run `dist/kone` on Linux/macOS or `dist/kone.exe` on Windows.
For an interactive development session, `just dev` builds and opens paused management.
`just package` creates an installation package for the current machine.
Build and packaging tasks reuse unchanged dependencies and frontend assets.

For file-based operation, start with the [annotated configuration](configs/kone.example.toml)
and [usage guide](docs/usage.md). Gateway deployment is covered in the
[Raspberry Pi guide](docs/guides/how-to-use-with-raspberry-pi.md).

## Development

See [development tasks](docs/development.md), [architecture](docs/architecture.md) and
[acceptance coverage](docs/acceptance.md). KONE is licensed under
[GPL-3.0-or-later](LICENSE); component notices remain with their sources and packages.
