# KONE

<img src="web/public/icon.svg" alt="KONE K1 dial icon" width="80">

[![Master CI](https://github.com/xjdrew/kone/actions/workflows/release.yml/badge.svg?branch=master&event=push)](https://github.com/xjdrew/kone/actions/workflows/release.yml)

KONE is a TUN proxy with desktop management and Linux/Raspberry Pi gateway support.
Its original [K1 dial mark](docs/development/development.md#6-维护资产与提交) represents reliable guidance for network traffic.

## Features

- **Transparent capture:** Selectively route application or LAN traffic through TUN, with optional IPv6 support.
- **Flexible policies:** Route by domain, IP or country, and update rules live without interrupting established connections.
- **Proxy support:** HTTP/HTTPS CONNECT for TCP, SOCKS5 and Shadowsocks AEAD for TCP/UDP, plus direct and reject policies.
- **Network-aware DNS:** Fake-IP routing, system resolver discovery and private DNS support for LAN and VPN environments.
- **Traffic insights:** Live flow visualization, connection details, DNS history and runtime logs.
- **Actionable diagnostics:** Compare connectivity, simulate routing and turn observed connections into precise rules.
- **Easy management:** A password-protected Web console, desktop tray controls and optional paired mobile access, alongside TOML and CLI operation.
- **Safe lifecycle:** Startup checks, failure rollback and network restoration, with management available while capture is paused.
- **Built-in choices:** Runtime-selectable system, gVisor and mixed stacks, plus offline and importable GeoIP data.

Browse the [documentation index](docs/README.md) for user guides, technical references, development and requirements.

## Use

**Prebuilt packages**

Download the package for your platform from [Releases](https://github.com/xjdrew/kone/releases).
Windows uses ZIP, macOS PKG and Linux DEB, for amd64 and arm64.
See [installation and platform notes](docs/user/usage.md) for checksums, permissions and package trust.
On Windows, double-click `kone.exe`; on macOS, open `Kone.app`.
They open management in your browser and keep a tray/menu icon **without a terminal**.
Set a password, configure the needed outbounds/rules,
then review the checks and explicitly start capture. Capture starts **paused**.
See the [desktop setup guide](docs/user/usage.md#2-首次配置) for setup steps and daily operation.
Use `kone-cli.exe` / `kone-cli` for terminal commands; Linux keeps the `kone` CLI.
Use `-no-browser` with the desktop entrypoint for quiet tray startup.

**From source**

Install the [development tools](docs/development/development.md), then run from the repository root:

```sh
just init
just build
```

Run `dist/kone` on Linux, double-click `dist/kone.exe` on Windows, or open `dist/Kone.app` on macOS.
For an interactive development session, `just dev` builds and starts paused management.
`just package` creates an installation package for the current machine.
Build and packaging tasks reuse unchanged dependencies and frontend assets.
Each daily task supports `-h` / `--help`, for example `just build --help`.

For file-based operation, start with the [annotated configuration](configs/kone.example.toml)
and [usage guide](docs/user/usage.md). Gateway deployment is covered in the
[Raspberry Pi guide](docs/user/usage.md#6-linux--raspberry-pi-网关).

## Development

See [development tasks](docs/development/development.md), [architecture](docs/technical/architecture.md) and
[acceptance coverage](docs/development/development.md#5-验收按风险定位). KONE is licensed under
[GPL-3.0-or-later](LICENSE); component notices remain with their sources and packages.
