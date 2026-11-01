# KONE

<img src="web/public/icon.svg" alt="KONE K1 dial icon" width="80">

[![Master CI](https://github.com/xjdrew/kone/actions/workflows/release.yml/badge.svg?branch=master&event=push)](https://github.com/xjdrew/kone/actions/workflows/release.yml)

KONE is a TUN proxy with desktop management and Linux gateway support.
Its original [K1 dial mark](docs/branding.md) represents reliable guidance for network traffic.

## Features

- Route application and LAN traffic through proxies without configuring every application.
- Use HTTP/HTTPS, SOCKS5 and Shadowsocks outbounds, with direct and reject policies.
- Run on Linux, macOS and Windows, including Raspberry Pi home and small-business gateways.
- Inspect traffic, DNS history, routing decisions and recent runtime logs.
- Use a password-protected Web console, desktop tray/menu, or paired phone and tablet.
- Preserve established connections during rule updates, roll back failed startup,
  and restore owned network settings on normal exit.

## Use

**Prebuilt packages**

Download the package for your platform from [Releases](https://github.com/xjdrew/kone/releases).
See [installation and platform notes](docs/usage.md) for checksums, permissions and package trust.
On Windows, double-click `kone.exe`; on macOS, open `Kone.app`.
They start in the tray/menu bar **without a terminal or automatic browser window**.
Choose **Open management**, set a password, configure the needed outbounds/rules,
then review the checks and explicitly start capture. Capture starts **paused**.
See the [desktop setup guide](docs/desktop.md) for the three steps and troubleshooting.
Use `kone-cli.exe` / `kone-cli` for terminal commands; Linux keeps the `kone` CLI.

**From source**

Install the [development tools](docs/development.md), then run from the repository root:

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
and [usage guide](docs/usage.md). Gateway deployment is covered in the
[Raspberry Pi guide](docs/guides/how-to-use-with-raspberry-pi.md).

## Development

See [development tasks](docs/development.md), [architecture](docs/architecture.md) and
[acceptance coverage](docs/acceptance.md). KONE is licensed under
[GPL-3.0-or-later](LICENSE); component notices remain with their sources and packages.
