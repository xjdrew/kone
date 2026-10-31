# Local SagerNet/sing-tun source

Source: https://github.com/SagerNet/sing-tun/tree/040db71fcd33
Go module: `github.com/sagernet/sing-tun v0.9.7-0.20261023115432-040db71fcd33`

This module is retained in-tree because the real Windows Wintun CI reproduces a `checkptr: converted pointer straddles multiple allocations` crash in the upstream memory loader. The upstream `dev` branch still has the same giant array conversion as of 2026-10-31. Disabling pointer checks or dropping real Wintun/race acceptance would hide the defect.

Local changes:

1. Use `unsafe.Add` and an exactly sized `unsafe.Slice` for the PE section table; cover heap-backed PE images under `-race`.
2. Immediately close the acquired Windows adapter when `StartSession` fails, instead of relying on a later finalizer.
3. Add an opt-in `EXP_Exclusive` device option: use Linux `IFF_TUN_EXCL` and disable Windows' existing-adapter fallback. KONE enables it so a process racing the preliminary name check cannot take over someone else's interface. Other library users retain the original default behavior.

All upstream source, tests, embedded official DLLs and license notices are retained. The root go.mod replaces only this module with `./pkg/singtun`; upstream version and other dependencies remain pinned. Root coverage concerns KONE code; this nested upstream module has its own targeted regression command in CI. Build/source artifacts include this module.

The embedded DLLs are the unmodified official Wintun 0.14.1 prebuilt binaries, covered by the [Wintun Prebuilt Binaries License](../../licenses/WINTUN.txt). All four architecture DLLs were verified byte-for-byte against the [official archive](https://wintun.net/builds/wintun-0.14.1.zip), SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`. Their license is separate from KONE's GPL-3.0-or-later declaration; no WireGuard LLC or Wintun project endorsement is implied.

When upgrading, compare the original version to this directory, reapply only fixes still needed, and run the Windows Wintun plus Linux system/mixed gateway acceptance. Remove the local replacement once an upstream release incorporates these fixes and passes the same checks. Original upstream notices apply; this file records modifications made on 2026-10-31.
