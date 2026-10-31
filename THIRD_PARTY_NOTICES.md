# Licensing and source availability

KONE's combined program is distributed under GPL-3.0-or-later starting with the SagerNet/sing-tun migration (2026-10-31). Copyright (c) 2016-2026 xjdrew and contributors. The original MIT notice is preserved in LICENSE-MIT and continues to apply to earlier MIT-licensed code. Existing third-party notices are not replaced by the project's license.

- `github.com/sagernet/sing-tun`: GPL-3.0-or-later, copyright nekohasekai. Pinned to `v0.9.7-0.20261023115432-040db71fcd33`, the revision used by sing-box v1.14.4. [Source and license](https://github.com/SagerNet/sing-tun/tree/040db71fcd33).
- `github.com/sagernet/sing`: GPL-3.0-or-later. [Source and license](https://github.com/SagerNet/sing).
- The optional `github.com/sagernet/gvisor` protocol stack contains Apache-2.0 and other individually licensed components. [Source and notices](https://github.com/SagerNet/gvisor).
- Windows builds embed the official Wintun 0.14.1 DLL through sing-tun. Wintun source is GPL-2.0; its official signed binary uses the [Prebuilt Binaries License](licenses/WINTUN.txt), reproduced unchanged from the official archive. [Official distribution](https://www.wintun.net/). Archive SHA-256: `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`. All four embedded architecture DLLs were verified byte-for-byte against that archive. KONE does not claim endorsement by WireGuard LLC or the Wintun project.
- `pkg/dnsconfig` retains its upstream MIT notice in `pkg/dnsconfig/LICENSE`, and its Go-derived portions retain the BSD notice in `pkg/dnsconfig/LICENSE-GO`.
- Other dependencies retain the licenses and copyright notices included in their pinned Go modules. Versions and checksums are recorded in go.mod and go.sum; test-only dependencies are not necessarily part of a built executable.

Distributors must accompany binaries with applicable licenses/notices and access to corresponding source, including pinned dependencies and build scripts. CI binary artifacts include project/driver notices and a matching source archive with vendored dependencies and their notices. Keep that source archive available alongside redistributed binaries. Container distributors must also provide matching source access; the repository commit and pinned module files identify the matching inputs.
