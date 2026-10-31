# Verified releases

KONE publishes one development prerelease for each qualifying first-parent commit added to `master`. A push with several commits is expanded in order; commits on a feature branch that are only reachable through a merge's second parent are represented by that merge commit. The workflow never substitutes the push head's CI result for an intermediate commit.

`Verified releases` calls the existing Go workflow for each exact SHA, with a separate artifact prefix and embedded version. Web tests, three-platform race tests, optional mixed-stack tests, vulnerability/fuzz checks, cross-compilation, container checks and Linux/Windows/macOS privileged acceptance all remain required. A verification artifact is emitted only after all required jobs succeed. A failed commit does not prevent another successful commit in the same push from qualifying. New pushes do not cancel earlier master runs; stale PR checks can still be canceled.

The development tag is `dev-<12-character SHA>`, and its executable reports `0.4.0-dev.<12-character SHA>`. `release.json` records the full SHA, version, CI run and attempt, gate evidence, asset hashes and which architectures passed a native executable/package check. `SHA256SUMS` includes every distributable, the corresponding source and manifests. The source archive includes vendored Go dependencies, frontend sources and built assets, build identity and component licenses. Reproduction uses the toolchain and `-ldflags` recorded in `build-info.json`/`BUILD-INFO.json`.

The required-gate workflow is reused rather than duplicated. The push head therefore has the ordinary master check and an independent release qualification run. This initially spends extra CI time to keep release evidence straightforward; it does not weaken a gate or infer success from another SHA.

## Packages and trust

| Platform | Packages | Validation |
| --- | --- | --- |
| Linux amd64/arm64/ARMv7 | Portable `.tar.gz`, `.deb` | Native runner architecture: extract, install into a temporary prefix and verify `-version`; other architectures are cross-compiled and marked experimental |
| macOS amd64/arm64 | Portable `.tar.gz`, unsigned `.pkg` | Native runner architecture: archive installation and package payload extraction, then `-version`; other architecture is marked experimental |
| Windows amd64/arm64 | Portable `.zip` with a per-user `install.ps1` | Native runner architecture: extract, install into a temporary directory and verify `-version`; other architecture and its driver behavior remain experimental |

The Linux ARMv7 build uses the system stack; the other builds include mixed-stack support. Privileged CI checks exercise Linux TUN, Windows Wintun and macOS utun on their runner hardware; their actual result belongs to the exact checked SHA. Cross-compilation is not evidence of Raspberry Pi throughput, ARM64 driver behavior, or a clean-machine desktop/permission experience.

Packages are unsigned, and macOS packages are not notarized. Verify checksums before installation; platform trust controls remain in effect. Signing/notarization and their credentials need a separate distribution decision. A portable installer only copies KONE-owned application files; installation does not enable capture, create services, configure autostart, change routes/DNS/firewall, or install certificate trust. System packages place the executable in the standard system path and may require installation privileges. The user profile is separate and is retained across upgrades and uninstallation.

## Retry and stable promotion

Use GitHub Actions → **Verified releases → Run workflow**, always selecting the `master` branch:

1. For an individual retry, choose `development` and enter the complete master SHA. The workflow re-runs required gates before publishing. A matching public release remains immutable; an automation-owned partial draft can be replaced and completed safely.
2. For a stable release, choose `stable`, enter the complete SHA and a tag such as `v0.4.0`. That SHA must already have a published development release with matching verification evidence and a successful required-gates job. The same SHA is rebuilt with the stable version and must pass all gates again. Merely creating a tag does not publish anything or bypass verification.
3. A tag that already points elsewhere is rejected. Public assets are never overwritten by retry. An unavailable/missing gate marker, source archive, platform package or checksum prevents publication.

The dispatcher rejects a rewritten/non-ancestor push range and an initial history without a reviewed starting SHA. A single push above 100 first-parent commits fails explicitly instead of silently truncating the list; dispatch the affected complete SHAs in reviewed batches. A canceled run or expired Actions artifact can be retried using the exact SHA; release assets are retained independently of Actions artifact retention.

Actions reruns replace same-run temporary artifacts without replacing public release assets. A publication-only retry can reuse that SHA's latest successful qualification; a failed or skipped later qualification attempt invalidates an older marker. The publisher verifies the actual job result and attempt through the Actions API before accepting the marker.

PRs and development-branch pushes cannot publish a release. Only the publisher/withdrawal jobs request repository write permission, and their scripts reject non-master or local invocation. No production signing credentials are used by PR checks.

## Withdrawal and rollback

Choose `withdraw` with the existing release tag and a reason. The workflow makes it a draft, records the warning, and retains the source tag for traceability. A withdrawn draft is not automatically republished by an ordinary retry. This cannot recall a package someone has already downloaded.

Before upgrade or rollback, export/back up the user profile, pause capture and exit the old process. Verify a known-good older release, replace the application files and start management with capture paused. Never let two versions write the same profile simultaneously. Restore a compatible profile backup explicitly when an older version cannot read newer settings; rollback does not silently overwrite settings or enable capture.

Portable uninstall removes the KONE application directory/files; preserve the profile until you choose to delete it. Linux `.deb` users may remove the package through their package manager. The macOS component package installs `/usr/local/bin/kone` and its license/build files under `/usr/local/share/kone`; remove these owned files after exiting, and optionally forget the corresponding `org.kone.cli.<architecture>` receipt. None of these steps should be combined with system network recovery: pause/recover KONE before removing its executable.
