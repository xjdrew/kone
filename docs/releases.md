# Verified releases

KONE publishes one development prerelease for each qualifying first-parent commit added to `master`. A push with several commits is expanded in order; commits on a feature branch that are only reachable through a merge's second parent are represented by that merge commit. The workflow never substitutes the push head's CI result for an intermediate commit.

`Verified releases` calls the existing Go workflow for each exact SHA, with a separate artifact prefix and embedded version. Web tests, three-platform race and protocol-stack tests, vulnerability/fuzz checks, cross-compilation, container checks and Linux/Windows/macOS privileged acceptance all remain required. A verification artifact is emitted only after all required jobs succeed. A failed commit does not prevent another successful commit in the same push from qualifying. New pushes do not cancel earlier master runs; stale PR checks can still be canceled.

The development version is `<next-version>-dev.<UTC YYYYMMDD>.<first-parent count>.g<12-character SHA>`, with a `v`-prefixed release tag. For example, `v0.4.0-dev.20261101.86.gae59375cc7cc` is a prerelease; `v0.4.0` is stable. The date comes from the commit, so retries do not change identity. The next stable version reflects the highest cumulative Conventional Commit change since the preceding stable tag, rather than a bump for every merge. See [version policy](versioning.md), including the initial `VERSION` floor and the 0.x breaking-change rule.

`release.json` records the full SHA, version, CI run and attempt, gate evidence, asset hashes, version context and embedded build metadata, including which architectures passed a native executable/package check. `SHA256SUMS` includes every distributable, the corresponding source and the manifest. The source archive includes vendored Go dependencies, frontend sources and built assets, build identity and component licenses. Reproduction uses the toolchain and `-ldflags` recorded in the manifest's `build` field and package-local `build-info.json`/source `BUILD-INFO.json`.

PRs invoke the Go workflow directly. A `master` push invokes the release dispatcher, which calls that same workflow for every qualifying SHA; the push head does not also run a duplicate ordinary Go workflow. Each SHA still receives its own complete qualification, version and artifact prefix. Development-branch pushes do not run CI.

The execution groups are:

| Group | Runners | Checks |
| --- | --- | --- |
| Web | 1 Linux | Frontend, three browser engines and genuine paused management persistence |
| Platform tests | 3 | Native unit/race and all supported stacks, each OS's package installation and privileged acceptance; Linux DNS/Shadowsocks/container checks; fresh Windows PR coverage comparison |
| Build | 1 Linux | Six default binary targets, matching source/licenses |
| Quality | 1 Linux | Fuzzing, vulnerability checks and shared core performance baseline |

These are six execution checks, plus the release-only verification marker. Grouping reuses setup, compiler caches and compatible test binaries; it does not remove platform, protocol or failure assertions. PR coverage still measures the exact target-branch SHA afresh with the same Windows toolchain and flags. The three-platform package checks and every native-stack subcheck must all succeed before release evidence is emitted.

All development and CI tasks enter through [just](development.md). Daily builds and local packages use the short root commands; detailed qualification and publication tasks use `just ci <task>`. PRs use their root justfile. For `workflow_call` qualification of a historical SHA, the workflow checks out trusted orchestration tools from `github.workflow_sha` into `.ci-tools`, sets `JUST_JUSTFILE` to that revision's root justfile and `JUST_WORKING_DIRECTORY` to the tested source. Application code, configuration, tests and packaging remain bound to the target SHA; task orchestration and release planning/evidence/publication use the fixed workflow revision. An older source checkout need not contain the newer justfile. Exact PR-base coverage similarly uses `just ci test-coverage .coverage-base ../coverage-base.out` from the current task entrypoint.

New evidence uses marker schema 2 with exactly the four current logical groups (`web`, `test`, `build`, `quality`). Previously published schema-1 evidence remains valid only with its complete original 12-gate or subsequent seven-group list. Missing, extra, duplicate or mixed groups are rejected; a partial old list cannot qualify merely because it contains the smaller current list. SHA, version, run/attempt and the actual latest successful verification job remain required for every supported schema.

## Packages and trust

Local `just package` and `just package-all` only build and create package files and manifests. They never run the resulting executable, including `-version`, or extract/install it into a temporary prefix. Local metadata records `native_version_checked=false` and conservatively marks these packages experimental and unverified. CI's default `just ci package` retains the actual executable, extraction and installation checks below; local output is not release qualification evidence.

| Platform | Packages | CI validation |
| --- | --- | --- |
| Linux amd64/arm64 | `.deb` | Native runner architecture: extract, install into a temporary prefix and verify `-version`; other architectures are cross-compiled and marked experimental |
| macOS amd64/arm64 | Unsigned `.pkg`, including `Kone.app` and `kone-cli` | Native runner architecture: package payload extraction, then CLI `-version`; app bundle/icon identity checked without launching its GUI; other architecture is marked experimental |
| Windows amd64/arm64 | Portable `.zip` with `kone.exe`, `kone-cli.exe` and per-user `install.ps1` | Native runner architecture: extract, install into a temporary directory and verify CLI `-version`; GUI identity/subsystem checked without launching capture; other architecture and its driver behavior remain experimental |

Releases upload nine custom assets: six application packages, `kone-source.tar.gz`, `release.json` and `SHA256SUMS`. GitHub also displays its two automatically generated source archives. `build-info.json` remains inside packages; its full content is embedded in `release.json` instead of being a separate download. Historical releases retain their original complete asset layout and immutable identities.

Linux ARMv7 remains available through an explicit source build for older Raspberry Pi systems, outside the six default release targets. Privileged CI checks exercise Linux TUN, Windows Wintun and macOS utun with each supported protocol stack on their runner hardware; their actual result belongs to the exact checked SHA. Cross-compilation is not evidence of Raspberry Pi throughput, ARM64 driver behavior, or a clean-machine desktop/permission experience.

Windows `kone.exe` and macOS `Kone.app` launch paused tray/menu management without a terminal or automatic browser window. Use `kone-cli.exe` / `kone-cli` for console output and file mode; Linux retains `kone`. See [desktop setup](desktop.md).

Packages are unsigned, and macOS packages are not notarized. Verify checksums before installation; platform trust controls remain in effect. Signing/notarization and their credentials need a separate distribution decision. A portable installer only copies KONE-owned application files; installation does not enable capture, create services, configure autostart, change routes/DNS/firewall, or install certificate trust. System packages place the console executable in the standard system path and may require installation privileges. The user profile is separate and is retained across upgrades and uninstallation.

## Retry and stable promotion

Use GitHub Actions → **Verified releases → Run workflow**, always selecting the `master` branch:

1. For an individual retry, choose `development` and enter the complete master SHA. The workflow re-runs required gates before publishing. A matching public release remains immutable; an automation-owned partial draft can be replaced and completed safely.
2. For a stable release, push the suggested canonical tag, such as `v0.4.0`, at the intended master SHA. This triggers full stable qualification automatically. Alternatively choose `stable` in the master workflow, enter the complete SHA and that tag. The SHA must already have a published development release with complete matching assets, verification evidence and a successful required-gates job; it must be reachable from master, and the tag must equal its calculated next version. The same SHA is rebuilt with the final version and must pass all gates again. For a historical source whose own workflow predates the tag trigger, use the manual master dispatch.
3. A tag that already points elsewhere is rejected. Public assets are never overwritten by retry. An unavailable/missing gate marker, source archive, platform package or checksum prevents publication.

The dispatcher rejects a rewritten/non-ancestor push range and an initial history without a reviewed starting SHA. A single push above 100 first-parent commits fails explicitly instead of silently truncating the list; dispatch the affected complete SHAs in reviewed batches. A canceled run or expired Actions artifact can be retried using the exact SHA; release assets are retained independently of Actions artifact retention.

Actions reruns replace same-run temporary artifacts without replacing public release assets. A published development SHA reuses its original version context even if a newly created ancestor stable tag changes today's calculation. An unpublished/failed SHA may be replanned using current stable refs. A publication-only retry can reuse that SHA's latest successful qualification; a failed or skipped later qualification attempt invalidates an older marker. The publisher verifies the actual job result and attempt through the Actions API before accepting the marker.

PRs and development-branch pushes cannot publish a release. Only the publisher/withdrawal jobs request repository write permission; publication accepts verified master or exact stable-tag workflow execution, and withdrawal accepts master dispatch. Local invocations are rejected. No production signing credentials are used by PR checks.

## Withdrawal and rollback

Choose `withdraw` with the existing release tag and a reason. The workflow makes it a draft, records the warning, and retains the source tag for traceability. A withdrawn draft is not automatically republished by an ordinary retry. This cannot recall a package someone has already downloaded.

Before upgrade or rollback, export/back up the user profile, pause capture and exit the old process. Verify a known-good older release, replace the application files and start management with capture paused. Never let two versions write the same profile simultaneously. Restore a compatible profile backup explicitly when an older version cannot read newer settings; rollback does not silently overwrite settings or enable capture.

Portable uninstall removes the KONE application directory/files; preserve the profile until you choose to delete it. Linux `.deb` users may remove the package through their package manager. The macOS component package installs `/Applications/Kone.app`, `/usr/local/bin/kone-cli` and license/build files under `/usr/local/share/kone`; remove these owned files after exiting, and optionally forget the corresponding `org.kone.cli.<architecture>` receipt. None of these steps should be combined with system network recovery: pause/recover KONE before removing its executable.
