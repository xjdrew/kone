// Run only in CI against already-verified artifacts. Never launches capture.
import { execFileSync } from "node:child_process";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  writeFile,
  chmod,
  rm,
} from "node:fs/promises";
import { resolve, join } from "node:path";
import { tmpdir } from "node:os";
import {
  hashFile,
  assertVersion,
  safeName,
  validSHA,
  targets,
} from "./model.mjs";

const input = resolve(process.env.RELEASE_INPUT || "release-input");
const output = resolve(process.env.RELEASE_OUTPUT || "release-assets");
const sha = validSHA(process.env.RELEASE_SHA);
const version = safeName(process.env.RELEASE_VERSION);
const platform = process.platform;
const architecture = { x64: "amd64", arm64: "arm64" }[process.arch];
const selected = targets.filter((target) =>
  target.startsWith(`${platform === "win32" ? "windows" : platform}-`),
);
if (!selected.length || !architecture)
  throw new Error("Unsupported packaging runner");
const build = JSON.parse(
  await readFile(join(input, "build-info.json"), "utf8"),
);
if (build.sha !== sha || build.version !== version)
  throw new Error(
    "Build manifest does not match exact verified source/version",
  );
await mkdir(output, { recursive: true });
const scratch = await mkdtemp(join(tmpdir(), "kone-package-"));
const assets = [];
try {
  for (const target of selected) {
    const metadata = build.binaries.find((binary) => binary.target === target);
    if (
      !metadata ||
      safeName(metadata.name) !==
        `kone-${target}${target.startsWith("windows-") ? ".exe" : ""}` ||
      (await hashFile(join(input, metadata.name))) !== metadata.sha256
    )
      throw new Error(`Binary integrity failed: ${target}`);
    const binary = join(input, metadata.name);
    if (platform !== "win32") await chmod(binary, 0o755);
    const native = target.endsWith(`-${architecture}`);
    if (native)
      assertVersion(
        execFileSync(binary, ["-version"], {
          encoding: "utf8",
          timeout: 15000,
        }),
        version,
      );
    const base = `kone-${version}-${target}`;
    const stage = join(scratch, base);
    await mkdir(stage);
    await cp(binary, join(stage, platform === "win32" ? "kone.exe" : "kone"));
    for (const filename of [
      "LICENSE",
      "LICENSE-MIT",
      "build-info.json",
      "licenses",
    ])
      await cp(join(input, filename), join(stage, filename), {
        recursive: true,
      });
    await cp(
      platform === "win32"
        ? "scripts/release/install.ps1"
        : "scripts/release/install.sh",
      join(stage, platform === "win32" ? "install.ps1" : "install.sh"),
    );
    await writeFile(
      join(stage, "README.txt"),
      `KONE ${version}\nCommit: ${sha}\n\nRun kone${platform === "win32" ? ".exe" : ""} without arguments to open local management with capture paused.\nPortable installer copies files only; no autostart, firewall, routes, DNS or certificate trust changes.\nTUN capture requires host privileges and explicit enablement after preflight.\nSettings live separately in the user configuration directory; back them up before upgrading or rolling back.\nThis package is unsigned${platform === "darwin" ? " and not notarized" : ""}. Verify SHA256SUMS before use.\n${native ? "The packaged executable passed -version on this architecture; required CI validates driver/lifecycle separately." : "Cross-compiled architecture: runtime and driver behavior require hardware acceptance; treat as experimental."}\nLinux ARMv7 uses only the system stack. Other targets include optional mixed-stack support.\nCorresponding source, vendored dependencies and licenses are included in this release.\n`,
    );
    const record = async (filename) =>
      assets.push({
        name: filename,
        sha256: await hashFile(join(output, filename)),
        target,
        native_version_checked: native,
        signed: false,
        experimental: !native,
      });
    if (platform === "win32") {
      const archive = `${base}.zip`;
      execFileSync(
        "pwsh",
        [
          "-NoProfile",
          "-File",
          "scripts/release/zip.ps1",
          "-Source",
          stage,
          "-Destination",
          join(output, archive),
        ],
        { stdio: "inherit" },
      );
      if (native) {
        const extracted = join(scratch, `${base}-extracted`);
        const installed = join(scratch, `${base}-installed`);
        execFileSync(
          "pwsh",
          [
            "-NoProfile",
            "-File",
            "scripts/release/expand.ps1",
            "-Source",
            join(output, archive),
            "-Destination",
            extracted,
          ],
          { stdio: "inherit" },
        );
        execFileSync(
          "pwsh",
          [
            "-NoProfile",
            "-File",
            join(extracted, base, "install.ps1"),
            "-Prefix",
            installed,
          ],
          { stdio: "inherit" },
        );
        assertVersion(
          execFileSync(join(installed, "kone.exe"), ["-version"], {
            encoding: "utf8",
            timeout: 15000,
          }),
          version,
        );
      }
      await record(archive);
    } else {
      await chmod(join(stage, "kone"), 0o755);
      await chmod(join(stage, "install.sh"), 0o755);
      const archive = `${base}.tar.gz`;
      execFileSync(
        "tar",
        ["-czf", join(output, archive), "-C", scratch, base],
        { stdio: "inherit" },
      );
      await record(archive);
      if (native) {
        const extracted = join(scratch, `${base}-extracted`);
        const installed = join(scratch, `${base}-installed`);
        await mkdir(extracted);
        execFileSync("tar", ["-xzf", join(output, archive), "-C", extracted], {
          stdio: "inherit",
        });
        execFileSync("sh", [join(extracted, base, "install.sh"), installed], {
          stdio: "inherit",
        });
        assertVersion(
          execFileSync(join(installed, "bin/kone"), ["-version"], {
            encoding: "utf8",
            timeout: 15000,
          }),
          version,
        );
      }
      const packageRoot = join(scratch, `${base}-root`);
      const executableDir = join(
        packageRoot,
        platform === "linux" ? "usr/bin" : "usr/local/bin",
      );
      await mkdir(executableDir, { recursive: true });
      await cp(join(stage, "kone"), join(executableDir, "kone"));
      await chmod(join(executableDir, "kone"), 0o755);
      const docs = join(
        packageRoot,
        platform === "linux" ? "usr/share/doc/kone" : "usr/local/share/kone",
      );
      await mkdir(docs, { recursive: true });
      for (const name of [
        "LICENSE",
        "LICENSE-MIT",
        "licenses",
        "build-info.json",
        "README.txt",
      ])
        await cp(join(stage, name), join(docs, name), { recursive: true });
      if (platform === "linux") {
        const deb = `${base}.deb`;
        await mkdir(join(packageRoot, "DEBIAN"));
        await writeFile(
          join(packageRoot, "DEBIAN/control"),
          `Package: kone\nVersion: ${version.replace("-dev.", "~dev.")}\nArchitecture: ${{ amd64: "amd64", arm64: "arm64", armv7: "armhf" }[target.split("-")[1]]}\nMaintainer: KONE maintainers <noreply@github.com>\nSection: net\nPriority: optional\nDepends: iproute2, ca-certificates\nDescription: KONE local TUN proxy and management console\n No network capture is enabled by installation.\n`,
        );
        execFileSync(
          "dpkg-deb",
          ["--root-owner-group", "--build", packageRoot, join(output, deb)],
          { stdio: "inherit" },
        );
        await record(deb);
        if (native) {
          const extracted = join(scratch, `${base}-deb-extracted`);
          execFileSync(
            "dpkg-deb",
            ["--extract", join(output, deb), extracted],
            { stdio: "inherit" },
          );
          assertVersion(
            execFileSync(join(extracted, "usr/bin/kone"), ["-version"], {
              encoding: "utf8",
              timeout: 15000,
            }),
            version,
          );
        }
      } else {
        const pkg = `${base}.pkg`;
        execFileSync(
          "pkgbuild",
          [
            "--root",
            packageRoot,
            "--identifier",
            `org.kone.cli.${target.split("-")[1]}`,
            "--version",
            version.split("-")[0],
            "--install-location",
            "/",
            join(output, pkg),
          ],
          { stdio: "inherit" },
        );
        await record(pkg);
        if (native) {
          const extracted = join(scratch, `${base}-pkg-extracted`);
          execFileSync(
            "pkgutil",
            ["--expand-full", join(output, pkg), extracted],
            { stdio: "inherit" },
          );
          assertVersion(
            execFileSync(
              join(extracted, "Payload/usr/local/bin/kone"),
              ["-version"],
              { encoding: "utf8", timeout: 15000 },
            ),
            version,
          );
        }
      }
    }
  }
  await writeFile(
    join(output, `packages-${platform}.json`),
    JSON.stringify({ schema: 1, sha, version, platform, assets }, null, 2) +
      "\n",
  );
} finally {
  if (!resolve(scratch).startsWith(join(resolve(tmpdir()), "kone-package-")))
    throw new Error("Unexpected package temporary directory");
  await rm(scratch, { recursive: true, force: true });
}
