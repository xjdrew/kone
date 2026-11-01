import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { gunzipSync, inflateRawSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { binaryName, entryDefinitions, nativeTarget, packagePlan, selectedTargets } from "../../scripts/release/targets.mjs";
import { targets, supportedTargets, hashFile } from "../../scripts/release/model.mjs";
import { createPortableArchive } from "../../scripts/release/portable.mjs";
import { verifyWindowsRole } from "../../scripts/release/desktop.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const sha = "1234567890abcdef1234567890abcdef12345678";

function inertExecutable(target, role) {
  if (!target.startsWith("windows-")) return Buffer.from("inert fixture; never run this program\n");
  const pe = Buffer.alloc(1024);
  pe.write("MZ"); pe.writeUInt32LE(64, 60); pe.writeUInt32LE(0x4550, 64);
  pe.writeUInt16LE(0x20b, 88); pe.writeUInt16LE(role === "gui" ? 2 : 3, 156);
  if (role === "gui") {
    pe.writeUInt16LE(1, 70); pe.writeUInt16LE(240, 84);
    pe.writeUInt32LE(0x1000, 216); pe.writeUInt32LE(128, 220);
    pe.writeUInt32LE(512, 336); pe.writeUInt32LE(0x1000, 340); pe.writeUInt32LE(512, 344); pe.writeUInt32LE(512, 348);
    pe.writeUInt16LE(1, 526); pe.writeUInt32LE(14, 528); pe.writeUInt32LE(0x80000020, 532);
    pe.writeUInt16LE(1, 558); pe.writeUInt32LE(101, 560); pe.writeUInt32LE(0x80000040, 564);
  }
  return pe;
}

async function executableFixture(input, target) {
  const entries = [];
  for (const entry of entryDefinitions(target)) {
    await writeFile(join(input, entry.name), inertExecutable(target, entry.role));
    entries.push({ ...entry, sha256: await hashFile(join(input, entry.name)) });
  }
  let icon;
  if (target.startsWith("darwin-")) {
    await writeFile(join(input, "kone.icns"), Buffer.from("icns\0\0\0\b"));
    icon = { name: "kone.icns", sha256: await hashFile(join(input, "kone.icns")) };
  }
  return { target, name: binaryName(target), sha256: entries[0].sha256, stack: "system", entries, ...(icon ? { icon } : {}) };
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "kone archive test "));
  t.after(async () => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert.ok(basename(directory).startsWith("kone archive test "));
    await rm(directory, { recursive: true, force: true });
  });
  return directory;
}

function tarEntries(archive) {
  const tar = gunzipSync(archive);
  const entries = new Map();
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512);
    const name = header.subarray(0, 100).toString().replace(/\0.*$/s, "");
    if (!name) break;
    const size = parseInt(header.subarray(124, 136).toString().replace(/\0.*$/s, "").trim(), 8) || 0;
    entries.set(name, { mode: parseInt(header.subarray(100, 108).toString(), 8), data: tar.subarray(offset + 512, offset + 512 + size) });
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return entries;
}

function zipEntries(archive) {
  const end = archive.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.ok(end >= 0, "ZIP must have a central directory");
  const entries = new Map();
  let offset = archive.readUInt32LE(end + 16);
  for (let index = 0; index < archive.readUInt16LE(end + 10); index++) {
    assert.equal(archive.readUInt32LE(offset), 0x02014b50);
    const length = archive.readUInt16LE(offset + 28);
    const name = archive.subarray(offset + 46, offset + 46 + length).toString("utf8");
    const local = archive.readUInt32LE(offset + 42);
    const dataOffset = local + 30 + archive.readUInt16LE(local + 26) + archive.readUInt16LE(local + 28);
    const compressed = archive.subarray(dataOffset, dataOffset + archive.readUInt32LE(offset + 20));
    const method = archive.readUInt16LE(offset + 10);
    assert.ok([0, 8].includes(method));
    entries.set(name, { mode: archive.readUInt32LE(offset + 38) >>> 16, data: method === 8 ? inflateRawSync(compressed) : compressed });
    offset += 46 + length + archive.readUInt16LE(offset + 30) + archive.readUInt16LE(offset + 32);
  }
  return entries;
}

test("package plans publish one native format per target and retain explicit ARMv7 builds", () => {
  assert.equal(nativeTarget("win32", "x64"), "windows-amd64");
  assert.equal(nativeTarget("darwin", "arm64"), "darwin-arm64");
  assert.equal(nativeTarget("linux", "arm"), "linux-armv7");
  for (const platform of ["win32", "linux", "darwin"]) {
    const native = nativeTarget(platform, "x64");
    const os = native.split("-")[0];
    const ci = packagePlan([], platform, "x64");
    assert.deepEqual(ci.targets, targets.filter(target => target.startsWith(`${os}-`)));
    assert.deepEqual(ci.installers, platform === "win32" ? [] : ci.targets);
    assert.deepEqual(ci.portables, platform === "win32" ? ci.targets : []);
    const all = packagePlan(["--all-portable"], platform, "x64");
    assert.deepEqual(all.targets, targets);
    assert.deepEqual(all.installers, platform === "win32" ? [] : [native]);
    assert.deepEqual(all.portables, targets);
    assert.deepEqual(packagePlan(["--all-portable", "--include-armv7"], platform, "x64").targets, supportedTargets);
    assert.deepEqual(packagePlan(["--target", native], platform, "x64").targets, [native]);
  }
  for (const value of ["../linux-amd64", "linux-amd64,linux-amd64", "", "other-amd64"])
    assert.throws(() => selectedTargets(value));
  for (const args of [["--unknown"], ["--target"], ["--all-portable", "extra"], ["--target", "linux-amd64,linux-arm64"]])
    assert.throws(() => packagePlan(args));
  assert.throws(() => nativeTarget("freebsd", "x64"));
});

test("desktop Windows executables require GUI subsystem and icon 101 while terminal tools require console subsystem", () => {
  verifyWindowsRole(inertExecutable("windows-amd64", "gui"), "gui");
  verifyWindowsRole(inertExecutable("windows-amd64", "cli"), "cli");
  assert.throws(() => verifyWindowsRole(inertExecutable("windows-amd64", "gui"), "cli"), /subsystem/);
  assert.throws(() => verifyWindowsRole(inertExecutable("windows-amd64", "cli"), "gui"), /subsystem/);
  const missingIcon = inertExecutable("windows-amd64", "gui");
  missingIcon.writeUInt32LE(102, 560);
  assert.throws(() => verifyWindowsRole(missingIcon, "gui"), /icon resource 101/);
  assert.throws(() => verifyWindowsRole(Buffer.from("not a PE"), "gui"), /Invalid Windows/);
});

test("portable archives preserve raw payloads, roots and Unix executable modes on every host, and replace local output", async (t) => {
  const directory = await fixture(t);
  const stage = join(directory, "stage with spaces [literal] 中文");
  await mkdir(join(stage, "licenses"), { recursive: true });
  const payload = Buffer.from([0, 13, 10, 255, 10]);
  await writeFile(join(stage, "kone"), payload);
  await writeFile(join(stage, "kone.exe"), payload);
  await writeFile(join(stage, "install.sh"), "#!/bin/sh\r\nexit 0\r\n");
  await writeFile(join(stage, "install.ps1"), "# inert fixture\r\n");
  await writeFile(join(stage, "licenses/component.txt"), "license\r\n");
  // Payload attributes must not omit files or rewrite bytes during archiving.
  await writeFile(join(stage, ".gitattributes"), "* export-ignore export-subst text eol=lf\n");
  for (const target of targets) {
    const windows = target.startsWith("windows-");
    const base = `kone-1.2.3-${target}`;
    const destination = join(directory, `${base}.${windows ? "zip" : "tar.gz"}`);
    await createPortableArchive({ stage, base, destination, unix: !windows });
    const entries = (windows ? zipEntries : tarEntries)(await readFile(destination));
    assert.deepEqual(entries.get(`${base}/${windows ? "kone.exe" : "kone"}`).data, payload);
    assert.equal(entries.get(`${base}/licenses/component.txt`).data.toString(), "license\r\n");
    assert.ok(entries.has(`${base}/.gitattributes`));
    if (!windows) {
      assert.equal(entries.get(`${base}/kone`).mode & 0o777, 0o755);
      assert.equal(entries.get(`${base}/install.sh`).mode & 0o777, 0o755);
    }
  }
  const destination = join(directory, "repeated.zip");
  await createPortableArchive({ stage, base: "repeat", destination, unix: false });
  await writeFile(join(stage, "kone.exe"), "updated fixture\n");
  await createPortableArchive({ stage, base: "repeat", destination, unix: false });
  assert.equal(zipEntries(await readFile(destination)).get("repeat/kone.exe").data.toString(), "updated fixture\n");
  const previous = await readFile(destination);
  await assert.rejects(() => createPortableArchive({ stage: join(directory, "missing stage"), base: "repeat", destination, unix: false }));
  assert.deepEqual(await readFile(destination), previous, "a failed build must preserve the previous local archive");
  assert.deepEqual((await readdir(directory)).filter(name => name.startsWith(".kone-archive-")), []);
});

test("foreign-target packaging checks source identity and hashes, never executes the fixture, and marks it experimental", async (t) => {
  const directory = await fixture(t);
  const target = process.platform === "win32" ? "linux-amd64" : "windows-amd64";
  const input = join(directory, "input with spaces");
  const output = join(directory, "output with spaces");
  await mkdir(join(input, "licenses"), { recursive: true });
  const name = binaryName(target);
  for (const file of ["LICENSE", "LICENSE-MIT", "licenses/component.txt"]) await writeFile(join(input, file), "fixture license\n");
  const metadata = { schema: 1, sha, version: "1.2.3", binaries: [await executableFixture(input, target)] };
  await writeFile(join(input, "build-info.json"), JSON.stringify(metadata));
  const env = { ...process.env, RELEASE_INPUT: input, RELEASE_OUTPUT: output, RELEASE_SHA: sha, RELEASE_VERSION: "1.2.3" };
  execFileSync(process.execPath, [join(root, "scripts/release/package.mjs"), "--target", target], { cwd: root, env, stdio: "pipe" });
  const manifest = JSON.parse(await readFile(join(output, `packages-${process.platform}.json`), "utf8"));
  assert.equal(manifest.assets.length, 1);
  const [asset] = manifest.assets;
  assert.equal(asset.target, target);
  assert.equal(asset.native_version_checked, false);
  assert.equal(asset.experimental, true);
  assert.equal(await hashFile(join(output, asset.name)), asset.sha256);
  const entries = (target.startsWith("windows-") ? zipEntries : tarEntries)(await readFile(join(output, asset.name)));
  const base = `kone-1.2.3-${target}`;
  assert.match(entries.get(`${base}/README.txt`).data.toString(), /Included stacks: system\./);
  await writeFile(join(input, name), "tampered\n");
  const invalid = spawnSync(process.execPath, [join(root, "scripts/release/package.mjs"), "--target", target], { cwd: root, env, encoding: "utf8" });
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /Binary integrity failed/);
});

test("local native and all-portable packaging never execute or install even host-native text fixtures", async (t) => {
  const directory = await fixture(t);
  const input = join(directory, "local build inputs");
  await mkdir(join(input, "licenses"), { recursive: true });
  const binaries = [];
  for (const target of targets) {
    binaries.push(await executableFixture(input, target));
  }
  for (const file of ["LICENSE", "LICENSE-MIT", "licenses/component.txt"]) await writeFile(join(input, file), "fixture license\n");
  await writeFile(join(input, "build-info.json"), JSON.stringify({ schema: 1, sha, version: "1.2.3", binaries }));
  for (const [mode, args, count] of [
    ["native", ["--target", nativeTarget()], 1],
    ["all", ["--all-portable"], targets.length + (process.platform === "win32" ? 0 : 1)],
  ]) {
    const output = join(directory, `${mode} package outputs`);
    const log = execFileSync(process.execPath, [join(root, "scripts/release/package.mjs"), ...args], {
      cwd: root,
      env: { ...process.env, GITHUB_ACTIONS: "false", RELEASE_INPUT: input, RELEASE_OUTPUT: output, RELEASE_SHA: sha, RELEASE_VERSION: "1.2.3" },
      encoding: "utf8", stdio: "pipe",
    });
    assert.doesNotMatch(log, /Installed KONE|Installed in/i);
    const manifest = JSON.parse(await readFile(join(output, `packages-${process.platform}.json`), "utf8"));
    assert.equal(manifest.sha, sha);
    assert.equal(manifest.version, "1.2.3");
    assert.equal(manifest.assets.length, count);
    for (const asset of manifest.assets) {
      assert.equal(asset.native_version_checked, false);
      assert.equal(asset.experimental, true);
      assert.equal(asset.sha256, await hashFile(join(output, asset.name)));
      assert.deepEqual(asset.entries.map(entry => ({ role: entry.role, name: entry.name })), entryDefinitions(asset.target));
      if (asset.name.endsWith(".tar.gz") || asset.name.endsWith(".zip")) {
        const entries = (asset.name.endsWith(".zip") ? zipEntries : tarEntries)(await readFile(join(output, asset.name)));
        const readme = entries.get(`kone-1.2.3-${asset.target}/README.txt`).data.toString();
        assert.match(readme, /without executing or installing its executable/);
        assert.doesNotMatch(readme, /passed -version/);
        const base = `kone-1.2.3-${asset.target}`;
        if (asset.target.startsWith("darwin-")) {
          assert.equal(entries.get(`${base}/Kone.app/Contents/MacOS/kone`).mode & 0o777, 0o755);
          assert.equal(entries.get(`${base}/bin/kone-cli`).mode & 0o777, 0o755);
          const plist = entries.get(`${base}/Kone.app/Contents/Info.plist`).data.toString();
          assert.match(plist, /<key>LSUIElement<\/key><true\/>/);
          assert.ok(plist.includes(sha));
          assert.ok(entries.has(`${base}/Kone.app/Contents/Resources/Kone.icns`));
        } else if (asset.target.startsWith("windows-")) {
          assert.ok(entries.has(`${base}/kone.exe`));
          assert.ok(entries.has(`${base}/kone-cli.exe`));
        } else assert.ok(!entries.has(`${base}/kone-cli`));
      }
    }
  }
});

test("build manifests record all runtime stacks, exact kernels and optional ARMv7", async (t) => {
  const directory = await fixture(t);
  const git = (...args) => execFileSync("git", args, { cwd: directory, encoding: "utf8", stdio: "pipe" }).trim();
  git("init", "--quiet", "--template=", "-b", "master");
  await writeFile(join(directory, "fixture"), "fixture\n");
  git("add", "fixture");
  git("-c", "user.name=Package Test", "-c", "user.email=package@example.invalid", "commit", "-m", "fixture");
  await mkdir(join(directory, "dist"));
  for (const target of supportedTargets) await executableFixture(join(directory, "dist"), target);
  await writeFile(join(directory, "go.mod"), `module fixture\nrequire (\n github.com/sagernet/sing-tun v0.9.7\n github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1\n)\nreplace github.com/sagernet/sing-tun => github.com/xjdrew/sing-tun v0.0.0-20261031132454-fc4685fee0a3\n`);
  await mkdir(join(directory, "web/native"), { recursive: true });
  await writeFile(join(directory, "web/native/kone.icns"), Buffer.from("icns\0\0\0\b"));
  const run = (args, stack = "") => execFileSync(process.execPath, [join(root, "scripts/release/build-info.mjs"), ...args], {
    cwd: directory, env: { ...process.env, KONE_VERSION: "1.2.3", KONE_BUILD_STACK: stack }, stdio: "pipe",
  });
  assert.throws(() => run(["--targets", nativeTarget()], "system"), /KONE_BUILD_STACK was removed/);
  run(["--targets", nativeTarget()]);
  let manifest = JSON.parse(await readFile(join(directory, "dist/build-info.json"), "utf8"));
  assert.deepEqual(manifest.binaries.map(binary => [binary.target, binary.stack]), [[nativeTarget(), "system,gvisor,mixed"]]);
  assert.equal(manifest.kernels.tun.replace.path, "github.com/xjdrew/sing-tun");
  assert.equal(manifest.kernels.tun.replace.version, "v0.0.0-20261031132454-fc4685fee0a3");
  assert.equal(manifest.kernels.gvisor.version, "v0.0.0-20260727.0-sing-box-mod.1");
  run(["--targets", "linux-armv7"]);
  manifest = JSON.parse(await readFile(join(directory, "dist/build-info.json"), "utf8"));
  assert.equal(manifest.binaries[0].target, "linux-armv7");
  assert.equal(manifest.binaries[0].stack, "system,gvisor,mixed");
  run([], "");
  manifest = JSON.parse(await readFile(join(directory, "dist/build-info.json"), "utf8"));
  assert.deepEqual(manifest.binaries.map(binary => binary.target), targets);
  assert.equal(manifest.default_stack, "system");
  assert.deepEqual(manifest.build_tags, ["with_gvisor"]);
  for (const binary of manifest.binaries) {
    assert.deepEqual(binary.stacks, ["system", "gvisor", "mixed"]);
    assert.equal(binary.default_stack, "system");
  }
});
