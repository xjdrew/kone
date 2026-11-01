import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { gunzipSync, inflateRawSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { binaryName, nativeTarget, packagePlan, selectedTargets } from "../../scripts/release/targets.mjs";
import { targets, hashFile } from "../../scripts/release/model.mjs";
import { createPortableArchive } from "../../scripts/release/portable.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const sha = "1234567890abcdef1234567890abcdef12345678";

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

test("native target and package plans distinguish OS, architecture and the unchanged CI installer matrix", () => {
  assert.equal(nativeTarget("win32", "x64"), "windows-amd64");
  assert.equal(nativeTarget("darwin", "arm64"), "darwin-arm64");
  assert.equal(nativeTarget("linux", "arm"), "linux-armv7");
  for (const platform of ["win32", "linux", "darwin"]) {
    const native = nativeTarget(platform, "x64");
    const os = native.split("-")[0];
    const ci = packagePlan([], platform, "x64");
    assert.deepEqual(ci.targets, targets.filter(target => target.startsWith(`${os}-`)));
    assert.deepEqual(ci.installers, platform === "win32" ? [] : ci.targets);
    const all = packagePlan(["--all-portable"], platform, "x64");
    assert.deepEqual(all.targets, targets);
    assert.deepEqual(all.installers, platform === "win32" ? [] : [native]);
    assert.deepEqual(packagePlan(["--target", native], platform, "x64").targets, [native]);
  }
  for (const value of ["../linux-amd64", "linux-amd64,linux-amd64", "", "other-amd64"])
    assert.throws(() => selectedTargets(value));
  for (const args of [["--unknown"], ["--target"], ["--all-portable", "extra"], ["--target", "linux-amd64,linux-arm64"]])
    assert.throws(() => packagePlan(args));
  assert.throws(() => nativeTarget("freebsd", "x64"));
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
  await writeFile(join(input, name), "inert binary fixture; attempting to execute this must fail\n");
  for (const file of ["LICENSE", "LICENSE-MIT", "licenses/component.txt"]) await writeFile(join(input, file), "fixture license\n");
  const metadata = { schema: 1, sha, version: "1.2.3", binaries: [{ target, name, sha256: await hashFile(join(input, name)), stack: "system" }] };
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
    const name = binaryName(target);
    await writeFile(join(input, name), "inert text fixture; this is not an executable program\n");
    binaries.push({ target, name, sha256: await hashFile(join(input, name)), stack: "system" });
  }
  for (const file of ["LICENSE", "LICENSE-MIT", "licenses/component.txt"]) await writeFile(join(input, file), "fixture license\n");
  await writeFile(join(input, "build-info.json"), JSON.stringify({ schema: 1, sha, version: "1.2.3", binaries }));
  for (const [mode, args, count] of [
    ["native", ["--target", nativeTarget()], process.platform === "win32" ? 1 : 2],
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
      if (asset.name.endsWith(".tar.gz") || asset.name.endsWith(".zip")) {
        const entries = (asset.name.endsWith(".zip") ? zipEntries : tarEntries)(await readFile(join(output, asset.name)));
        const readme = entries.get(`kone-1.2.3-${asset.target}/README.txt`).data.toString();
        assert.match(readme, /without executing or installing its executable/);
        assert.doesNotMatch(readme, /passed -version/);
      }
    }
  }
});

test("build manifests support a native subset, preserve the all-target default, and accurately record stacks", async (t) => {
  const directory = await fixture(t);
  const git = (...args) => execFileSync("git", args, { cwd: directory, encoding: "utf8", stdio: "pipe" }).trim();
  git("init", "--quiet", "--template=", "-b", "master");
  await writeFile(join(directory, "fixture"), "fixture\n");
  git("add", "fixture");
  git("-c", "user.name=Package Test", "-c", "user.email=package@example.invalid", "commit", "-m", "fixture");
  await mkdir(join(directory, "dist"));
  for (const target of targets) await writeFile(join(directory, "dist", binaryName(target)), `inert ${target}\n`);
  const run = (args, stack) => execFileSync(process.execPath, [join(root, "scripts/release/build-info.mjs"), ...args], {
    cwd: directory, env: { ...process.env, KONE_VERSION: "1.2.3", KONE_BUILD_STACK: stack }, stdio: "pipe",
  });
  run(["--targets", nativeTarget()], "system");
  let manifest = JSON.parse(await readFile(join(directory, "dist/build-info.json"), "utf8"));
  assert.deepEqual(manifest.binaries.map(binary => [binary.target, binary.stack]), [[nativeTarget(), "system"]]);
  run(["--targets", "linux-amd64"], "mixed");
  manifest = JSON.parse(await readFile(join(directory, "dist/build-info.json"), "utf8"));
  assert.equal(manifest.binaries[0].stack, "system,mixed");
  run([], "");
  manifest = JSON.parse(await readFile(join(directory, "dist/build-info.json"), "utf8"));
  assert.deepEqual(manifest.binaries.map(binary => binary.target), targets);
  for (const binary of manifest.binaries) assert.equal(binary.stack, binary.target === "linux-armv7" ? "system" : "system,mixed");
});
