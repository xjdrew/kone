import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, delimiter, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { targets } from "../../scripts/release/model.mjs";

const script = fileURLToPath(new URL("../../scripts/ci/build-all.sh", import.meta.url));
const targetModule = fileURLToPath(new URL("../../scripts/release/targets.mjs", import.meta.url));
const legacyTargets = ["linux-amd64", "linux-arm64", "linux-armv7", "darwin-amd64", "darwin-arm64", "windows-amd64", "windows-arm64"];

async function fixture(t, mode) {
  const directory = await mkdtemp(join(tmpdir(), "kone matrix fixtures "));
  t.after(async () => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true });
  });
  await mkdir(join(directory, "scripts/release"), { recursive: true });
  await mkdir(join(directory, "licenses"));
  await mkdir(join(directory, "tools"));
  const modern = mode === "modern";
  await writeFile(join(directory, "scripts/release/model.mjs"), `export const targets=${JSON.stringify(modern ? targets : legacyTargets)}; export const supportedTargets=${JSON.stringify(legacyTargets)};\n`);
  await cp(targetModule, join(directory, "scripts/release/targets.mjs"));
  for (const name of ["LICENSE", "LICENSE-MIT"]) await writeFile(join(directory, name), "fixture\n");
  const metadataGuard = modern
    ? 'if (process.argv[2] !== "--targets" || process.argv.length !== 4) throw new Error("Missing explicit target selection");'
    : 'if (process.argv.length !== 2) throw new Error("Historical writer accepts no arguments");';
  await writeFile(join(directory, "scripts/release/build-info.mjs"), `import { writeFileSync } from "node:fs"; ${metadataGuard} writeFileSync("dist/metadata-called", "yes"); writeFileSync("dist/metadata-args", JSON.stringify({argv:process.argv.slice(2),stack:process.env.KONE_BUILD_STACK}));\n`);
  if (mode !== "legacy") await mkdir(join(directory, "pkg/application"), { recursive: true });
  if (mode === "desktop" || modern) {
    await mkdir(join(directory, "cmd/kone-cli"), { recursive: true });
    await writeFile(join(directory, "cmd/kone-cli/main.go"), "fixture\n");
  }
  if (modern) {
    await mkdir(join(directory, "pkg/kone"), { recursive: true });
    await writeFile(join(directory, "pkg/kone/stack_modes.go"), 'package kone\nconst StackGVisor = "gvisor"\n');
  }
  await writeFile(join(directory, "tools/go"), `#!/usr/bin/env node
const fs = require('node:fs');
const argv = process.argv.slice(2);
fs.appendFileSync(process.env.KONE_MATRIX_LOG, JSON.stringify({argv, os:process.env.GOOS, arch:process.env.GOARCH})+'\\n');
if (argv.at(-1)==='./cmd/kone-cli' && !fs.existsSync('cmd/kone-cli/main.go')) process.exit(42);
fs.writeFileSync(argv[argv.indexOf('-o')+1], 'inert build fixture');
`);
  await chmod(join(directory, "tools/go"), 0o755);
  return directory;
}

async function runMatrix(directory, overrides = {}) {
  const log = join(directory, "calls.jsonl");
  const result = spawnSync("bash", [script], {
    cwd: directory,
    env: { ...process.env, PATH: `${join(directory, "tools")}${delimiter}${process.env.PATH}`, KONE_VERSION: "1.2.3", KONE_BUILD_TARGETS: "", KONE_BUILD_STACK: "removed-override", KONE_MATRIX_LOG: log, ...overrides },
    encoding: "utf8", timeout: 20000,
  });
  assert.ifError(result.error);
  let calls = [];
  try { calls = (await readFile(log, "utf8")).trim().split("\n").filter(Boolean).map(line => JSON.parse(line)); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  return { result, calls };
}

test("the release matrix builds eleven role-specific executables while retaining historical seven-entry qualification", async (t) => {
  for (const mode of ["legacy", "desktop", "partial"]) await t.test(mode, async (t) => {
    const directory = await fixture(t, mode);
    const { result, calls } = await runMatrix(directory);
    if (mode === "partial") {
      assert.notEqual(result.status, 0);
      assert.ok(calls.some(call => call.argv.at(-1) === "./cmd/kone-cli"));
      return;
    }
    assert.equal(result.status, 0, result.stderr);
    assert.equal(calls.length, mode === "desktop" ? 11 : 7);
    assert.equal(await readFile(join(directory, "dist/metadata-called"), "utf8"), "yes");
    assert.deepEqual(JSON.parse(await readFile(join(directory, "dist/metadata-args"), "utf8")).argv, [], "historical metadata writers cannot receive new flags");
    for (const call of calls) {
      const flags = call.argv.find(arg => arg.startsWith("-ldflags="));
      const gui = mode === "desktop" && call.os === "windows" && call.argv.at(-1) === "./cmd/kone";
      assert.equal(flags.includes("-H=windowsgui"), gui);
      assert.equal(call.argv.includes("with_gvisor"), call.arch !== "arm");
      assert.ok(flags.includes("-X main.VERSION=1.2.3"));
    }
  });
});

test("the unified matrix builds six targets and ten roles; explicit ARMv7 also includes all runtime stacks", async (t) => {
  for (const armv7 of [false, true]) await t.test(`armv7=${armv7}`, async (t) => {
    const directory = await fixture(t, "modern");
    const selected = armv7 ? legacyTargets : targets;
    const { result, calls } = await runMatrix(directory, armv7 ? { KONE_BUILD_TARGETS: selected.join(",") } : {});
    assert.equal(result.status, 0, result.stderr);
    assert.equal(calls.length, armv7 ? 11 : 10);
    const built = calls.map(call => call.argv[call.argv.indexOf("-o") + 1].replace(/^dist\/kone(?:-cli)?-/, "").replace(/\.exe$/, ""));
    assert.deepEqual([...new Set(built)].sort(), [...selected].sort());
    assert.ok(calls.every(call => call.argv.includes("with_gvisor")), "every target includes all three runtime stacks");
    const metadata = JSON.parse(await readFile(join(directory, "dist/metadata-args"), "utf8"));
    assert.deepEqual(metadata.argv, ["--targets", selected.join(",")]);
    assert.equal(metadata.stack, undefined, "removed build-stack overrides cannot affect shared metadata");
  });
});

test("historical sources need no target selector and cannot mislabel a partial build as their full matrix", async (t) => {
  for (const selector of ["missing", "old"]) await t.test(selector, async (t) => {
    const directory = await fixture(t, "legacy");
    const file = join(directory, "scripts/release/targets.mjs");
    if (selector === "missing") await rm(file);
    else await writeFile(file, "export const historical = true;\n");
    const { result, calls } = await runMatrix(directory);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(calls.length, 7);
  });
  const partial = await fixture(t, "legacy");
  assert.notEqual((await runMatrix(partial, { KONE_BUILD_TARGETS: "linux-amd64" })).result.status, 0);
  await assert.rejects(readFile(join(partial, "dist/metadata-called")), { code: "ENOENT" });
  const invalid = await fixture(t, "modern");
  const bad = await runMatrix(invalid, { KONE_BUILD_TARGETS: "linux-amd64,linux-amd64" });
  assert.notEqual(bad.result.status, 0);
  assert.deepEqual(bad.calls, [], "reject ambiguous selections before compiling");
});
