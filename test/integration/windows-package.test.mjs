import { test } from "node:test";
import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runWindowsScript } from "../../scripts/release/windows-powershell.mjs";

const scripts = fileURLToPath(new URL("../../scripts/release/", import.meta.url));

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "kone windows package "));
  t.after(async () => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert.ok(basename(directory).startsWith("kone windows package "));
    await rm(directory, { recursive: true, force: true });
  });
  // Git Bash need not expose either pwsh or powershell in PATH.
  const env = { ...process.env, PATH: directory };
  return {
    directory,
    run(script, args) {
      return runWindowsScript(script, args, {
        env, stdio: "pipe", encoding: "utf8", timeout: 30000,
      });
    },
  };
}

test("Windows packages zip, extract and install with no PowerShell in PATH", {
  skip: process.platform !== "win32",
}, async (t) => {
  const f = await fixture(t);
  const base = "kone-test-windows-amd64";
  const source = join(f.directory, "staging [literal] & 中文", base);
  await mkdir(join(source, "licenses"), { recursive: true });
  const files = {
    "kone.exe": "inert packaging fixture; never executed\n",
    LICENSE: "license fixture\n",
    "LICENSE-MIT": "legacy license fixture\n",
    "build-info.json": '{"fixture":true}\n',
    "README.txt": "Windows package fixture\n",
    "licenses/component.txt": "component license\n",
  };
  for (const [name, contents] of Object.entries(files))
    await writeFile(join(source, name), contents);
  await cp(join(scripts, "install.ps1"), join(source, "install.ps1"));
  const archive = join(f.directory, "package 中文 with spaces.zip");
  const extracted = join(f.directory, "extracted 中文 with spaces");
  const installed = join(f.directory, "installed 中文 with spaces");
  f.run(join(scripts, "zip.ps1"), ["-Source", source, "-Destination", archive]);
  assert.equal((await readFile(archive)).subarray(0, 2).toString(), "PK");
  f.run(join(scripts, "expand.ps1"), ["-Source", archive, "-Destination", extracted]);
  f.run(join(extracted, base, "install.ps1"), ["-Prefix", installed]);
  for (const [name, contents] of Object.entries(files)) {
    assert.equal(await readFile(join(extracted, base, name), "utf8"), contents);
    assert.equal(await readFile(join(installed, name), "utf8"), contents);
  }
});

test("Windows packaging propagates the PowerShell script exit code", {
  skip: process.platform !== "win32",
}, async (t) => {
  const f = await fixture(t);
  const script = join(f.directory, "failure with spaces.ps1");
  await writeFile(script, "exit 37\n");
  assert.throws(() => f.run(script, []), (error) => error.status === 37);
});
