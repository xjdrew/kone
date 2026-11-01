import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, delimiter, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("../../scripts/ci/build-all.sh", import.meta.url));

async function fixture(t, mode) {
  const directory = await mkdtemp(join(tmpdir(), "kone matrix fixtures "));
  t.after(async () => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true });
  });
  await mkdir(join(directory, "scripts/release"), { recursive: true });
  await mkdir(join(directory, "licenses"));
  await mkdir(join(directory, "tools"));
  for (const name of ["LICENSE", "LICENSE-MIT"]) await writeFile(join(directory, name), "fixture\n");
  await writeFile(join(directory, "scripts/release/build-info.mjs"), 'import { writeFileSync } from "node:fs"; writeFileSync("dist/metadata-called", "yes");\n');
  if (mode !== "legacy") await mkdir(join(directory, "pkg/application"), { recursive: true });
  if (mode === "desktop") {
    await mkdir(join(directory, "cmd/kone-cli"), { recursive: true });
    await writeFile(join(directory, "cmd/kone-cli/main.go"), "fixture\n");
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

test("the release matrix builds eleven role-specific executables while retaining historical seven-entry qualification", async (t) => {
  for (const mode of ["legacy", "desktop", "partial"]) await t.test(mode, async (t) => {
    const directory = await fixture(t, mode);
    const log = join(directory, "calls.jsonl");
    const result = spawnSync("bash", [script], {
      cwd: directory,
      env: { ...process.env, PATH: `${join(directory, "tools")}${delimiter}${process.env.PATH}`, KONE_VERSION: "1.2.3", KONE_MATRIX_LOG: log },
      encoding: "utf8", timeout: 20000,
    });
    assert.ifError(result.error);
    const calls = (await readFile(log, "utf8")).trim().split("\n").map(line => JSON.parse(line));
    if (mode === "partial") {
      assert.notEqual(result.status, 0);
      assert.ok(calls.some(call => call.argv.at(-1) === "./cmd/kone-cli"));
      return;
    }
    assert.equal(result.status, 0, result.stderr);
    assert.equal(calls.length, mode === "desktop" ? 11 : 7);
    assert.equal(await readFile(join(directory, "dist/metadata-called"), "utf8"), "yes");
    for (const call of calls) {
      const flags = call.argv.find(arg => arg.startsWith("-ldflags="));
      const gui = mode === "desktop" && call.os === "windows" && call.argv.at(-1) === "./cmd/kone";
      assert.equal(flags.includes("-H=windowsgui"), gui);
      assert.equal(call.argv.includes("with_gvisor"), call.arch !== "arm");
      assert.ok(flags.includes("-X main.VERSION=1.2.3"));
    }
  });
});
