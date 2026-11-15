import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { bun, context } from "../../scripts/tasks/common.mjs";

test("Windows Bun calls resolve shell launchers and preserve arguments, cwd and failures", async t => {
  const directory = await mkdtemp(join(tmpdir(), "kone bun launcher "));
  t.after(async () => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true });
  });
  const bin = join(directory, "tools with spaces");
  const cwd = join(directory, "web with spaces");
  await Promise.all([mkdir(bin), mkdir(cwd)]);
  const launcher = join(bin, "bun");
  const fixture = join(directory, "bun-fixture.cjs");
  const log = join(directory, "calls.jsonl");
  await writeFile(launcher, '#!/usr/bin/env bash\nexec node "$KONE_BUN_FIXTURE" "$@"\n');
  await chmod(launcher, 0o755);
  await writeFile(fixture, `
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.KONE_BUN_LOG, JSON.stringify({ args, cwd: process.cwd() }) + '\\n');
if (args[0] === '--version') console.log('1.4.4');
process.exit(Number(process.env.KONE_BUN_EXIT || 0));
`);
  const env = {
    ...process.env,
    PATH: `${bin}${delimiter}${process.env.PATH}`,
    KONE_BUN_FIXTURE: fixture,
    KONE_BUN_LOG: log,
  };
  if (process.platform === "win32") {
    const direct = spawnSync(launcher, ["--version"], { env, cwd, encoding: "utf8" });
    assert.ok(direct.error, "Windows cannot directly execute the extensionless shell launcher");
  }
  const ctx = context({ cwd, env, platform: "win32" });
  assert.equal(bun(ctx, ["--version"], { capture: true }), "1.4.4");
  bun(ctx, ["install", "--frozen-lockfile"], { capture: true });
  const args = ["run", "build", "--", "a path with spaces", '$(echo WRONG); & "quoted"'];
  bun(ctx, args, { capture: true });
  const records = (await readFile(log, "utf8")).trim().split("\n").map(line => JSON.parse(line));
  assert.deepEqual(records.map(record => record.args), [["--version"], ["install", "--frozen-lockfile"], args]);
  for (const record of records) assert.equal(resolve(record.cwd), resolve(cwd));
  assert.throws(() => bun(ctx, ["run", "build"], { capture: true, env: { ...env, KONE_BUN_EXIT: "37" } }), /exit 37/);
});
