import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { context } from "../../scripts/tasks/common.mjs";
import { maintainIcons } from "../../scripts/tasks/icons.mjs";

test("explicit icon maintenance pins the generator, reuses dependencies and checks both executable resource copies", async (t) => {
  const cwd = await mkdtemp(join(tmpdir(), "kone icon task "));
  t.after(async () => {
    assert.equal(dirname(resolve(cwd)), resolve(tmpdir()));
    await rm(cwd, { recursive: true, force: true });
  });
  await mkdir(join(cwd, "scripts/assets"), { recursive: true });
  await mkdir(join(cwd, "web/native"), { recursive: true });
  for (const name of ["package.json", "package-lock.json"]) await writeFile(join(cwd, "scripts/assets", name), "{}\n");
  const calls = [];
  const ctx = context({ cwd, log: () => {}, run(command, args, options = {}) {
    calls.push({ command, args, options });
    if (command === "bash") {
      const folder = join(cwd, "scripts/assets/node_modules/sharp");
      mkdirSync(folder, { recursive: true });
      writeFileSync(join(folder, "package.json"), "{}");
    }
    if (command === "go") {
      assert.equal(args[1], "github.com/tc-hib/go-winres@v0.3.3");
      assert.equal(options.cwd, join(cwd, "web/native"));
      const output = args[args.indexOf("--out") + 1];
      for (const arch of ["amd64", "arm64"]) writeFileSync(`${output}_windows_${arch}.syso`, `resource-${arch}`);
    }
  } });
  await assert.rejects(maintainIcons(ctx, "invalid"), /generate or check/);
  assert.equal(calls.length, 0);
  await maintainIcons(ctx, "generate");
  await maintainIcons(ctx, "check");
  assert.equal(calls.filter(call => call.command === "bash").length, 1);
  for (const arch of ["amd64", "arm64"]) for (const entry of ["kone", "kone-cli"])
    assert.equal(await readFile(join(cwd, "cmd", entry, `rsrc_windows_${arch}.syso`), "utf8"), `resource-${arch}`);
  await writeFile(join(cwd, "cmd/kone-cli/rsrc_windows_arm64.syso"), "stale");
  await assert.rejects(maintainIcons(ctx, "check"), /is stale/);
});
