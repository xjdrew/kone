import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { basename, delimiter, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { showHelp, taskHelp } from "../../scripts/tasks/help.mjs";

const commands = ["init", "dev", "quality", "build", "build-all", "package", "package-all"];
const root = fileURLToPath(new URL("../../", import.meta.url));

test("task help defines defaults, options and examples and rejects surplus or invalid arguments", () => {
  for (const command of commands) {
    for (const flag of ["-h", "--help"]) {
      const messages = [];
      assert.equal(showHelp(command, [flag], message => messages.push(message)), true);
      assert.equal(messages.length, 1);
      assert.match(messages[0], new RegExp(`Usage: just ${command}`));
      for (const label of ["Default:", "Options:", "Examples:"]) assert.ok(messages[0].includes(label));
    }
    assert.equal(showHelp(command, []), false);
    for (const args of [["bogus"], ["--help", "extra"], ["system", "ignored"]])
      assert.throws(() => showHelp(command, args), /Invalid arguments.*\nUsage:/);
  }
  assert.equal(showHelp("build", ["mixed"]), false);
  assert.equal(showHelp("quality", ["vet"]), false);
  assert.throws(() => taskHelp("unknown"), /Unknown task/);
});

test("every public just command supports side-effect-free help and rejects extra argv before tool invocation", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "kone help tasks "));
  t.after(async () => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert.ok(basename(directory).startsWith("kone help tasks "));
    await rm(directory, { recursive: true, force: true });
  });
  const source = join(directory, "empty source with spaces");
  const bin = join(directory, "fake tools");
  const log = join(directory, "calls.jsonl");
  await mkdir(source);
  await mkdir(bin);
  for (const command of ["go", "git", "npm", "npx"]) {
    const file = join(bin, command);
    await writeFile(file, `#!/usr/bin/env node\nrequire('node:fs').appendFileSync(process.env.KONE_HELP_LOG, ${JSON.stringify(command)} + '\\n'); process.exit(79);\n`);
    await chmod(file, 0o755);
  }
  const env = {
    ...process.env,
    PATH: `${bin}${delimiter}${process.env.PATH || ""}`,
    JUST_JUSTFILE: join(root, "justfile"),
    JUST_WORKING_DIRECTORY: source,
    KONE_HELP_LOG: log,
  };
  const run = (args) => {
    const result = spawnSync(process.env.KONE_JUST_BINARY || "just", args, { cwd: directory, env, encoding: "utf8", timeout: 15000 });
    assert.ifError(result.error);
    return result;
  };
  for (const command of commands) {
    for (const flag of ["-h", "--help"]) {
      const result = run([command, flag]);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, new RegExp(`Usage: just ${command}`));
    }
    const invalid = run([command, "--help", "unexpected"]);
    assert.notEqual(invalid.status, 0);
    assert.match(invalid.stderr, /Invalid arguments/);
  }
  assert.deepEqual(await readdir(source), [], "help must not initialize or build files");
  await assert.rejects(readFile(log), { code: "ENOENT" });
});
