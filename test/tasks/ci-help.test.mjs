import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { delimiter, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
test("mock browser maintenance excludes real-manager journeys and real fixtures use the terminal entrypoint", async () => {
  const justfile = await readFile(join(root, "scripts/ci/justfile"), "utf8");
  const mock = justfile.split("test-web-e2e-mock *args:\n")[1].split("\n\n")[0];
  assert.match(mock, /npx playwright test console\.spec\.js --project=chromium-1440x900 --grep-invert '@real'/);
  assert.doesNotMatch(mock, /go build|KONE_MANAGEMENT_TEST_BINARY|ci-web-fixture/);
  for (const name of ["web-e2e.sh", "web-fixture.sh"]) {
    const source = await readFile(join(root, "scripts/ci", name), "utf8");
    assert.match(source, /if \[\[ -d cmd\/kone-cli \]\]; then entry=\.\/cmd\/kone-cli; fi/);
    assert.match(source, /go build .*"\$entry"/);
  }
});

test("every CI task supports Bash-only help before any tool, privileged action or dependency recipe", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "kone ci help "));
  t.after(async () => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true });
  });
  const tools = join(directory, "tools");
  const source = join(directory, "empty source");
  const bin = join(directory, "fake commands");
  await Promise.all([mkdir(tools), mkdir(source), mkdir(bin)]);
  await cp(join(root, "justfile"), join(tools, "justfile"));
  await cp(join(root, "scripts/ci"), join(tools, "scripts/ci"), { recursive: true });
  const log = join(directory, "unexpected-tools");
  for (const name of ["node", "go", "git", "npm", "npx", "gofmt", "docker", "pwsh", "powershell.exe", "sudo"]) {
    await writeFile(join(bin, name), '#!/bin/bash\nprintf "unexpected tool\\n" >> "$KONE_HELP_LOG"\nexit 99\n');
    await chmod(join(bin, name), 0o755);
  }
  const text = await readFile(join(root, "scripts/ci/justfile"), "utf8");
  const names = [...text.matchAll(/^([a-z][a-z0-9-]*) \*args:/gm)].map(match => match[1]);
  assert.ok(names.length > 40);
  const env = { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}`, JUST_JUSTFILE: join(tools, "justfile"), JUST_WORKING_DIRECTORY: source, KONE_HELP_LOG: log, GITHUB_ACTIONS: "false" };
  const run = args => {
    const result = spawnSync(process.env.KONE_JUST_BINARY || "just", ["ci", ...args], { cwd: directory, env, encoding: "utf8", timeout: 10000 });
    assert.ifError(result.error);
    return result;
  };
  for (const name of names) {
    for (const flag of ["-h", "--help"]) {
      const result = run([name, flag]);
      assert.equal(result.status, 0, `${name}: ${result.stderr}`);
      for (const section of ["Usage:", "Default:", "Options:", "Examples:"]) assert.ok(result.stdout.includes(section), `${name} must explain ${section}`);
      const description = result.stdout.split("\n")[1];
      assert.ok(description.length > 20, `${name} needs an actual explanation`);
      assert.notEqual(description, name.replaceAll("-", " "));
      const example = result.stdout.match(/Examples:\n  (.+)/)[1];
      assert.doesNotMatch(example, /[\[\]<>]/, `${name} needs a concrete command example`);
    }
    const invalid = run([name, "--help", "extra"]);
    assert.notEqual(invalid.status, 0, name);
  }
  assert.deepEqual(await readdir(source), []);
  await assert.rejects(readFile(log), { code: "ENOENT" });
});
