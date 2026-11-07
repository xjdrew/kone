import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";

const repository = fileURLToPath(new URL("../../", import.meta.url));

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "kone container cache "));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const tools = join(directory, "tools");
  const source = join(directory, "source");
  const bin = join(directory, "bin");
  const runner = join(directory, "runner temp");
  await Promise.all([mkdir(tools), mkdir(source), mkdir(bin), mkdir(runner)]);
  await cp(join(repository, "justfile"), join(tools, "justfile"));
  await cp(join(repository, "scripts/ci"), join(tools, "scripts/ci"), { recursive: true });
  const log = join(directory, "docker.jsonl");
  await writeFile(join(bin, "docker"), `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.KONE_DOCKER_LOG, JSON.stringify({ args, cwd: process.cwd() }) + '\\n');
if (args[0] === 'buildx' && args[1] === 'build') {
  if (process.env.KONE_FAIL_BUILD === '1') process.exit(41);
  const output = args[args.indexOf('--cache-to') + 1].match(/dest=(.*),mode=max$/)[1];
  fs.writeFileSync(path.join(output, 'index.json'), 'fresh');
}
`);
  await chmod(join(bin, "docker"), 0o755);
  const cache = join(runner, "kone-buildkit-cache");
  return {
    directory, runner, cache, source,
    run(overrides = {}) {
      const result = spawnSync(process.env.KONE_JUST_BINARY || "just", ["ci", "docker-build"], {
        cwd: source, encoding: "utf8", timeout: 20000,
        env: { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}`,
          JUST_JUSTFILE: join(tools, "justfile"), JUST_WORKING_DIRECTORY: source,
          KONE_DOCKER_LOG: log, KONE_DOCKER_CACHE: "1", RUNNER_TEMP: runner,
          GITHUB_ACTIONS: "true", RUNNER_OS: "Linux", GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "2",
          ...overrides },
      });
      assert.ifError(result.error);
      return result;
    },
    async calls() {
      try { return (await readFile(log, "utf8")).trim().split("\n").map(JSON.parse); }
      catch (error) { if (error.code === "ENOENT") return []; throw error; }
    },
  };
}

test("ordinary container builds need no CI environment or buildx cache", async (t) => {
  const f = await fixture(t);
  const result = f.run({ KONE_DOCKER_CACHE: "", GITHUB_ACTIONS: "false", RUNNER_TEMP: "" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(await f.calls(), [{ args: ["build", "-f", "deploy/docker/Dockerfile", "-t", "kone:ci", "."], cwd: f.source }]);
});

test("CI cache mode refuses a local host before invoking Docker", async (t) => {
  const f = await fixture(t);
  const result = f.run({ GITHUB_ACTIONS: "false" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /disposable Linux GitHub runner/);
  assert.deepEqual(await f.calls(), []);
});

for (const warm of [false, true]) {
  test(`container cache ${warm ? "hit" : "miss"} builds the selected source and replaces only exported layers`, async (t) => {
    const f = await fixture(t);
    if (warm) {
      await mkdir(f.cache);
      await writeFile(join(f.cache, "index.json"), "old");
      await writeFile(join(f.cache, "unreferenced-layer"), "old");
    }
    await writeFile(join(f.runner, "unrelated"), "preserve");
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
    const calls = await f.calls();
    const build = calls.find(call => call.args[1] === "build");
    assert.equal(build.cwd, f.source);
    assert.ok(build.args.includes("--load"), "the following container check must use this build");
    assert.deepEqual(build.args.slice(-5), ["-f", "deploy/docker/Dockerfile", "-t", "kone:ci", "."]);
    assert.equal(build.args.includes("--cache-from"), warm);
    if (warm) assert.equal(build.args[build.args.indexOf("--cache-from") + 1], `type=local,src=${f.cache}`);
    assert.equal(await readFile(join(f.cache, "index.json"), "utf8"), "fresh");
    assert.deepEqual(await readdir(f.cache), ["index.json"]);
    assert.deepEqual((await readdir(f.runner)).sort(), ["kone-buildkit-cache", "unrelated"]);
    assert.deepEqual(calls.at(-1).args, ["buildx", "rm", "kone-ci-123-2"]);
  });
}

test("a failed container build propagates failure, preserves the restored cache and removes temporary resources", async (t) => {
  const f = await fixture(t);
  await mkdir(f.cache);
  await writeFile(join(f.cache, "index.json"), "old");
  const result = f.run({ KONE_FAIL_BUILD: "1" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /41/);
  assert.equal(await readFile(join(f.cache, "index.json"), "utf8"), "old");
  assert.deepEqual(await readdir(f.runner), ["kone-buildkit-cache"]);
  assert.deepEqual((await f.calls()).at(-1).args, ["buildx", "rm", "kone-ci-123-2"]);
});
