import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = fileURLToPath(new URL("../../", import.meta.url));
const just = process.env.KONE_JUST_BINARY || "just";

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "kone tasks "));
  t.after(async () => {
    assert.ok(resolve(directory).startsWith(join(resolve(tmpdir()), "kone tasks ")));
    await rm(directory, { recursive: true, force: true });
  });
  const tools = join(directory, "entrypoint tools with spaces");
  const source = join(directory, "selected source with spaces");
  const bin = join(directory, "fake tools");
  const log = join(directory, "calls.jsonl");
  await Promise.all([mkdir(tools), mkdir(source), mkdir(bin)]);
  await cp(join(repository, "justfile"), join(tools, "justfile"));
  await cp(join(repository, "scripts/ci"), join(tools, "scripts/ci"), { recursive: true });
  await mkdir(join(source, "scripts"));
  await cp(join(repository, "scripts/test-shadowsocks-interop.sh"), join(source, "scripts/test-shadowsocks-interop.sh"));
  await writeFile(join(bin, "go"), `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const argv = process.argv.slice(2);
fs.appendFileSync(process.env.KONE_FAKE_LOG, JSON.stringify({ argv, cwd: process.cwd(), goos: process.env.GOOS, goarch: process.env.GOARCH, cgo: process.env.CGO_ENABLED }) + '\\n');
if (process.env.KONE_FAKE_FAIL === argv[0]) process.exit(37);
if (argv[0] === 'list') process.stdout.write(process.env.KONE_FAKE_EMPTY_LIST ? '' : 'example.invalid/one\\r\\nexample.invalid/two\\r\\n');
const profile = argv.find(value => value.startsWith('-coverprofile='));
if (profile) fs.writeFileSync(path.resolve(profile.slice('-coverprofile='.length)), 'mode: atomic\\n');
`);
  await chmod(join(bin, "go"), 0o755);
  await writeFile(join(source, "COMMIT"), "1234567890abcdef1234567890abcdef12345678\n");
  await writeFile(join(bin, "git"), `#!/usr/bin/env node
if (JSON.stringify(process.argv.slice(2)) !== JSON.stringify(['rev-parse', 'HEAD'])) process.exit(97);
process.stdout.write(require('node:fs').readFileSync('COMMIT', 'utf8'));
`);
  await chmod(join(bin, "git"), 0o755);
  const env = {
    ...process.env,
    PATH: `${bin}${delimiter}${process.env.PATH || ""}`,
    JUST_JUSTFILE: join(tools, "justfile"),
    JUST_WORKING_DIRECTORY: source,
    KONE_FAKE_LOG: log,
    KONE_VERSION: "",
    GITHUB_ACTIONS: "false",
    KONE_WINDOWS_SYSTEM_TEST: "",
    RUNNER_TEMP: join(directory, "not a runner"),
  };
  return {
    directory, source, tools,
    run(args, overrides = {}) {
      const result = spawnSync(just, args, {
        cwd: directory,
        env: { ...env, ...overrides },
        encoding: "utf8",
        timeout: 20000,
      });
      assert.ifError(result.error);
      return result;
    },
    async calls() {
      try {
        return (await readFile(log, "utf8")).trim().split("\n").filter(Boolean).map(line => JSON.parse(line));
      } catch (error) {
        if (error.code === "ENOENT") return [];
        throw error;
      }
    },
  };
}

test("the default task only lists help and does not build or enable capture", async (t) => {
  const f = await fixture(t);
  const result = f.run([]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Available recipes/);
  assert.match(result.stdout, /test-coverage/);
  assert.match(result.stdout, /release-plan/);
  assert.deepEqual(await f.calls(), []);
});

test("build derives its development version from the selected source and uses the native executable name", async (t) => {
  const f = await fixture(t);
  const result = f.run(["build"]);
  assert.equal(result.status, 0, result.stderr);
  const calls = await f.calls();
  assert.deepEqual(calls.map(call => call.argv), [[
    "build", "-trimpath", "-ldflags=-X main.VERSION=0.4.0-dev.1234567890abcdef1234567890abcdef12345678",
    "-o", process.platform === "win32" ? "dist/kone.exe" : "dist/kone", "./cmd/kone",
  ]]);
  assert.equal(resolve(calls[0].cwd), resolve(f.source));
});

test("mixed build preserves explicit version and an output path with spaces, and propagates compiler failure", async (t) => {
  const f = await fixture(t);
  const output = "artifacts with spaces/kone custom.exe";
  const result = f.run(["build-mixed", output], { KONE_VERSION: "1.2.3+custom", KONE_FAKE_FAIL: "build" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /37/);
  const calls = await f.calls();
  assert.deepEqual(calls.map(call => call.argv), [[
    "build", "-tags", "with_gvisor", "-trimpath", "-ldflags=-X main.VERSION=1.2.3+custom",
    "-o", output, "./cmd/kone",
  ]]);
  assert.equal(resolve(calls[0].cwd), resolve(f.source));
});

test("coverage follows the selected source and preserves directory and output arguments containing spaces", async (t) => {
  const f = await fixture(t);
  const module = join(f.source, "module with spaces");
  const profile = join(f.directory, "coverage with spaces.out");
  await mkdir(module);
  const result = f.run(["test-coverage", "module with spaces", profile]);
  assert.equal(result.status, 0, result.stderr);
  const calls = await f.calls();
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0].argv, ["list", "./..."]);
  assert.deepEqual(calls[1].argv, [
    "test", "-race", "-count=1", "-coverpkg=example.invalid/one,example.invalid/two",
    `-coverprofile=${profile}`, "-covermode=atomic", "./...",
  ]);
  for (const call of calls) assert.equal(resolve(call.cwd), resolve(module));
  assert.equal(await readFile(profile, "utf8"), "mode: atomic\n");
});

test("coverage propagates go list and go test failures and rejects an empty package set", async (t) => {
  for (const failure of ["list", "test", "empty"]) {
    await t.test(failure, async (t) => {
      const f = await fixture(t);
      const result = f.run(["test-coverage"], failure === "empty"
        ? { KONE_FAKE_EMPTY_LIST: "1" }
        : { KONE_FAKE_FAIL: failure });
      assert.notEqual(result.status, 0, result.stdout);
      const calls = await f.calls();
      assert.deepEqual(calls.map(call => call.argv[0]), failure === "test" ? ["list", "test"] : ["list"]);
      if (failure === "empty") assert.match(result.stderr, /refusing an empty coverage baseline/);
      else assert.match(result.stderr, /37/);
    });
  }
});

test("coverage comparison forwards paths as individual arguments and propagates failures", async (t) => {
  const f = await fixture(t);
  const base = "baseline with spaces.out";
  const head = "head with spaces.out";
  const result = f.run(["coverage-check", base, head], { KONE_FAKE_FAIL: "run" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /37/);
  const calls = await f.calls();
  assert.deepEqual(calls.map(call => call.argv), [["run", "./cmd/covercheck", "-base", base, "-head", head]]);
  assert.equal(resolve(calls[0].cwd), resolve(f.source));
});

test("native CI tasks refuse local execution before invoking Go or system-network commands", async (t) => {
  const recipes = ["ci-linux-build", "ci-linux-tun", "ci-linux-dns-tools", "ci-linux-dns", "ci-macos-build", "ci-macos-tun", "ci-macos-session", "ci-ss"];
  if (process.platform === "win32") recipes.push("ci-windows-tun");
  for (const recipe of recipes) {
    await t.test(recipe, async (t) => {
      const f = await fixture(t);
      const result = f.run([recipe]);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /restricted to disposable GitHub Actions|only in disposable CI/);
      assert.deepEqual(await f.calls(), []);
    });
  }
});
