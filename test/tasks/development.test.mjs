import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { context, ensureFrontend } from "../../scripts/tasks/common.mjs";
import { initialize } from "../../scripts/tasks/init.mjs";
import { build } from "../../scripts/tasks/build.mjs";
import { packageBuild } from "../../scripts/tasks/package.mjs";
import { quality } from "../../scripts/tasks/quality.mjs";
import { develop } from "../../scripts/tasks/dev.mjs";

const taskRoot = fileURLToPath(new URL("../../", import.meta.url));
const sha = "a".repeat(40);

async function fixture(t, options = {}) {
  const cwd = await mkdtemp(join(tmpdir(), "kone daily tasks "));
  t.after(async () => {
    assert.equal(dirname(resolve(cwd)), resolve(tmpdir()));
    await rm(cwd, { recursive: true, force: true });
  });
  await mkdir(join(cwd, "web/src"), { recursive: true });
  await mkdir(join(cwd, "licenses"));
  await writeFile(join(cwd, "LICENSE"), "license\n");
  await writeFile(join(cwd, "LICENSE-MIT"), "legacy license\n");
  await writeFile(join(cwd, "web/package.json"), "{}\n");
  await writeFile(join(cwd, "web/package-lock.json"), "{}\n");
  await writeFile(join(cwd, "web/src/app.js"), "initial source\n");
  const calls = [];
  const logs = [];
  const run = (command, args, settings = {}) => {
    calls.push({ command, args, settings });
    if (command === options.missing) throw new Error("ENOENT");
    if (command === "git") return args[0] === "rev-parse" ? sha : "git version 2.50";
    if (command === "go" && args[0] === "version") return "go version go1.27.3 windows/amd64";
    if (command === "node") return "v26.13.0";
    if (command === "just" && args[0] === "--version") return "just 1.59.0";
    if (command === "bash" && args[0] === "--version") return "GNU bash, version 5";
    if (command === "bash" && args.includes("kone-npm")) {
      const npmArgs = args.slice(args.indexOf("kone-npm") + 1);
      if (npmArgs[0] === "--version") return "11.20.0";
      if (npmArgs[0] === "ci") {
        for (const path of ["vite", "@playwright/test"]) {
          const folder = join(cwd, "web/node_modules", path);
          mkdirSync(folder, { recursive: true });
          writeFileSync(join(folder, "package.json"), "{}");
        }
      } else if (npmArgs.join(" ") === "run build") {
        mkdirSync(join(cwd, "web/dist"), { recursive: true });
        writeFileSync(join(cwd, "web/dist/index.html"), `built ${calls.length}`);
      }
    }
    if (command === "go" && args[0] === "build") {
      if (options.compileFailure) throw new Error("compile failure");
      writeFileSync(join(cwd, args[args.indexOf("-o") + 1]), "compiled fixture\n");
    }
    return "";
  };
  return { cwd, calls, logs, ctx: context({ cwd, taskRoot, run, log: (message) => logs.push(message), env: {}, platform: "win32", arch: "x64", ...options }) };
}

const npmCalls = (calls, command) => calls.filter((call) =>
  call.command === "bash" && call.args.includes("kone-npm") &&
  call.args.slice(call.args.indexOf("kone-npm") + 1).join(" ") === command);

test("init reports missing base tools before installing any dependencies", async (t) => {
  const f = await fixture(t, { missing: "go" });
  await assert.rejects(initialize(f.ctx), /Install these tools manually.*Go 1.27.3/);
  assert.equal(npmCalls(f.calls, "ci").length, 0);
  assert.ok(!f.calls.some((call) => call.args.join(" ") === "list -deps ./cmd/kone"));
});

test("init prepares project dependencies once and detects lockfile changes", async (t) => {
  const f = await fixture(t);
  await initialize(f.ctx);
  await initialize(f.ctx);
  assert.equal(npmCalls(f.calls, "ci").length, 1);
  await writeFile(join(f.cwd, "web/package-lock.json"), '{"changed":true}\n');
  await initialize(f.ctx);
  assert.equal(npmCalls(f.calls, "ci").length, 2);
  assert.ok(!f.calls.some((call) => call.args.join(" ").includes("playwright install")));
});

test("frontend rebuilds only for changed inputs or missing/changed outputs", async (t) => {
  const f = await fixture(t);
  await ensureFrontend(f.ctx);
  await ensureFrontend(f.ctx);
  assert.equal(npmCalls(f.calls, "run build").length, 1);
  await writeFile(join(f.cwd, "web/src/app.js"), "changed source");
  await ensureFrontend(f.ctx);
  assert.equal(npmCalls(f.calls, "run build").length, 2);
  await rm(join(f.cwd, "web/dist/index.html"));
  await ensureFrontend(f.ctx);
  assert.equal(npmCalls(f.calls, "run build").length, 3);
  assert.equal(npmCalls(f.calls, "ci").length, 1);
  assert.ok(f.logs.some((message) => message.includes("skipped")));
});

test("native builds only the host target, embeds its version and records the selected stack", async (t) => {
  const f = await fixture(t, { env: { GOOS: "linux", KONE_VERSION: "0.4.0-local" } });
  const result = await build(f.ctx, "native", "mixed");
  const compiler = f.calls.filter((call) => call.command === "go" && call.args[0] === "build");
  assert.equal(compiler.length, 1);
  assert.equal(compiler[0].settings.env.GOOS, "windows");
  assert.equal(compiler[0].settings.env.GOARCH, "amd64");
  assert.equal(compiler[0].settings.env.CGO_ENABLED, "0");
  assert.ok(compiler[0].args.includes("with_gvisor"));
  assert.ok(compiler[0].args.includes("-X main.VERSION=0.4.0-local"));
  assert.equal(result.target, "windows-amd64");
  assert.equal(await readFile(join(f.cwd, "dist/kone.exe"), "utf8"), "compiled fixture\n");
  const metadata = f.calls.find((call) => call.args.some((arg) => arg.endsWith("build-info.mjs")));
  assert.deepEqual(metadata.args.slice(-2), ["--targets", "windows-amd64"]);
  assert.equal(metadata.settings.env.KONE_BUILD_STACK, "mixed");
  await build(f.ctx);
  assert.equal(npmCalls(f.calls, "run build").length, 1);
});

test("invalid stacks and compiler failures stop before packaging or launching the application", async (t) => {
  const f = await fixture(t, { compileFailure: true });
  await assert.rejects(build(f.ctx, "native", "invalid"), /Stack/);
  assert.equal(f.calls.length, 0);
  await assert.rejects(packageBuild(f.ctx), /compile failure/);
  assert.ok(!f.calls.some((call) => call.args.some((arg) => arg.endsWith("package.mjs"))));
});

test("package defaults to one native target; package-all requests all portable targets", async (t) => {
  const f = await fixture(t, { env: { KONE_BUILD_STACK: "system" } });
  await packageBuild(f.ctx);
  let packager = f.calls.find((call) => call.args.some((arg) => arg.endsWith("/release/package.mjs") || arg.endsWith("\\release\\package.mjs")));
  assert.deepEqual(packager.args.slice(-2), ["--target", "windows-amd64"]);
  assert.equal(packager.settings.env.RELEASE_SHA, sha);
  f.calls.length = 0;
  await packageBuild(f.ctx, "all");
  const matrix = f.calls.find((call) => call.command === "just" && call.args.join(" ") === "ci build-all");
  assert.ok(matrix);
  assert.ok(!("KONE_BUILD_STACK" in matrix.settings.env));
  packager = f.calls.find((call) => call.args.some((arg) => arg.endsWith("/release/package.mjs") || arg.endsWith("\\release\\package.mjs")));
  assert.equal(packager.args.at(-1), "--all-portable");
  assert.ok(!f.calls.some((call) => call.args.includes("release-publish")));
});

test("quick quality checks omit race, browsers, fuzzing and benchmarks", async (t) => {
  const f = await fixture(t);
  await quality(f.ctx);
  assert.ok(f.calls.some((call) => call.command === "go" && call.args.join(" ") === "test -vet=off ./cmd/... ./pkg/... ./web/..."));
  assert.ok(!f.calls.some((call) => call.args.some((arg) => ["test-release", "test-data", "test-tasks"].includes(arg))));
  assert.ok(!f.calls.some((call) => /race|fuzz|vuln|browser|benchmark/.test(call.args.join(" "))));
});

test("dev launches only the explicit default management entrypoint after building", async (t) => {
  const f = await fixture(t);
  await develop(f.ctx);
  assert.equal(f.calls.at(-1).command, join(f.cwd, "dist/kone.exe"));
  assert.deepEqual(f.calls.at(-1).args, []);
});

test("full quality restores removed dependencies even when embedded Web assets are unchanged", async (t) => {
  const f = await fixture(t);
  await ensureFrontend(f.ctx);
  const dependencies = join(f.cwd, "web/node_modules");
  assert.equal(dirname(dependencies), join(f.cwd, "web"));
  await rm(dependencies, { recursive: true, force: true });
  await quality(f.ctx, "full");
  assert.equal(npmCalls(f.calls, "ci").length, 2);
  assert.equal(npmCalls(f.calls, "run build").length, 1);
});
