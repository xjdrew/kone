import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertVersion,
  expectedPackages,
  latestVerificationAttempt,
  requiredJobs,
  releaseTag,
  stableVersion,
  validSHA,
  verifyMarker,
  versionFor,
  safeName,
} from "../../scripts/release/model.mjs";
const sha = "1234567890abcdef1234567890abcdef12345678";
const scripts = fileURLToPath(
  new URL("../../scripts/release/", import.meta.url),
);
const workflows = fileURLToPath(
  new URL("../../.github/workflows/", import.meta.url),
);
const taskRoot = fileURLToPath(new URL("../../", import.meta.url));

async function taskImplementation(name) {
  const root = await readFile(join(taskRoot, "justfile"), "utf8");
  assert.match(root, /^mod ci 'scripts\/ci\/justfile'$/m, "CI tasks must use the real module");
  const justfile = (await readFile(join(taskRoot, "scripts/ci/justfile"), "utf8")).replaceAll("\r\n", "\n");
  const lines = justfile.split("\n");
  const start = lines.findIndex(line => new RegExp(`^${name}(?:\\s[^\\n]*)?:`).test(line));
  assert.notEqual(start, -1, `the ${name} recipe must exist`);
  const body = [];
  for (let index = start; index < lines.length; index++) {
    if (index > start && lines[index] && !/^\s/.test(lines[index])) break;
    body.push(lines[index]);
  }
  let implementation = body.join("\n");
  for (const match of implementation.matchAll(/scripts\/ci\/([\w-]+\.(?:sh|ps1|mjs))/g))
    implementation += `\n${await readFile(join(taskRoot, "scripts/ci", match[1]), "utf8")}`;
  return implementation;
}

function invokesTask(job, name) {
  assert.match(job, new RegExp(`\\bjust\\s+ci\\s+${name}(?:\\s|$)`), `workflow must invoke the ci ${name} recipe`);
}

function jobSections(workflow) {
  const body = workflow.replaceAll("\r\n", "\n").split("\njobs:\n")[1];
  assert.ok(body, "workflow must declare jobs");
  const entries = [...body.matchAll(/^  ([a-z][a-z0-9-]*):\s*$/gm)];
  return Object.fromEntries(
    entries.map((entry, index) => [
      entry[1],
      body.slice(entry.index, entries[index + 1]?.index),
    ]),
  );
}

function flowList(body, key) {
  const match = body.match(
    new RegExp(`^\\s+${key}:\\s*\\[([^\\]]+)\\]`, "m"),
  );
  assert.ok(
    match,
    `workflow must explicitly declare the ${key} matrix/dependency list`,
  );
  return match[1]
    .split(",")
    .map((value) => value.trim().replace(/^['"]|['"]$/g, ""))
    .sort();
}

test("release channel identities are unique, traceable and reject unsafe tags", () => {
  assert.equal(releaseTag(sha), "dev-1234567890ab");
  assert.equal(versionFor(sha), "0.4.0-dev.1234567890ab");
  assert.equal(releaseTag(sha, "v1.2.3"), "v1.2.3");
  assert.equal(versionFor(sha, "v1.2.3"), "1.2.3");
  for (const value of ["master", "1234", "../file", "A".repeat(40)])
    assert.throws(() => validSHA(value));
  for (const value of ["latest", "v01.2.3", "v1.2.3;echo bad", "v1.2.3-dev"])
    assert.throws(() => stableVersion(value));
  for (const value of ["../secret", "/absolute", "--option", "with space"])
    assert.throws(() => safeName(value));
});

test("qualification binds all required gates to the exact SHA/version/run/attempt", () => {
  const marker = {
    schema: 2,
    sha,
    version: "0.4.0",
    run_id: 123,
    run_attempt: 2,
    verified: true,
    required_jobs: requiredJobs,
  };
  verifyMarker(marker, {
    sha,
    version: "0.4.0",
    runID: "123",
    runAttempt: "2",
  });
  for (const replacement of [
    { sha: "a".repeat(40) },
    { version: "0.5.0" },
    { run_id: 456 },
    { run_attempt: 1 },
    { verified: false },
    { required_jobs: ["test", "build"] },
    { required_jobs: [...requiredJobs, "extra"] },
    { required_jobs: [...requiredJobs, requiredJobs[0]] },
    { schema: 1 },
  ])
    assert.throws(() =>
      verifyMarker(
        { ...marker, ...replacement },
        { sha, version: "0.4.0", runID: 123, runAttempt: 2 },
      ),
    );
  for (const omitted of requiredJobs)
    assert.throws(
      () => verifyMarker(
        { ...marker, required_jobs: requiredJobs.filter((job) => job !== omitted) },
        { sha, version: "0.4.0", runID: 123, runAttempt: 2 },
      ),
      /missing required gates/,
      `omitting ${omitted} cannot qualify a release`,
    );
});

test("historical qualification accepts only whole gate sets and new evidence uses current groups", async () => {
  const histories = [["web", "test", "build", "packages", "quality", "linux-system", "windows-system"], [
    "web", "test", "build", "packages", "performance", "robustness", "docker",
    "system", "dns-system", "shadowsocks-interop", "windows-system", "mac-system",
  ]];
  const marker = {
    schema: 1, sha, version: "0.4.0", run_id: 123, run_attempt: 2,
    verified: true,
  };
  const expected = { sha, version: "0.4.0", runID: 123, runAttempt: 2 };
  for (const legacy of histories) {
    verifyMarker({ ...marker, required_jobs: legacy }, expected);
    for (const omitted of legacy)
      assert.throws(
        () => verifyMarker({ ...marker, required_jobs: legacy.filter((job) => job !== omitted) }, expected),
        /missing required gates/,
        `historical qualification still requires ${omitted}`,
      );
    for (const invalid of [[...legacy, "extra"], [...legacy, legacy[0]]])
      assert.throws(() => verifyMarker({ ...marker, required_jobs: invalid }, expected), /missing required gates/);
    assert.throws(() => verifyMarker({ ...marker, schema: 2, required_jobs: legacy }, expected), /missing required gates/);
  }
  assert.throws(() => verifyMarker({ ...marker, required_jobs: requiredJobs }, expected), /missing required gates/);
  for (const replacement of [
    { schema: 3 }, { sha: "a".repeat(40) }, { version: "0.5.0" },
    { run_id: 456 }, { run_attempt: 1 }, { verified: false },
  ])
    assert.throws(() => verifyMarker({ ...marker, required_jobs: histories[0], ...replacement }, expected));
  const mixed = [...new Set([...histories[0], ...histories[1]])];
  assert.throws(() => verifyMarker({ ...marker, required_jobs: mixed }, expected), /missing required gates/);
  const directory = await mkdtemp(join(tmpdir(), "kone-marker-test-"));
  try {
    execFileSync(process.execPath, [join(scripts, "marker.mjs")], {
      cwd: directory,
      env: {
        ...process.env,
        RELEASE_SHA: sha,
        RELEASE_VERSION: "0.4.0",
        GITHUB_RUN_ID: "123",
        GITHUB_RUN_ATTEMPT: "2",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const generated = JSON.parse(await readFile(join(directory, "verification/verification.json"), "utf8"));
    assert.deepEqual(generated.required_jobs, requiredJobs);
    assert.equal(generated.required_jobs.length, 5);
    assert.equal(generated.schema, 2);
    verifyMarker(generated, expected);
  } finally {
    const absolute = resolve(directory);
    assert.ok(absolute.startsWith(join(resolve(tmpdir()), "kone-marker-test-")));
    await rm(absolute, { recursive: true, force: true });
  }
});

test("workflow qualification covers every grouped gate and retains exact-source publication contracts", async () => {
  const go = await readFile(join(workflows, "go.yml"), "utf8");
  const release = await readFile(join(workflows, "release.yml"), "utf8");
  const jobs = jobSections(go);
  assert.deepEqual(Object.keys(jobs).sort(), [...requiredJobs, "verified"].sort());
  assert.deepEqual(flowList(jobs.verified, "needs"), [...requiredJobs].sort());
  for (const id of requiredJobs) {
    assert.ok(jobs[id].includes("ref: ${{ inputs.ref || github.sha }}"), `${id} must test the requested source SHA`);
    assert.ok(jobs.verified.includes(`needs.${id}.result == 'success'`), `${id} must succeed before verification`);
  }
  assert.ok(jobs.verified.includes("name: Required gates verified (${{ inputs.ref || github.sha }})"));
  assert.ok(jobs.verified.includes("inputs.ref != ''"), "PRs cannot emit a publication marker");
  assert.ok(jobs.verified.includes("RELEASE_SHA: ${{ inputs.ref }}"));
  invokesTask(jobs.verified, "release-marker");
  assert.match(await taskImplementation("release-marker"), /node "\$KONE_TASK_ROOT\/scripts\/release\/marker\.mjs"/);
  assert.ok(jobs.verified.includes("name: ${{ inputs.artifact-prefix }}verification"));
  assert.ok(jobs.build.includes("name: ${{ inputs.artifact-prefix }}binaries"));
  assert.ok(jobs.build.includes("install-packages-"), "Linux packages remain required inside the build group");
  assert.ok(jobs.test.includes("install-packages-"), "native packages remain required inside each platform group");
  assert.ok(release.includes("name: ${{ matrix.prefix }}binaries"));
  assert.ok(release.includes("pattern: ${{ matrix.prefix }}install-packages-*"));
  assert.ok(release.includes("name: ${{ matrix.prefix }}verification"));
  const verify = jobSections(release).verify;
  assert.ok(verify.includes("uses: ./.github/workflows/go.yml"));
  assert.ok(verify.includes("ref: ${{ matrix.sha }}"));
  assert.ok(verify.includes("artifact-prefix: ${{ matrix.prefix }}"));
  for (const [job, recipe] of [["plan", "release-plan"], ["publish", "release-publish"], ["withdraw", "release-withdraw"]]) {
    invokesTask(jobSections(release)[job], recipe);
    assert.match(await taskImplementation(recipe), new RegExp(`node "\\$KONE_TASK_ROOT/scripts/release/${job}\\.mjs"`));
  }
});

test("workflow grouping preserves platform, coverage, protocol and container acceptance without duplicate master CI", async () => {
  const go = (await readFile(join(workflows, "go.yml"), "utf8")).replaceAll("\r\n", "\n");
  const release = (await readFile(join(workflows, "release.yml"), "utf8")).replaceAll("\r\n", "\n");
  const trigger = go.split("\njobs:\n")[0];
  assert.match(trigger, /^  pull_request:\n    branches: \[master\]/m);
  assert.match(trigger, /^  workflow_call:/m);
  assert.doesNotMatch(trigger, /^  push:/m, "master must not run a duplicate ordinary CI workflow");
  assert.match(release.split("\njobs:\n")[0], /^  push:\n    branches: \[master\]/m);
  assert.match(release, /if: github\.ref == 'refs\/heads\/master'/);
  const jobs = jobSections(go);
  assert.deepEqual(flowList(jobs.test, "os"), ["macos-latest", "ubuntu-latest", "windows-latest"]);
  assert.deepEqual(flowList(jobs["windows-native"], "stack"), ["gvisor", "mixed", "system"]);
  assert.equal(requiredJobs.length - 2 + flowList(jobs.test, "os").length + flowList(jobs["windows-native"], "stack").length, 9, "matrix expansion has nine active qualification jobs");
  assert.doesNotMatch(jobs.test, /^    needs:/m, "unit/native checks must not wait for cross-builds to start");
  assert.ok(jobs.test.includes("github.event.pull_request.base.sha"), "coverage must measure the exact PR base");
  for (const recipe of ["go-verify", "vet", "test-coverage", "test-pe", "test-macos-desktop", "coverage-check", "ci-macos-build", "ci-macos-tun", "ci-macos-session", "wait-build", "package"])
    invokesTask(jobs.test, recipe);
  assert.doesNotMatch(jobs.test, /just ci test-mixed/, "the unified binary must avoid repeating the full race suite per stack");
  assert.match(jobs.test, /steps\.package-input\.outcome == 'success'/);
  assert.match(jobs.test, /steps\.package-download\.outcome == 'success'/);
  assert.ok(jobs.test.indexOf("just ci wait-build") > jobs.test.indexOf("just ci ci-macos-session"));
  assert.doesNotMatch(jobs.test, /just ci ci-windows-tun|name: .*windows-native/);
  const waitBuild = await taskImplementation("wait-build");
  assert.match(waitBuild, /attempts\/\$\{env\.GITHUB_RUN_ATTEMPT\}\/jobs/);
  assert.match(waitBuild, /buildJobName\(env\.KONE_BUILD_SHA\)/);
  assert.ok(jobs.build.includes("name: Cross-build and Linux packages (${{ inputs.ref || github.sha }})"), "wait-build must select the exact source-labelled build job");
  assert.match(await taskImplementation("vet"), /go vet -tags with_gvisor/);
  assert.match(await taskImplementation("coverage-check"), /go run \.\/cmd\/covercheck -base "\$1" -head "\$2"/);
  const coverage = await taskImplementation("test-coverage");
  assert.match(coverage, /go test -tags with_gvisor -race/);
  assert.match(coverage, /-coverpkg=\$packages/);
  assert.match(coverage, /go list -tags with_gvisor \.\/\.\.\./);
  const nativeMac = await taskImplementation("ci-macos-build");
  for (const name of ["TestSystemDarwinUTUN", "TestSystemDarwinDNSGuidance", "TestDarwinOwnedSystemDNSSessionDeath"])
    assert.ok(nativeMac.includes(`-test.list '^${name}$' | grep -qx ${name}`), `${name} must be present in the native binary`);
  const nativeMacRun = await taskImplementation("ci-macos-tun");
  assert.match(nativeMacRun, /-test\.run '\^TestSystemDarwin\(UTUN\|DNSGuidance\)\$' -test\.v/);
  assert.match(nativeMacRun, /stacks=\(system gvisor mixed\)/);
  assert.match(nativeMacRun, /--- PASS: TestSystemDarwinUTUN\/\$stack\/\$case/);
  assert.match(nativeMacRun, /--- PASS: TestSystemDarwinDNSGuidance\/\$stack\/late-failure=\$failure/);
  assert.match(nativeMacRun, /-test\.timeout 8m 2>&1 \| tee/, "archive native race diagnostics with the actual pass evidence");
  assert.match(await taskImplementation("ci-macos-session"), /-test\.run '\^TestDarwinOwnedSystemDNSSessionDeath\$' -test\.v/);
  for (const recipe of ["ci-linux-build", "ci-linux-tun", "ci-linux-dns-tools", "ci-linux-dns", "ci-ss", "docker-build", "docker-check"])
    invokesTask(jobs.test, recipe);
  assert.match(await taskImplementation("ci-linux-tun"), /stacks=\(system gvisor mixed\)/);
  assert.match(await taskImplementation("ci-linux-tun"), /-f pkg\/kone\/stack_modes\.go/);
  assert.match(await taskImplementation("ci-linux-tun"), /--- PASS: \$test/);
  assert.match(await taskImplementation("ci-linux-tun"), /"\$stack" 2>&1 \| tee/, "keep the race detector's stderr in per-stack artifacts");
  assert.match(await taskImplementation("ci-linux-dns"), /scripts\/test-system-dns\.sh/);
  assert.match(await taskImplementation("ci-ss"), /scripts\/test-shadowsocks-interop\.sh/);
  assert.match(await taskImplementation("docker-build"), /docker build/);
  assert.match(await taskImplementation("docker-check"), /docker run/);
  for (const recipe of ["quality-check", "fuzz", "vuln", "benchmark-metadata", "benchmark"])
    invokesTask(jobs.quality, recipe);
  assert.match(await taskImplementation("vuln"), /govulncheck/);
  assert.match(await taskImplementation("fuzz"), /-fuzz/);
  assert.match(await taskImplementation("benchmark"), /-bench/);
  invokesTask(jobs["windows-native"], "ci-windows-tun");
  assert.doesNotMatch(jobs["windows-native"], /^    needs:/m, "native modes start independently of unit coverage and cross-builds");
  assert.ok(jobs["windows-native"].includes("KONE_TEST_STACK: ${{ matrix.stack }}"));
  assert.ok(jobs["windows-native"].includes("name: ${{ inputs.artifact-prefix }}windows-native-${{ matrix.stack }}"));
  assert.ok(jobs["windows-native"].includes("path: native-windows-${{ matrix.stack }}.jsonl"));
  assert.ok(jobs["windows-native"].includes("matrix.stack != 'gvisor' || hashFiles('pkg/kone/stack_modes.go') != ''"));
  assert.doesNotMatch(jobs.test, /KONE_TEST_STACK:/, "native opt-ins must not leak into ordinary Windows unit or coverage tests");
  const nativeWindows = await taskImplementation("ci-windows-tun");
  assert.match(nativeWindows, /\$buildArguments = @\('test', '-tags', 'with_gvisor', '-race', '-c'/);
  assert.equal((nativeWindows.match(/& go @buildArguments/g) || []).length, 1, "compile the native acceptance binary once");
  assert.match(nativeWindows, /@\('system', 'gvisor', 'mixed'\)/);
  assert.match(nativeWindows, /foreach \(\$stack in \$stacks\)/);
  assert.match(nativeWindows, /& go @testArguments/);
  const nativeArguments = await readFile(join(taskRoot, "scripts/ci/windows-test-arguments.ps1"), "utf8");
  assert.match(nativeArguments, /'tool', 'test2json'/);
  assert.match(nativeArguments, /'-test\.v=test2json'/);
  assert.match(nativeArguments, /'-test\.count=1'/);
  for (const name of ["traffic", "udp6_rollback", "tcp6_rollback", "route_rollback"])
    assert.ok(nativeWindows.includes(`'${name}'`));
  assert.match(nativeWindows, /\$passed -notcontains "TestSystemWindowsIPv6Wintun\/\$stack\/\$case"/);
  assert.match(nativeWindows, /\$passed -notcontains "TestSystemWindowsWintun\/\$stack\/occupied=\$occupied"/);
  assert.match(nativeWindows, /Unexpected stack executed in this test process/);
  assert.match(nativeWindows, /KONE_TEST_STACK -ceq 'gvisor' -and \$stacks -cnotcontains 'gvisor'/);
  assert.match(nativeWindows, /Historical source has no gvisor runtime mode/);
});

test("the container uses checksum-pinned task bootstrap and keeps task tools out of the runtime image", async () => {
  const dockerfile = await readFile(join(taskRoot, "deploy/docker/Dockerfile"), "utf8");
  const [builder, runtime] = dockerfile.split("FROM debian:bookworm-slim");
  assert.match(builder, /github\.com\/casey\/just\/releases\/download\/1\.59\.0\/just-1\.59\.0-/);
  assert.match(builder, /sha256sum --check --strict/);
  assert.match(builder, /just ci go-deps/);
  assert.match(builder, /just ci build-container/);
  assert.match(await taskImplementation("build-container"), /CGO_ENABLED=0 GOOS="\$\{TARGETOS:-linux\}" GOARCH="\$\{TARGETARCH:-amd64\}" go build -tags with_gvisor -trimpath -ldflags='-s -w' -o \/out\/kone/);
  assert.ok(runtime, "the runtime must remain a separate image");
  assert.doesNotMatch(runtime, /just|curl|golang:/);
  assert.match(runtime, /COPY --from=builder \/out\/kone \/usr\/local\/bin\/kone/);
});

test("publication retry accepts the latest successful gate and rejects stale evidence after a failed rerun", () => {
  const gate = {
    name: `Verify ${sha} / Required gates verified (${sha})`,
    run_attempt: 1,
    status: "completed",
    conclusion: "success",
  };
  assert.equal(latestVerificationAttempt([gate], sha), 1);
  assert.equal(
    latestVerificationAttempt([gate, { ...gate, run_attempt: 2 }], sha),
    2,
  );
  for (const status of ["failure", "skipped", "cancelled"]) {
    assert.throws(() =>
      latestVerificationAttempt(
        [gate, { ...gate, run_attempt: 2, conclusion: status }],
        sha,
      ),
    );
  }
  assert.throws(() => latestVerificationAttempt([], sha));
  assert.throws(() =>
    latestVerificationAttempt([{ ...gate, run_attempt: undefined }], sha),
  );
  assert.throws(() =>
    latestVerificationAttempt([{ ...gate, status: "in_progress" }], sha),
  );
  assert.throws(() => latestVerificationAttempt([gate, gate], sha));
  assert.throws(() =>
    latestVerificationAttempt(
      [{ ...gate, name: `Required gates verified (${"a".repeat(40)})` }],
      sha,
    ),
  );
});

test("release packages cover three platforms and every declared architecture", () => {
  const packages = expectedPackages("1.2.3");
  assert.equal(packages.length, 6);
  assert.equal(new Set(packages).size, 6);
  assert.ok(!packages.some(name => name.includes("armv7") || name.endsWith(".tar.gz")));
  assert.ok(packages.includes("kone-1.2.3-linux-arm64.deb"));
  assert.ok(packages.includes("kone-1.2.3-darwin-arm64.pkg"));
  assert.ok(packages.includes("kone-1.2.3-windows-arm64.zip"));
  assertVersion("Version: 1.2.3\r\n", "1.2.3");
  assert.throws(() => assertVersion("Version: 0.3-dev", "1.2.3"));
});

test("a batched master push plans every first-parent commit in order", async () => {
  const directory = await mkdtemp(join(tmpdir(), "kone-release-test-"));
  const git = (...args) =>
    execFileSync("git", args, {
      cwd: directory,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  try {
    git("init", "-b", "master");
    const commit = async (text) => {
      await writeFile(join(directory, "fixture"), text);
      git("add", "fixture");
      git(
        "-c",
        "user.name=Release Test",
        "-c",
        "user.email=release@example.invalid",
        "commit",
        "-m",
        text,
      );
      return git("rev-parse", "HEAD");
    };
    const before = await commit("one");
    const second = await commit("two");
    const third = await commit("three");
    git("remote", "add", "origin", directory);
    await writeFile(
      join(directory, "event.json"),
      JSON.stringify({ before, after: third }),
    );
    const output = join(directory, "output");
    const env = {
      ...process.env,
      GITHUB_REF: "refs/heads/master",
      GITHUB_SHA: third,
      GITHUB_EVENT_NAME: "push",
      GITHUB_EVENT_PATH: join(directory, "event.json"),
      GITHUB_OUTPUT: output,
    };
    execFileSync(process.execPath, [join(scripts, "plan.mjs")], {
      cwd: directory,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const line = (await readFile(output, "utf8"))
      .split("\n")
      .find((line) => line.startsWith("matrix="));
    const matrix = JSON.parse(line.slice(7));
    assert.deepEqual(
      matrix.include.map((item) => item.sha),
      [second, third],
    );
    assert.match(matrix.include[0].tag, new RegExp(`^v0\\.4\\.0-dev\\.\\d{8}\\.2\\.g${second.slice(0, 12)}$`));
    assert.equal(matrix.include[0].context.sha, second);
    assert.notEqual(matrix.include[0].prefix, matrix.include[1].prefix);
    await writeFile(
      join(directory, "event.json"),
      JSON.stringify({ before: "0".repeat(40), after: third }),
    );
    const invalid = spawnSync(process.execPath, [join(scripts, "plan.mjs")], {
      cwd: directory,
      env,
      encoding: "utf8",
    });
    assert.notEqual(invalid.status, 0);
    assert.match(invalid.stderr, /explicit reviewed SHA/);
  } finally {
    const absolute = resolve(directory);
    assert.ok(
      absolute.startsWith(join(resolve(tmpdir()), "kone-release-test-")),
    );
    await rm(absolute, { recursive: true, force: true });
  }
});

test("local and PR invocations cannot publish or withdraw releases", () => {
  for (const script of ["publish.mjs", "withdraw.mjs"]) {
    const result = spawnSync(process.execPath, [join(scripts, script)], {
      env: {
        ...process.env,
        GITHUB_ACTIONS: "false",
        GITHUB_REF: "refs/heads/master",
      },
      encoding: "utf8",
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /only|requires explicit/);
  }
});
