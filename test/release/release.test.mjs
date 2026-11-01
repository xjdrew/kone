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
  const justfile = (await readFile(join(taskRoot, "justfile"), "utf8")).replaceAll("\r\n", "\n");
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
  assert.match(job, new RegExp(`\\bjust\\s+${name}(?:\\s|$)`), `workflow must invoke the ${name} recipe`);
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
    schema: 1,
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
  const legacy = [
    "web", "test", "build", "packages", "performance", "robustness", "docker",
    "system", "dns-system", "shadowsocks-interop", "windows-system", "mac-system",
  ];
  const marker = {
    schema: 1, sha, version: "0.4.0", run_id: 123, run_attempt: 2,
    verified: true, required_jobs: legacy,
  };
  const expected = { sha, version: "0.4.0", runID: 123, runAttempt: 2 };
  verifyMarker(marker, expected);
  for (const omitted of legacy)
    assert.throws(
      () => verifyMarker({ ...marker, required_jobs: legacy.filter((job) => job !== omitted) }, expected),
      /missing required gates/,
      `historical qualification still requires ${omitted}`,
    );
  for (const replacement of [
    { schema: 2 }, { sha: "a".repeat(40) }, { version: "0.5.0" },
    { run_id: 456 }, { run_attempt: 1 }, { verified: false },
  ])
    assert.throws(() => verifyMarker({ ...marker, ...replacement }, expected));
  for (const currentMissing of requiredJobs.filter((job) => !legacy.includes(job))) {
    for (const legacyMissing of legacy.filter((job) => !requiredJobs.includes(job))) {
      const partialSets = [...new Set([
        ...requiredJobs.filter((job) => job !== currentMissing),
        ...legacy.filter((job) => job !== legacyMissing),
      ])];
      assert.throws(
        () => verifyMarker({ ...marker, required_jobs: partialSets }, expected),
        /missing required gates/,
        "labels from two incomplete gate sets cannot qualify a release",
      );
    }
  }
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
    assert.equal(generated.required_jobs.length, 7);
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
  assert.match(await taskImplementation("release-marker"), /node scripts\/release\/marker\.mjs/);
  assert.ok(jobs.verified.includes("name: ${{ inputs.artifact-prefix }}verification"));
  assert.ok(jobs.build.includes("name: ${{ inputs.artifact-prefix }}binaries"));
  assert.ok(jobs.build.includes("install-packages-"), "Linux packages remain required inside the build group");
  assert.ok(jobs.packages.includes("install-packages-"));
  assert.ok(release.includes("name: ${{ matrix.prefix }}binaries"));
  assert.ok(release.includes("pattern: ${{ matrix.prefix }}install-packages-*"));
  assert.ok(release.includes("name: ${{ matrix.prefix }}verification"));
  const verify = jobSections(release).verify;
  assert.ok(verify.includes("uses: ./.github/workflows/go.yml"));
  assert.ok(verify.includes("ref: ${{ matrix.sha }}"));
  assert.ok(verify.includes("artifact-prefix: ${{ matrix.prefix }}"));
  for (const [job, recipe] of [["plan", "release-plan"], ["publish", "release-publish"], ["withdraw", "release-withdraw"]]) {
    invokesTask(jobSections(release)[job], recipe);
    assert.match(await taskImplementation(recipe), new RegExp(`node scripts/release/${job}\\.mjs`));
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
  assert.deepEqual(flowList(jobs.packages, "os"), ["macos-latest", "windows-latest"]);
  assert.deepEqual(flowList(jobs["windows-system"], "stack"), ["mixed", "system"]);
  assert.ok(jobs.test.includes("github.event.pull_request.base.sha"), "coverage must measure the exact PR base");
  for (const recipe of ["go-verify", "vet", "test-coverage", "test-mixed", "test-pe", "test-macos-desktop", "coverage-check", "ci-macos-build", "ci-macos-tun", "ci-macos-session"])
    invokesTask(jobs.test, recipe);
  assert.match(await taskImplementation("coverage-check"), /go run \.\/cmd\/covercheck -base "\$1" -head "\$2"/);
  const coverage = await taskImplementation("test-coverage");
  assert.match(coverage, /go test -race/);
  assert.match(coverage, /-coverpkg=\$packages/);
  assert.match(coverage, /go list \.\/\.\.\./);
  const nativeMac = await taskImplementation("ci-macos-build");
  for (const name of ["TestSystemDarwinUTUN", "TestSystemDarwinDNSGuidance", "TestDarwinOwnedSystemDNSSessionDeath"])
    assert.ok(nativeMac.includes(`-test.list '^${name}$' | grep -qx ${name}`), `${name} must be present in the native binary`);
  assert.match(await taskImplementation("ci-macos-tun"), /-test\.run '\^TestSystemDarwin\(UTUN\|DNSGuidance\)\$' -test\.v/);
  assert.match(await taskImplementation("ci-macos-session"), /-test\.run '\^TestDarwinOwnedSystemDNSSessionDeath\$' -test\.v/);
  for (const recipe of ["ci-linux-build", "ci-linux-tun", "ci-linux-dns-tools", "ci-linux-dns", "ci-ss", "docker-build", "docker-check"])
    invokesTask(jobs["linux-system"], recipe);
  assert.match(await taskImplementation("ci-linux-tun"), /for stack in system mixed/);
  assert.match(await taskImplementation("ci-linux-dns"), /scripts\/test-system-dns\.sh/);
  assert.match(await taskImplementation("ci-ss"), /scripts\/test-shadowsocks-interop\.sh/);
  assert.match(await taskImplementation("docker-build"), /docker build/);
  assert.match(await taskImplementation("docker-check"), /docker run/);
  for (const recipe of ["quality-check", "fuzz", "vuln", "benchmark-metadata", "benchmark"])
    invokesTask(jobs.quality, recipe);
  assert.match(await taskImplementation("vuln"), /govulncheck/);
  assert.match(await taskImplementation("fuzz"), /-fuzz/);
  assert.match(await taskImplementation("benchmark"), /-bench/);
  invokesTask(jobs["windows-system"], "ci-windows-tun");
  const nativeWindows = await taskImplementation("ci-windows-tun");
  assert.match(nativeWindows, /go test -tags with_gvisor -race -failfast -count=1/);
  for (const name of ["traffic", "udp6_rollback", "tcp6_rollback", "route_rollback"])
    assert.ok(nativeWindows.includes(`'${name}'`));
  assert.match(nativeWindows, /\$passed -notcontains "TestSystemWindowsIPv6Wintun\/\$stack\/\$case"/);
  assert.match(nativeWindows, /\$passed -notcontains "TestSystemWindowsWintun\/\$stack\/occupied=\$occupied"/);
  assert.match(nativeWindows, /Unexpected stack executed on this runner/);
});

test("the container uses checksum-pinned task bootstrap and keeps task tools out of the runtime image", async () => {
  const dockerfile = await readFile(join(taskRoot, "deploy/docker/Dockerfile"), "utf8");
  const [builder, runtime] = dockerfile.split("FROM debian:bookworm-slim");
  assert.match(builder, /github\.com\/casey\/just\/releases\/download\/1\.59\.0\/just-1\.59\.0-/);
  assert.match(builder, /sha256sum --check --strict/);
  assert.match(builder, /just go-deps/);
  assert.match(builder, /just build-container/);
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
  assert.equal(packages.length, 12);
  assert.equal(new Set(packages).size, 12);
  assert.ok(packages.includes("kone-1.2.3-linux-armv7.deb"));
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
    assert.equal(matrix.include[0].tag, releaseTag(second));
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
