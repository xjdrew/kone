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
