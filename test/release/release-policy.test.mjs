import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { assertVersionContext, changeLevel, plannedVersion, planReleaseVersion, selectReleaseVersion, versionContext } from "../../scripts/release/version-policy.mjs";
import { assertExistingRelease, historicalPackages } from "../../scripts/release/integrity.mjs";
import { expectedPackages } from "../../scripts/release/model.mjs";

const sha = "1234567890abcdef1234567890abcdef12345678";
const identity = (next = "0.4.0") => ({ schema: 1, sha, next_version: next, next_tag: `v${next}`, date: "20261101", sequence: 12,
  version: `${next}-dev.20261101.12.g${sha.slice(0, 12)}`, tag: `v${next}-dev.20261101.12.g${sha.slice(0, 12)}` });

test("one cumulative semantic bump represents all changes since the stable baseline", () => {
  assert.equal(plannedVersion({ baseVersion: "1.2.3", floor: "0.4.0", messages: ["fix: one", "fix: two"] }).next_version, "1.2.4");
  assert.equal(plannedVersion({ baseVersion: "1.2.3", messages: ["feat: one", "fix: two", "feat: three"] }).next_version, "1.3.0");
  assert.equal(plannedVersion({ baseVersion: "0.4.0", messages: ["feat!: incompatible", "feat: another"] }).next_version, "0.5.0");
  assert.equal(plannedVersion({ baseVersion: "1.4.2", messages: ["fix: safer\n\nBREAKING CHANGE: config format"] }).next_version, "2.0.0");
  assert.equal(changeLevel("Merge pull request #7 from feature\n\nfeat(net): a feature", "1.0.0"), "minor");
  assert.equal(plannedVersion({ messages: ["fix: old project"] }).next_version, "0.4.0", "pending floor is not an already-published baseline");
});

test("Release-As is an immutable, canonical upward-only override", () => {
  assert.equal(plannedVersion({ baseVersion: "0.4.0", messages: ["fix: fix\n\nRelease-As: 0.8.0"] }).next_version, "0.8.0");
  assert.equal(plannedVersion({ baseVersion: "1.0.0", messages: ["feat: feature\n\nRelease-As: v1.2.0"] }).release_as, "1.2.0");
  for (const footer of ["0.4.0", "01.2.3", "1.2.3-dev.1", "../../bad", "999999999999999999.0.0", "0.6.0\nRelease-As: 0.7.0"])
    assert.throws(() => plannedVersion({ baseVersion: "0.4.0", messages: [`feat: change\n\nRelease-As: ${footer}`] }));
});

test("published development identities remain immutable while stable tags lock a rebuilt final version", () => {
  const prior = identity("0.5.0"), calculated = identity("0.4.1");
  assert.deepEqual(selectReleaseVersion({ calculated, prior }).context, prior, "a newly-added ancestor stable tag cannot rename a published SHA");
  assert.deepEqual(selectReleaseVersion({ calculated }).context, calculated, "an unpublished SHA may use the current stable refs");
  assert.throws(() => selectReleaseVersion({ calculated, stableTag: "v0.4.1" }), /published, verified/);
  assert.throws(() => selectReleaseVersion({ calculated, prior, stableTag: "v0.5.0" }), /calculated next version/);
  const stable = selectReleaseVersion({ calculated, prior, stableTag: "v0.4.1" });
  assert.equal(stable.version, "0.4.1");
  assert.equal(stable.context.version, calculated.version, "stable validation retains its separate source context, never relabeling dev bytes");
  for (const replacement of [{ sha: "a".repeat(40) }, { tag: "v0.4.1-dev.20261101.12.gaaaaaaaaaaaa" }, { sequence: 0 }, { schema: 99 }, { next_tag: "v8.0.0" }])
    assert.throws(() => assertVersionContext({ ...calculated, ...replacement }, { sha, version: calculated.version, tag: calculated.tag }));
  const legacy = { schema: 0, sha, next_version: "0.4.0", next_tag: "v0.4.0", version: `0.4.0-dev.${sha.slice(0, 12)}`, tag: `dev-${sha.slice(0, 12)}` };
  assert.equal(selectReleaseVersion({ calculated, prior: legacy }).tag, legacy.tag);
});

test("Git history gives deterministic UTC and first-parent identities and resets only at an ancestral stable tag", async () => {
  const directory = await mkdtemp(join(tmpdir(), "kone-version-test-"));
  const git = (...args) => execFileSync("git", args, { cwd: directory, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  let serial = 0;
  const commit = async message => {
    await writeFile(join(directory, "file"), String(++serial));
    git("add", "--", "file", "VERSION");
    execFileSync("git", ["-c", "user.name=KONE Test", "-c", "user.email=test@example.invalid", "commit", "-qm", message], {
      cwd: directory, env: { ...process.env, GIT_AUTHOR_DATE: "2026-10-31T23:59:59Z", GIT_COMMITTER_DATE: "2026-10-31T23:59:59Z" }, stdio: "pipe" });
    return git("rev-parse", "HEAD");
  };
  try {
    git("init", "-q", "-b", "master");
    await writeFile(join(directory, "VERSION"), "0.4.0\n");
    const first = await commit("feat: initial feature");
    git("tag", "v0.1");
    const initial = versionContext({ cwd: directory });
    assert.equal(initial.next_version, "0.4.0");
    assert.equal(initial.date, "20261031");
    assert.equal(initial.sequence, 1);
    git("tag", "v0.4.0");
    assert.deepEqual(versionContext({ cwd: directory }), initial, "a tag at the exact SHA is excluded when validating that tag");
    const second = await commit("fix: first fix");
    assert.equal(versionContext({ cwd: directory }).next_version, "0.4.1");
    const third = await commit("feat: add a feature");
    const thirdContext = versionContext({ cwd: directory });
    assert.equal(thirdContext.next_version, "0.5.0");
    await commit("feat: add another feature");
    assert.equal(versionContext({ cwd: directory }).next_version, "0.5.0", "two features cause one cumulative minor bump");
    assert.notEqual(versionContext({ cwd: directory }).tag, thirdContext.tag);
    git("checkout", "-qb", "unrelated", first);
    await commit("feat!: unrelated history");
    git("tag", "v9.0.0");
    git("checkout", "-q", "master");
    assert.equal(versionContext({ cwd: directory }).base_tag, "v0.4.0", "non-ancestral tags cannot affect the release");
    assert.equal(versionContext({ cwd: directory, sha: third }).tag, thirdContext.tag);
    assert.equal(versionContext({ cwd: directory, sha: second }).sequence, 2);
    const pinned = await commit("fix: pin release\n\nRelease-As: 0.8.0");
    const published = versionContext({ cwd: directory, sha: pinned });
    git("tag", "v0.8.0", "HEAD~1");
    assert.throws(() => versionContext({ cwd: directory, sha: pinned }), /cannot lower/);
    assert.equal(planReleaseVersion({ cwd: directory, sha: pinned, prior: published }).version, published.version,
      "a retry must reuse verified published context before potentially failing history recalculation");
    git("remote", "add", "origin", directory);
    git("tag", "v0.4.1", pinned);
    const eventPath = join(directory, "event.json");
    await writeFile(eventPath, JSON.stringify({ after: second, ref: "refs/tags/v0.4.1" }));
    const runPlan = (tag, source) => spawnSync(process.execPath, [fileURLToPath(new URL("../../scripts/release/plan.mjs", import.meta.url))], {
      cwd: directory, encoding: "utf8", env: { ...process.env, GH_TOKEN: "", GITHUB_REPOSITORY: "", GITHUB_EVENT_PATH: eventPath,
        GITHUB_REF: `refs/tags/${tag}`, GITHUB_EVENT_NAME: "push", GITHUB_SHA: source, GITHUB_OUTPUT: join(directory, "output") } });
    const moved = runPlan("v0.4.1", second);
    assert.notEqual(moved.status, 0);
    assert.match(moved.stderr, /tag moved after the triggering event/);
    git("-c", "user.name=KONE Test", "-c", "user.email=test@example.invalid", "tag", "-a", "v0.5.0", third, "-m", "stable candidate");
    await writeFile(eventPath, JSON.stringify({ after: git("rev-parse", "v0.5.0"), ref: "refs/tags/v0.5.0" }));
    const annotated = runPlan("v0.5.0", third);
    assert.notEqual(annotated.status, 0);
    assert.match(annotated.stderr, /published, verified development/, "annotated event/tag identities peel to the same commit, but still require published evidence");
  } finally {
    assert.ok(resolve(directory).startsWith(join(resolve(tmpdir()), "kone-version-test-")));
    await rm(directory, { recursive: true, force: true });
  }
});

test("release retries require complete current nine-asset or historical sixteen-asset publications", () => {
  const version = "0.4.0", tag = "v0.4.0", digest = "a".repeat(64);
  for (const names of [[...expectedPackages(version), "kone-source.tar.gz"], [...historicalPackages(version), "kone-source.tar.gz", "build-info.json"]]) {
    const manifest = { sha, version, tag, verified: true, channel: "stable", build: { sha, version }, assets: names.map(name => ({ name, sha256: digest })) };
    const manifestText = JSON.stringify(manifest, null, 2) + "\n";
    const hash = value => createHash("sha256").update(value).digest("hex");
    const manifestHash = hash(manifestText);
    const sumText = [...manifest.assets, { name: "release.json", sha256: manifestHash }].sort((a, b) => a.name.localeCompare(b.name)).map(asset => `${asset.sha256}  ${asset.name}`).join("\n") + "\n";
    const release = { isPrerelease: false, assets: [...manifest.assets.map(asset => ({ name: asset.name, digest: `sha256:${asset.sha256}` })), { name: "release.json", digest: `sha256:${manifestHash}` }, { name: "SHA256SUMS", digest: `sha256:${hash(sumText)}` }] };
    const expected = { sha, version, tag, manifestText };
    assertExistingRelease(release, manifest, expected);
    assert.equal(release.assets.length, names.length === 7 ? 9 : 16);
    for (const name of names) assert.throws(() => assertExistingRelease({ ...release, assets: release.assets.filter(asset => asset.name !== name) }, manifest, expected));
    assert.throws(() => assertExistingRelease({ ...release, assets: [...release.assets, { name: "surprise.zip" }] }, manifest, expected));
    for (const name of [names[0], "release.json", "SHA256SUMS"])
      assert.throws(() => assertExistingRelease({ ...release, assets: release.assets.map(asset => asset.name === name ? { ...asset, digest: `sha256:${"b".repeat(64)}` } : asset) }, manifest, expected));
    assert.throws(() => assertExistingRelease(release, { ...manifest, assets: manifest.assets.slice(1) }, expected));
    assert.throws(() => assertExistingRelease({ ...release, isPrerelease: true }, manifest, expected), /channel/);
    assert.throws(() => assertExistingRelease(release, { ...manifest, channel: "development" }, expected), /channel/);
    const invalidVersion = `${version}-dev.20261101.12.g${sha.slice(0, 12)}`;
    const invalid = { ...manifest, version: invalidVersion, tag: `v${invalidVersion}` };
    assert.throws(() => assertExistingRelease(release, invalid, { ...expected, version: invalidVersion, tag: invalid.tag }), /Stable tag must be/);
  }
});

test("stable tag pushes retain exact-SHA full requalification and channel context", async () => {
  const workflow = await readFile(fileURLToPath(new URL("../../.github/workflows/release.yml", import.meta.url)), "utf8");
  const plan = await readFile(fileURLToPath(new URL("../../scripts/release/plan.mjs", import.meta.url)), "utf8");
  assert.match(workflow, /tags:\s*\['v\*\.\*\.\*'\]/);
  assert.match(workflow, /uses: \.\/\.github\/workflows\/go\.yml/);
  assert.match(workflow, /ref: \$\{\{ matrix\.sha \}\}/);
  assert.match(workflow, /version: \$\{\{ matrix\.version \}\}/);
  assert.match(workflow, /RELEASE_CONTEXT: \$\{\{ toJSON\(matrix\.context\) \}\}/);
  assert.match(plan, /merge-base", "--is-ancestor", sha, "origin\/master"/);
  assert.match(plan, /latestVerificationAttempt/);
  assert.match(plan, /assertExistingRelease\(release, manifest/);
  assert.match(plan, /verifyMarker\(manifest\.verification/);
});
