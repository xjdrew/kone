import { execFileSync } from "node:child_process";
import { appendFile, readFile } from "node:fs/promises";
import { releaseTag, stableVersion, validSHA, latestVerificationAttempt, verifyMarker } from "./model.mjs";
import { assertVersionContext, planReleaseVersion } from "./version-policy.mjs";
import { assertExistingRelease } from "./integrity.mjs";

const git = (...args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const gh = (...args) => execFileSync("gh", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const event = JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH, "utf8"));
const ref = process.env.GITHUB_REF || "";
const tagPush = process.env.GITHUB_EVENT_NAME === "push" && ref.startsWith("refs/tags/" );
if (ref !== "refs/heads/master" && !tagPush) throw new Error("Release dispatch must run from master or a stable version tag");
const mode = tagPush ? "stable" : process.env.GITHUB_EVENT_NAME === "push" ? "development" : event.inputs?.channel || "development";
if (!["development", "stable", "withdraw"].includes(mode)) throw new Error("Unknown release channel");
const stableTag = mode === "stable" ? tagPush ? ref.slice("refs/tags/".length) : event.inputs?.tag || "" : "";
if (mode === "stable") stableVersion(stableTag);
if (mode === "withdraw") {
  const tag = event.inputs?.tag || "";
  if (!/^(dev-[a-f0-9]{12}|v\d+\.\d+\.\d+(?:-dev\.\d{8}\.\d+\.g[a-f0-9]{12})?)$/.test(tag) || !event.inputs?.reason?.trim())
    throw new Error("Withdrawal requires an existing release tag and a reason");
  await appendFile(process.env.GITHUB_OUTPUT, `withdraw=true\ntag=${tag}\nmatrix={"include":[]}\n`);
  process.exit(0);
}
git("fetch", "origin", "master", "--tags");
let shas;
if (tagPush) {
  if (event.deleted) throw new Error("Deleting a tag does not publish or withdraw a release");
  const current = validSHA(git("rev-parse", `${stableTag}^{commit}`));
  const triggered = validSHA(git("rev-parse", `${validSHA(process.env.GITHUB_SHA)}^{commit}`));
  const after = event.after ? validSHA(git("rev-parse", `${validSHA(event.after)}^{commit}`)) : triggered;
  if (current !== triggered || current !== after || (event.ref && event.ref !== ref))
    throw new Error("Stable tag moved after the triggering event; refusing to qualify another SHA");
  shas = [current];
} else if (process.env.GITHUB_EVENT_NAME === "push") {
  const head = validSHA(event.after), before = event.before;
  if (!before || /^0+$/.test(before)) throw new Error("Initial master history requires an explicit reviewed SHA; no silent history truncation");
  validSHA(before);
  git("merge-base", "--is-ancestor", before, head);
  shas = git("rev-list", "--reverse", "--first-parent", `${before}..${head}`).split("\n").filter(Boolean);
} else shas = [validSHA(event.inputs?.sha || process.env.GITHUB_SHA)];
if (!shas.length || shas.length > 100) throw new Error("Use a reviewed batch of 1..100 master commits; no commits are silently omitted");

// Real dispatches provide token/repository explicitly. Local planning regression
// fixtures need only a private temporary Git repository and never call GitHub.
const repository = process.env.GITHUB_REPOSITORY;
const releases = repository && process.env.GH_TOKEN
  ? JSON.parse(gh("api", `repos/${repository}/releases?per_page=100`, "--paginate", "--slurp")).flat()
  : [];
function priorDevelopment(sha) {
  const candidates = releases.filter(release => release.tag_name === releaseTag(sha) || release.tag_name.endsWith(`.g${sha.slice(0, 12)}`));
  if (candidates.some(release => release.draft && release.body?.startsWith("Withdrawn release")))
    throw new Error("The development release was withdrawn; it cannot be republished under a new version");
  const published = candidates.filter(release => !release.draft && release.prerelease);
  if (published.length > 1) throw new Error("Multiple development identities exist for this source SHA");
  if (!published.length) return null;
  const release = published[0];
  const asset = release.assets.find(asset => asset.name === "release.json");
  if (!asset) throw new Error("Published development release has no verification manifest");
  const manifestText = execFileSync("gh", ["api", asset.url, "-H", "Accept: application/octet-stream"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const manifest = JSON.parse(manifestText);
  if (manifest.sha !== sha || manifest.tag !== release.tag_name || manifest.verified !== true || manifest.channel !== "development")
    throw new Error("Development release verification does not match the requested source SHA");
  assertExistingRelease(release, manifest, { sha, version: manifest.version, tag: manifest.tag, manifestText });
  if (!/^\d+$/.test(String(manifest.ci_run_id))) throw new Error("Development release has no traceable verification run");
  const pages = JSON.parse(gh("api", `repos/${repository}/actions/runs/${manifest.ci_run_id}/jobs?filter=all&per_page=100`, "--paginate", "--slurp"));
  const attempt = latestVerificationAttempt(pages.flatMap(page => page.jobs), sha);
  verifyMarker(manifest.verification, { sha, version: manifest.version, runID: manifest.ci_run_id, runAttempt: attempt });
  if (String(attempt) !== String(manifest.ci_run_attempt)) throw new Error("Development verification attempt changed or failed");
  let context = manifest.version_context;
  if (context) {
    if (context.sha !== sha || context.version !== manifest.version || context.tag !== manifest.tag)
      throw new Error("Published development version context does not match its manifest");
  } else {
    const base = manifest.version.match(/^(\d+\.\d+\.\d+)-dev\./)?.[1];
    if (!base || manifest.tag !== releaseTag(sha)) throw new Error("Historical development identity is invalid");
    stableVersion(`v${base}`);
    context = { schema: 0, sha, version: manifest.version, tag: manifest.tag, next_version: base, next_tag: `v${base}` };
  }
  return assertVersionContext(context, { sha, version: manifest.version, tag: manifest.tag });
}

const entries = [];
for (const sha of shas) {
  git("merge-base", "--is-ancestor", sha, "origin/master");
  const prior = priorDevelopment(sha);
  const selected = planReleaseVersion({ sha, prior, stableTag });
  entries.push({ sha, ...selected, prefix: `release-${sha}-${stableTag || "dev"}-`, stable: mode === "stable" });
}
await appendFile(process.env.GITHUB_OUTPUT, `withdraw=false\nmatrix=${JSON.stringify({ include: entries })}\n`);
if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY,
  entries.map(entry => `- ${entry.sha}: ${entry.version}; next stable tag: **${entry.context.next_tag}**`).join("\n") + "\n");
