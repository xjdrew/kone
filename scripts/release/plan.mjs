import { execFileSync } from "node:child_process";
import { appendFile, readFile } from "node:fs/promises";
import {
  releaseTag,
  stableVersion,
  validSHA,
  versionFor,
  latestVerificationAttempt,
} from "./model.mjs";
const git = (...args) =>
  execFileSync("git", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
const event = JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH, "utf8"));
if (process.env.GITHUB_REF !== "refs/heads/master")
  throw new Error("Release dispatch must run from master");
git("fetch", "origin", "master", "--tags");
let shas;
const mode =
  process.env.GITHUB_EVENT_NAME === "push"
    ? "development"
    : event.inputs?.channel || "development";
if (!["development", "stable", "withdraw"].includes(mode))
  throw new Error("Unknown release channel");
const stableTag = mode === "stable" ? event.inputs?.tag || "" : "";
if (stableTag) stableVersion(stableTag);
if (mode === "withdraw") {
  const tag = event.inputs?.tag || "";
  if (
    !/^(dev-[a-f0-9]{12}|v\d+\.\d+\.\d+)$/.test(tag) ||
    !event.inputs?.reason?.trim()
  )
    throw new Error("Withdrawal requires an existing release tag and a reason");
  await appendFile(
    process.env.GITHUB_OUTPUT,
    `withdraw=true\ntag=${tag}\nmatrix={"include":[]}\n`,
  );
  process.exit(0);
}
if (process.env.GITHUB_EVENT_NAME === "push") {
  const head = validSHA(event.after);
  const before = event.before;
  if (!before || /^0+$/.test(before))
    throw new Error(
      "Initial master history requires an explicit reviewed SHA; no silent history truncation",
    );
  validSHA(before);
  git("merge-base", "--is-ancestor", before, head);
  shas = git("rev-list", "--reverse", "--first-parent", `${before}..${head}`)
    .split("\n")
    .filter(Boolean);
} else shas = [validSHA(event.inputs?.sha || process.env.GITHUB_SHA)];
if (!shas.length) throw new Error("No master commits to verify");
// Keep workflow matrices bounded; never silently drop a qualifying commit.
if (shas.length > 100)
  throw new Error(
    "Push exceeds 100 master commits; dispatch explicit SHAs in reviewed batches",
  );
const entries = [];
for (const sha of shas) {
  validSHA(sha);
  git("merge-base", "--is-ancestor", sha, "origin/master");
  if (mode === "stable") {
    const tag = releaseTag(sha);
    const release = JSON.parse(
      execFileSync(
        "gh",
        ["release", "view", tag, "--json", "isDraft,assets,targetCommitish"],
        { encoding: "utf8" },
      ),
    );
    if (
      release.isDraft ||
      !release.assets.some((asset) => asset.name === "release.json")
    )
      throw new Error(
        "Stable promotion requires a published, verified development release of the same SHA",
      );
    // Download to a temporary directory via a separate verification script below;
    // the dispatcher cannot substitute another SHA or bypass the required gates.
    const manifest = JSON.parse(
      execFileSync(
        "gh",
        [
          "api",
          release.assets.find((asset) => asset.name === "release.json").apiUrl,
          "-H",
          "Accept: application/octet-stream",
        ],
        { encoding: "utf8" },
      ),
    );
    if (
      manifest.sha !== sha ||
      manifest.verified !== true ||
      manifest.tag !== tag
    )
      throw new Error(
        "Development release verification does not match the requested master SHA",
      );
    if (!/^\d+$/.test(String(manifest.ci_run_id)))
      throw new Error("Development release has no traceable verification run");
    const pages = JSON.parse(
      execFileSync(
        "gh",
        [
          "api",
          `repos/${process.env.GITHUB_REPOSITORY}/actions/runs/${manifest.ci_run_id}/jobs?filter=all&per_page=100`,
          "--paginate",
          "--slurp",
        ],
        { encoding: "utf8" },
      ),
    );
    if (
      String(
        latestVerificationAttempt(
          pages.flatMap((page) => page.jobs),
          sha,
        ),
      ) !== String(manifest.ci_run_attempt)
    )
      throw new Error(
        "The development release does not have a successful required-gates job for this exact SHA",
      );
  }
  entries.push({
    sha,
    version: versionFor(sha, stableTag),
    tag: releaseTag(sha, stableTag),
    prefix: `release-${sha}-${stableTag || "dev"}-`,
    stable: mode === "stable",
  });
}
await appendFile(
  process.env.GITHUB_OUTPUT,
  `withdraw=false\nmatrix=${JSON.stringify({ include: entries })}\n`,
);
