import { execFileSync } from "node:child_process";
import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import {
  expectedPackages,
  hashFile,
  releaseTag,
  validSHA,
  verifyMarker,
} from "./model.mjs";

if (
  process.env.GITHUB_ACTIONS !== "true" ||
  process.env.GITHUB_REF !== "refs/heads/master" ||
  process.env.GITHUB_EVENT_NAME === "pull_request"
)
  throw new Error("Publishing is allowed only in the master release workflow");
const sha = validSHA(process.env.RELEASE_SHA);
const version = process.env.RELEASE_VERSION;
const tag = process.env.RELEASE_TAG;
const stable = process.env.RELEASE_STABLE === "true";
if (releaseTag(sha, stable ? tag : "") !== tag)
  throw new Error("Release tag does not match the verified commit/channel");
const input = resolve("release-input");
const output = resolve("release-assets");
const marker = JSON.parse(
  await readFile("verification/verification.json", "utf8"),
);
verifyMarker(marker, { sha, version, runID: process.env.GITHUB_RUN_ID });
execFileSync("git", ["fetch", "origin", "master", "--tags"], {
  stdio: "inherit",
});
execFileSync("git", ["merge-base", "--is-ancestor", sha, "origin/master"]);
const gh = (...args) =>
  execFileSync("gh", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
const repo = process.env.GITHUB_REPOSITORY;
const view = () =>
  JSON.parse(
    gh(
      "release",
      "view",
      tag,
      "--json",
      "isDraft,isPrerelease,tagName,targetCommitish,assets,url,body",
    ),
  );
function absent(error) {
  return /release not found|Not Found|HTTP 404/i.test(
    String(error.stderr || error.message),
  );
}
let existing;
try {
  existing = view();
} catch (error) {
  if (!absent(error)) throw error;
}
let ref;
try {
  ref = JSON.parse(gh("api", `repos/${repo}/git/ref/tags/${tag}`));
} catch (error) {
  if (!absent(error)) throw error;
}
if (ref) {
  let object = ref.object;
  for (let i = 0; object.type === "tag" && i < 8; i++)
    object = JSON.parse(
      gh("api", `repos/${repo}/git/tags/${object.sha}`),
    ).object;
  if (object.type !== "commit" || object.sha !== sha)
    throw new Error(
      "Existing tag points at a different commit; refusing to retag",
    );
}
if (existing && !existing.isDraft) {
  const asset = existing.assets.find((asset) => asset.name === "release.json");
  if (!asset)
    throw new Error("Existing public release has no verifiable manifest");
  const prior = JSON.parse(
    gh("api", asset.apiUrl, "-H", "Accept: application/octet-stream"),
  );
  if (
    prior.sha !== sha ||
    prior.version !== version ||
    prior.tag !== tag ||
    prior.verified !== true ||
    !existing.assets.some((asset) => asset.name === "SHA256SUMS")
  )
    throw new Error(
      "Existing public release does not match the verified build",
    );
  for (const item of prior.assets || [])
    if (
      !existing.assets.some(
        (asset) =>
          asset.name === item.name && asset.digest === `sha256:${item.sha256}`,
      )
    )
      throw new Error(
        "Published asset integrity no longer matches its manifest",
      );
  console.log(`Already published and unchanged: ${existing.url}`);
  process.exit(0);
}
if (
  existing &&
  !existing.body.startsWith(
    `Automated KONE release\nSHA: ${sha}\nVersion: ${version}\n`,
  )
)
  throw new Error(
    "Draft is withdrawn or not owned by this release automation; refusing to overwrite it",
  );
const build = JSON.parse(
  await readFile(join(input, "build-info.json"), "utf8"),
);
if (build.sha !== sha || build.version !== version)
  throw new Error(
    "Binary/source build identity does not match CI verification",
  );
const records = [];
for (const platform of ["linux", "darwin", "win32"]) {
  const value = JSON.parse(
    await readFile(join(output, `packages-${platform}.json`), "utf8"),
  );
  if (
    value.sha !== sha ||
    value.version !== version ||
    value.platform !== platform
  )
    throw new Error("Package identity mismatch");
  records.push(...value.assets);
}
const expected = expectedPackages(version);
if (
  records.length !== expected.length ||
  new Set(records.map((record) => record.name)).size !== expected.length ||
  expected.some((name) => !records.some((record) => record.name === name))
)
  throw new Error(
    "Incomplete or duplicate platform packages; release remains unpublished",
  );
for (const record of records)
  if ((await hashFile(join(output, record.name))) !== record.sha256)
    throw new Error(`Package checksum mismatch: ${record.name}`);
for (const filename of ["kone-source.tar.gz", "build-info.json"]) {
  await cp(join(input, filename), join(output, filename));
  records.push({
    name: filename,
    sha256: await hashFile(join(output, filename)),
    target:
      filename === "kone-source.tar.gz"
        ? "corresponding-source"
        : "build-metadata",
  });
}
const manifest = {
  schema: 1,
  verified: true,
  sha,
  version,
  tag,
  channel: stable ? "stable" : "development",
  ci_run_id: String(marker.run_id),
  ci_url: marker.ci_url,
  verification: marker,
  assets: records,
};
await writeFile(
  join(output, "release.json"),
  JSON.stringify(manifest, null, 2) + "\n",
);
const checksums = [
  ...records,
  {
    name: "release.json",
    sha256: await hashFile(join(output, "release.json")),
  },
].sort((a, b) => a.name.localeCompare(b.name));
await writeFile(
  join(output, "SHA256SUMS"),
  checksums.map((record) => `${record.sha256}  ${record.name}`).join("\n") +
    "\n",
);
const notes = `Automated KONE release\nSHA: ${sha}\nVersion: ${version}\n\n${stable ? "Stable promotion of a previously verified master SHA; this exact version was rebuilt and passed all required gates." : "Development prerelease. This exact master commit passed the required CI gates independently."}\n\nCI evidence: ${marker.ci_url}\n\nVerify SHA256SUMS and read release.json before installation. Linux archives/.deb, macOS archives/unsigned .pkg, and Windows portable .zip with a per-user install script are included. Packages never enable capture or change firewall/certificate trust during installation. All packages are unsigned; macOS packages are not notarized. Cross-compiled architectures without native version checks are experimental (see release.json); real Raspberry Pi and ARM64 driver acceptance remains deployment-specific.\n\nThe matching source archive includes vendored Go dependencies, frontend sources/assets and component licenses. Back up your user profile before upgrade or rollback; pause capture, replace the executable with a verified older release, then explicitly restart management. Never run two versions against one profile simultaneously. Configuration import/default restoration is explicit and does not silently enable capture.\n`;
await mkdir("release-notes", { recursive: true });
await writeFile("release-notes/body.md", notes);
if (!existing) {
  gh(
    "release",
    "create",
    tag,
    "--target",
    sha,
    "--draft",
    ...(stable ? [] : ["--prerelease"]),
    "--title",
    `KONE ${version}`,
    "--notes-file",
    "release-notes/body.md",
  );
  existing = view();
}
// Only unpublished, automation-owned drafts are reset for a retry. Public assets
// are immutable above; a partial draft can converge after a failed upload.
if (!existing.isDraft)
  throw new Error(
    "Release changed while preparing upload; refusing asset mutation",
  );
for (const asset of existing.assets)
  gh("release", "delete-asset", tag, "--yes", "--", asset.name);
const files = [
  ...checksums.map((record) => join(output, record.name)),
  join(output, "SHA256SUMS"),
];
gh("release", "upload", tag, ...files);
const uploaded = view();
for (const file of files) {
  const name = file.split(/[\\/]/).pop();
  const asset = uploaded.assets.find((asset) => asset.name === name);
  if (!asset || asset.digest !== `sha256:${await hashFile(file)}`)
    throw new Error(`Uploaded asset checksum mismatch: ${name}`);
}
gh(
  "release",
  "edit",
  tag,
  "--draft=false",
  `--prerelease=${!stable}`,
  `--latest=${stable}`,
  "--notes-file",
  "release-notes/body.md",
);
console.log(`Published verified ${sha}: ${view().url}`);
