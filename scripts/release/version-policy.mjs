import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { stableVersion, validSHA } from "./model.mjs";

export function parseVersion(value) {
  stableVersion(`v${value}`);
  const parts = value.split(".").map(Number);
  if (parts.some(part => !Number.isSafeInteger(part))) throw new Error("Version components exceed the supported integer range");
  return parts;
}
export function compareVersions(a, b) {
  const left = parseVersion(a), right = parseVersion(b);
  for (let i = 0; i < 3; i++) if (left[i] !== right[i]) return left[i] < right[i] ? -1 : 1;
  return 0;
}
export function changeLevel(message, baseVersion) {
  const lines = message.trim().split(/\r?\n/);
  const header = /^Merge (pull request|[a-f0-9]+ into)/.test(lines[0])
    ? lines.slice(1).find(line => /^[a-z]+(?:\([^)]*\))?!?:\s/.test(line)) || lines[0]
    : lines[0];
  if (/^[a-z]+(?:\([^)]*\))?!:\s/.test(header) || /^BREAKING[ -]CHANGE:\s/m.test(message))
    return parseVersion(baseVersion)[0] === 0 ? "minor" : "major";
  return /^feat(?:\([^)]*\))?:\s/.test(header) ? "minor" : "patch";
}
export function bumpVersion(base, level) {
  const [major, minor, patch] = parseVersion(base);
  const result = level === "major" ? [major + 1, 0, 0] : level === "minor" ? [major, minor + 1, 0] : [major, minor, patch + 1];
  if (result.some(part => !Number.isSafeInteger(part))) throw new Error("Version overflow");
  return result.join(".");
}
export function assertVersionContext(context, { sha, version, tag, stable = false }) {
  validSHA(sha);
  if (!context || context.sha !== sha || ![0, 1].includes(context.schema)) throw new Error("Release version context does not match source SHA");
  parseVersion(context.next_version);
  if (context.next_tag !== `v${context.next_version}`) throw new Error("Invalid next stable tag in version context");
  if (context.schema === 0) {
    if (context.version !== `${context.next_version}-dev.${sha.slice(0, 12)}` || context.tag !== `dev-${sha.slice(0, 12)}`)
      throw new Error("Invalid historical development identity");
  } else if (!/^\d{8}$/.test(context.date) || !Number.isSafeInteger(context.sequence) || context.sequence < 1 ||
    context.version !== `${context.next_version}-dev.${context.date}.${context.sequence}.g${sha.slice(0, 12)}` || context.tag !== `v${context.version}`)
    throw new Error("Invalid development version identity");
  if (stable ? context.schema !== 1 || context.next_version !== version || context.next_tag !== tag : context.version !== version || context.tag !== tag)
    throw new Error("Release version context does not match the verified source/channel");
  return context;
}
// prior is supplied only after the dispatcher verifies the published manifest,
// its complete assets and the latest successful qualification attempt.
export function selectReleaseVersion({ calculated, prior = null, stableTag = "" }) {
  const sha = validSHA(calculated.sha);
  assertVersionContext(calculated, { sha, version: calculated.version, tag: calculated.tag });
  if (prior) assertVersionContext(prior, { sha, version: prior.version, tag: prior.tag });
  if (stableTag) {
    const version = stableVersion(stableTag);
    if (!prior) throw new Error("Stable promotion requires a published, verified development release of the same SHA");
    if (calculated.next_tag !== stableTag) throw new Error(`Stable tag must match the calculated next version: ${calculated.next_tag}`);
    return { version, tag: stableTag, context: calculated };
  }
  const context = prior || calculated;
  return { version: context.version, tag: context.tag, context };
}
export function planReleaseVersion({ sha, prior = null, stableTag = "", cwd = process.cwd() }) {
  // Check published evidence before recalculating: newly-added stable tags can
  // make a historical Release-As footer lower than today's automatic version.
  const calculated = !stableTag && prior ? prior : versionContext({ cwd, sha });
  return selectReleaseVersion({ calculated, prior, stableTag });
}
export function plannedVersion({ baseVersion = "0.0.0", floor = "0.4.0", messages = [] }) {
  parseVersion(floor);
  const rank = { patch: 1, minor: 2, major: 3 };
  const level = messages.reduce((highest, message) => {
    const next = changeLevel(message, baseVersion);
    return rank[next] > rank[highest] ? next : highest;
  }, "patch");
  let version = bumpVersion(baseVersion, level);
  if (compareVersions(floor, version) > 0) version = floor;
  let releaseAs = null;
  for (const [index, message] of messages.entries()) {
    const matches = [...message.matchAll(/^Release-As:\s*(.+)\s*$/gmi)];
    if (matches.length > 1) throw new Error("A commit must contain at most one Release-As trailer");
    if (!matches.length) continue;
    const value = matches[0][1].trim().replace(/^v/, "");
    parseVersion(value);
    if (compareVersions(value, version) < 0 && index === messages.length - 1)
      throw new Error("Release-As cannot lower the automatically calculated version");
    if (compareVersions(value, version) >= 0) { version = value; releaseAs = value; }
  }
  return { next_version: version, bump: level, release_as: releaseAs };
}

// Local calculation is read-only and never fetches refs or publishes anything.
// Published development contexts are reused by the dispatcher instead of being
// recalculated after someone adds a new ancestor stable tag.
export function versionContext({ cwd = process.cwd(), sha = "HEAD" } = {}) {
  const git = (...args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  sha = validSHA(git("rev-parse", "--verify", `${sha}^{commit}`));
  if (git("rev-parse", "--is-shallow-repository") === "true")
    throw new Error("Version calculation requires complete Git history and tags; fetch with --unshallow --tags first");
  let floor = "0.4.0";
  try { floor = git("show", `${sha}:VERSION`); }
  catch (error) { if (!/does not exist|exists on disk, but not in/.test(String(error.stderr))) throw error; }
  parseVersion(floor);
  let baseTag = "", baseVersion = "0.0.0", baseSHA = "";
  for (const tag of git("tag", "--list", "v*.*.*").split("\n").filter(Boolean)) {
    if (!/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(tag)) continue;
    const commit = git("rev-parse", `${tag}^{commit}`);
    if (commit === sha || compareVersions(tag.slice(1), baseVersion) <= 0) continue;
    try { git("merge-base", "--is-ancestor", commit, sha); }
    catch { continue; }
    baseTag = tag; baseVersion = tag.slice(1); baseSHA = commit;
  }
  const messages = git("log", "--reverse", "--first-parent", "--format=%B%x00", baseSHA ? `${baseSHA}..${sha}` : sha).split("\0").map(message => message.trim()).filter(Boolean);
  const plan = plannedVersion({ baseVersion, floor, messages });
  const sequence = Number(git("rev-list", "--first-parent", "--count", sha));
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error("Invalid first-parent sequence");
  const date = new Date(Number(git("show", "-s", "--format=%ct", sha)) * 1000).toISOString().slice(0, 10).replaceAll("-", "");
  const version = `${plan.next_version}-dev.${date}.${sequence}.g${sha.slice(0, 12)}`;
  return { schema: 1, sha, base_tag: baseTag, base_version: baseVersion, floor, ...plan, sequence, date, version, tag: `v${version}`, next_tag: `v${plan.next_version}` };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = { format: "json", sha: "HEAD" };
    for (let i = 2; i < process.argv.length; i += 2) {
      if (!["--format", "--sha"].includes(process.argv[i]) || !process.argv[i + 1]) throw new Error("Usage: version-policy.mjs [--format json|version|next-tag] [--sha SHA]");
      options[process.argv[i].slice(2)] = process.argv[i + 1];
    }
    const context = versionContext({ sha: options.sha });
    if (options.format === "json") console.log(JSON.stringify(context));
    else if (options.format === "version") console.log(context.version);
    else if (options.format === "next-tag") console.log(context.next_tag);
    else throw new Error("Format must be json, version or next-tag");
  } catch (error) { console.error(`KONE version: ${error.message}`); process.exitCode = 1; }
}
