import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

export const targets = [
  "linux-amd64",
  "linux-arm64",
  "darwin-amd64",
  "darwin-arm64",
  "windows-amd64",
  "windows-arm64",
];
// ARMv7 remains available for explicit Raspberry Pi builds, outside releases.
export const supportedTargets = [...targets, "linux-armv7"];
export const requiredJobs = [
  "web",
  "test",
  "build",
  "quality",
];
// Published development releases retain their original complete gate set.
// New markers use requiredJobs; compatibility never fills missing current
// gates with individual historical labels (or the reverse).
const legacyRequiredJobs = [
  "web",
  "test",
  "build",
  "packages",
  "performance",
  "robustness",
  "docker",
  "system",
  "dns-system",
  "shadowsocks-interop",
  "windows-system",
  "mac-system",
];
const groupedLegacyRequiredJobs = ["web", "test", "build", "packages", "quality", "linux-system", "windows-system"];
export function validSHA(value) {
  if (!/^[a-f0-9]{40}$/.test(value || ""))
    throw new Error("Use a complete, lowercase 40-character commit SHA");
  return value;
}
export function stableVersion(tag) {
  if (!/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(tag || ""))
    throw new Error("Stable tag must be vMAJOR.MINOR.PATCH");
  return tag.slice(1);
}
export function versionFor(sha, stableTag = "", context) {
  validSHA(sha);
  if (context && (context.sha !== sha || !context.version)) throw new Error("Version context does not match source SHA");
  if (!stableTag && context) return context.version;
  return stableTag ? stableVersion(stableTag) : `0.4.0-dev.${sha.slice(0, 12)}`;
}
export function releaseTag(sha, stableTag = "", context) {
  validSHA(sha);
  if (stableTag) stableVersion(stableTag);
  if (context && (context.sha !== sha || !context.tag)) throw new Error("Tag context does not match source SHA");
  return stableTag || context?.tag || `dev-${sha.slice(0, 12)}`;
}
export function safeName(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(value))
    throw new Error("Invalid release filename");
  return value;
}
export async function hashFile(path) {
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}
export function latestVerificationAttempt(jobs, sha) {
  validSHA(sha);
  const matches = jobs.filter((job) =>
    job.name?.endsWith(`Required gates verified (${sha})`),
  );
  const latest = Math.max(...matches.map((job) => Number(job.run_attempt)));
  const current = matches.filter((job) => Number(job.run_attempt) === latest);
  if (
    !Number.isSafeInteger(latest) ||
    latest < 1 ||
    current.length !== 1 ||
    current[0].status !== "completed" ||
    current[0].conclusion !== "success"
  )
    throw new Error(
      "Latest required-gates attempt is not successful for this SHA",
    );
  return latest;
}
export function verifyMarker(marker, { sha, version, runID, runAttempt }) {
  validSHA(sha);
  if (
    ![1, 2].includes(marker.schema) ||
    marker.sha !== sha ||
    marker.version !== version ||
    String(marker.run_id) !== String(runID) ||
    !/^[1-9]\d*$/.test(String(runAttempt)) ||
    String(marker.run_attempt) !== String(runAttempt) ||
    marker.verified !== true
  )
    throw new Error(
      "CI verification marker does not match this SHA, version, run and attempt",
    );
  if (
    !Array.isArray(marker.required_jobs) ||
    !(marker.schema === 2 ? [requiredJobs] : [groupedLegacyRequiredJobs, legacyRequiredJobs]).some((jobs) =>
      marker.required_jobs.length === jobs.length && new Set(marker.required_jobs).size === jobs.length && jobs.every((job) => marker.required_jobs.includes(job)),
    )
  )
    throw new Error("CI verification marker is missing required gates");
}
export function expectedPackages(version) {
  return targets.map((target) => {
    const base = `kone-${safeName(version)}-${target}`;
    return `${base}.${target.startsWith("windows-") ? "zip" : target.startsWith("linux-") ? "deb" : "pkg"}`;
  });
}
export function assertVersion(output, version) {
  if (String(output).trim() !== `Version: ${version}`)
    throw new Error("Packaged executable version does not match the release");
}
