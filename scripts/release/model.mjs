import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

export const targets = [
  "linux-amd64",
  "linux-arm64",
  "linux-armv7",
  "darwin-amd64",
  "darwin-arm64",
  "windows-amd64",
  "windows-arm64",
];
export const requiredJobs = [
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
export function versionFor(sha, stableTag = "") {
  validSHA(sha);
  return stableTag ? stableVersion(stableTag) : `0.4.0-dev.${sha.slice(0, 12)}`;
}
export function releaseTag(sha, stableTag = "") {
  validSHA(sha);
  if (stableTag) stableVersion(stableTag);
  return stableTag || `dev-${sha.slice(0, 12)}`;
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
    marker.schema !== 1 ||
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
    requiredJobs.some((job) => !marker.required_jobs.includes(job))
  )
    throw new Error("CI verification marker is missing required gates");
}
export function expectedPackages(version) {
  return targets.flatMap((target) => {
    const base = `kone-${safeName(version)}-${target}`;
    if (target.startsWith("windows-")) return [`${base}.zip`];
    return [
      `${base}.tar.gz`,
      `${base}.${target.startsWith("linux-") ? "deb" : "pkg"}`,
    ];
  });
}
export function assertVersion(output, version) {
  if (String(output).trim() !== `Version: ${version}`)
    throw new Error("Packaged executable version does not match the release");
}
