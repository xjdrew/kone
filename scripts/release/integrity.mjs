import { expectedPackages, safeName, stableVersion } from "./model.mjs";
import { createHash } from "node:crypto";

export const historicalTargets = ["linux-amd64", "linux-arm64", "linux-armv7", "darwin-amd64", "darwin-arm64", "windows-amd64", "windows-arm64"];
export function historicalPackages(version) {
  safeName(version);
  return historicalTargets.flatMap(target => target.startsWith("windows-")
    ? [`kone-${version}-${target}.zip`]
    : [`kone-${version}-${target}.tar.gz`, `kone-${version}-${target}.${target.startsWith("linux-") ? "deb" : "pkg"}`]);
}
export function completeAssetRecords(manifest, version) {
  const names = manifest.assets?.map(asset => asset.name);
  const layouts = [
    [...expectedPackages(version), "kone-source.tar.gz"],
    [...historicalPackages(version), "kone-source.tar.gz", "build-info.json"],
  ];
  if (!Array.isArray(names) || new Set(names).size !== names.length || !layouts.some(layout => layout.length === names.length && layout.every(name => names.includes(name))))
    throw new Error("Published release manifest does not declare a complete supported asset layout");
  if (names.length === layouts[0].length && (!manifest.build || manifest.build.sha !== manifest.sha || manifest.build.version !== version))
    throw new Error("Published release is missing matching embedded build metadata");
  for (const asset of manifest.assets) if (!/^[a-f0-9]{64}$/.test(asset.sha256)) throw new Error("Published asset digest is invalid");
}

export function assertExistingRelease(release, manifest, { sha, version, tag, manifestText }) {
  if (manifest.sha !== sha || manifest.version !== version || manifest.tag !== tag || manifest.verified !== true)
    throw new Error("Existing public release does not match the verified build");
  if (!["stable", "development"].includes(manifest.channel) || release.draft === true || release.isDraft === true ||
    (release.isPrerelease ?? release.prerelease) !== (manifest.channel === "development") ||
    (manifest.channel === "stable" ? tag !== `v${version}` : !version.includes("-dev.")))
    throw new Error("Published release channel does not match its manifest");
  if (manifest.channel === "stable") stableVersion(tag);
  completeAssetRecords(manifest, version);
  const expected = [...manifest.assets.map(asset => asset.name), "release.json", "SHA256SUMS"];
  if (release.assets.length !== expected.length || new Set(release.assets.map(asset => asset.name)).size !== expected.length || expected.some(name => !release.assets.some(asset => asset.name === name)))
    throw new Error("Published release asset list is incomplete or contains unexpected files");
  for (const asset of manifest.assets) if (!release.assets.some(item => item.name === asset.name && item.digest === `sha256:${asset.sha256}`))
    throw new Error("Published asset integrity no longer matches its manifest");
  if (typeof manifestText !== "string" || JSON.stringify(JSON.parse(manifestText)) !== JSON.stringify(manifest))
    throw new Error("Published manifest bytes are required for checksum verification");
  const digest = value => createHash("sha256").update(value).digest("hex");
  const manifestHash = digest(manifestText);
  const checksums = [...manifest.assets, { name: "release.json", sha256: manifestHash }].sort((a, b) => a.name.localeCompare(b.name));
  const sumsHash = digest(checksums.map(asset => `${asset.sha256}  ${asset.name}`).join("\n") + "\n");
  if (release.assets.find(asset => asset.name === "release.json").digest !== `sha256:${manifestHash}` ||
    release.assets.find(asset => asset.name === "SHA256SUMS").digest !== `sha256:${sumsHash}`)
    throw new Error("Published manifest/checksum file integrity does not match the declared assets");
}
