import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { targets, hashFile, validSHA } from "./model.mjs";
const sha = validSHA(
  execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
);
const binaries = [];
for (const target of targets) {
  const name = `kone-${target}${target.startsWith("windows-") ? ".exe" : ""}`;
  binaries.push({
    target,
    name,
    sha256: await hashFile(`dist/${name}`),
    stack: target === "linux-armv7" ? "system" : "system,mixed",
  });
}
await writeFile(
  "dist/build-info.json",
  JSON.stringify(
    {
      schema: 1,
      sha,
      version: process.env.KONE_VERSION,
      go: execFileSync("go", ["version"], { encoding: "utf8" }).trim(),
      binaries,
      ldflags: `-X main.VERSION=${process.env.KONE_VERSION}`,
      cgo: false,
    },
    null,
    2,
  ) + "\n",
);
