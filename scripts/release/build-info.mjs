import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { targets, hashFile, validSHA } from "./model.mjs";
import { binaryName, selectedTargets } from "./targets.mjs";
const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== "--targets"))
  throw new Error("Usage: build-info.mjs [--targets target[,target...]]");
const selected = args.length ? selectedTargets(args[1]) : targets;
const stack = process.env.KONE_BUILD_STACK;
if (stack && !["system", "mixed"].includes(stack)) throw new Error("KONE_BUILD_STACK must be system or mixed");
const sha = validSHA(
  execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
);
const binaries = [];
for (const target of selected) {
  if (target === "linux-armv7" && stack === "mixed") throw new Error("Linux ARMv7 supports only the system stack");
  const name = binaryName(target);
  binaries.push({
    target,
    name,
    sha256: await hashFile(`dist/${name}`),
    stack: stack === "system" || target === "linux-armv7" ? "system" : "system,mixed",
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
