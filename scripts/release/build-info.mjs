import { execFileSync } from "node:child_process";
import { cp, readFile, writeFile } from "node:fs/promises";
import { targets, hashFile, validSHA } from "./model.mjs";
import { binaryName, entryDefinitions, selectedTargets } from "./targets.mjs";
import { createMacApplication, verifyMacApplication, verifyWindowsRole } from "./desktop.mjs";
const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== "--targets"))
  throw new Error("Usage: build-info.mjs [--targets target[,target...]]");
const selected = args.length ? selectedTargets(args[1]) : targets;
if (process.env.KONE_BUILD_STACK) throw new Error("KONE_BUILD_STACK was removed; all stacks are included and core.stack selects at runtime");
const stacks = ["system", "gvisor", "mixed"];
const mod = await readFile("go.mod", "utf8");
const moduleVersion = (path) => {
  const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const version = mod.match(new RegExp(`^\\s*${escaped}\\s+(v[^\\s]+)`, "m"))?.[1];
  const replace = mod.match(new RegExp(`^replace\\s+${escaped}\\s+=>\\s+([^\\s]+)\\s+(v[^\\s]+)`, "m"));
  return version ? { path, version, ...(replace ? { replace: { path: replace[1], version: replace[2] } } : {}) } : null;
};
const kernels = { tun: moduleVersion("github.com/sagernet/sing-tun"), gvisor: moduleVersion("github.com/sagernet/gvisor") };
const sha = validSHA(
  execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
);
const binaries = [];
for (const target of selected) {
  const name = binaryName(target);
  const entries = [];
  let icon;
  for (const entry of entryDefinitions(target)) {
    if (target.startsWith("windows-")) verifyWindowsRole(await readFile(`dist/${entry.name}`), entry.role);
    entries.push({
      ...entry,
      sha256: await hashFile(`dist/${entry.name}`),
      entrypoint: entry.role === "cli" && !target.startsWith("linux-") ? "./cmd/kone-cli" : "./cmd/kone",
      ldflags: `${entry.role === "gui" && target.startsWith("windows-") ? "-H=windowsgui " : ""}-X main.VERSION=${process.env.KONE_VERSION}`,
    });
  }
  if (target.startsWith("darwin-")) {
    await cp("web/native/kone.icns", "dist/kone.icns");
    icon = { name: "kone.icns", sha256: await hashFile("dist/kone.icns") };
    const output = `dist/apps/${target}/Kone.app`;
    await createMacApplication({ binary: `dist/${name}`, output, version: process.env.KONE_VERSION, sha, icon: "web/native/kone.icns" });
    await verifyMacApplication(output, { version: process.env.KONE_VERSION, sha });
  }
  binaries.push({
    target,
    name,
    sha256: await hashFile(`dist/${name}`),
    stack: stacks.join(","),
    stacks,
    default_stack: "system",
    entries,
    ...(icon ? { icon } : {}),
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
      stacks,
      default_stack: "system",
      kernels,
      build_tags: ["with_gvisor"],
    },
    null,
    2,
  ) + "\n",
);
