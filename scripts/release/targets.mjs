import { targets, supportedTargets } from "./model.mjs";

export function nativeTarget(platform = process.platform, architecture = process.arch) {
  const os = platform === "win32" ? "windows" : platform;
  const arch = { x64: "amd64", arm64: "arm64", arm: "armv7" }[architecture];
  const target = `${os}-${arch}`;
  if (!supportedTargets.includes(target)) throw new Error(`Unsupported native target: ${platform}/${architecture}`);
  return target;
}

export function selectedTargets(value) {
  const selected = typeof value === "string" ? value.split(",") : value;
  if (!Array.isArray(selected) || !selected.length || new Set(selected).size !== selected.length || selected.some(target => !supportedTargets.includes(target)))
    throw new Error("Select unique supported build targets");
  return selected;
}

export function binaryName(target) {
  selectedTargets([target]);
  return `kone-${target}${target.startsWith("windows-") ? ".exe" : ""}`;
}

export function entryDefinitions(target) {
  const name = binaryName(target);
  if (target.startsWith("linux-")) return [{ role: "cli", name }];
  return [{ role: "gui", name }, { role: "cli", name: `kone-cli-${target}${target.startsWith("windows-") ? ".exe" : ""}` }];
}

export function packagePlan(args = [], platform = process.platform, architecture = process.arch) {
  const native = nativeTarget(platform, architecture);
  const os = native.split("-")[0];
  let mode;
  let selected;
  if (!args.length) {
    mode = "ci";
    selected = targets.filter(target => target.startsWith(`${os}-`));
  } else if ((args.length === 1 || args.length === 2 && args[1] === "--include-armv7") && args[0] === "--all-portable") {
    mode = "all-portable";
    selected = args.includes("--include-armv7") ? [...supportedTargets] : [...targets];
  } else if (args.length === 2 && args[0] === "--target") {
    mode = "target";
    selected = selectedTargets(args[1]);
    if (selected.length !== 1) throw new Error("Package --target accepts one target");
  } else throw new Error("Usage: package.mjs [--target target | --all-portable [--include-armv7]]");
  const installers = selected.filter(target => os !== "windows" && target.startsWith(`${os}-`) && (mode === "ci" || target === native));
  const portables = selected.filter(target => target.startsWith("windows-") || mode === "all-portable" || !installers.includes(target));
  return { native, mode, targets: selected, installers, portables };
}
