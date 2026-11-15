import { bun, ensureWebDependencies, main, npm } from "./common.mjs";
import { showHelp } from "./help.mjs";

function minimumVersion(format, minimum) {
  return value => {
    const match = value.trim().match(format);
    if (!match) return false;
    for (let index = 0; index < minimum.length; index++) {
      const part = Number(match[index + 1]);
      if (part !== minimum[index]) return part > minimum[index];
    }
    return true;
  };
}

export async function initialize(ctx) {
  ctx.log("[1/3] Checking development tools…");
  const tools = [
    ["git", ["--version"], () => true, "Git"],
    ["go", ["version"], minimumVersion(/^go version go(\d+)\.(\d+)\.(\d+)(?:\s|$)/, [1, 27, 0]), "Go 1.27 or later"],
    ["node", ["--version"], minimumVersion(/^v(\d+)\.(\d+)\.(\d+)\s*$/, [22, 12, 0]), "Node 22.12 or later"],
    ["bun", ["--version"], minimumVersion(/^(\d+)\.(\d+)\.(\d+)(?:\+[^\s]+)?\s*$/, [1, 4, 0]), "Bun 1.4 or later"],
    ["just", ["--version"], minimumVersion(/^just (\d+)\.(\d+)\.(\d+)(?:\s|$)/, [1, 55, 0]), "just 1.55 or later"],
    ["bash", ["--version"], () => true, "Bash (Git Bash on Windows)"],
  ];
  const installed = [];
  const issues = [];
  for (const [command, args, valid, label] of tools) {
    try {
      // Inspect the installed SDK without triggering a module-driven download.
      const settings = command === "go" ? { env: { ...ctx.env, GOTOOLCHAIN: "local" } } : {};
      const version = command === "bun"
        ? bun(ctx, args, { capture: true })
        : ctx.run(command, args, { ...settings, capture: true });
      const detected = version.split(/\r?\n/)[0];
      if (valid(version)) installed.push(`${command}: ${detected}`);
      else issues.push(`${command}: installed ${detected}; requires ${label}. Update this tool.`);
    } catch (error) {
      issues.push(error.code === "ENOENT"
        ? `${command}: not found on PATH; install ${label}.`
        : `${command}: could not check version; check that ${label} runs in this terminal.`);
    }
  }
  try {
    const version = npm(ctx, ["--version"], { capture: true });
    installed.push(`npm: ${version.split(/\r?\n/)[0]}`);
  } catch {
    issues.push("npm: unavailable; install npm (included with Node) and check that Bash can run it.");
  }
  ctx.log("  Installed and ready:");
  for (const tool of installed) ctx.log(`    [OK] ${tool}`);
  if (!installed.length) ctx.log("    None detected.");
  if (issues.length) {
    ctx.log("  Tools needing attention:");
    for (const issue of issues) ctx.log(`    [!] ${issue}`);
    throw new Error("Development setup needs attention. Fix the tools listed above, reopen your terminal if PATH changed, then run `just init` again. Project dependencies have not been installed.");
  }
  ctx.log("[2/3] Preparing Go modules…");
  // Resolve only the native application graph, rather than downloading optional
  // platforms, test tools and unused transitive modules on every developer PC.
  ctx.run("go", ["list", "-tags", "with_gvisor", "-deps", "./cmd/kone"], { stdio: ["ignore", "ignore", "inherit"] });
  ctx.log("[3/3] Preparing Web dependencies…");
  await ensureWebDependencies(ctx);
  ctx.log("Ready. Use just dev, just build, or just package.");
}

await main(import.meta.url, (ctx) => {
  if (showHelp("init", process.argv.slice(2))) return;
  return initialize(ctx);
});
