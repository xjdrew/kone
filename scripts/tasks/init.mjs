import { ensureWebDependencies, main, npm } from "./common.mjs";
import { showHelp } from "./help.mjs";

export async function initialize(ctx) {
  ctx.log("[1/3] Checking development tools…");
  const tools = [
    ["git", ["--version"], () => true, "Git"],
    ["go", ["version"], (value) => /^go version go1\.27\.3\s/.test(value), "Go 1.27.3"],
    ["node", ["--version"], (value) => /^v26\.(\d+)\./.test(value) && Number(value.split(".")[1]) >= 13, "Node 26.13 or later in the 26.x series"],
    ["bun", ["--version"], (value) => value.trim() === "1.4.4", "Bun 1.4.4"],
    ["just", ["--version"], (value) => /^just 1\.(\d+)/.test(value) && Number(value.split(".")[1]) >= 59, "just 1.59 or later"],
    ["bash", ["--version"], () => true, "Bash (Git Bash on Windows)"],
  ];
  const installed = [];
  const issues = [];
  for (const [command, args, valid, label] of tools) {
    try {
      const version = ctx.run(command, args, { capture: true });
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
