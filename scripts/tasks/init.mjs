import { ensureWebDependencies, main, npm } from "./common.mjs";
import { showHelp } from "./help.mjs";

export async function initialize(ctx) {
  ctx.log("[1/3] Checking development tools…");
  const tools = [
    ["git", ["--version"], () => true, "Git"],
    ["go", ["version"], (value) => /^go version go1\.27\.3\s/.test(value), "Go 1.27.3"],
    ["node", ["--version"], (value) => /^v26\.(\d+)\./.test(value) && Number(value.split(".")[1]) >= 13, "Node 26.13 or later in the 26.x series"],
    ["just", ["--version"], (value) => /^just 1\.(\d+)/.test(value) && Number(value.split(".")[1]) >= 59, "just 1.59 or later"],
    ["bash", ["--version"], () => true, "Bash (Git Bash on Windows)"],
  ];
  const missing = [];
  for (const [command, args, valid, label] of tools) {
    try {
      const version = ctx.run(command, args, { capture: true });
      if (!valid(version)) throw new Error("unsupported version");
      ctx.log(`  ${version.split(/\r?\n/)[0]}`);
    } catch { missing.push(label); }
  }
  try { npm(ctx, ["--version"], { capture: true }); }
  catch { missing.push("npm (included with Node)"); }
  if (missing.length)
    throw new Error(`Install these tools manually, reopen your terminal, then run just init: ${missing.join(", ")}`);
  ctx.log("[2/3] Preparing Go modules…");
  // Resolve only the native application graph, rather than downloading optional
  // platforms, test tools and unused transitive modules on every developer PC.
  ctx.run("go", ["list", "-deps", "./cmd/kone"], { stdio: ["ignore", "ignore", "inherit"] });
  ctx.log("[3/3] Preparing Web dependencies…");
  await ensureWebDependencies(ctx);
  ctx.log("Ready. Use just dev, just build, or just package.");
}

await main(import.meta.url, (ctx) => {
  if (showHelp("init", process.argv.slice(2))) return;
  return initialize(ctx);
});
