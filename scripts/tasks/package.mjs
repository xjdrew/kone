import { join } from "node:path";
import { build } from "./build.mjs";
import { main } from "./common.mjs";
import { showHelp } from "./help.mjs";

export async function packageBuild(ctx, mode = "native", stack = "system") {
  const result = await build(ctx, mode, stack);
  ctx.log(mode === "all" ? "Packaging all portable targets and the native installer…" : `Packaging ${result.target}…`);
  ctx.run(process.execPath, [
    join(ctx.taskRoot, "scripts/release/package.mjs"),
    ...(mode === "all" ? ["--all-portable"] : ["--target", result.target]),
  ], { env: {
    ...result.env,
    RELEASE_INPUT: "dist",
    RELEASE_SHA: result.sha,
    RELEASE_VERSION: result.version,
  } });
  ctx.log("Packages are ready in release-assets/.");
}

await main(import.meta.url, (ctx) => {
  const [mode = "native", ...args] = process.argv.slice(2);
  if (showHelp(mode === "all" ? "package-all" : "package", args)) return;
  return packageBuild(ctx, mode, ...args);
});
