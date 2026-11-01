import { join } from "node:path";
import { build } from "./build.mjs";
import { ensureWebDependencies, main, npm } from "./common.mjs";

export async function develop(ctx, mode = "desktop") {
  if (mode === "web") {
    await ensureWebDependencies(ctx);
    ctx.log("Starting the Web development server…");
    npm(ctx, ["run", "dev"], { cwd: join(ctx.cwd, "web") });
  } else if (mode === "desktop") {
    await build(ctx);
    ctx.log("Opening management with capture paused. Stop with Ctrl+C or the tray menu.");
    ctx.run(join(ctx.cwd, "dist", ctx.platform === "win32" ? "kone.exe" : "kone"), []);
  } else throw new Error("Development mode must be desktop or web");
}

await main(import.meta.url, (ctx) => develop(ctx, process.argv[2]));
