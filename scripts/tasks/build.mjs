import { cp, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { binaryName, entryDefinitions, nativeTarget } from "../release/targets.mjs";
import { createMacApplication } from "../release/desktop.mjs";
import { safeName, targets, supportedTargets } from "../release/model.mjs";
import { ensureFrontend, main } from "./common.mjs";
import { showHelp } from "./help.mjs";

export async function build(ctx, mode = "native", option = "") {
  if (!["native", "all"].includes(mode)) throw new Error("Build mode must be native or all");
  if (option && (mode !== "all" || option !== "--include-armv7")) throw new Error("Builds include system, gvisor and mixed; select core.stack at runtime. Only build-all accepts --include-armv7.");
  const target = nativeTarget(ctx.platform, ctx.arch);
  const sha = ctx.run("git", ["rev-parse", "HEAD"], { capture: true });
  const version = safeName(ctx.env.KONE_VERSION || ctx.run(process.execPath, [join(ctx.taskRoot, "scripts/release/version-policy.mjs"), "--format", "version", "--sha", sha], { capture: true }));
  ctx.log("[1/2] Preparing Web assets…");
  await ensureFrontend(ctx);
  const env = { ...ctx.env, KONE_VERSION: version, CGO_ENABLED: "0" };
  if (mode === "all") {
    const selected = option === "--include-armv7" ? supportedTargets : targets;
    ctx.log(`[2/2] Building ${selected.length} targets with system, gvisor and mixed…`);
    env.KONE_BUILD_TARGETS = selected.join(",");
    delete env.KONE_BUILD_STACK;
    ctx.run("just", ["ci", "build-all"], { env });
  } else {
    ctx.log(`[2/2] Building ${target} (system, gvisor, mixed)…`);
    const [os, arch] = target.split("-");
    Object.assign(env, { GOOS: os, GOARCH: arch === "armv7" ? "arm" : arch, GOARM: "7" });
    delete env.KONE_BUILD_STACK;
    await mkdir(join(ctx.cwd, "dist"), { recursive: true });
    const output = `dist/${binaryName(target)}`;
    for (const entry of entryDefinitions(target)) {
      const ldflags = `${entry.role === "gui" && os === "windows" ? "-H=windowsgui " : ""}-X main.VERSION=${version}`;
      ctx.run("go", ["build", "-tags", "with_gvisor", "-trimpath", "-ldflags", ldflags, "-o", `dist/${entry.name}`, entry.role === "cli" && os !== "linux" ? "./cmd/kone-cli" : "./cmd/kone"], { env });
      if (entry.role === "cli" && os !== "linux") await cp(join(ctx.cwd, "dist", entry.name), join(ctx.cwd, "dist", os === "windows" ? "kone-cli.exe" : "kone-cli"));
    }
    const alias = ctx.platform === "win32" ? "kone.exe" : "kone";
    await cp(join(ctx.cwd, output), join(ctx.cwd, "dist", alias));
    if (os === "darwin") await createMacApplication({ binary: join(ctx.cwd, output), output: join(ctx.cwd, "dist/Kone.app"), version, sha, icon: join(ctx.cwd, "web/native/kone.icns") });
    await cp(join(ctx.cwd, "LICENSE"), join(ctx.cwd, "dist/LICENSE"));
    await cp(join(ctx.cwd, "LICENSE-MIT"), join(ctx.cwd, "dist/LICENSE-MIT"));
    await cp(join(ctx.cwd, "licenses"), join(ctx.cwd, "dist/licenses"), { recursive: true });
    ctx.run(process.execPath, [join(ctx.taskRoot, "scripts/release/build-info.mjs"), "--targets", target], { env });
    ctx.log(`Built dist/${alias}`);
  }
  return { sha, version, target, env };
}

await main(import.meta.url, (ctx) => {
  const [mode = "native", ...args] = process.argv.slice(2);
  if (showHelp(mode === "all" ? "build-all" : "build", args)) return;
  return build(ctx, mode, ...args);
});
