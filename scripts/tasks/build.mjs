import { cp, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { binaryName, nativeTarget } from "../release/targets.mjs";
import { safeName } from "../release/model.mjs";
import { ensureFrontend, main } from "./common.mjs";

export async function build(ctx, mode = "native", stack = "system") {
  if (!["native", "all"].includes(mode)) throw new Error("Build mode must be native or all");
  if (!["system", "mixed"].includes(stack)) throw new Error("Stack must be system or mixed");
  const target = nativeTarget(ctx.platform, ctx.arch);
  if (target === "linux-armv7" && stack === "mixed") throw new Error("ARMv7 supports the system stack only");
  const sha = ctx.run("git", ["rev-parse", "HEAD"], { capture: true });
  const version = safeName(ctx.env.KONE_VERSION || `0.4.0-dev.${sha}`);
  ctx.log("[1/2] Preparing Web assets…");
  await ensureFrontend(ctx);
  const env = { ...ctx.env, KONE_VERSION: version, CGO_ENABLED: "0" };
  if (mode === "all") {
    ctx.log("[2/2] Building all seven release targets…");
    // This fixed matrix selects mixed per target; never inherit a native override.
    delete env.KONE_BUILD_STACK;
    ctx.run("just", ["ci", "build-all"], { env });
  } else {
    ctx.log(`[2/2] Building ${target} (${stack})…`);
    const [os, arch] = target.split("-");
    Object.assign(env, { GOOS: os, GOARCH: arch === "armv7" ? "arm" : arch, GOARM: "7", KONE_BUILD_STACK: stack });
    await mkdir(join(ctx.cwd, "dist"), { recursive: true });
    const output = `dist/${binaryName(target)}`;
    ctx.run("go", ["build", ...(stack === "mixed" ? ["-tags", "with_gvisor"] : []), "-trimpath", "-ldflags", `-X main.VERSION=${version}`, "-o", output, "./cmd/kone"], { env });
    const alias = ctx.platform === "win32" ? "kone.exe" : "kone";
    await cp(join(ctx.cwd, output), join(ctx.cwd, "dist", alias));
    await cp(join(ctx.cwd, "LICENSE"), join(ctx.cwd, "dist/LICENSE"));
    await cp(join(ctx.cwd, "LICENSE-MIT"), join(ctx.cwd, "dist/LICENSE-MIT"));
    await cp(join(ctx.cwd, "licenses"), join(ctx.cwd, "dist/licenses"), { recursive: true });
    ctx.run(process.execPath, [join(ctx.taskRoot, "scripts/release/build-info.mjs"), "--targets", target], { env });
    ctx.log(`Built dist/${alias}`);
  }
  return { sha, version, target, env };
}

await main(import.meta.url, (ctx) => build(ctx, ...process.argv.slice(2)));
