import { join } from "node:path";
import { ensureFrontend, ensureWebDependencies, main } from "./common.mjs";

export async function quality(ctx, mode = "quick") {
  const ci = (...recipes) => ctx.run("just", ["ci", ...recipes]);
  const module = join(ctx.taskRoot, "scripts/ci/justfile");
  switch (mode) {
    case "quick":
      await ensureWebDependencies(ctx);
      ctx.log("[1/3] Checking formatting and Go code…");
      ctx.run("just", ["--fmt", "--check"]);
      ctx.run("just", ["--justfile", module, "--fmt", "--check"]);
      if (ctx.run("gofmt", ["-l", "cmd", "pkg", "test", "web/embed.go"], { capture: true }))
        throw new Error("Run just quality fmt to format Go sources");
      ci("vet");
      ctx.log("[2/3] Running cached Go unit tests (without race)…");
      ctx.run("go", ["test", "-vet=off", "./cmd/...", "./pkg/...", "./web/..."]);
      ctx.log("[3/3] Running Web unit tests…");
      ci("test-web");
      break;
    case "full":
      ctx.log("Running the full portable suite; privileged network acceptance runs in CI only.");
      await ensureWebDependencies(ctx);
      await ensureFrontend(ctx);
      ci("quality-check", "go-verify", "vet", "test-coverage", "test-mixed", "test-web", "test-release", "test-data", "fuzz", "vuln");
      ci("web-browsers", "test-web-e2e");
      break;
    case "fmt":
      ctx.run("just", ["--fmt"]);
      ctx.run("just", ["--justfile", module, "--fmt"]);
      ci("fmt");
      break;
    case "vet": ci("vet"); break;
    case "benchmark": ci("benchmark-metadata", "benchmark"); break;
    default: throw new Error("Quality mode must be quick, full, fmt, vet, or benchmark");
  }
}

await main(import.meta.url, (ctx) => quality(ctx, process.argv[2]));
