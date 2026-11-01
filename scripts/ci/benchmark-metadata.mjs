import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import os from "node:os";

const output = (command, args) =>
  execFileSync(command, args, { encoding: "utf8" });
mkdirSync("baseline", { recursive: true });
writeFileSync(
  "baseline/environment.json",
  JSON.stringify(
    {
      sha: output("git", ["rev-parse", "HEAD"]).trim(),
      time: new Date().toISOString(),
      os: os.platform(),
      release: os.release(),
      arch: os.arch(),
      cpu: os.cpus()[0]?.model,
      logical_cpus: os.cpus().length,
      memory_bytes: os.totalmem(),
      concurrency: [1, 2],
      samples: 3,
      benchtime: "500ms",
      datasets: "deterministic fixtures in benchmark source at this SHA",
      network: "stack-independent core fixtures; actual TUN is sampled separately",
    },
    null,
    2,
  ) + "\n",
);
writeFileSync(
  "baseline/toolchain.txt",
  output("go", ["version"]) +
    output("go", ["env", "GOOS", "GOARCH", "GOVERSION", "CGO_ENABLED"]),
);
