import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";

test("just init reports an incompatible Go version with recovery instructions", { skip: process.platform === "win32" }, async t => {
  const bin = await mkdtemp(join(tmpdir(), "kone-init-"));
  t.after(() => rm(bin, { recursive: true, force: true }));
  await writeFile(join(bin, "go"), '#!/bin/sh\nif [ "$1" = version ]; then echo "go version go1.26.0 linux/amd64"; else echo unexpected dependency installation >&2; exit 99; fi\n', { mode: 0o755 });
  const result = spawnSync(process.env.KONE_JUST_BINARY || "just", ["init"], {
    cwd: fileURLToPath(new URL("../../", import.meta.url)),
    env: { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}` },
    encoding: "utf8", timeout: 20000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /Installed and ready:/);
  assert.match(result.stdout, /go: installed go version go1.26.0 linux\/amd64; requires Go 1.27.3/);
  assert.match(result.stderr, /KONE: Development setup needs attention.*just init/);
  assert.doesNotMatch(result.stdout + result.stderr, /Preparing Go modules|Preparing Web dependencies|unexpected dependency installation/);
});
