import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const helper = fileURLToPath(new URL("../../scripts/ci/windows-test-arguments.ps1", import.meta.url));

test("PowerShell passes native test flags as literal argv for every stack without running KONE", async (t) => {
  if (process.platform !== "win32") { t.skip("Windows PowerShell process boundary"); return; }
  const directory = await mkdtemp(join(tmpdir(), "kone native argv "));
  t.after(async () => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true });
  });
  const receiver = join(directory, "harmless argument receiver.mjs");
  const harness = join(directory, "argument harness.ps1");
  const binary = join(directory, "binary path with spaces", "inert.test.exe");
  await mkdir(dirname(binary));
  // No executable is written at this path. Node receives the intended Go argv;
  // this tests the real PowerShell/native boundary without loading the app/TUN.
  await writeFile(receiver, "console.log(JSON.stringify(process.argv.slice(2)));\n");
  await writeFile(harness, `param([string] $Helper, [string] $Receiver, [string] $NodeExecutable, [string] $Binary)
$ErrorActionPreference = 'Stop'
. $Helper
foreach ($stack in @('system', 'gvisor', 'mixed')) {
  $arguments = Get-KoneWindowsTestArguments -Binary $Binary -Stack $stack
  & $NodeExecutable $Receiver @arguments
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
`);
  const result = spawnSync("pwsh", ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", harness, "-Helper", helper, "-Receiver", receiver, "-NodeExecutable", process.execPath, "-Binary", binary], { encoding: "utf8", timeout: 20000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  const calls = result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
  assert.equal(calls.length, 3);
  for (const [index, stack] of ["system", "gvisor", "mixed"].entries())
    assert.deepEqual(calls[index], ["tool", "test2json", "-t", "-p", "github.com/xjdrew/kone/test/integration", binary, "-test.run", `^TestSystemWindows(Wintun|IPv6Wintun)$/^${stack}$`, "-test.v=test2json", "-test.failfast", "-test.count=1", "-test.timeout", "12m"]);
});
