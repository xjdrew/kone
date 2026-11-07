import { test } from "node:test";
import assert from "node:assert/strict";
import { initialize } from "./init.mjs";

for (const failure of ["missing", "incompatible", "unusable"]) {
  test(`init explains ${failure} tools and still checks every tool`, async () => {
    const logs = [];
    const calls = [];
    await assert.rejects(initialize({
      log: line => logs.push(line),
      run(command, args) {
        calls.push([command, ...args]);
        if (command === "go") {
          if (failure === "incompatible") return "go version go1.26.0 linux/amd64";
          throw Object.assign(new Error("failure"), { code: failure === "missing" ? "ENOENT" : "EACCES" });
        }
        if (command === "bun") return "1.4.4";
        if (command === "node") return "v26.13.0";
        if (command === "just") return "just 1.59.0";
        if (args.includes("kone-npm")) throw new Error("npm unavailable");
        return `${command} version\nextra line`;
      },
    }), /Fix the tools listed above.*just init.*Project dependencies have not been installed/);
    const output = logs.join("\n");
    assert.match(output, /Installed and ready:\n    \[OK\] git: git version/);
    assert.match(output, /\[OK\] node: v26.13.0/);
    assert.match(output, /\[OK\] bash: bash version/);
    assert.doesNotMatch(output, /extra line/);
    assert.match(output, /Tools needing attention:/);
    assert.match(output, {
      missing: /go: not found on PATH; install Go 1.27.3/,
      incompatible: /go: installed go version go1.26.0 linux\/amd64; requires Go 1.27.3. Update this tool/,
      unusable: /go: could not check version; check that Go 1.27.3 runs/,
    }[failure]);
    assert.match(output, /npm: unavailable; install npm/);
    assert.equal(calls.length, 7, "only version probes run, including npm after the Go failure");
  });
}
