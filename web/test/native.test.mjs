import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const source = await readFile(
  new URL("../native/tray-darwin.js", import.meta.url),
  "utf8",
);
const sandbox = vm.createContext({});
new vm.Script(source).runInContext(sandbox);

test("native companion state has explicit booleans, bounded labels, and no executable interpolation", () => {
  const state = sandbox.normalizeTrayState({
    status: "paused\n'\"; run()",
    detail: "a\u0000" + "x".repeat(800),
    can_start: "true",
    can_pause: 1,
    can_diagnose: true,
  });
  assert.equal(state.status, "paused '\"; run()");
  assert.equal(state.detail.length, 500);
  assert.equal(state.detail.includes("\u0000"), false);
  assert.equal(state.can_start, false);
  assert.equal(state.can_pause, false);
  assert.equal(state.can_diagnose, true);
  assert.equal(sandbox.normalizeTrayState({}).status, "unknown");
  for (const value of [null, [], "state", 1]) {
    assert.throws(() => sandbox.normalizeTrayState(value));
  }
});
