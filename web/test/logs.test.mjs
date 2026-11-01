import { test } from "node:test";
import assert from "node:assert/strict";
import { mergeLogs } from "../src/logs.js";

test("runtime logs deduplicate incremental pages without rounding cursor IDs", () => {
  const first = { id: "9007199254740992", message: "first" };
  const next = { id: "9007199254740993", message: "next" };
  assert.deepEqual(mergeLogs([first], { records: [first, next] }), [first, next]);
  assert.deepEqual(mergeLogs([first], { records: [next] }, true), [next]);
});

test("runtime log view retains only the latest 200 records", () => {
  const records = Array.from({ length: 250 }, (_, i) => ({ id: String(i) }));
  assert.deepEqual(mergeLogs([], { records }), records.slice(50));
  assert.deepEqual(mergeLogs([], {}), []);
});
