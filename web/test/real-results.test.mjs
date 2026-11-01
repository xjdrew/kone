import { test } from "node:test";
import assert from "node:assert/strict";
import { assertRealManagementResult } from "../e2e/assert-real-results.mjs";

test("genuine management browser gate rejects missing, skipped and flaky executions", () => {
  const report = (results, expectedStatus = "passed") => ({ suites: [{ suites: [{ specs: [{ title: "@real management", tests: [{ projectName: "chromium-1440x900", expectedStatus, results }] }] }] }] });
  assert.doesNotThrow(() => assertRealManagementResult(report([{ status: "passed" }])));
  assert.throws(() => assertRealManagementResult({ suites: [] }));
  assert.throws(() => assertRealManagementResult(report([])));
  assert.throws(() => assertRealManagementResult(report([{ status: "skipped" }], "skipped")));
  assert.throws(() => assertRealManagementResult(report([{ status: "failed" }, { status: "passed" }])));
});
