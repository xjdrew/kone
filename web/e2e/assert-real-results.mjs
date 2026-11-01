import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function assertRealManagementResult(report) {
  const specs = [];
  const visit = (suite) => { specs.push(...(suite.specs || [])); for (const child of suite.suites || []) visit(child); };
  for (const suite of report.suites || []) visit(suite);
  const tests = specs.filter((spec) => spec.title.startsWith("@real ")).flatMap((spec) => spec.tests || []);
  if (tests.length !== 1 || tests[0].projectName !== "chromium-1440x900" || tests[0].expectedStatus !== "passed" || !tests[0].results?.length || tests[0].results.some((result) => result.status !== "passed")) {
    throw new Error("The genuine Chromium management journey must run and pass; empty, skipped or flaky results are rejected");
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assertRealManagementResult(JSON.parse(await readFile(process.argv[2], "utf8")));
  console.log("Genuine management browser journey: passed without skipping");
}
