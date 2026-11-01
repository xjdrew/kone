import { test } from "node:test";
import assert from "node:assert/strict";
import { buildJobName, buildJob, main, waitForBuild } from "../../scripts/ci/wait-build.mjs";

const sha = "1234567890abcdef1234567890abcdef12345678";
const name = buildJobName(sha);
const success = { name, status: "completed", conclusion: "success" };

test("package input selects the exact source from all pages and rejects ambiguous jobs", () => {
  assert.equal(buildJob([{ jobs: [{ ...success, name: buildJobName("a".repeat(40)) }] }, { jobs: [{ ...success, name: `Verify ${sha} / ${name}` }] }], name)?.conclusion, "success");
  assert.equal(buildJob([{ jobs: [{ ...success, name: `${name} unrelated suffix` }] }], name), undefined);
  assert.throws(() => buildJob([{ jobs: [success] }, { jobs: [success] }], name), /Ambiguous/);
  for (const invalid of ["master", "../file", "A".repeat(40)]) assert.throws(() => buildJobName(invalid));
});

test("platform checks may start immediately, but packaging waits for a successful current-attempt build", async () => {
  let clock = 0, calls = 0;
  const messages = [];
  await waitForBuild({ name, now: () => clock, sleep: async ms => { clock += ms; }, log: value => messages.push(value), readJobs: async () => [{ jobs: ++calls < 3 ? [{ name, status: "in_progress" }] : [success] }] });
  assert.equal(calls, 3);
  assert.equal(clock, 10000);
  assert.equal(messages.length, 2, "only status changes and completion need progress output");
  for (const conclusion of ["failure", "cancelled", "skipped", "timed_out"])
    await assert.rejects(waitForBuild({ name, log: () => {}, readJobs: async () => [{ jobs: [{ ...success, conclusion }] }] }), /did not succeed/);
});

test("missing build evidence times out and local invocation never polls GitHub", async () => {
  let clock = 0;
  await assert.rejects(waitForBuild({ name, now: () => clock, timeout: 10000, sleep: async ms => { clock += ms; }, log: () => {}, readJobs: async () => [{ jobs: [] }] }), /Timed out/);
  await assert.rejects(main({}), /restricted to GitHub Actions/);
  await assert.rejects(main({ GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "bad repo" }), /repository, run and exact attempt/);
});
