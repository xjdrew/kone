import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export function buildJobName(sha) {
  if (!/^[a-f0-9]{40}$/.test(sha || "")) throw new Error("A complete build source SHA is required");
  return `Cross-build and Linux packages (${sha})`;
}

export function buildJob(pages, name) {
  const matches = pages.flatMap(page => page.jobs || []).filter(job => job.name === name || job.name?.endsWith(` / ${name}`));
  if (matches.length > 1) throw new Error("Ambiguous package-input build job");
  return matches[0];
}

export async function waitForBuild({ name, readJobs, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)), now = Date.now, timeout = 15 * 60_000, log = console.log }) {
  const started = now();
  let previous = "";
  while (now() - started < timeout) {
    const job = buildJob(await readJobs(), name);
    if (job?.status === "completed") {
      if (job.conclusion !== "success") throw new Error(`Package-input build did not succeed: ${job.conclusion}`);
      log(`Package input is ready (waited ${Math.round((now() - started) / 1000)}s).`);
      return;
    }
    const status = job?.status || "queued";
    if (status !== previous) { log(`Waiting for this source's current-attempt build: ${status}.`); previous = status; }
    await sleep(5000);
  }
  throw new Error("Timed out waiting for the current-attempt package input");
}

export async function main(env = process.env) {
  if (env.GITHUB_ACTIONS !== "true") throw new Error("Package-input waits are restricted to GitHub Actions");
  if (!/^[\w.-]+\/[\w.-]+$/.test(env.GITHUB_REPOSITORY || "") || !/^[1-9]\d*$/.test(env.GITHUB_RUN_ID || "") || !/^[1-9]\d*$/.test(env.GITHUB_RUN_ATTEMPT || ""))
    throw new Error("A repository, run and exact attempt are required");
  const name = buildJobName(env.KONE_BUILD_SHA);
  const endpoint = `repos/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}/attempts/${env.GITHUB_RUN_ATTEMPT}/jobs?per_page=100`;
  await waitForBuild({ name, readJobs: async () => JSON.parse(execFileSync("gh", ["api", "--paginate", "--slurp", endpoint], { encoding: "utf8", env, maxBuffer: 16 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] })) });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
