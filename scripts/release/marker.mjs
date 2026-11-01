import { writeFile, mkdir } from "node:fs/promises";
import { requiredJobs, validSHA } from "./model.mjs";
const sha = validSHA(process.env.RELEASE_SHA);
await mkdir("verification", { recursive: true });
await writeFile(
  "verification/verification.json",
  JSON.stringify(
    {
      schema: 2,
      verified: true,
      sha,
      version: process.env.RELEASE_VERSION,
      run_id: process.env.GITHUB_RUN_ID,
      run_attempt: process.env.GITHUB_RUN_ATTEMPT,
      required_jobs: requiredJobs,
      ci_url: `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`,
    },
    null,
    2,
  ) + "\n",
);
