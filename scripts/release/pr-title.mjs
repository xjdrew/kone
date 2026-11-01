import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function validatePullRequestTitle(title) {
  if (typeof title !== "string" || !/^(feat|fix|perf|refactor|docs|test|build|ci|chore|revert)(\([^\r\n()]+\))?!?: [^\r\n]+$/.test(title))
    throw new Error("Use a Conventional Commit PR title, e.g. feat: add a feature, fix: repair a bug, or feat!: breaking change. The final merge/squash subject must preserve it.");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url) && process.env.GITHUB_EVENT_NAME === "pull_request") {
  const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"));
  validatePullRequestTitle(event.pull_request?.title);
  console.log("PR title follows the automatic version policy.");
}
