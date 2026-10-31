import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
if (
  process.env.GITHUB_ACTIONS !== "true" ||
  process.env.GITHUB_REF !== "refs/heads/master" ||
  process.env.GITHUB_EVENT_NAME !== "workflow_dispatch"
)
  throw new Error("Withdrawal requires explicit master dispatch");
const event = JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH, "utf8"));
const tag = event.inputs?.tag || "";
const reason = event.inputs?.reason?.trim();
if (
  !/^(dev-[a-f0-9]{12}|v\d+\.\d+\.\d+)$/.test(tag) ||
  !reason ||
  reason.length > 2000
)
  throw new Error("Specify an existing KONE release and withdrawal reason");
const release = JSON.parse(
  execFileSync("gh", ["release", "view", tag, "--json", "body,url"], {
    encoding: "utf8",
  }),
);
await writeFile(
  "withdrawal.md",
  `Withdrawn release\n\nReason: ${reason}\n\nDo not install this version. Pause capture and manually roll back to a known-good verified release. The source tag is retained for traceability.\n\n---\n${release.body}`,
);
execFileSync(
  "gh",
  [
    "release",
    "edit",
    tag,
    "--draft=true",
    "--latest=false",
    "--notes-file",
    "withdrawal.md",
  ],
  { stdio: "inherit" },
);
console.log(`Withdrawn without deleting source tag: ${release.url}`);
