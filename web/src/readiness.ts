import type { Readiness } from "./model";

// Only explicit direct-only consent can resolve a blocker in the start dialog.
export function canEnable(report: Readiness) {
  return (
    (report.ready && report.blockers.length === 0) ||
    (report.direct_only &&
      report.blockers.length > 0 &&
      report.blockers.every((check) => check.code === "direct_only_confirmation"))
  );
}
