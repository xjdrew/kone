import type { Readiness } from "./model";

// Empty rules and built-in direct routing are ready without additional consent.
export function canEnable(report: Readiness) {
  return report.ready && report.blockers.length === 0;
}
