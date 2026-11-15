import type { Notice } from "./model";
export interface ClientError {
  code: string;
  status: number;
  details: Notice;
  uncertain?: boolean;
}
export interface ErrorEntry {
  id: number;
  error: ClientError;
  count: number;
  first: number;
  last: number;
}
let snapshot: { entries: ErrorEntry[]; active: number | null } = { entries: [], active: null };
let serial = 0;
const listeners = new Set<() => void>();
const seen = new WeakSet<object>();
export function globalError(error: ClientError) {
  return (
    !["session_changed", "unauthorized"].includes(error.code) &&
    (error.status === 0 || error.status >= 500 || error.code === "invalid_response")
  );
}
function publish() {
  for (const listener of listeners) listener();
}
export function recordError(error: ClientError) {
  if (!globalError(error) || seen.has(error)) return;
  seen.add(error);
  const now = Date.now();
  const previous = snapshot.entries.find(
    (e) =>
      e.error.code === error.code &&
      e.error.details.details === error.details.details &&
      e.error.uncertain === error.uncertain,
  );
  if (previous) {
    snapshot = {
      ...snapshot,
      entries: snapshot.entries.map((e) =>
        e.id === previous.id ? { ...e, count: e.count + 1, last: now } : e,
      ),
    };
  } else {
    const entry = { id: ++serial, error, count: 1, first: now, last: now };
    snapshot = { entries: [entry, ...snapshot.entries].slice(0, 100), active: entry.id };
  }
  publish();
}
export function dismissError() {
  snapshot = { ...snapshot, active: null };
  publish();
}
export function clearErrors() {
  snapshot = { entries: [], active: null };
  publish();
}
export function errorSnapshot() {
  return snapshot;
}
export function subscribeErrors(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
