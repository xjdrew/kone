import { test } from "node:test";
import assert from "node:assert/strict";
import { mergeLogs, compareLogIDs, parseLogTimeRange, logQuery, logFieldPreview } from "../src/logs.js";

test("runtime logs deduplicate incremental pages without rounding cursor IDs", () => {
  const first = { id: "9007199254740992", message: "first" };
  const next = { id: "9007199254740993", message: "next" };
  assert.deepEqual(mergeLogs([first], { records: [first, next] }), [first, next]);
  assert.deepEqual(mergeLogs([first], { records: [next] }, true), [next]);
});

test("runtime log view retains only the latest 200 records", () => {
  const records = Array.from({ length: 250 }, (_, i) => ({ id: String(i) }));
  assert.deepEqual(mergeLogs([], { records }), records.slice(50));
  assert.deepEqual(mergeLogs([], {}), []);
});

test("paged log merges sort exact string cursors, replace duplicates and respect the selected page size", () => {
  const records = Array.from({ length: 240 }, (_, index) => ({ id: String(9007199254740991n + BigInt(index)), message: String(index) }));
  const updated = { ...records[239], message: "updated once" };
  const result = mergeLogs(records.slice(0, 120), { records: [...records.slice(120).reverse(), updated] }, false, 100);
  assert.deepEqual(result, [...records.slice(-100, -1), updated]);
  assert.equal(mergeLogs([], { records }, true, 50).length, 50);
  assert.equal(mergeLogs([], { records }, true, 200).length, 200);
});

test("log IDs compare numerically without losing precision or sorting 10 before 2", () => {
  const ids = ["18446744073709551615", "9007199254740993", "2", "10", "9007199254740992"];
  assert.deepEqual(ids.sort(compareLogIDs), ["2", "10", "9007199254740992", "9007199254740993", "18446744073709551615"]);
  assert.equal(compareLogIDs("9007199254740993", "9007199254740993"), 0);
});

test("log time ranges accept independent inclusive endpoints and reject invalid or inverted input", () => {
  assert.deepEqual(parseLogTimeRange(), { from: "", to: "", error: "" });
  assert.deepEqual(parseLogTimeRange("2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z"), { from: "2026-11-01T00:00:00.000Z", to: "2026-11-01T00:00:00.000Z", error: "" });
  assert.equal(parseLogTimeRange("", "2026-11-01T00:00:00Z").to, "2026-11-01T00:00:00.000Z");
  assert.equal(parseLogTimeRange("2026-11-01T00:00:00Z").from, "2026-11-01T00:00:00.000Z");
  assert.ok(parseLogTimeRange("not-a-time").error);
  assert.ok(parseLogTimeRange("2026-02-30T03:00").error, "an impossible local calendar date must not silently roll into March");
  assert.ok(parseLogTimeRange("2026-11-02T00:00:00Z", "2026-11-01T00:00:00Z").error);
});

test("log queries retain applied filters and emit only one exact before or after cursor", () => {
  assert.deepEqual(logQuery({}), { limit: "100", min_level: "info" });
  const filters = { logPageSize: 50, logLevel: "debug", logSource: "helper", logFrom: "2026-11-01T00:00:00.000Z", logTo: "2026-11-01T01:00:00.000Z" };
  const query = logQuery(filters, { before: "9007199254740993", after: "9007199254740992" });
  assert.deepEqual(query, { limit: "50", min_level: "debug", source: "helper", from: filters.logFrom, to: filters.logTo, before: "9007199254740993" });
  assert.equal(Object.hasOwn(query, "after"), false);
  assert.deepEqual(logQuery({ logPageSize: 200 }, { after: "9007199254740993" }), { limit: "200", min_level: "info", after: "9007199254740993" });
});

test("log field previews prioritize routing evidence, stay on one line and retain the complete value", () => {
  const attrs = { extra: { retries: 0, enabled: false }, error: "first line\nsecond line " + "detail ".repeat(40), target: "example.com:443", stage: "connect", outbound: "Office", empty: null };
  const preview = logFieldPreview(attrs);
  assert.match(preview.text, /^outbound=Office · stage=connect · target=example\.com:443 · error=first line second line/);
  assert.equal(preview.text.length, 120);
  assert.ok(preview.text.endsWith("…"));
  assert.doesNotMatch(preview.text, /[\r\n]/);
  assert.match(preview.full, /first line\nsecond line/);
  assert.match(preview.full, /extra=\{"retries":0,"enabled":false\}/);
  assert.match(preview.full, /empty=null/);
  assert.deepEqual(logFieldPreview({}), { text: "", full: "" });
});
