// Cursor IDs can exceed JavaScript's safe integer range. Keep them as strings.
export function mergeLogs(previous, page, reset = false, limit = 200) {
  const records = new Map((reset ? [] : previous).map((record) => [record.id, record]));
  for (const record of page.records || []) records.set(record.id, record);
  return [...records.values()].sort((a, b) => compareLogIDs(a.id, b.id)).slice(-limit);
}

export function compareLogIDs(a, b) {
  const left = String(a), right = String(b);
  if (/^\d+$/.test(left) && /^\d+$/.test(right)) {
    const x = BigInt(left), y = BigInt(right);
    return x < y ? -1 : x > y ? 1 : 0;
  }
  return left.localeCompare(right);
}

export function parseLogTimeRange(from = "", to = "") {
  const result = { from: "", to: "", error: "" };
  for (const [key, value] of [["from", from], ["to", to]]) {
    if (!value) continue;
    const date = new Date(value);
    if (!Number.isFinite(date.valueOf())) return { ...result, error: "请输入有效的开始和结束时间。" };
    const local = /^(\d{4,})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?$/.exec(value);
    if (local && [date.getFullYear(), date.getMonth() + 1, date.getDate(), date.getHours(), date.getMinutes(), date.getSeconds()].some((part, index) => part !== Number(local[index + 1] || 0)))
      return { ...result, error: "请输入有效的开始和结束时间。" };
    result[key] = date.toISOString();
  }
  if (result.from && result.to && result.from > result.to) result.error = "开始时间不能晚于结束时间。";
  return result;
}

export function logQuery(filters, cursor = {}) {
  const query = { limit: String(filters.logPageSize || 100), min_level: filters.logLevel || "info" };
  if (filters.logSource) query.source = filters.logSource;
  if (filters.logFrom) query.from = filters.logFrom;
  if (filters.logTo) query.to = filters.logTo;
  if (cursor.before != null) query.before = String(cursor.before);
  else if (cursor.after != null) query.after = String(cursor.after);
  return query;
}

export function logFieldPreview(attrs = {}, limit = 120) {
  const keys = [...new Set(["outbound", "stage", "target", "error", ...Object.keys(attrs)])].filter(key => Object.hasOwn(attrs, key));
  const full = keys.map(key => `${key}=${typeof attrs[key] === "string" ? attrs[key] : JSON.stringify(attrs[key])}`).join(" · ");
  const singleLine = full.replace(/\s+/g, " ");
  return { text: singleLine.length > limit ? singleLine.slice(0, Math.max(0, limit - 1)) + "…" : singleLine, full };
}
