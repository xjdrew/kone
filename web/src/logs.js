// Cursor IDs can exceed JavaScript's safe integer range. Keep them as strings.
export function mergeLogs(previous, page, reset = false) {
  const records = new Map((reset ? [] : previous).map((record) => [record.id, record]));
  for (const record of page.records || []) records.set(record.id, record);
  return [...records.values()].slice(-200);
}
