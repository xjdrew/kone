// Group only observed records: pagination/filtering never invents missing flows.
export function flowTarget(flow) {
  let value = String(flow.domain || flow.target || flow.destination || "").trim().toLowerCase();
  const bracket = value.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracket) value = bracket[1];
  else if (/^[^:]+:\d+$/.test(value)) value = value.replace(/:\d+$/, "");
  value = value.replace(/\.$/, "");
  if (value.includes(":")) {
    try { value = new URL(`http://[${value}]`).hostname.slice(1, -1); } catch {}
  }
  return value && value !== "未知目的" ? value : `未知目的 (${flow.id})`;
}

export function groupFlows(flows) {
  const groups = new Map();
  for (const flow of flows) {
    const target = flowTarget(flow);
    let group = groups.get(target);
    if (!group) {
      group = { target, flows: [], upload: 0, download: 0, upload_rate: 0, download_rate: 0, active: 0, failed: 0, latest: flow };
      groups.set(target, group);
    }
    group.flows.push(flow);
    for (const field of ["upload", "download", "upload_rate", "download_rate"]) group[field] += Math.max(0, Number(flow[field]) || 0);
    if (["active", "connecting"].includes(flow.status)) group.active++;
    if (flow.error || ["failed", "rejected"].includes(flow.status)) group.failed++;
    if (String(flow.started_at) > String(group.latest.started_at)) group.latest = flow;
  }
  return [...groups.values()].sort((a, b) => String(b.latest.started_at).localeCompare(String(a.latest.started_at)) || a.target.localeCompare(b.target));
}
