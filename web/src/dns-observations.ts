import type { DNSQuery } from "./model";

export function groupBusinessDNSQueries(events: DNSQuery[]) {
  const groups = new Map<string, DNSQuery[]>();
  for (const event of events) {
    if (event.origin !== "business") continue;
    const name = event.name.toLowerCase().replace(/\.$/, "");
    const history = groups.get(name) ?? [];
    history.push(event);
    groups.set(name, history);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b, "en"))
    .map(([name, history]) => ({
      name,
      history: history.sort(
        (a, b) =>
          Date.parse(b.time) - Date.parse(a.time) ||
          b.id.localeCompare(a.id, "en", { numeric: true }),
      ),
    }));
}

export function dnsQueryAge(time: string, now: number) {
  const elapsed = Math.max(0, Math.floor((now - Date.parse(time)) / 1000));
  if (!Number.isFinite(elapsed)) return "—";
  if (elapsed < 60) return `${elapsed}s`;
  if (elapsed < 3600) return `${Math.floor(elapsed / 60)}m`;
  if (elapsed < 86400) return `${Math.floor(elapsed / 3600)}h`;
  return `${Math.floor(elapsed / 86400)}d`;
}

// Keep RDATA intact (including quoted TXT whitespace); omit owner/TTL/class in the table.
export function dnsAnswerLines(event: DNSQuery): string[] {
  const virtual = event.virtual_addresses ?? [];
  if (event.answers?.length)
    return event.answers.map((record) => {
      const answer = record.replace(/^\S+\s+\d+\s+\S+\s+/, "");
      const address = answer.match(/^(?:A|AAAA)\s+(\S+)$/)?.[1];
      if (address) return virtual.includes(address) ? `Fake-IP ${address}` : address;
      return answer;
    });
  return [
    ...virtual.map((address) => `Fake-IP ${address}`),
    ...(event.real_addresses ?? []).filter((address) => !virtual.includes(address)),
  ];
}
