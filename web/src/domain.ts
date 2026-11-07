import type { Flow, Rule, Document, SaveRequest, Config, Credentials, SankeyPath } from "./model";

let formattingLocale = "en";
export function setFormattingLocale(locale: string) {
  formattingLocale = locale;
}
export function formatNumber(value: number, digits = 0) {
  return value.toLocaleString(formattingLocale, { maximumFractionDigits: digits });
}

export function formatBytes(value: number | undefined, rate = false): string {
  if (value === undefined || !Number.isFinite(value)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let unit = 0;
  let number = Math.max(value, 0);
  while (number >= 1024 && unit < units.length - 1) {
    number /= 1024;
    unit++;
  }
  return `${formatNumber(number, unit ? 1 : 0)} ${units[unit]}${rate ? "/s" : ""}`;
}
export function timestamp(value?: string): string {
  if (!value) return "—";
  const time = new Date(value);
  return Number.isNaN(time.getTime()) ? "—" : time.toLocaleString(formattingLocale);
}
export function targetHost(target: string): { host: string; port?: number } {
  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(target.trim());
  const ipv4OrDomain = /^([^:]+):(\d+)$/.exec(target.trim());
  const match = bracketed || ipv4OrDomain;
  let host = (match?.[1] ?? target.trim()).toLowerCase().replace(/\.$/, "");
  if (host.includes(":")) {
    try {
      host = new URL(`http://[${host}]/`).hostname.slice(1, -1);
    } catch {
      /* The server validates malformed addresses. */
    }
  }
  return {
    host,
    port: match?.[2] ? Number(match[2]) : undefined,
  };
}
export function exactRule(target: string, protocol?: string): Rule {
  const { host, port } = targetHost(target);
  const ipv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  const ipv6 = host.includes(":");
  return {
    id: crypto.randomUUID(),
    type: ipv4 ? "IP-CIDR" : ipv6 ? "IP-CIDR6" : "DOMAIN",
    pattern: ipv4 ? `${host}/32` : ipv6 ? `${host}/128` : host,
    source: "one-click",
    outbound: "direct",
    ...(["tcp", "udp"].includes(protocol ?? "") ? { protocol } : {}),
    ...(port && port <= 65535 ? { ports: [port] } : {}),
  };
}
export function flowTarget(flow: Flow): string {
  const address = flow.domain
    ? flow.target || flow.destination
    : flow.real_destination || flow.target || flow.destination;
  if (!flow.domain && flow.fake_ip && targetHost(address).host === targetHost(flow.fake_ip).host)
    return "";
  const port = targetHost(address).port ?? targetHost(flow.destination).port;
  // Observed domain takes priority over a synthetic destination; preserve the
  // transport scope so a one-click rule cannot silently grow to every port.
  const host = targetHost(flow.domain || address).host;
  return port ? `${host.includes(":") ? `[${host}]` : host}:${port}` : host;
}
export interface FlowGroup {
  key: string;
  target: string;
  flows: Flow[];
  upload: number;
  download: number;
  active: number;
  failed: number;
}
export function groupFlows(flows: Flow[]): FlowGroup[] {
  const groups = new Map<string, FlowGroup>();
  for (const flow of flows) {
    const target = targetHost(flow.domain || flow.target || flow.destination).host;
    const key = target;
    let group = groups.get(key);
    if (!group) {
      group = { key, target, flows: [], upload: 0, download: 0, active: 0, failed: 0 };
      groups.set(key, group);
    }
    group.flows.push(flow);
    group.upload += flow.upload;
    group.download += flow.download;
    group.active += flow.status === "active" ? 1 : 0;
    group.failed += ["failed", "rejected"].includes(flow.status) ? 1 : 0;
  }
  return [...groups.values()];
}
export function saveRequest(
  document: Document,
  config: Config,
  credentials?: Record<string, Credentials>,
): SaveRequest {
  return {
    base_version: document.version,
    inbound: structuredClone(document.inbound),
    config,
    credential_actions:
      credentials ??
      Object.fromEntries(
        document.config.outbounds.map((outbound) => [
          outbound.name,
          { action: "preserve" as const },
        ]),
      ),
  };
}
export function addPreciseRule(config: Config, rule: Rule): Config {
  const next = structuredClone(config);
  const existing = next.rules.findIndex(
    (item) =>
      item.type === rule.type &&
      item.pattern === rule.pattern &&
      (item.protocol ?? "") === (rule.protocol ?? "") &&
      (item["expires-at"] ?? "") === (rule["expires-at"] ?? "") &&
      JSON.stringify(item.ports ?? []) === JSON.stringify(rule.ports ?? []),
  );
  if (existing >= 0) next.rules[existing] = { ...next.rules[existing], outbound: rule.outbound };
  else next.rules.unshift(rule);
  return next;
}
export function renamedOutbound(config: Config, oldName: string, newName: string): Config {
  const next = structuredClone(config);
  next.rules = next.rules.map((rule) =>
    rule.outbound === oldName ? { ...rule, outbound: newName } : rule,
  );
  return next;
}

export function pathDrill(paths: SankeyPath[], anchor: string) {
  return {
    anchor,
    path_ids: [...new Set(paths.flatMap((path) => path.filter.path_ids || [path.id]))].join(","),
    flow_ids: [...new Set(paths.flatMap((path) => path.filter.flow_ids || []))].join(","),
    window_start: paths[0]?.filter.since,
    window_end: paths[0]?.filter.until,
  };
}
