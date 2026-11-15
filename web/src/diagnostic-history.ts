import { targetHost } from "./domain";
import { connectionTarget } from "./diagnostic-request";

export interface DiagnosticHistoryEntry {
  mode: "connection" | "dns";
  target: string;
  tls: boolean;
  dnsName?: string;
  dnsType?: "A" | "AAAA";
  dnsComparison?: boolean;
}

export const diagnosticHistoryKey = "kone.diagnostic-history.v1";
const initialHistory: DiagnosticHistoryEntry[] = [
  { mode: "connection", target: "www.google.com:443", tls: true },
  { mode: "connection", target: "149.154.167.50:443", tls: false },
];

function normalizedTarget(value: string): string {
  const { host, port } = targetHost(value);
  return port ? `${host.includes(":") ? `[${host}]` : host}:${port}` : host;
}

export function rememberDiagnostic(
  history: DiagnosticHistoryEntry[],
  entry: DiagnosticHistoryEntry,
): DiagnosticHistoryEntry[] {
  const next = {
    ...entry,
    target: normalizedTarget(
      entry.mode === "connection" ? connectionTarget(entry.target) : entry.target,
    ),
    ...(entry.mode === "dns"
      ? { dnsName: entry.target.trim().toLowerCase().replace(/\.$/, ""), dnsComparison: true }
      : {}),
  };
  const identity = (item: DiagnosticHistoryEntry) =>
    JSON.stringify([
      item.mode,
      normalizedTarget(item.mode === "connection" ? connectionTarget(item.target) : item.target),
      item.mode === "dns" ? item.dnsName : "",
      item.mode === "dns" ? item.dnsType : "",
    ]);
  return [next, ...history.filter((item) => identity(item) !== identity(next))].slice(0, 20);
}

export function readDiagnosticHistory(raw: string | null): DiagnosticHistoryEntry[] {
  if (raw === null) return initialHistory.map((entry) => ({ ...entry }));
  try {
    const values: unknown = JSON.parse(raw);
    if (!Array.isArray(values)) throw new Error("Invalid history");
    const valid = values
      .slice(0, 20)
      .filter(
        (item): item is DiagnosticHistoryEntry =>
          item &&
          (item.mode === "connection" || item.mode === "dns") &&
          typeof item.target === "string" &&
          item.target.length <= 320 &&
          !/[\s/@?#\\]/.test(item.target) &&
          typeof item.tls === "boolean" &&
          (item.mode !== "dns" ||
            (item.dnsComparison === true &&
              typeof item.dnsName === "string" &&
              item.dnsName.length <= 253 &&
              ["A", "AAAA"].includes(item.dnsType))),
      );
    return valid.reduceRight(
      (history, entry) =>
        rememberDiagnostic(history, {
          mode: entry.mode,
          target: entry.target,
          tls: entry.tls,
          ...(entry.mode === "dns" ? { dnsName: entry.dnsName, dnsType: entry.dnsType } : {}),
        }),
      [] as DiagnosticHistoryEntry[],
    );
  } catch {
    return initialHistory.map((entry) => ({ ...entry }));
  }
}

export function diagnosticElapsed(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "—";
  return value < 1 ? "<1 ms" : `${value} ms`;
}
