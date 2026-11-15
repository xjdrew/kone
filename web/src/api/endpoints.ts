import { query, request } from "./client";
import { normalizeRuleTarget } from "../target-rule";
import type {
  Document,
  RuntimeState,
  SaveRequest,
  Validation,
  Operation,
  TrafficFilter,
  TrafficResponse,
  Traffic,
  Readiness,
  PolicyState,
  PolicyRequest,
  PolicyPlan,
  LogPage,
  OutboundHealth,
  Json,
} from "../model";

export interface Auth {
  local_access: boolean;
  local_session?: boolean;
  setup_required?: boolean;
  setup_authorized?: boolean;
  csrf_token?: string;
  locale?: string;
  password_configured?: boolean;
}

// Collection fields may arrive as null while talking to a helper-backed host.
const trafficRecords = (data: Traffic): Traffic => ({ ...data, records: data.records ?? [] });

export const api = {
  auth: (signal?: AbortSignal) => request<Auth>("/auth", { signal }),
  session: (body: object) =>
    request<{ csrf_token: string; setup_required?: boolean }>("/session", { method: "POST", body }),
  state: (signal?: AbortSignal) => request<RuntimeState>("/state", { signal }),
  document: (signal?: AbortSignal) => request<Document>("/config", { signal }),
  readiness: () => request<Readiness>("/readiness"),
  validate: (body: SaveRequest) =>
    request<Validation>("/config/validate", { method: "POST", body }),
  save: (body: SaveRequest) => request<Document>("/config", { method: "PUT", body }),
  lifecycle: (action: string, body: object = {}) =>
    request<Operation>(`/lifecycle/${action}`, { method: "POST", body }),
  apply: () => request<Operation>("/config/apply", { method: "POST", body: {} }),
  operation: (id: string, signal?: AbortSignal) =>
    request<Operation>(`/operations/${encodeURIComponent(id)}`, { signal }),
  operations: (signal?: AbortSignal) =>
    request<{ operations: Operation[] }>("/operations", { signal }),
  traffic: async (values: TrafficFilter & { metric?: string }, signal?: AbortSignal) => {
    const data = await request<TrafficResponse>(`/traffic?${query({ ...values })}`, { signal });
    return {
      traffic: trafficRecords(data.traffic),
      sankey: {
        ...data.sankey,
        nodes: data.sankey.nodes ?? [],
        links: data.sankey.links ?? [],
        paths: data.sankey.paths ?? [],
      },
    };
  },
  flows: (values: TrafficFilter, signal?: AbortSignal) =>
    request<Traffic>(`/flows?${query({ ...values })}`, { signal }).then(trafficRecords),
  flow: (id: string, signal?: AbortSignal) =>
    request<import("../model").Flow>(`/flows/${encodeURIComponent(id)}`, { signal }),
  dnsConfiguration: (signal?: AbortSignal) =>
    request<{
      running: boolean;
      defaults: { servers: string[]; source: string; public_fallback: boolean; warnings: string[] };
      status: {
        mode: string;
        listen_address: string;
        system_active: boolean;
        system_requested: boolean;
        fake_ip_pools?: {
          prefix: string;
          persistent: boolean;
          storage_bytes?: number;
          storage_limit?: number;
          used: number;
          capacity: number;
          warning: boolean;
          error?: string;
        }[];
        retired_fake_ip_pools?: string[];
      };
      interfaces: { address: string; interface: string }[];
    }>("/dns/configuration", { signal }),
  dns: (signal?: AbortSignal) =>
    request<{ status: Record<string, Json>; queries: import("../model").DNSQuery[] }>("/dns", {
      signal,
    }),
  policy: () => request<PolicyState>("/policy"),
  ruleTarget: (target: string, signal?: AbortSignal) =>
    request<import("../model").RuleTarget>(
      `/rules/target?target=${encodeURIComponent(normalizeRuleTarget(target))}`,
      { signal },
    ),
  policyPreview: (body: PolicyRequest) =>
    request<PolicyPlan>("/policy/preview", { method: "POST", body }),
  policyApply: (body: PolicyRequest) => request<Document>("/policy", { method: "PUT", body }),
  health: () => request<{ statuses: OutboundHealth[] }>("/outbounds/health"),
  diagnose: (body: object) => request<Operation>("/diagnostics", { method: "POST", body }),
  diagnoseDNS: (body: { name: string; type: string }) =>
    request<Operation>("/diagnostics/dns", { method: "POST", body }),
  cancel: (id: string) =>
    request<Json>(`/diagnostics/${encodeURIComponent(id)}/cancel`, { method: "POST", body: {} }),
  logs: (values: Record<string, string | undefined>, signal?: AbortSignal) =>
    request<LogPage>(`/logs?${query(values)}`, { signal }),
};
