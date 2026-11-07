import { query, request } from "./client";
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
  traffic: (values: TrafficFilter & { metric?: string }, signal?: AbortSignal) =>
    request<TrafficResponse>(`/traffic?${query({ ...values })}`, { signal }),
  flows: (values: TrafficFilter, signal?: AbortSignal) =>
    request<Traffic>(`/flows?${query({ ...values })}`, { signal }),
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
      };
      interfaces: { address: string; interface: string }[];
    }>("/dns/configuration", { signal }),
  dns: (signal?: AbortSignal) =>
    request<{ status: Record<string, Json>; queries: import("../model").DNSQuery[] }>("/dns", {
      signal,
    }),
  policy: () => request<PolicyState>("/policy"),
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
