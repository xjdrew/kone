export type LocaleChoice = "auto" | string;
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export interface Notice {
  code: string;
  params?: Record<string, string | number>;
  details?: string;
  message?: string;
  request_id?: string;
}
export interface RemoteAccess {
  enabled: boolean;
  https: boolean;
  transport: "http" | "https";
  listen_address?: string;
  address?: string;
  fingerprint?: string;
  trust_required: boolean;
  interfaces: { address: string; interface: string }[];
  interfaces_unavailable?: boolean;
  urls: string[];
}
export interface RuntimeState {
  state: string;
  control_state: string;
  data_state: string;
  host: string;
  role: "admin" | "read";
  remote_session: boolean;
  local_access: boolean;
  password_configured: boolean;
  session_id: string;
  capabilities: string[];
  version: string;
  saved_version: number;
  running_version: number;
  confirmed_version: number;
  last_error: string;
  config_error: string;
  time: string;
  csrf_token: string;
  capture_locked: boolean;
  locale?: string;
  totals?: Totals;
}
export interface Rule {
  id: string;
  type: string;
  pattern?: string;
  outbound: string;
  source?: string;
  protocol?: string;
  ports?: number[];
  "expires-at"?: string;
}
export interface Outbound {
  id: string;
  name: string;
  url: string;
  enabled?: boolean;
  "udp-fallback"?: string;
  "check-enabled"?: boolean;
  "check-target"?: string;
  "check-tls"?: boolean;
}
export interface CoreConfig {
  tun: string;
  stack: string;
  "auto-route": boolean;
  "outbound-interface": string;
  network: string;
  "ipv6-network": string;
  "auto-route6": boolean;
}
export interface DNSRule {
  suffix: string;
  servers: string[];
  interface?: string;
  automatic?: boolean;
  unavailable?: boolean;
  reason?: string;
}
export interface DNSConfig {
  system: boolean;
  "listen-port": number;
  ttl: number;
  "packet-size": number;
  "read-timeout": number;
  "write-timeout": number;
  "history-limit": number;
  "history-retention": number;
  "cache-limit": number;
  servers?: string[];
  rules?: DNSRule[];
}
export interface Config {
  general: { "log-level": string; "log-format": string };
  core: CoreConfig;
  dns: DNSConfig;
  geoip: Record<string, Json>;
  outbounds: Outbound[];
  rules: Rule[];
  policy?: { mode: string; "ipv4-only"?: boolean; "udp-exception"?: boolean };
}
export interface Inbound {
  id: string;
  name: string;
  enabled: boolean;
}
export interface Document {
  version: number;
  running_version: number;
  confirmed_version: number;
  config: Config;
  inbound: Inbound;
  credential_state: Record<string, { configured: boolean }>;
  config_error: string;
  capture_locked: boolean;
  direct_only_confirmed: boolean;
  applied?: boolean;
  apply_error?: string;
}
export interface Credentials {
  action: "preserve" | "replace" | "clear";
  username?: string;
  password?: string;
  original_name?: string;
}
export interface SaveRequest {
  base_version: number;
  config: Config;
  inbound: Inbound;
  credential_actions?: Record<string, Credentials>;
  direct_only_confirmed?: boolean;
}
export interface Validation {
  valid: boolean;
  restart_required: boolean;
  issues: Notice[];
}
export interface Operation {
  target?: string;
  outbounds?: string[];
  protocol?: string;
  id: string;
  kind: string;
  status: string;
  stage: string;
  started_at: string;
  finished_at?: string;
  error?: string;
  result?: Json;
}
export interface Flow {
  id: string;
  session_id: string;
  config_version: number;
  inbound: string;
  protocol: string;
  source: string;
  destination: string;
  target: string;
  domain?: string;
  domain_source?: string;
  fake_ip?: string;
  real_destination?: string;
  process_name?: string;
  process_pid?: number;
  process_status?: string;
  rule_id: string;
  rule_name: string;
  rule_source: string;
  rule_order: number;
  expected_outbound: string;
  effective_outbound: string;
  attempted_outbound?: string;
  protected?: boolean;
  status: string;
  stage: string;
  error?: string;
  error_kind?: string;
  started_at: string;
  updated_at: string;
  ended_at?: string;
  upload: number;
  download: number;
}
export interface Totals {
  started: number;
  active: number;
  closed: number;
  failed: number;
  rejected: number;
  canceled: number;
  upload: number;
  download: number;
  bytes: number;
  upload_rate: number;
  download_rate: number;
}
export interface Traffic {
  frozen: boolean;
  session_id: string;
  timestamp: string;
  totals: Totals;
  records: Flow[];
  total: number;
  next_cursor?: string;
  anchor: string;
  capacity: number;
  dropped_details: number;
  truncated: boolean;
  anchor_expired: boolean;
}
export interface TrafficFilter {
  since?: string;
  until?: string;
  target?: string;
  protocol?: string;
  status?: string;
  outbound?: string;
  rule_id?: string;
  anchor?: string;
  cursor?: string;
  flow_ids?: string;
  path_ids?: string;
  limit?: string;
}
export interface SankeyNode {
  id: string;
  label: string;
  kind: string;
  column: number;
}
export interface SankeyLink {
  id: string;
  source: string;
  target: string;
  value: number;
  path_ids: string[];
}
export interface SankeyPath {
  id: string;
  inbound: string;
  rule_id: string;
  rule_name: string;
  effective_outbound: string;
  target: string;
  value: number;
  connections: number;
  failures: number;
  other: boolean;
  filter: Omit<TrafficFilter, "path_ids" | "flow_ids" | "limit"> & {
    path_ids?: string[];
    flow_ids?: string[];
    limit?: number;
  };
}
export interface Sankey {
  frozen: boolean;
  timestamp: string;
  metric: string;
  total: number;
  nodes: SankeyNode[];
  links: SankeyLink[];
  paths: SankeyPath[];
  anchor: string;
  truncated: boolean;
  anchor_expired: boolean;
}
export interface TrafficResponse {
  traffic: Traffic;
  sankey: Sankey;
}
export interface ReadinessCheck {
  id: string;
  code: string;
  status: string;
  severity: string;
  message: string;
  page: string;
  field?: string;
  action?: string;
}
export interface Readiness {
  ready: boolean;
  direct_only: boolean;
  direct_only_confirmed: boolean;
  checks: ReadinessCheck[];
  blockers: ReadinessCheck[];
  warnings: ReadinessCheck[];
}
export interface PolicyState {
  mode: string;
  outbound: string;
  explicit: boolean;
  version: number;
  ipv4_only: boolean;
  udp_exception: boolean;
  interface: string;
  interfaces: string[];
  ipv6_available: boolean;
  protection: { prefix: string; interface?: string; kind: string }[];
}
export interface PolicyRequest {
  base_version: number;
  mode: string;
  outbound: string;
  interface: string;
  ipv4_only: boolean;
  udp_exception: boolean;
  reject_udp: boolean;
  convert_custom: boolean;
}
export interface PolicyPlan extends Validation {
  config: Config;
  base_version: number;
  mode: string;
  udp: string;
  protection: PolicyState["protection"];
  preserved_rules: number;
  added_rules?: number;
}
export interface LogEntry {
  id: string;
  time: string;
  level: string;
  source: string;
  message: string;
  fields?: Record<string, Json>;
}
export interface LogPage {
  records: LogEntry[];
  next_cursor: string;
  oldest_cursor: string;
  gap: boolean;
  dropped: number;
  has_more: boolean;
  capacity: number;
  bytes: number;
}
export interface DNSQuery {
  id: string;
  time: string;
  name: string;
  type: string;
  source: string;
  scope: string;
  transport: string;
  upstream?: string;
  upstream_transport?: string;
  resolver_interface?: string;
  attempted_resolvers?: string[];
  route?: string;
  status: string;
  error?: string;
  duration_ms: number;
  cache: string;
  version: number;
  virtual_addresses?: string[];
  real_addresses?: string[];
}
export interface OutboundHealth {
  id: string;
  name: string;
  status: string;
  stage: string;
  message: string;
  connect_latency_ms?: number;
  checked_at?: string;
  expires_at?: string;
  duration_ms?: number;
  target?: string;
  automatic?: boolean;
  host?: Json;
  protocols?: Json;
  progress?: Json;
}
