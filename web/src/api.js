export class ApiError extends Error {
  constructor(message, status = 0, details = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.details = details;
  }
}

export function explainError(message) {
  return {
    "enable the TUN inbound before starting capture": "请先在“入站”启用 TUN 入口并保存，再启用接管。",
    "Current management password is incorrect": "当前管理密码不正确，请重新输入。",
    "Management session or password changed; sign in again": "管理会话或密码已变更，请重新登录。",
    "Use matching passwords of at least 8 characters and at most 128 UTF-8 bytes": "两次密码需一致，至少 8 个字符，UTF-8 长度不超过 128 字节。",
    "Clear the interrupted startup record, then run preflight before enabling capture": "上次启动在配置网络前中断。请前往“设置与恢复”点击“检查并恢复”，清除中断记录后重新预检。",
    "Clear the completed recovery record, then run preflight before enabling capture": "上次接管的 TUN 已不存在。请前往“设置与恢复”点击“检查并恢复”，确认清除恢复记录后重新预检。",
    "Startup stopped before device ownership was recorded; no capture network settings were applied": "上次启动在记录设备所有权前中断，尚未应用接管网络设置。",
    "The recorded transient interface is absent": "上次接管记录的临时 TUN 设备已不存在。",
    "Device-scoped capture routes were released with the absent transient interface": "依附于该临时 TUN 的接管路由已随设备释放。",
    "A program-scoped firewall exception may remain; it is preserved because its ownership cannot be verified and does not capture traffic without the absent TUN": "可能仍有程序防火墙例外。因无法验证所有权，KONE 会保留它；TUN 已不存在，该例外不会接管流量。",
    "Inspect the remaining interface and external network changes on this host before retrying": "接管记录对应的设备名称或索引仍存在，请先检查本机设备与网络变更，再重试恢复。",
    "Inspect the previous capture on this host; KONE will not delete an interface with uncertain ownership": "无法确认旧接管设备的所有权，请先检查本机设备；KONE 不会删除所有权不明的接口。",
  }[message] || message;
}

export function targetWithPort(value, port) {
  const target = String(value).trim();
  if (/^\[[^\]]+\]:\d+$/.test(target) || /^[^:]+:\d+$/.test(target))
    return target;
  if (/^\[[^\]]+\]$/.test(target)) return `${target}:${port}`;
  return target.includes(":") ? `[${target}]:${port}` : `${target}:${port}`;
}

// GET requests stay below the control server's request-header budget. Flow IDs
// identify exact graph contributors, so large queries can omit redundant paths.
export function flowQueryChunks(base, pathIDs, flowIDs) {
  const paths = [...new Set(pathIDs)];
  const ids = [...new Set(flowIDs)].slice(0, 5000);
  const pathQuery = paths.join(",");
  if (!ids.length) return [{ ...base, path_ids: pathQuery, limit: "500" }];
  const result = [];
  for (let offset = 0; offset < ids.length; offset += 100) {
    const query = {
      ...base,
      flow_ids: ids.slice(offset, offset + 100).join(","),
      limit: "500",
    };
    if (
      new URLSearchParams({ ...query, path_ids: pathQuery }).toString().length <
      8000
    )
      query.path_ids = pathQuery;
    result.push(query);
  }
  return result;
}

let bearer = "";
let csrf = "";
let sessionEpoch = 0;
export function invalidateSession({ clear = false } = {}) {
  sessionEpoch++;
  if (clear) { bearer = ""; csrf = ""; }
}
export function setSession(data = {}) {
  csrf = data.csrf_token || data.csrfToken || csrf;
  if (data.token) bearer = data.token;
}

export async function request(path, method = "GET", body, options = {}) {
  const epoch = sessionEpoch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeout || 15000);
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  if (csrf && method !== "GET") headers["X-CSRF-Token"] = csrf;
  if (method !== "GET")
    headers["X-Request-ID"] = options.requestId || crypto.randomUUID();
  Object.assign(headers, options.headers || {});
  try {
    const response = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: "same-origin",
      signal: controller.signal,
      body:
        body === undefined
          ? undefined
          : options.rawBody
            ? body
            : JSON.stringify(body),
      cache: "no-store",
    });
    let data = {};
    if (response.status !== 204) {
      try {
        data =
          response.ok && options.responseType === "text"
            ? await response.text()
            : await response.json();
      } catch {
        throw new ApiError("服务返回了无法读取的响应。", response.status);
      }
    }
    // Responses from an earlier login must neither restore its CSRF token nor
    // reach callers that could restore private UI state after logout.
    if (epoch !== sessionEpoch)
      throw new ApiError("管理会话已变更，请重新执行操作。", 0, { session_changed: true });
    if (!response.ok)
      throw new ApiError(
        explainError(data.error?.message ||
          data.message ||
          (typeof data.error === "string" ? data.error : "操作未完成。")),
        response.status,
        data.error || data,
      );
    if (typeof data === "object") setSession(data);
    return data;
  } catch (error) {
    if (epoch !== sessionEpoch)
      throw new ApiError("管理会话已变更，请重新执行操作。", 0, { session_changed: true });
    if (error.name === "AbortError")
      throw new ApiError(
        "请求已超时，操作可能仍在主机上执行。请先刷新状态，勿重复提交。",
        0,
        { uncertain: method !== "GET" },
      );
    if (error instanceof ApiError) throw error;
    throw new ApiError("无法连接 KONE 主机，请检查连接后重试。", 0);
  } finally {
    clearTimeout(timer);
  }
}

export async function bootstrap() {
  const params = new URLSearchParams(location.hash.slice(1));
  const token = params.get("token");
  if (token) {
    const page = params.get("page") === "diagnostics" ? "diagnostics" : "home";
    // Remove bootstrap credentials before creating links or making requests.
    history.replaceState(
      null,
      "",
      `${location.pathname}${location.search}#${page}`,
    );
    bearer = token;
    try {
      const session = await request("/session", "POST", { token });
      if (session.setup_required) return { ...session, setup_authorized: true, authenticated: false };
    } finally {
      // One-use bootstrap credentials must never shadow a newly paired cookie,
      // including when their initial exchange expired or was rejected.
      bearer = "";
    }
  }
  return request("/state");
}

export const endpoints = {
  state: () => request("/state"),
  readiness: () => request("/readiness"),
  auth: () => request("/auth"),
  passwordLogin: (password) => request("/session", "POST", { password }),
  setPassword: (body) => request("/auth/password", "POST", body),
  changePassword: (body) => request("/auth/password", "PUT", body),
  logout: () => request("/session/logout", "POST", {}),
  outboundHealth: () => request("/outbounds/health"),
  outboundTest: (body) => request("/outbounds/test", "POST", body),
  config: () => request("/config"),
  validate: (body) => request("/config/validate", "POST", body),
  save: (body) => request("/config", "PUT", body),
  apply: (body) => request("/config/apply", "POST", body),
  undo: (body) => request("/config/undo", "POST", body),
  lifecycle: (action) => request(`/lifecycle/${action}`, "POST", {}),
  traffic: (query) => request(`/traffic?${new URLSearchParams(query)}`),
  flows: (query) => request(`/flows?${new URLSearchParams(query || {})}`),
  flow: (id) => request(`/flows/${encodeURIComponent(id)}`),
  dns: () => request("/dns"),
  simulate: (body) => request("/rules/simulate", "POST", body),
  diagnostics: () => request("/diagnostics"),
  logs: (query) => request(`/logs?${new URLSearchParams(query || {})}`),
  diagnose: (body) => request("/diagnostics", "POST", body),
  cancel: (id) =>
    request(`/diagnostics/${encodeURIComponent(id)}/cancel`, "POST", {}),
  sessions: () => request("/sessions"),
  pair: (body) => request("/pairing", "POST", body),
  operation: (id) => request(`/operations/${encodeURIComponent(id)}`),
  lan: () => request("/access/lan"),
  revoke: (id) =>
    request(`/sessions/${encodeURIComponent(id)}/revoke`, "POST", {}),
  login: (code) => request("/session", "POST", { pairing_code: code }),
};

const lookup = (item, ...keys) => {
  for (const key of keys) if (item?.[key] !== undefined) return item[key];
  return undefined;
};
export function normalizeFlow(item = {}) {
  const start = lookup(
    item,
    "started_at",
    "started",
    "Started",
    "start",
    "StartTime",
  );
  const end = lookup(item, "ended_at", "ended", "Ended", "EndTime");
  return {
    ...item,
    id: String(lookup(item, "id", "ID") || ""),
    protocol: String(
      lookup(item, "protocol", "Protocol", "network", "Network") || "unknown",
    ).toLowerCase(),
    source: lookup(item, "source", "Source", "src", "Src") || "未知来源",
    target:
      lookup(
        item,
        "target",
        "Target",
        "domain",
        "Domain",
        "hostname",
        "Hostname",
        "destination",
        "Destination",
      ) || "未知目的",
    destination:
      lookup(item, "destination", "Destination", "target", "Target") || "",
    domain: lookup(item, "domain", "Domain", "hostname", "Hostname") || "",
    real_ip: lookup(item, "real_destination", "real_ip", "RealIP") || "",
    virtual_ip: lookup(item, "fake_ip", "virtual_ip", "VirtualIP") || "",
    inbound:
      lookup(item, "inbound", "Inbound", "inbound_id", "InboundID") || "TUN",
    rule_id: lookup(item, "rule_id", "RuleID", "rule", "Rule") || "default",
    rule:
      lookup(
        item,
        "rule_name",
        "RuleName",
        "rule",
        "Rule",
        "rule_id",
        "RuleID",
      ) || "默认策略",
    expected_outbound:
      lookup(
        item,
        "expected_outbound",
        "ExpectedOutbound",
        "outbound",
        "Outbound",
      ) || "未知",
    outbound:
      lookup(
        item,
        "effective_outbound",
        "EffectiveOutbound",
        "actual_outbound",
        "ActualOutbound",
        "outbound",
        "Outbound",
      ) || "未知",
    upload: Number(
      lookup(item, "upload", "Upload", "upload_bytes", "UploadBytes") || 0,
    ),
    download: Number(
      lookup(item, "download", "Download", "download_bytes", "DownloadBytes") ||
        0,
    ),
    upload_rate: Number(lookup(item, "upload_rate", "UploadRate") || 0),
    download_rate: Number(lookup(item, "download_rate", "DownloadRate") || 0),
    status: String(
      lookup(item, "status", "Status") || (end ? "closed" : "active"),
    ),
    stage: lookup(item, "stage", "Stage") || "",
    error: lookup(item, "error", "Error") || "",
    version:
      lookup(item, "version", "Version", "config_version", "ConfigVersion") ||
      "",
    started_at: start || "",
    ended_at: end || "",
  };
}

// A shortcut inherits only the exact observed endpoint and known protocol.
// Hostname and address validation remains shared with the configuration API.
export function exactRuleTarget(target, protocol = "") {
  let value = String(target).trim();
  const bracketed = value.match(/^\[([^\]]+)\](?::(\d+))?$/);
  const hostPort = value.match(/^([^:]+):(\d+)$/);
  const match = bracketed || hostPort;
  const port = Number(match?.[2]);
  if (match) value = match[1];
  const ipv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
  const ipv6 = value.includes(":");
  return {
    type: ipv4 ? "IP-CIDR" : ipv6 ? "IP-CIDR6" : "DOMAIN",
    pattern: ipv4 ? `${value}/32` : ipv6 ? `${value}/128` : value.toLowerCase().replace(/\.$/, ""),
    source: "one-click",
    ...(["tcp", "udp"].includes(protocol) ? { protocol } : {}),
    ...(Number.isInteger(port) && port >= 1 && port <= 65535 ? { ports: [port] } : {}),
  };
}

export function normalizeTraffic(data = {}) {
  if (data.traffic) data = { ...data.traffic, sankey: data.sankey };
  const rawFlows =
    lookup(
      data,
      "flows",
      "Flows",
      "connections",
      "Connections",
      "records",
      "Records",
    ) || [];
  return {
    ...data,
    frozen: data.frozen === true || data.sankey?.frozen === true,
    flows: rawFlows.map(normalizeFlow),
    at:
      lookup(
        data,
        "at",
        "At",
        "timestamp",
        "Timestamp",
        "captured_at",
        "CapturedAt",
      ) || "",
    session_id:
      lookup(data, "session_id", "SessionID", "session", "Session") || "",
    dropped: Number(
      lookup(data, "dropped", "Dropped", "dropped_details", "DroppedDetails") ||
        0,
    ),
    stats: lookup(data, "totals", "stats", "Stats", "summary", "Summary") || {},
  };
}
