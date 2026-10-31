export class ApiError extends Error {
  constructor(message, status = 0, details = {}) { super(message); this.name = 'ApiError'; this.status = status; this.details = details; }
}

let bearer = '';
let csrf = '';
export function setSession(data = {}) {
  csrf = data.csrf_token || data.csrfToken || csrf;
  if (data.token) bearer = data.token;
}

export async function request(path, method = 'GET', body, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeout || 15000);
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  if (csrf && method !== 'GET') headers['X-CSRF-Token'] = csrf;
  if (method !== 'GET') headers['X-Request-ID'] = options.requestId || crypto.randomUUID();
  try {
    const response = await fetch(`/api/v1${path}`, { method, headers, credentials: 'same-origin', signal: controller.signal, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store' });
    let data = {};
    if (response.status !== 204) {
      try { data = response.ok && options.responseType === 'text' ? await response.text() : await response.json(); } catch { throw new ApiError('服务返回了无法读取的响应。', response.status); }
    }
    if (!response.ok) throw new ApiError(data.error?.message || data.message || (typeof data.error === 'string' ? data.error : '操作未完成。'), response.status, data.error || data);
    if (typeof data === 'object') setSession(data);
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new ApiError('请求已超时，操作可能仍在主机上执行。请先刷新状态，勿重复提交。', 0, { uncertain: method !== 'GET' });
    if (error instanceof ApiError) throw error;
    throw new ApiError('无法连接 KONE 主机，请检查连接后重试。', 0);
  } finally { clearTimeout(timer); }
}

export async function bootstrap() {
  const params = new URLSearchParams(location.hash.slice(1));
  const token = params.get('token');
  if (token) {
    // Remove bootstrap credentials before creating links or making requests.
    history.replaceState(null, '', `${location.pathname}${location.search}#home`);
    bearer = token;
    await request('/session', 'POST', { token });
    // The bootstrap token is exchanged, not reused as an API session token.
    // Subsequent requests authenticate with the HttpOnly cookie and CSRF value.
    bearer = '';
  }
  return request('/state');
}

export const endpoints = {
  state: () => request('/state'), config: () => request('/config'),
  validate: body => request('/config/validate', 'POST', body),
  save: body => request('/config', 'PUT', body),
  apply: body => request('/config/apply', 'POST', body),
  undo: body => request('/config/undo', 'POST', body),
  lifecycle: action => request(`/lifecycle/${action}`, 'POST', {}),
  traffic: query => request(`/traffic?${new URLSearchParams(query)}`),
  flows: query => request(`/flows?${new URLSearchParams(query || {})}`),
  flow: id => request(`/flows/${encodeURIComponent(id)}`),
  dns: () => request('/dns'), simulate: body => request('/rules/simulate', 'POST', body),
  diagnostics: () => request('/diagnostics'), diagnose: body => request('/diagnostics', 'POST', body),
  cancel: id => request(`/diagnostics/${encodeURIComponent(id)}/cancel`, 'POST', {}),
  sessions: () => request('/sessions'), pair: body => request('/pairing', 'POST', body),
  operation: id => request(`/operations/${encodeURIComponent(id)}`),
  lan: () => request('/access/lan'),
  revoke: id => request(`/sessions/${encodeURIComponent(id)}/revoke`, 'POST', {}),
  login: code => request('/session', 'POST', { pairing_code: code }),
};

const lookup = (item, ...keys) => { for (const key of keys) if (item?.[key] !== undefined) return item[key]; return undefined; };
export function normalizeFlow(item = {}) {
  const start = lookup(item, 'started_at', 'started', 'Started', 'start', 'StartTime');
  const end = lookup(item, 'ended_at', 'ended', 'Ended', 'EndTime');
  return {
    ...item,
    id: String(lookup(item, 'id', 'ID') || ''),
    protocol: String(lookup(item, 'protocol', 'Protocol', 'network', 'Network') || 'unknown').toLowerCase(),
    source: lookup(item, 'source', 'Source', 'src', 'Src') || '未知来源',
    target: lookup(item, 'target', 'Target', 'domain', 'Domain', 'hostname', 'Hostname', 'destination', 'Destination') || '未知目的',
    destination: lookup(item, 'destination', 'Destination', 'target', 'Target') || '',
    domain: lookup(item, 'domain', 'Domain', 'hostname', 'Hostname') || '',
    real_ip: lookup(item, 'real_destination', 'real_ip', 'RealIP') || '',
    virtual_ip: lookup(item, 'fake_ip', 'virtual_ip', 'VirtualIP') || '',
    inbound: lookup(item, 'inbound', 'Inbound', 'inbound_id', 'InboundID') || 'TUN',
    rule_id: lookup(item, 'rule_id', 'RuleID', 'rule', 'Rule') || 'default',
    rule: lookup(item, 'rule_name', 'RuleName', 'rule', 'Rule', 'rule_id', 'RuleID') || '默认策略',
    expected_outbound: lookup(item, 'expected_outbound', 'ExpectedOutbound', 'outbound', 'Outbound') || '未知',
    outbound: lookup(item, 'effective_outbound', 'EffectiveOutbound', 'actual_outbound', 'ActualOutbound', 'outbound', 'Outbound') || '未知',
    upload: Number(lookup(item, 'upload', 'Upload', 'upload_bytes', 'UploadBytes') || 0),
    download: Number(lookup(item, 'download', 'Download', 'download_bytes', 'DownloadBytes') || 0),
    upload_rate: Number(lookup(item, 'upload_rate', 'UploadRate') || 0),
    download_rate: Number(lookup(item, 'download_rate', 'DownloadRate') || 0),
    status: String(lookup(item, 'status', 'Status') || (end ? 'closed' : 'active')),
    stage: lookup(item, 'stage', 'Stage') || '', error: lookup(item, 'error', 'Error') || '',
    version: lookup(item, 'version', 'Version', 'config_version', 'ConfigVersion') || '',
    started_at: start || '', ended_at: end || '',
  };
}

export function normalizeTraffic(data = {}) {
  if (data.traffic) data = { ...data.traffic, sankey: data.sankey };
  const rawFlows = lookup(data, 'flows', 'Flows', 'connections', 'Connections', 'records', 'Records') || [];
  return { ...data, flows: rawFlows.map(normalizeFlow),
    at: lookup(data, 'at', 'At', 'timestamp', 'Timestamp', 'captured_at', 'CapturedAt') || new Date().toISOString(),
    session_id: lookup(data, 'session_id', 'SessionID', 'session', 'Session') || '',
    dropped: Number(lookup(data, 'dropped', 'Dropped', 'dropped_details', 'DroppedDetails') || 0),
    stats: lookup(data, 'totals', 'stats', 'Stats', 'summary', 'Summary') || {},
  };
}
