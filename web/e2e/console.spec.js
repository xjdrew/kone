import { test, expect } from '@playwright/test';

const start = '2026-11-01T00:00:00Z';
const end = '2026-11-01T00:00:01Z';
function fixture() {
  const records = [
    { id: 'flow-a', session_id: 'traffic-session', config_version: 1, inbound: 'tun-main', protocol: 'tcp', source: '192.168.50.2:50000', destination: '198.18.0.2:443', target: 'example.com:443', domain: 'example.com', domain_source: 'fake-ip', fake_ip: '198.18.0.2', process_status: 'remote', rule_id: 'rule-1', rule_name: 'example.com', expected_outbound: 'Proxy A', effective_outbound: 'Proxy A', status: 'active', started_at: start, upload: 1000, download: 3000 },
    { id: 'flow-b', session_id: 'traffic-session', config_version: 1, inbound: 'tun-main', protocol: 'udp', source: '192.168.50.3:50001', destination: '192.168.50.1:123', target: '192.168.50.1:123', process_status: 'remote', rule_id: 'default', rule_name: '默认直连', expected_outbound: 'direct', effective_outbound: 'direct', status: 'active', started_at: start, upload: 100, download: 100 },
    { id: 'flow-f', session_id: 'traffic-session', config_version: 1, inbound: 'tun-main', protocol: 'udp', source: '192.168.50.2:50002', target: 'unsupported.example:443', destination: '198.18.0.3:443', domain: 'unsupported.example', expected_outbound: 'Proxy A', effective_outbound: '', status: 'failed', stage: 'capability', error: 'Proxy A does not support UDP; fallback is not configured', started_at: start, ended_at: end, upload: 0, download: 0 },
  ];
  const config = { version: 1, inbound: { id: 'tun-main', name: '家庭网关', enabled: false }, config: { general: { 'manager-addr': '127.0.0.1:9200', 'log-level': 'info', 'log-format': 'text' }, core: { network: '10.192.0.1/16', stack: 'system', tun: '', 'auto-route': false, 'outbound-interface': '' }, dns: { servers: [], 'listen-port': 53, ttl: 600, 'read-timeout': 5, 'write-timeout': 5, 'packet-size': 4096, 'history-limit': 512, 'history-retention': 3600, 'cache-limit': 1024 }, outbounds: [{ name: 'Proxy A', url: 'http://REDACTED:REDACTED@127.0.0.1:18080' }], rules: [{ id: 'rule-1', type: 'DOMAIN', pattern: 'example.com', outbound: 'Proxy A' }, { type: 'FINAL', outbound: 'direct' }] } };
  return { records, config, role: 'admin', offline: false, conflict: false, empty: false, requests: [], writes: [], expired: false, state: 'paused' };
}

async function mount(page, options = {}) {
  const data = Object.assign(fixture(), options);
  await page.route('**/api/v1/**', async route => {
    const request = route.request(); const url = new URL(request.url()); const path = url.pathname.slice('/api/v1'.length); const method = request.method();
    data.requests.push({ path, method, query: Object.fromEntries(url.searchParams), headers: request.headers(), body: request.postDataJSON() });
    if (data.offline) return route.abort('connectionfailed');
    const respond = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    const body = request.postDataJSON();
    if (path === '/session') return respond({ role: data.role, csrf_token: 'test-csrf', session_id: 'test-session' });
    if (options.unauthorized) return respond({ error: { message: 'Authorization expired' } }, 401);
    if (method !== 'GET') { data.writes.push({ path, body }); if (data.role === 'read') return respond({ error: { message: 'This session is read-only' } }, 403); }
    if (path === '/state') return respond({ csrf_token: 'test-csrf', state: data.state, data_state: data.state, control_state: 'ready', host: 'Gateway · 测试主机', role: data.role, capabilities: { stacks: ['system', 'mixed'], tcp: true, udp_direct: true, proxy_udp_schemes: ['socks5'], ipv6: false }, version: 'test-version', session_id: 'test-session', saved_version: data.config.version, running_version: 1 });
    if (path === '/config' && method === 'GET') return respond(data.config);
    if (path === '/config/validate') return respond({ valid: true, restart_required: false, issues: [] });
    if (path === '/config' && method === 'PUT') {
      if (data.conflict) return respond({ error: { message: 'Version conflict' } }, 409);
      data.config = { version: data.config.version + 1, config: body.config, inbound: body.inbound }; return respond(data.config);
    }
    if (path === '/config/apply') return respond({ status: 'completed' });
    if (path === '/config/undo') return respond(data.config);
    if (path === '/traffic' || path === '/flows') {
      let records = data.empty ? [] : data.records;
      if (url.searchParams.get('protocol')) records = records.filter(record => record.protocol === url.searchParams.get('protocol'));
      if (url.searchParams.get('flow_ids')) records = records.filter(record => url.searchParams.get('flow_ids').split(',').includes(record.id));
      if (path === '/flows' && data.expired) return respond({ error: { message: 'Original detail expired' } }, 410);
      const totals = { upload: records.reduce((sum, r) => sum + r.upload, 0), download: records.reduce((sum, r) => sum + r.download, 0), upload_rate: records.length ? 250 : 0, download_rate: records.length ? 650 : 0, active: records.filter(r => r.status === 'active').length, failed: records.filter(r => r.status === 'failed').length, rejected: 0 };
      const traffic = { records, totals, timestamp: end, session_id: 'traffic-session', anchor: 'traffic-session:3', dropped_details: 0, recording: true, capacity: 4096 };
      if (path === '/flows') return respond(traffic);
      const metric = url.searchParams.get('metric'); const cumulative = metric === 'cumulative';
      const paths = records.filter(r => r.upload + r.download > 0).map(r => ({ id: `path-${r.id}`, inbound: r.inbound, rule_id: r.rule_id, rule_name: r.rule_name, effective_outbound: r.effective_outbound, target: r.target, upload: r.upload, download: r.download, value: cumulative ? r.upload + r.download : metric === 'upload' ? r.upload / 4 : metric === 'download' ? r.download / 4 : (r.upload + r.download) / 4, connections: 1, filter: { anchor: traffic.anchor, path_ids: [`path-${r.id}`], flow_ids: [r.id], since: start, until: end } }));
      return respond({ traffic, sankey: { session_id: traffic.session_id, timestamp: end, scope: 'business', metric, unit: cumulative ? 'B' : 'B/s', window_start: start, window_end: end, anchor: traffic.anchor, paths, failures: totals.failed, total: paths.reduce((sum, p) => sum + p.value, 0) } });
    }
    if (path === '/dns') return respond({ status: { automatic: true, servers: ['192.168.50.1:53'], tcp: true, history_dropped: 0 }, queries: [{ id: 'q-1', time: end, name: 'example.com.', type: 'A', scope: 'dns', transport: 'udp', upstream: '192.168.50.1:53', upstream_transport: 'udp', status: 'NOERROR', cache: 'miss', duration_ms: 4, virtual_addresses: ['198.18.0.2'], real_addresses: [] }] });
    if (path === '/diagnostics' && method === 'GET') return respond({ operations: [] });
    if (path === '/diagnostics') return respond({ id: 'diag-1', status: 'running' }, 202);
    if (path === '/sessions') return respond({ sessions: [{ id: 'phone-1', role: 'read', expires: end }] });
    if (path === '/access/lan') return respond({ enabled: false, transport: 'https', trust_required: true });
    if (path === '/pairing') return respond({ code: '12345678', role: body.role, expires: end });
    if (path === '/rules/simulate') return respond({ outbound: 'Proxy A', rule: 'rule-1', protocol: 'tcp', source: 'saved-config' });
    if (path === '/lifecycle/preflight') return respond({ valid: true, ok: true, checks: [{ name: 'configuration', ok: true }] });
    if (path.startsWith('/lifecycle/')) { data.state = path.endsWith('pause') ? 'paused' : 'running'; return respond({ status: 'completed', message: 'Operation completed' }); }
    if (path === '/privacy/clear') { data.records = []; return respond({ cleared: true, network_changed: false }); }
    if (path === '/export') return route.fulfill({ contentType: 'application/toml', body: '[core]\nstack = "system"\n' });
    return respond({ error: { message: `Unimplemented test route: ${path}` } }, 404);
  });
  await page.goto('/#token=local-test-only');
  await expect(page.getByRole('heading', { name: '首页', exact: true })).toBeVisible();
  await expect(page.locator('#runtime-status')).toContainText('已暂停');
  return data;
}

test('uses embedded offline assets, removes token fragment, and renders native measured paths', async ({ page }, testInfo) => {
  const external = []; page.on('request', request => { if (!request.url().startsWith('http://127.0.0.1:4173/')) external.push(request.url()); });
  const data = await mount(page);
  await expect(page).toHaveURL(/#home$/);
  await expect(page.locator('.sankey-node')).toHaveCount(7);
  await expect(page.locator('.sankey-node').filter({ hasText: 'example.com:443' })).toBeVisible();
  expect(data.requests.find(r => r.path === '/traffic').query.metric).toBe('total');
  expect(data.requests.find(r => r.path === '/session').headers.authorization).toBe('Bearer local-test-only');
  expect(data.requests.find(r => r.path === '/state').headers.authorization).toBeUndefined();
  expect(external).toEqual([]);
  await page.screenshot({ path: testInfo.outputPath('desktop-home.png') });
});

test('touch/keyboard Sankey drilldown preserves exact sample and returns to its selection', async ({ page }) => {
  const data = await mount(page);
  const node = page.locator('.sankey-node').filter({ hasText: 'example.com:443' });
  await node.focus(); await page.keyboard.press('Enter');
  await expect(page.locator('#path-selection')).toContainText('1 条连接');
  await page.getByRole('button', { name: '查看连接', exact: true }).click();
  await expect(page.getByRole('heading', { name: '连接', exact: true })).toBeVisible();
  await expect(page.locator('tbody tr')).toHaveCount(1);
  const drill = data.requests.find(r => r.path === '/flows');
  expect(drill.query).toMatchObject({ anchor: 'traffic-session:3', path_ids: 'path-flow-a', flow_ids: 'flow-a', since: start, until: end });
  await page.getByRole('button', { name: '详情', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('fake-ip');
  await expect(page.getByRole('dialog')).toContainText('来自其他设备');
  await page.getByRole('button', { name: '关闭详情' }).click();
  await page.locator('.nav-link[data-page=home]').click();
  await expect(page.locator('#path-selection')).toContainText('example.com:443');
});

test('expired graph details are reported without silently substituting live records', async ({ page }) => {
  await mount(page, { expired: true });
  await page.locator('.sankey-node').filter({ hasText: 'example.com:443' }).click();
  await page.getByRole('button', { name: '查看连接', exact: true }).click();
  await expect(page.locator('#page-notice')).toContainText('已过期');
  await expect(page.getByRole('heading', { name: '首页', exact: true })).toBeVisible();
});

test('rename updates rule references atomically and explicitly preserves masked credentials', async ({ page }) => {
  const data = await mount(page);
  await page.locator('.nav-link[data-page=outbounds]').click();
  await page.locator('#outbound-name-0').fill('Office');
  await page.getByRole('button', { name: '保存', exact: true }).click();
  await expect(page.locator('#page-notice')).toContainText('已保存');
  const save = data.writes.find(r => r.path === '/config');
  expect(save.body.config.outbounds[0].name).toBe('Office');
  expect(save.body.config.rules[0].outbound).toBe('Office');
  expect(save.body.credential_actions.Office).toMatchObject({ action: 'preserve', original_name: 'Proxy A' });
  expect(save.body.config.general['manager-addr']).toBe('127.0.0.1:9200');
  await expect(page.locator('#outbound-name-0')).toBeEnabled();
});

test('version conflict retains draft and offers a persistent actionable message', async ({ page }) => {
  await mount(page, { conflict: true });
  await page.locator('.nav-link[data-page=inbounds]').click();
  await page.locator('#inbound-name').fill('保留的草稿');
  await page.getByRole('button', { name: '保存', exact: true }).click();
  await expect(page.locator('#page-notice')).toContainText('其他页面或文件修改');
  await expect(page.locator('#inbound-name')).toHaveValue('保留的草稿');
  await expect(page.locator('#draft-status')).toContainText('未保存');
});

test('readonly session sees every page but cannot save, diagnose, or start', async ({ page }) => {
  const data = await mount(page, { role: 'read' });
  await expect(page.locator('#lifecycle-toggle')).toBeDisabled();
  for (const name of ['connections', 'inbounds', 'outbounds', 'rules', 'dns', 'diagnostics', 'settings']) {
    await page.locator(`.nav-link[data-page=${name}]`).click();
    await expect(page.locator('#main h1')).toBeVisible();
  }
  expect(data.writes).toEqual([]);
  await expect(page.getByRole('button', { name: '应用已保存设置' })).toBeDisabled();
  await expect(page.locator('#runtime-status')).toContainText('已暂停');
});

test('mobile 320px all pages retain navigation, editing, and no body overflow', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 320, height: 760 });
  await mount(page);
  for (const name of ['home', 'connections', 'inbounds', 'outbounds', 'rules', 'dns', 'diagnostics', 'settings']) {
    await page.locator('#menu-toggle').click();
    await page.locator(`.nav-link[data-page=${name}]`).click();
    const title = { home: '首页', connections: '连接', inbounds: '入站', outbounds: '出站', rules: '规则', dns: 'DNS', diagnostics: '诊断', settings: '设置与恢复' }[name];
    await expect(page.getByRole('heading', { name: title, exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  }
  await page.locator('#menu-toggle').click(); await page.locator('.nav-link[data-page=home]').click();
  await expect(page.getByRole('heading', { name: '首页', exact: true })).toBeVisible();
  await expect(page.locator('#sidebar')).not.toHaveClass(/open/);
  await page.screenshot({ path: testInfo.outputPath('mobile-home.png'), animations: 'disabled' });
});

test('empty and disconnected states never imply traffic or current healthy operation', async ({ page }) => {
  const data = await mount(page, { empty: true });
  await expect(page.getByText('尚无可绘制的业务流量')).toBeVisible();
  await expect(page.locator('.sankey-edge')).toHaveCount(0);
  data.offline = true;
  await page.getByRole('button', { name: '刷新', exact: true }).click();
  await expect(page.locator('#runtime-status')).toHaveText('状态未知');
  await expect(page.locator('#connection-banner')).toContainText('管理连接中断');
  await expect(page.locator('#lifecycle-toggle')).toBeDisabled();
});

test('untrusted domain and error strings render as text, never executable markup', async ({ page }) => {
  const data = fixture(); data.records[0].target = '<img src=x onerror=alert(1)>:443';
  let dialogs = 0; page.on('dialog', dialog => { dialogs++; dialog.dismiss(); });
  await mount(page, data);
  await page.locator('.nav-link[data-page=connections]').click();
  await expect(page.locator('tbody')).toContainText('<img src=x onerror=alert(1)>:443');
  expect(await page.locator('tbody img').count()).toBe(0); expect(dialogs).toBe(0);
});

test('diagnosis sends one explicit TCP target and never replays business payload', async ({ page }) => {
  const data = await mount(page);
  await page.locator('.nav-link[data-page=diagnostics]').click();
  await page.locator('#diagnose-target').fill('example.com');
  await page.locator('#diagnose-port').fill('8443');
  await page.getByRole('button', { name: '开始独立诊断' }).click();
  await expect(page.locator('#page-notice')).toContainText('独立诊断任务');
  const writes = data.writes.filter(r => r.path === '/diagnostics');
  expect(writes).toHaveLength(1);
  expect(writes[0].body).toEqual({ target: 'example.com:8443', tls: false, outbounds: ['direct', 'Proxy A'] });
});
