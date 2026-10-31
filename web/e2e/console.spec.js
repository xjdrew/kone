import { test, expect } from "@playwright/test";
import { createHash } from "node:crypto";

const start = "2026-11-01T00:00:00Z";
const end = "2026-11-01T00:00:01Z";
function fixture() {
  const records = [
    {
      id: "flow-a",
      session_id: "traffic-session",
      config_version: 1,
      inbound: "tun-main",
      protocol: "tcp",
      source: "192.168.50.2:50000",
      destination: "198.18.0.2:443",
      target: "example.com:443",
      domain: "example.com",
      domain_source: "fake-ip",
      fake_ip: "198.18.0.2",
      process_status: "remote",
      rule_id: "rule-1",
      rule_name: "example.com",
      expected_outbound: "Proxy A",
      effective_outbound: "Proxy A",
      status: "active",
      started_at: start,
      upload: 1000,
      download: 3000,
    },
    {
      id: "flow-b",
      session_id: "traffic-session",
      config_version: 1,
      inbound: "tun-main",
      protocol: "udp",
      source: "192.168.50.3:50001",
      destination: "192.168.50.1:123",
      target: "192.168.50.1:123",
      process_status: "remote",
      rule_id: "default",
      rule_name: "默认直连",
      expected_outbound: "direct",
      effective_outbound: "direct",
      status: "active",
      started_at: start,
      upload: 100,
      download: 100,
    },
    {
      id: "flow-f",
      session_id: "traffic-session",
      config_version: 1,
      inbound: "tun-main",
      protocol: "udp",
      source: "192.168.50.2:50002",
      target: "unsupported.example:443",
      destination: "198.18.0.3:443",
      domain: "unsupported.example",
      expected_outbound: "Proxy A",
      effective_outbound: "",
      status: "failed",
      stage: "capability",
      error: "Proxy A does not support UDP; fallback is not configured",
      started_at: start,
      ended_at: end,
      upload: 0,
      download: 0,
    },
  ];
  const config = {
    version: 1,
    inbound: { id: "tun-main", name: "家庭网关", enabled: false },
    config: {
      general: {
        "manager-addr": "127.0.0.1:9200",
        "log-level": "info",
        "log-format": "text",
      },
      core: {
        network: "10.192.0.1/16",
        stack: "system",
        tun: "",
        "auto-route": false,
        "outbound-interface": "",
      },
      dns: {
        servers: [],
        "listen-port": 53,
        ttl: 600,
        "read-timeout": 5,
        "write-timeout": 5,
        "packet-size": 4096,
        "history-limit": 512,
        "history-retention": 3600,
        "cache-limit": 1024,
      },
      outbounds: [
        {
          id: "outbound-id-1",
          enabled: true,
          name: "Proxy A",
          url: "http://REDACTED:REDACTED@127.0.0.1:18080",
        },
      ],
      rules: [
        {
          id: "rule-1",
          type: "DOMAIN",
          pattern: "example.com",
          outbound: "Proxy A",
        },
        { type: "FINAL", outbound: "direct" },
      ],
    },
  };
  return {
    records,
    config,
    role: "admin",
    offline: false,
    conflict: false,
    empty: false,
    requests: [],
    writes: [],
    expired: false,
    state: "paused",
  };
}

async function mount(page, options = {}) {
  const data = Object.assign(fixture(), options);
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.slice("/api/v1".length);
    const method = request.method();
    data.requests.push({
      path,
      method,
      query: Object.fromEntries(url.searchParams),
      headers: request.headers(),
      body: request.postDataJSON(),
    });
    if (data.delay)
      await new Promise((resolve) => setTimeout(resolve, data.delay));
    if (data.offline) return route.abort("connectionfailed");
    const respond = (body, status = 200) =>
      route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(body),
      });
    const body = request.postDataJSON();
    if (path === "/session")
      return respond({
        role: data.role,
        csrf_token: "test-csrf",
        session_id: "test-session",
      });
    if (options.unauthorized)
      return respond({ error: { message: "Authorization expired" } }, 401);
    if (method !== "GET") {
      data.writes.push({ path, body });
      if (data.role === "read")
        return respond(
          { error: { message: "This session is read-only" } },
          403,
        );
    }
    if (path === "/state")
      return respond({
        csrf_token: "test-csrf",
        state: data.state,
        data_state: data.state,
        control_state: "ready",
        host: "Gateway · 测试主机",
        role: data.role,
        capabilities: {
          stacks: ["system", "mixed"],
          tcp: true,
          udp_direct: true,
          proxy_udp_schemes: ["socks5", "ss"],
          ipv6: Boolean(data.ipv6),
          system_dns: Boolean(data.systemDNS),
        },
        version: "test-version",
        session_id: "test-session",
        saved_version: data.config.version,
        running_version: 1,
      });
    if (path === "/config" && method === "GET") return respond(data.config);
    if (path === "/config/validate")
      return respond({ valid: true, restart_required: false, issues: [] });
    if (path === "/config/import/validate")
      return respond({
        valid: true,
        restart_required: true,
        candidate_document: data.config,
      });
    if (path === "/config/import") {
      data.config.version++;
      return respond(data.config);
    }
    if (path === "/config/defaults") {
      data.config.version++;
      data.config.inbound.enabled = false;
      data.config.config.rules = [];
      data.config.config.outbounds = [];
      return respond(data.config);
    }
    if (path === "/config" && method === "PUT") {
      if (data.conflict)
        return respond({ error: { message: "Version conflict" } }, 409);
      data.config = {
        version: data.config.version + 1,
        config: body.config,
        inbound: body.inbound,
      };
      return respond(data.config);
    }
    if (path === "/config/apply") return respond({ status: "completed" });
    if (path === "/config/undo") return respond(data.config);
    if (path === "/traffic" || path === "/flows") {
      let records = data.empty ? [] : data.records;
      if (url.searchParams.get("protocol"))
        records = records.filter(
          (record) => record.protocol === url.searchParams.get("protocol"),
        );
      if (url.searchParams.get("flow_ids"))
        records = records.filter((record) =>
          url.searchParams.get("flow_ids").split(",").includes(record.id),
        );
      if (path === "/flows" && data.expired)
        return respond({ error: { message: "Original detail expired" } }, 410);
      const totals = {
        upload: records.reduce((sum, r) => sum + r.upload, 0),
        download: records.reduce((sum, r) => sum + r.download, 0),
        upload_rate: records.length ? 250 : 0,
        download_rate: records.length ? 650 : 0,
        active: records.filter((r) => r.status === "active").length,
        failed: records.filter((r) => r.status === "failed").length,
        rejected: 0,
      };
      const traffic = {
        frozen: Boolean(data.frozen),
        records,
        totals,
        timestamp: end,
        session_id: "traffic-session",
        anchor: "traffic-session:3",
        dropped_details: 0,
        recording: true,
        capacity: 4096,
        total: records.length,
      };
      const offset = url.searchParams.get("cursor")
        ? records.findIndex(
            (record) => record.id === url.searchParams.get("cursor"),
          ) + 1
        : 0;
      const limit = Math.min(500, Number(url.searchParams.get("limit")) || 100);
      traffic.records = records.slice(offset, offset + limit);
      if (offset + limit < records.length)
        traffic.next_cursor = traffic.records.at(-1).id;
      if (path === "/flows") return respond(traffic);
      const metric = url.searchParams.get("metric");
      const cumulative = metric === "cumulative";
      let paths = records
        .filter((r) => r.upload + r.download > 0)
        .map((r) => ({
          id: `path-${r.id}`,
          config_version: r.config_version,
          inbound: r.inbound,
          rule_id: r.rule_id,
          rule_name: r.rule_name,
          effective_outbound: r.effective_outbound,
          target: r.target,
          upload: r.upload,
          download: r.download,
          value: cumulative
            ? r.upload + r.download
            : metric === "upload"
              ? r.upload / 4
              : metric === "download"
                ? r.download / 4
                : (r.upload + r.download) / 4,
          connections: 1,
          filter: {
            anchor: traffic.anchor,
            path_ids: [`path-${r.id}`],
            flow_ids: [r.id],
            since: start,
            until: end,
          },
        }));
      if (data.aggregateAll && paths.length)
        paths = [
          {
            ...paths[0],
            id: "path-all",
            target: "Other",
            other: true,
            value: paths.reduce((sum, path) => sum + path.value, 0),
            upload: paths.reduce((sum, path) => sum + path.upload, 0),
            download: paths.reduce((sum, path) => sum + path.download, 0),
            connections: paths.length,
            filter: {
              anchor: traffic.anchor,
              path_ids: ["path-all"],
              flow_ids: records.map((record) => record.id),
              since: start,
              until: end,
            },
          },
        ];
      return respond({
        traffic,
        sankey: {
          frozen: Boolean(data.frozen),
          session_id: traffic.session_id,
          timestamp: end,
          scope: "business",
          metric,
          unit: cumulative ? "B" : "B/s",
          window_start: start,
          window_end: end,
          anchor: traffic.anchor,
          paths,
          failures: totals.failed,
          total: paths.reduce((sum, p) => sum + p.value, 0),
        },
      });
    }
    if (path === "/dns")
      return respond({
        status: {
          automatic: true,
          system_source: "test-system-scope",
          search_domains: ["corp.example"],
          warnings: data.autoScopes
            ? ["Per-application VPN policy is not reproduced"]
            : [],
          rules: data.autoScopes
            ? [
                {
                  suffix: "corp.example",
                  servers: ["192.168.50.1:53"],
                  interface: "eth0",
                  automatic: true,
                  exact: false,
                },
              ]
            : [],
          servers: ["192.168.50.1:53"],
          tcp: true,
          history_dropped: 0,
        },
        queries: [
          {
            id: "q-1",
            time: end,
            name: "example.com.",
            type: "A",
            scope: "dns",
            transport: "udp",
            upstream: "192.168.50.1:53",
            upstream_transport: "udp",
            status: "NOERROR",
            cache: "miss",
            duration_ms: 4,
            virtual_addresses: ["198.18.0.2"],
            real_addresses: [],
          },
        ],
      });
    if (path === "/diagnostics" && method === "GET")
      return respond({ operations: [] });
    if (path === "/diagnostics")
      return respond({ id: "diag-1", status: "running" }, 202);
    if (path === "/sessions")
      return respond({
        sessions: [{ id: "phone-1", role: "read", expires: end }],
      });
    if (path === "/access/lan")
      return respond({
        enabled: false,
        transport: "https",
        trust_required: true,
      });
    if (path === "/recovery")
      return respond({ required: false, ownership: "none", items: [] });
    if (path === "/geoip" && method === "PUT")
      return respond({
        saved: {
          ...body,
          sha256: request.headers()["x-content-sha256"],
          ranges: body.ranges.length,
        },
        restart_required: false,
      });
    if (path === "/geoip/rollback")
      return respond({
        saved: {
          version: "recovered-v1",
          source: "verified previous dataset",
          license: "CC0-1.0",
          sha256: "b".repeat(64),
          ranges: 1,
        },
      });
    if (path === "/geoip" && data.geoCorrupt)
      return respond(
        {
          error: { code: "geoip", message: "Saved active dataset is corrupt" },
        },
        400,
      );
    if (path === "/geoip")
      return respond({
        saved: {
          version: "builtin",
          source: "legacy bundled dataset",
          license: "bundled notices",
          sha256: "a".repeat(64),
          ranges: 0,
          builtin: true,
        },
        restart_required: false,
      });
    if (path === "/pairing")
      return respond({ code: "12345678", role: body.role, expires: end });
    if (path === "/rules/simulate")
      return respond({
        outbound: "Proxy A",
        rule: "rule-1",
        protocol: "tcp",
        source: "saved-config",
      });
    if (path === "/lifecycle/preflight")
      return respond({
        valid: true,
        ok: true,
        checks: [{ name: "configuration", ok: true }],
      });
    if (path.startsWith("/lifecycle/")) {
      data.state = path.endsWith("pause") ? "paused" : "running";
      return respond({ status: "completed", message: "Operation completed" });
    }
    if (path === "/privacy/clear") {
      data.records = [];
      return respond({ cleared: true, network_changed: false });
    }
    if (path === "/export")
      return route.fulfill({
        contentType: "application/toml",
        body: '[core]\nstack = "system"\n',
      });
    return respond(
      { error: { message: `Unimplemented test route: ${path}` } },
      404,
    );
  });
  await page.goto("/#token=local-test-only");
  await expect(
    page.getByRole("heading", { name: "首页", exact: true }),
  ).toBeVisible();
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  return data;
}

async function navigate(page, name) {
  if (
    (await page.locator("#menu-toggle").isVisible()) &&
    !(await page.locator("#sidebar").getAttribute("class")).includes("open")
  )
    await page.locator("#menu-toggle").click();
  await page.locator(`.nav-link[data-page=${name}]`).click();
}

test("@compat uses embedded offline assets, removes token fragment, and renders native measured paths", async ({
  page,
}, testInfo) => {
  const external = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("http://127.0.0.1:4173/"))
      external.push(request.url());
  });
  const data = await mount(page);
  await expect(page).toHaveURL(/#home$/);
  await expect(page.locator(".sankey-node")).toHaveCount(7);
  await expect(
    page.locator(".sankey-node").filter({ hasText: "example.com:443" }),
  ).toBeVisible();
  expect(data.requests.find((r) => r.path === "/traffic").query.metric).toBe(
    "total",
  );
  expect(
    data.requests.find((r) => r.path === "/session").headers.authorization,
  ).toBe("Bearer local-test-only");
  expect(
    data.requests.find((r) => r.path === "/state").headers.authorization,
  ).toBeUndefined();
  expect(external).toEqual([]);
  const viewport = page.viewportSize();
  await page.screenshot({
    path: testInfo.outputPath(
      `home-${testInfo.project.use.browserName}-${viewport.width}x${viewport.height}.png`,
    ),
  });
});

test("@compat touch/keyboard Sankey drilldown preserves exact sample and returns to its selection", async ({
  page,
}, testInfo) => {
  const data = await mount(page);
  const node = page
    .locator(".sankey-node")
    .filter({ hasText: "example.com:443" });
  if (testInfo.project.use.hasTouch) await node.locator("rect").tap();
  else {
    await node.focus();
    await page.keyboard.press("Enter");
  }
  await expect(page.locator("#path-selection")).toContainText("1 条连接");
  await page.getByRole("button", { name: "查看连接", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "连接", exact: true }),
  ).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(1);
  const drill = data.requests.find((r) => r.path === "/flows");
  expect(drill.query).toMatchObject({
    anchor: "traffic-session:3",
    path_ids: "path-flow-a",
    flow_ids: "flow-a",
    since: start,
    until: end,
  });
  await page.getByRole("button", { name: "详情", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("fake-ip");
  await expect(page.getByRole("dialog")).toContainText("来自其他设备");
  await page.getByRole("button", { name: "关闭详情" }).click();
  await navigate(page, "home");
  await expect(page.locator("#path-selection")).toContainText(
    "example.com:443",
  );
});

test("expired graph details are reported without silently substituting live records", async ({
  page,
}) => {
  await mount(page, { expired: true });
  await page
    .locator(".sankey-node")
    .filter({ hasText: "example.com:443" })
    .click();
  await page.getByRole("button", { name: "查看连接", exact: true }).click();
  await expect(page.locator("#page-notice")).toContainText("已过期");
  await expect(
    page.getByRole("heading", { name: "首页", exact: true }),
  ).toBeVisible();
});

test("rename updates rule references atomically and explicitly preserves masked credentials", async ({
  page,
}) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=outbounds]").click();
  await page.locator("#outbound-name-0").fill("Office");
  await page.locator("#outbound-name-0").dispatchEvent("input");
  await page.getByRole("button", { name: "保存", exact: true }).click();
  await expect(page.locator("#page-notice")).toContainText("已保存");
  const save = data.writes.find((r) => r.path === "/config");
  expect(save.body.config.outbounds[0].name).toBe("Office");
  expect(save.body.config.outbounds[0].id).toBe("outbound-id-1");
  expect(save.body.config.rules[0].outbound).toBe("Office");
  expect(save.body.credential_actions.Office).toMatchObject({
    action: "preserve",
    original_name: "Proxy A",
  });
  expect(save.body.config.general["manager-addr"]).toBe("127.0.0.1:9200");
  await expect(page.locator("#outbound-name-0")).toBeEnabled();
});

test("version conflict retains draft and offers a persistent actionable message", async ({
  page,
}) => {
  await mount(page, { conflict: true });
  await page.locator(".nav-link[data-page=inbounds]").click();
  await page.locator("#inbound-name").fill("保留的草稿");
  await page.getByRole("button", { name: "保存", exact: true }).click();
  await expect(page.locator("#page-notice")).toContainText(
    "其他页面或文件修改",
  );
  await expect(page.locator("#inbound-name")).toHaveValue("保留的草稿");
  await expect(page.locator("#draft-status")).toContainText("未保存");
});

test("@compat readonly session sees every page but cannot save, diagnose, or start", async ({
  page,
}) => {
  const data = await mount(page, { role: "read" });
  await expect(page.locator("#lifecycle-toggle")).toBeDisabled();
  for (const name of [
    "connections",
    "inbounds",
    "outbounds",
    "rules",
    "dns",
    "diagnostics",
    "settings",
  ]) {
    await navigate(page, name);
    await expect(page.locator("#main h1")).toBeVisible();
  }
  expect(data.writes).toEqual([]);
  await expect(
    page.getByRole("button", { name: "应用已保存设置" }),
  ).toBeDisabled();
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
});

test("@compat mobile 320px all pages retain navigation, editing, and no body overflow", async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 320, height: 760 });
  await mount(page);
  for (const name of [
    "home",
    "connections",
    "inbounds",
    "outbounds",
    "rules",
    "dns",
    "diagnostics",
    "settings",
  ]) {
    await page.locator("#menu-toggle").click();
    await page.locator(`.nav-link[data-page=${name}]`).click();
    const title = {
      home: "首页",
      connections: "连接",
      inbounds: "入站",
      outbounds: "出站",
      rules: "规则",
      dns: "DNS",
      diagnostics: "诊断",
      settings: "设置与恢复",
    }[name];
    await expect(
      page.getByRole("heading", { name: title, exact: true }),
    ).toBeVisible();
    await expect(
      page.locator(".workspace-footer").getByRole("link", {
        name: "IP Geolocation by DB-IP",
      }),
    ).toBeVisible();
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth), {
        message: `Horizontal body overflow on ${name} at 320px`,
      })
      .toBeLessThanOrEqual(320);
  }
  await page.locator("#menu-toggle").click();
  await page.locator(".nav-link[data-page=home]").click();
  await expect(
    page.getByRole("heading", { name: "首页", exact: true }),
  ).toBeVisible();
  await expect(page.locator("#sidebar")).not.toHaveClass(/open/);
  await page.screenshot({
    path: testInfo.outputPath(
      `home-${testInfo.project.use.browserName}-320x760.png`,
    ),
    animations: "disabled",
  });
});

test("empty and disconnected states never imply traffic or current healthy operation", async ({
  page,
}) => {
  const data = await mount(page, { empty: true });
  await expect(page.getByText("尚无可绘制的业务流量")).toBeVisible();
  await expect(page.locator(".sankey-edge")).toHaveCount(0);
  data.offline = true;
  await page.getByRole("button", { name: "刷新", exact: true }).click();
  await expect(page.locator("#runtime-status")).toHaveText("状态未知");
  await expect(page.locator("#connection-banner")).toContainText(
    "管理连接中断",
  );
  await expect(page.locator("#lifecycle-toggle")).toBeDisabled();
});

test("@compat weak network recovery refreshes real state without repeating a mutation", async ({
  page,
}) => {
  const data = await mount(page);
  data.offline = true;
  await page.getByRole("button", { name: "刷新", exact: true }).click();
  await expect(page.locator("#runtime-status")).toHaveText("状态未知");
  await expect(page.locator("#lifecycle-toggle")).toBeDisabled();
  await expect(page.locator("#connection-banner")).toContainText(
    "管理连接中断",
  );
  data.offline = false;
  data.delay = 200;
  await page.getByRole("button", { name: "刷新", exact: true }).click();
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  await expect(page.locator("#connection-banner")).toBeHidden();
  await expect(page.locator("#lifecycle-toggle")).toBeEnabled();
  expect(data.writes).toEqual([]);
});

test("untrusted domain and error strings render as text, never executable markup", async ({
  page,
}) => {
  const data = fixture();
  data.records[0].target = "<img src=x onerror=alert(1)>:443";
  let dialogs = 0;
  page.on("dialog", (dialog) => {
    dialogs++;
    dialog.dismiss();
  });
  await mount(page, data);
  await page.locator(".nav-link[data-page=connections]").click();
  await expect(page.locator("tbody")).toContainText(
    "<img src=x onerror=alert(1)>:443",
  );
  expect(await page.locator("tbody img").count()).toBe(0);
  expect(dialogs).toBe(0);
});

test("diagnosis sends one explicit TCP target and never replays business payload", async ({
  page,
}) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=diagnostics]").click();
  await page.locator("#diagnose-target").fill("example.com");
  await page.locator("#diagnose-port").fill("8443");
  await page.getByRole("button", { name: "开始独立诊断" }).click();
  await expect(page.locator("#page-notice")).toContainText("独立诊断任务");
  const writes = data.writes.filter((r) => r.path === "/diagnostics");
  expect(writes).toHaveLength(1);
  expect(writes[0].body).toEqual({
    target: "example.com:8443",
    tls: false,
    outbounds: ["direct", "Proxy A"],
  });
});

test("manual refresh never silently rebases a dirty draft onto a concurrent saved version", async ({
  page,
}) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=inbounds]").click();
  await page.locator("#inbound-name").fill("My draft");
  data.config.version = 2;
  await page.getByRole("button", { name: "刷新", exact: true }).click();
  await expect(page.locator("#inbound-name")).toHaveValue("My draft");
  await expect(
    page.getByText("已保存版本发生变化", { exact: false }),
  ).toBeVisible();
  await page.getByRole("button", { name: "保存", exact: true }).click();
  await expect
    .poll(
      () =>
        data.writes.find((write) => write.path === "/config")?.body
          .base_version,
    )
    .toBe(1);
});

test("TOML import validates before explicit confirmation and never starts capture", async ({
  page,
}) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=settings]").click();
  await page.getByRole("button", { name: "导入 TOML 设置" }).click();
  await page.locator("#import-toml").fill('[core]\nstack = "system"');
  await page.getByRole("button", { name: "校验导入", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("显式重启");
  expect(
    data.writes.filter((write) => write.path === "/config/import"),
  ).toHaveLength(0);
  await page.getByRole("button", { name: "确认保存导入" }).click();
  await expect(page.locator("#page-notice")).toContainText("尚未应用");
  expect(
    data.writes.filter((write) => write.path === "/config/import"),
  ).toHaveLength(1);
  expect(
    data.writes.some((write) => write.path.startsWith("/lifecycle/")),
  ).toBe(false);
});

test("GeoIP requires an independent checksum and sends a raw bounded upload with both base identities", async ({
  page,
}) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=settings]").click();
  const attribution = page.locator("main").getByRole("link", {
    name: "IP Geolocation by DB-IP",
  });
  await expect(attribution).toHaveAttribute("href", "https://db-ip.com");
  await expect(attribution).toHaveAttribute("rel", "noopener noreferrer");
  const content = JSON.stringify({
    format: 1,
    version: "test-v2",
    source: "https://provider.example.invalid/dataset",
    license: "CC0-1.0",
    license_url: "https://provider.example.invalid/license",
    published_at: start,
    ranges: [{ start: "192.0.2.0", end: "192.0.2.255", country: "CN" }],
  });
  const digest = createHash("sha256").update(content).digest("hex");
  await page.locator("#geoip-file").setInputFiles({
    name: "geoip.json",
    mimeType: "application/json",
    buffer: Buffer.from(content),
  });
  await page.locator("#geoip-expected").fill("0".repeat(64));
  await page.getByRole("button", { name: "校验并准备更新" }).click();
  await expect(page.locator("#page-notice")).toContainText(
    "SHA-256 与预期不一致",
  );
  expect(data.writes.filter((write) => write.path === "/geoip")).toHaveLength(
    0,
  );
  await page.locator("#geoip-expected").fill(digest);
  await page.getByRole("button", { name: "校验并准备更新" }).click();
  await page.getByRole("button", { name: "确认保存数据", exact: true }).click();
  await expect(page.locator("#page-notice")).toContainText("GeoIP 已保存");
  const upload = data.requests.find(
    (request) => request.path === "/geoip" && request.method === "PUT",
  );
  expect(upload.headers).toMatchObject({
    "if-match": "1",
    "x-content-sha256": digest,
    "x-geoip-base-sha256": "a".repeat(64),
    "x-csrf-token": "test-csrf",
  });
  expect(upload.body.version).toBe("test-v2");
  expect(
    data.writes.some((write) => write.path.startsWith("/lifecycle/")),
  ).toBe(false);
});

for (const width of [360, 390, 430, 768, 1024])
  test(`home graph and equivalent paths remain usable at ${width}px`, async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width, height: 844 });
    await mount(page);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await page.getByRole("button", { name: "放大图形", exact: true }).click();
    await expect(page.locator("#sankey")).toHaveClass(/zoomed/);
    await page.getByText("同口径路径列表", { exact: true }).click();
    await expect(
      page.getByRole("button", { name: "选择路径" }).first(),
    ).toBeVisible();
    if (width === 390) {
      await page.locator("#sankey").scrollIntoViewIfNeeded();
      await page.screenshot({
        path: testInfo.outputPath("mobile-graph-390.png"),
        animations: "disabled",
      });
    }
  });

test("IPv6 is an explicit saved opt-in and unavailable platforms cannot enable it", async ({
  page,
}) => {
  const data = await mount(page, { ipv6: true });
  await page.locator(".nav-link[data-page=inbounds]").click();
  await page.locator("#inbound-ipv6-network").fill("fd7a:203::1/120");
  await page.locator("#inbound-outbound-interface").fill("eth0");
  await page.locator("#inbound-auto-route6").check();
  await page.getByRole("button", { name: "保存", exact: true }).click();
  await expect
    .poll(
      () =>
        data.writes.find((write) => write.path === "/config")?.body.config.core[
          "ipv6-network"
        ],
    )
    .toBe("fd7a:203::1/120");
  expect(
    data.writes.find((write) => write.path === "/config").body.config.core[
      "auto-route6"
    ],
  ).toBe(true);
  expect(
    data.writes.some((write) => write.path.startsWith("/lifecycle/")),
  ).toBe(false);
  data.ipv6 = false;
  data.config.config.core["ipv6-network"] = "";
  data.config.config.core["auto-route6"] = false;
  await page.reload();
  await expect(page.locator("#inbound-ipv6-network")).toBeDisabled();
  await expect(page.locator("#inbound-auto-route6")).toBeDisabled();
});

test("Other drilldown reads every original contributor in bounded requests and list pagination stays anchored", async ({
  page,
}) => {
  const original = fixture().records[0];
  const records = Array.from({ length: 250 }, (_, i) => ({
    ...original,
    id: `flow-${String(i).padStart(4, "0")}`,
  }));
  const data = await mount(page, { records, aggregateAll: true });
  await page.locator(".sankey-node").filter({ hasText: "其他目的" }).click();
  await page.getByRole("button", { name: "查看连接", exact: true }).click();
  await expect(page.locator(".search-summary")).toContainText("已载入 250 条");
  const reads = data.requests.filter((request) => request.path === "/flows");
  expect(reads).toHaveLength(3);
  expect(reads.flatMap((read) => read.query.flow_ids.split(","))).toEqual(
    records.map((record) => record.id),
  );
  expect(reads.every((read) => read.query.anchor === "traffic-session:3")).toBe(
    true,
  );
  await page.getByRole("button", { name: "切换实时", exact: true }).click();
  await expect(page.locator(".search-summary")).toContainText("已载入 100 条");
  await page.getByRole("button", { name: "固定快照并加载更早记录" }).click();
  await expect(page.locator(".search-summary")).toContainText("已载入 250 条");
  await expect(page.getByText("固定观察快照", { exact: false })).toBeVisible();
});

test("temporary domain rules and outbound disable are explicit saved drafts with stable identities", async ({
  page,
}) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=rules]").click();
  await page.locator(".editor-item").first().locator("summary").click();
  await page.locator("#rule-lifetime-0").selectOption("temporary");
  await expect(page.locator("#rule-expires-0")).toBeVisible();
  await page.getByRole("button", { name: "保存", exact: true }).click();
  await expect
    .poll(
      () =>
        data.writes.find((write) => write.path === "/config")?.body.config
          .rules[0]["expires-at"],
    )
    .toMatch(/^\d{4}-\d{2}-\d{2}T/);
  await page.locator(".nav-link[data-page=outbounds]").click();
  await page.locator("#outbound-enabled-0").uncheck();
  await page.getByRole("button", { name: "保存", exact: true }).click();
  await expect
    .poll(
      () =>
        data.writes.filter((write) => write.path === "/config").at(-1)?.body
          .config.outbounds[0].enabled,
    )
    .toBe(false);
  expect(
    data.writes.filter((write) => write.path === "/config").at(-1).body.config
      .outbounds[0].id,
  ).toBe("outbound-id-1");
  expect(
    data.writes.some((write) => write.path.startsWith("/lifecycle/")),
  ).toBe(false);
});

test("DNS system guidance saves explicit intent while automatic scopes remain read-only", async ({
  page,
}) => {
  const data = await mount(page, { systemDNS: true, autoScopes: true });
  await page.locator(".nav-link[data-page=dns]").click();
  await expect(page.getByText("系统解析范围", { exact: true })).toBeVisible();
  await page.locator("#dns-system").check();
  await page.getByRole("button", { name: "＋ 添加解析规则" }).click();
  await page.locator("#dns-route-suffix-0").fill("private.example");
  await page.locator("#dns-route-servers-0").fill("192.168.50.1:53");
  await page.locator("#dns-route-interface-0").fill("eth0");
  await page.getByRole("button", { name: "保存", exact: true }).first().click();
  await expect
    .poll(
      () =>
        data.writes.find((write) => write.path === "/config")?.body.config.dns
          .system,
    )
    .toBe(true);
  const saved = data.writes.find((write) => write.path === "/config").body
    .config.dns;
  expect(saved.rules).toEqual([
    {
      suffix: "private.example",
      servers: ["192.168.50.1:53"],
      interface: "eth0",
    },
  ]);
  expect(JSON.stringify(saved)).not.toContain("automatic");
  expect(
    data.writes.some((write) => write.path.startsWith("/lifecycle/")),
  ).toBe(false);
});

test("corrupt GeoIP still permits explicit revalidation of the saved previous dataset", async ({
  page,
}) => {
  const data = await mount(page, { geoCorrupt: true });
  await page.locator(".nav-link[data-page=settings]").click();
  await expect(
    page.getByText("Saved active dataset is corrupt", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "尝试恢复已保存上一版" }).click();
  await expect(page.getByRole("dialog")).toContainText(
    "不会猜测或自动替换成内置版",
  );
  expect(data.writes.some((write) => write.path === "/geoip/rollback")).toBe(
    false,
  );
  await page.getByRole("button", { name: "确认回退数据", exact: true }).click();
  await expect
    .poll(
      () => data.writes.find((write) => write.path === "/geoip/rollback")?.body,
    )
    .toEqual({ base_version: 1, base_sha256: "" });
});

test("initial transport failure displays unknown counters instead of invented zero observations", async ({
  page,
}) => {
  await page.route("**/api/v1/**", (route) => route.abort("connectionfailed"));
  await page.goto("/#home");
  await expect(page.locator("#runtime-status")).toHaveText("状态未知");
  await expect(page.locator(".metric-value")).toHaveText(["—", "—", "—", "—"]);
  await expect(page.locator("#lifecycle-toggle")).toBeDisabled();
});

test("@compat retained capture observations never claim live sampling after repeated refresh", async ({ page }) => {
  const data = await mount(page, { frozen: true, state: "paused" });
  await expect(page.locator(".metric-label").filter({ hasText: "上次采样上传 / 下载" })).toBeVisible();
  await expect(page.locator(".metric-label").filter({ hasText: "上次采样活动连接" })).toBeVisible();
  await expect(page.getByText(/接管已停止：这里是/)).toContainText("不会继续实时更新");
  await expect(page.getByRole("button", {name: "上次采样速率", exact: true})).toBeVisible();
  const note = await page.getByText(/接管已停止：这里是/).textContent();
  await page.getByRole("button", {name: "刷新", exact: true}).first().click();
  await expect.poll(() => data.requests.filter((request) => request.path === "/traffic").length).toBeGreaterThan(1);
  await expect(page.getByText(/接管已停止：这里是/)).toHaveText(note);
  await expect(page.locator(".metric-label").filter({ hasText: "实时上传 / 下载" })).toHaveCount(0);
  await expect(page.getByRole("button", {name: "实时速率", exact: true})).toHaveCount(0);
});

test("observed UDP shortcuts retain transport and port, precede broad rules and never silently save", async ({ page }) => {
  const data = await mount(page);
  await page.getByRole("button", { name: "详情", exact: true }).first().click();
  await page.getByRole("dialog").getByRole("button", { name: "为此目标建规则" }).click();
  await expect(page.locator("#rule-pattern-0")).toHaveValue("unsupported.example");
  await expect(page.locator("#rule-protocol-0")).toHaveValue("udp");
  await expect(page.locator("#rule-ports-0")).toHaveValue("443");
  await expect(page.locator("#rule-pattern-1")).toHaveValue("example.com");
  expect(data.writes.some((write) => write.path === "/config")).toBe(false);
  await page.getByRole("button", { name: "保存", exact: true }).first().click();
  await expect.poll(() => data.writes.find((write) => write.path === "/config")?.body.config.rules[0]).toMatchObject({
    type: "DOMAIN", pattern: "unsupported.example", protocol: "udp", ports: [443], source: "one-click",
  });
  await page.locator(".nav-link[data-page=home]").click();
  await page.getByRole("button", { name: "详情", exact: true }).first().click();
  await page.getByRole("dialog").getByRole("button", { name: "为此目标建规则" }).click();
  await expect(page.locator(".editor-item")).toHaveCount(3);
  await expect(page.getByText(/没有重复添加/)).toBeVisible();
  expect(data.writes.filter((write) => write.path === "/config")).toHaveLength(1);
  expect(data.writes.some((write) => write.path.startsWith("/lifecycle/") || write.path === "/config/apply")).toBe(false);
});

test("routing simulation sends the selected protocol and destination port without probing", async ({ page }) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=rules]").click();
  await page.locator("#simulate-target").fill("example.com");
  await page.locator("#simulate-port").fill("8443");
  await page.getByRole("combobox", { name: "模拟协议" }).selectOption("udp");
  await page.getByRole("button", { name: "模拟匹配" }).click();
  await expect.poll(() => data.requests.find((request) => request.path === "/rules/simulate")?.body).toEqual({ target: "example.com:8443", protocol: "udp" });
  expect(data.writes.some((write) => write.path === "/diagnostics" || write.path === "/config")).toBe(false);
});
