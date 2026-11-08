import { test, expect } from "@playwright/test";
import { fixture } from "./fixture";

test("@compat default direct routing starts immediately; only real blockers require recovery", async ({
  page,
}) => {
  const data = await fixture(page);
  data.document.config.outbounds = [];
  data.document.config.rules = [{ id: "final", type: "FINAL", outbound: "direct" }];
  data.document.direct_only_confirmed = false;
  data.readiness = {
    ready: true,
    direct_only: true,
    direct_only_confirmed: false,
    checks: [],
    blockers: [],
    warnings: [],
  };
  await page.goto("/#/traffic");
  await page.getByRole("switch", { name: "Enable proxy" }).click();
  await expect(page.getByRole("switch", { name: "Pause proxy" })).toBeVisible();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  expect(data.requests.filter(({ path }) => path === "/lifecycle/start")).toHaveLength(1);
  expect(data.requests.some(({ method, path }) => method === "PUT" && path === "/config")).toBe(
    false,
  );
  await page.getByRole("switch", { name: "Pause proxy" }).click();

  const permissions = {
    id: "privileges",
    code: "privileges",
    status: "error",
    severity: "error",
    message: "CAP_NET_ADMIN is required",
    page: "settings",
    action: "authorize",
  };
  const advisory = {
    id: "scope",
    code: "capture_scope",
    status: "warning",
    severity: "warning",
    message: "Selective capture",
    page: "inbounds",
    action: "edit_inbound",
  };
  data.readiness = {
    ...data.readiness,
    ready: false,
    checks: [permissions, advisory],
    blockers: [permissions],
    warnings: [advisory],
  };
  await page.getByRole("switch", { name: "Enable proxy" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Network permission is missing", { exact: true })).toBeVisible();
  await expect(dialog.getByText(/The browser cannot grant OS permissions/)).toBeVisible();
  await expect(dialog.getByText("Unknown", { exact: true })).toHaveCount(0);
  const enable = dialog.getByRole("button", { name: "Enable proxy", exact: true });
  await expect(enable).toBeDisabled();
  await dialog.getByText("Recommendations · 1 · do not block startup").click();
  await expect(dialog.getByText("Does not block startup", { exact: true })).toBeVisible();
  await expect(dialog.getByRole("link", { name: "Configure capture" })).toHaveAttribute(
    "href",
    /section=capture/,
  );
  await page.route("**/api/v1/readiness", (route) =>
    route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "request", details: "Host check failed" } }),
    }),
  );
  await dialog.getByRole("button", { name: "Check again" }).click();
  await expect(page.locator(".errorToast")).toBeVisible();
  await page.locator(".errorToast").getByText("Technical details").click();
  await expect(page.locator(".errorToast")).toContainText("Host check failed");
  await page.unroute("**/api/v1/readiness");

  // Rechecking cannot start; enabling must revalidate a changed environment.
  data.readiness = { ...data.readiness, ready: true, blockers: [], checks: [advisory] };
  await dialog.getByRole("button", { name: "Check again" }).click();
  await expect(enable).toBeEnabled();
  expect(data.requests.filter(({ path }) => path === "/lifecycle/start")).toHaveLength(1);
  data.readiness = {
    ...data.readiness,
    ready: false,
    blockers: [permissions],
    checks: [permissions],
  };
  await enable.click();
  await expect(enable).toBeDisabled();
  expect(data.requests.filter(({ path }) => path === "/lifecycle/start")).toHaveLength(1);
  data.readiness = {
    ...data.readiness,
    ready: true,
    blockers: [],
    checks: [{ ...permissions, severity: "info", status: "ready" }],
  };
  await dialog.getByRole("button", { name: "Check again" }).click();
  await dialog.getByText("Passed checks · 1").click();
  await expect(dialog.getByText("System authorization on enable", { exact: true })).toBeVisible();
  await expect(dialog.getByText(/No restart is required/)).toBeVisible();
  await dialog.getByRole("button", { name: "Check again" }).click();
  await enable.click();
  await expect(dialog).not.toBeVisible();
  expect(data.requests.filter(({ path }) => path === "/lifecycle/start")).toHaveLength(2);
  expect(data.requests.some(({ method, path }) => method === "PUT" && path === "/config")).toBe(
    false,
  );
});

test("policy conversion is previewed and preserves exceptions; conflicts retain the draft", async ({
  page,
}) => {
  const data = await fixture(page);
  await page.goto("/#/policy");
  await page.getByRole("button", { name: "Change base policy", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Proxy rules").selectOption("proxy-first");
  await dialog.getByLabel("Outbound", { exact: true }).selectOption("Local HTTP");
  await dialog.getByLabel("Allow the existing UDP direct exception").check();
  await dialog.getByRole("button", { name: "Preview changes" }).click();
  await expect(dialog.getByText("UDP has a direct exception")).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Apply", exact: true })).toBeEnabled();
  data.conflict = true;
  await dialog.getByRole("button", { name: "Apply", exact: true }).click();
  await expect(dialog.getByRole("alert")).toContainText("changed elsewhere");
  await expect(dialog.getByLabel("Outbound", { exact: true })).toHaveValue("Local HTTP");
  data.conflict = false;
  await dialog.getByRole("button", { name: "Apply", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  expect(data.document.config.rules[0].pattern).toBe("google.com");
  expect(data.document.config.rules.at(-1)?.outbound).toBe("Local HTTP");
  expect(data.requests.some((request) => request.path.startsWith("/lifecycle/"))).toBe(false);
});
test("traffic evidence creates one precise TCP rule and scoped undo restores it", async ({
  page,
}) => {
  const data = await fixture(page);
  await page.goto("/#/traffic?view=connections");
  const row = page.getByRole("row").filter({ hasText: "149.154.167.50:443" });
  await row.getByRole("button", { name: "More actions" }).click();
  await page.getByRole("menuitem", { name: /Proxy through.*Local HTTP/ }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByLabel("Domain / address / country")).toHaveValue("149.154.167.50/32");
  await expect(dialog.getByLabel("Protocol", { exact: true })).toHaveValue("tcp");
  await expect(dialog.getByLabel("Ports", { exact: true })).toHaveValue("443");
  await dialog.getByRole("button", { name: "Save", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  expect(data.document.config.rules[0]).toMatchObject({
    type: "IP-CIDR",
    pattern: "149.154.167.50/32",
    protocol: "tcp",
    ports: [443],
    outbound: "Local HTTP",
  });
  await page.getByRole("button", { name: "Undo this change" }).click();
  await expect.poll(() => data.document.config.rules.length).toBe(2);
  await page.getByRole("link", { name: "Overview", exact: true }).click();
  await page.getByRole("button", { name: /www.google.com:.*B\/s/ }).click();
  await expect(page).toHaveURL(/anchor=anchor-1/);
  await expect(page).toHaveURL(/path_ids=path-1/);
});
test("DNS context stays unscoped and Telegram comparison disables TLS", async ({ page }) => {
  const data = await fixture(page);
  await page.goto("/#/traffic?view=dns");
  await page
    .getByRole("row")
    .filter({ hasText: "www.google.com" })
    .getByRole("button", { name: "More actions" })
    .click();
  await page.getByRole("menuitem", { name: "Send directly" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByLabel("Protocol", { exact: true })).toHaveValue("");
  await expect(dialog.getByLabel("Ports", { exact: true })).toBeEmpty();
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("button", { name: "Diagnostics", exact: true }).click();
  await page.getByRole("button", { name: "Recent targets", exact: true }).click();
  await page.getByRole("option", { name: /149.154.167.50/ }).click();
  await expect(page.getByLabel("Verify target TLS")).toBeDisabled();
  await page.getByRole("button", { name: "Start comparison" }).click();
  await expect
    .poll(
      () =>
        data.requests.filter(
          (request) => request.path === "/diagnostics" && request.method === "POST",
        ).length,
    )
    .toBe(1);
  expect(
    data.requests.find((request) => request.path === "/diagnostics" && request.method === "POST")
      ?.body,
  ).toMatchObject({
    target: "149.154.167.50:443",
    protocol: "tcp",
    tls: false,
    outbounds: ["direct", "Local HTTP"],
  });
  await expect(page.getByText("Reachable", { exact: true })).toBeVisible();
});
test("remote session loss removes protected data and read-only actions are disabled", async ({
  page,
}) => {
  const data = await fixture(page, { readonly: true, remote: true });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Open your network workspace" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "KONE" })).toHaveCount(0);
  await page.getByLabel("Management password").fill("fixture-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Network overview" })).toBeVisible();
  await expect(page.getByRole("switch", { name: "Enable proxy" })).toBeDisabled();
  data.authenticated = false;
  await expect(page.getByRole("heading", { name: "Open your network workspace" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Network overview" })).toHaveCount(0);
  expect(
    data.requests.filter((request) => request.path === "/config" && request.method === "PUT"),
  ).toHaveLength(0);
});
test("@compat compact navigation, inline outbound editing and en/zh changes work by keyboard", async ({
  page,
}) => {
  const data = await fixture(page);
  await page.goto("/#/policy?view=outbounds");
  await page.getByRole("button", { name: "Local HTTP", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Name", { exact: true }).fill("Office");
  await dialog.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("button", { name: "Office", exact: true })).toBeVisible();
  expect(data.document.config.rules[0].outbound).toBe("Office");
  await page.getByRole("link", { name: "Settings", exact: true }).click();
  await page.getByRole("link", { name: "Interface", exact: true }).click();
  await page.getByLabel("Language", { exact: true }).focus();
  await page.getByLabel("Language", { exact: true }).selectOption("zh");
  await expect(page.locator("html")).toHaveAttribute("lang", "zh");
  await expect(page.getByRole("heading", { name: "设置", exact: true })).toBeVisible();
  await page.getByLabel("语言", { exact: true }).selectOption("en");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("dialog", { name: "Commands" })).toBeVisible();
  await page.getByRole("textbox", { name: "Commands" }).fill("Connections");
  await page.getByRole("button", { name: "Connections", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Connections", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("snapshot drilling and settings navigation retain evidence; edits survive conflicts", async ({
  page,
}) => {
  const data = await fixture(page);
  await page.goto("/#/traffic");
  await page.getByRole("button", { name: /www.google.com:.*B\/s/ }).click();
  await expect(page).toHaveURL(/window_start=/);
  const evidenceURL = page.url();
  await page.getByRole("link", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: /Back to workspace/ }).click();
  await expect(page).toHaveURL(evidenceURL);
  await page.goBack();
  await page.getByRole("link", { name: "Capture", exact: true }).click();
  await page.getByLabel("TUN name", { exact: true }).fill("draft-tun");
  await page.getByRole("link", { name: "Resolvers", exact: true }).click();
  await page.getByRole("link", { name: "Capture", exact: true }).click();
  await expect(page.getByLabel("TUN name", { exact: true })).toHaveValue("draft-tun");
  data.conflict = true;
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("changed elsewhere");
  await expect(page.getByLabel("TUN name", { exact: true })).toHaveValue("draft-tun");
});

test("@compat 320 px, long translated labels and 200% zoom preserve primary actions", async ({
  page,
}) => {
  await fixture(page);
  await page.setViewportSize({ width: 320, height: 720 });
  await page.goto("/#/settings?section=interface");
  await page.getByLabel("Language", { exact: true }).focus();
  await page.getByLabel("Language", { exact: true }).selectOption("zh");
  await expect(page.getByLabel("语言", { exact: true })).toBeFocused();
  // Long-label stress uses the real component and reflow, without adding a
  // pseudo language to the shipped catalog.
  await page.getByRole("link", { name: "配置与数据", exact: true }).evaluate((element) => {
    element.textContent = "［配置与数据 · Configuration and datasets］";
  });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole("link", { name: "流量", exact: true }).click();
  await expect(page.getByRole("switch", { name: "启用代理" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole("button", { name: "诊断", exact: true }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole("button", { name: "诊断", exact: true }).click();
  await page.setViewportSize({ width: 1280, height: 900 });
  // CSS zoom preserves the 640 CSS-pixel reflow budget at a 1280-pixel viewport.
  await page.evaluate(() => {
    document.documentElement.style.zoom = "2";
  });
  await expect(page.getByRole("switch", { name: "启用代理" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("@compat remote access sets a password first and preserves listener drafts across failure", async ({
  page,
}) => {
  const data = await fixture(page);
  data.state.password_configured = false;
  // A non-secure HTTP origin has getRandomValues, but no randomUUID or Clipboard API.
  await page.addInitScript(() => {
    Object.defineProperty(crypto, "randomUUID", { value: undefined });
    Object.defineProperty(navigator, "clipboard", { value: undefined });
  });
  await page.goto("/#/settings?section=access");
  await expect(page.getByLabel("Listen on", { exact: true })).toHaveValue("192.168.40.2");
  await page.getByLabel("Listen on", { exact: true }).selectOption("0.0.0.0");
  await page.getByLabel("Use HTTPS", { exact: true }).uncheck();
  await expect(page.getByText("HTTPS certificate", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Set password and enable", exact: true }).first().click();
  expect(data.requests.some((item) => item.path === "/access/lan" && item.method === "POST")).toBe(
    false,
  );
  await page.getByLabel("New password", { exact: true }).fill("fixture-management-password");
  await page.getByLabel("Confirm password", { exact: true }).fill("fixture-management-password");
  data.accessFailure = true;
  await page.getByRole("button", { name: "Set password and enable", exact: true }).last().click();
  await expect(page.getByRole("alert")).toContainText("Could not bind");
  expect(
    data.requests
      .filter(
        ({ method, path }) => method === "POST" && ["/auth/password", "/access/lan"].includes(path),
      )
      .map(({ path }) => path),
  ).toEqual(["/auth/password", "/access/lan"]);
  await expect(page.getByLabel("Listen on", { exact: true })).toHaveValue("0.0.0.0");
  data.accessFailure = false;
  await page.getByRole("button", { name: "Enable listener", exact: true }).click();
  await expect(
    page.getByRole("link", { name: "http://192.168.40.2:9443", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Copy http://192.168.40.2:9443", exact: true }).click();
  expect(
    data.requests.some(({ path }) => path === "/access/certificate" || path === "/pairing"),
  ).toBe(false);
  await page.getByLabel("Use HTTPS", { exact: true }).check();
  await page.getByRole("button", { name: "Apply changes", exact: true }).click();
  await expect(
    page.getByRole("link", { name: "https://192.168.40.2:9443", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("HTTPS certificate", { exact: true })).toBeVisible();
  await page.getByText("How to trust the CA", { exact: true }).click();
  await expect(page.getByText(/macOS: import the CA/)).toBeVisible();
  await page.getByRole("button", { name: "Stop listener", exact: true }).click();
  await expect(page.getByRole("button", { name: "Enable listener", exact: true })).toBeVisible();
  await expect(page.getByText(/Pairing code|Create pairing/)).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("@compat generic diagnostics keep per-outbound progress and expand one result at a time", async ({
  page,
}) => {
  const data = await fixture(page);
  const target = "10.23.4.5:8443";
  const rows = [
    {
      target,
      outbound: "direct",
      protocol: "tcp",
      status: "reachable",
      stage: "connect",
      duration_ms: 4,
      connect_latency_ms: 3,
    },
    {
      target,
      outbound: "Local HTTP",
      protocol: "tcp",
      status: "running",
      stage: "proxy_handshake",
      duration_ms: 0,
      connect_latency_ms: 0,
    },
  ];
  data.operations.push({
    id: "progress",
    kind: "diagnostics",
    status: "running",
    stage: "connect",
    started_at: "2026-11-07T09:30:00Z",
    target,
    outbounds: ["direct", "Local HTTP", "queued-outbound"],
    protocol: "tcp",
    result: { results: rows },
  });
  await page.goto("/#/outbounds");
  await expect(page.getByRole("navigation", { name: "KONE" }).getByRole("link")).toHaveCount(3);
  await expect(page.getByRole("heading", { name: "Outbounds", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Diagnostics", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Network diagnostics", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("combobox", { name: "Target · domain or IP, optional port" }),
  ).toBeVisible();
  await expect(
    page.getByLabel("Target · domain or IP, optional port", { exact: true }),
  ).toHaveValue("");
  const summaries = page.locator("summary").filter({ hasText: target });
  await expect(summaries).toHaveCount(3);
  await expect(summaries.nth(2)).toContainText("Pending");
  await expect(summaries.nth(1)).toHaveAttribute("aria-busy", "true");
  await expect(summaries.nth(0).locator("..")).not.toHaveAttribute("open");
  await summaries.nth(0).click();
  await expect(summaries.nth(0).locator("..")).toHaveAttribute("open", "");
  await expect(summaries.nth(1).locator("..")).not.toHaveAttribute("open");
  await page
    .getByLabel("Target · domain or IP, optional port", { exact: true })
    .fill("internal.example:9443");
  await expect(summaries).toHaveCount(3);
  rows[1] = {
    ...rows[1]!,
    status: "reachable",
    stage: "connect",
    duration_ms: 19,
    connect_latency_ms: 12,
  };
  data.operations[0]!.status = "canceled";
  await expect(summaries.nth(1)).toHaveAttribute("aria-busy", "false");
  await expect(summaries.nth(1)).toContainText("19 ms");
  await expect(summaries.nth(2)).toContainText("Not run");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("@compat diagnostic history survives reload and DNS compares system and KONE resolution", async ({
  page,
}) => {
  const data = await fixture(page);
  await page.goto("/#/outbounds");
  await page.getByRole("button", { name: "Diagnostics", exact: true }).click();
  await page
    .getByRole("combobox", { name: "Target · domain or IP, optional port" })
    .fill("internal.example");
  await page.getByRole("button", { name: "Start comparison", exact: true }).click();
  await expect.poll(() => data.operations.length).toBe(1);
  expect(
    data.requests.find((entry) => entry.path === "/diagnostics" && entry.method === "POST")?.body,
  ).toMatchObject({ target: "internal.example:80", tls: false });
  // The server fixture records requests before the browser receives the reply.
  // Wait for the client to persist the accepted target before navigating away.
  await expect
    .poll(() => page.evaluate(() => localStorage.getItem("kone.diagnostic-history.v1")))
    .toContain("internal.example:80");
  await page.reload();
  await page.getByRole("button", { name: "Diagnostics", exact: true }).click();
  await page.getByRole("button", { name: "Recent targets", exact: true }).click();
  const trigger = page.getByRole("button", { name: "Recent targets", exact: true });
  await expect(trigger.locator("svg")).toBeVisible();
  expect(await trigger.evaluate((el) => getComputedStyle(el).appearance)).toBe("none");
  await page.getByRole("option", { name: /internal.example:80/ }).click();
  await expect(
    page.getByRole("combobox", { name: "Target · domain or IP, optional port" }),
  ).toHaveValue("internal.example:80");
  await page.getByRole("button", { name: "DNS query", exact: true }).click();
  await expect(page.getByLabel("Verify target TLS")).not.toBeVisible();
  const name = page.getByRole("combobox", { name: "Query name" });
  await expect(name).toHaveValue("example.com");
  await expect(page.getByLabel("Outbound", { exact: true })).not.toBeVisible();
  await name.fill("service.internal");
  await page.getByLabel("DNS query type", { exact: true }).selectOption("AAAA");
  await page.getByRole("button", { name: "Compare DNS", exact: true }).click();
  await expect.poll(() => data.operations.length).toBe(2);
  expect(data.requests.filter((entry) => entry.path === "/diagnostics/dns").at(-1)?.body).toEqual({
    name: "service.internal",
    type: "AAAA",
  });
  const summaries = page.locator("summary").filter({ hasText: "service.internal" });
  await expect(summaries).toHaveCount(2);
  await expect(summaries.nth(0)).toContainText("System DNS");
  await expect(summaries.nth(1)).toContainText("KONE DNS");
  await expect(summaries.nth(1)).toContainText("<1 ms");
  await summaries.nth(1).click();
  await expect(page.getByText("Saved settings · capture paused", { exact: true })).toBeVisible();
  await expect(page.getByText("example.com. 30 IN AAAA fd00::4", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Recent targets", exact: true }).click();
  await expect(page.getByRole("option", { name: /service.internal/ })).toBeVisible();
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Connection", exact: true }).click();
  await expect(
    page.getByRole("combobox", { name: "Target · domain or IP, optional port" }),
  ).toHaveValue("internal.example:80");
  await page.getByRole("button", { name: "Recent targets", exact: true }).click();
  await expect(
    page.getByRole("listbox", { name: "Recent targets" }).getByRole("option"),
  ).toHaveCount(3);
  await page.getByRole("option", { name: /internal.example:80/ }).click();
  await page.getByRole("button", { name: "Start comparison", exact: true }).click();
  await expect.poll(() => data.operations.length).toBe(3);
  await page.getByRole("button", { name: "Recent targets", exact: true }).click();
  await expect(
    page.getByRole("listbox", { name: "Recent targets" }).getByRole("option"),
  ).toHaveCount(3);
});

test("@compat Resolvers separates Host and Gate from automatic upstream selection", async ({
  page,
}) => {
  const data = await fixture(page);
  data.state.state = "paused";
  data.state.capture_locked = false;
  await page.goto("/#/settings?section=resolvers");
  await expect(page.getByRole("button", { name: "Host · this PC", exact: true })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(page.getByLabel("Discovered upstream DNS")).toContainText("192.168.40.1:53");
  await expect(page.getByLabel("LAN listener address", { exact: true })).not.toBeVisible();
  await page.getByRole("button", { name: "Gate · LAN", exact: true }).click();
  await expect(page.getByLabel("LAN listener address", { exact: true })).toHaveValue(
    "192.168.40.2",
  );
  await expect(page.getByLabel("Port", { exact: true })).toHaveValue("53");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => data.document.config.dns.mode).toBe("gate");
  expect(data.document.config.dns.system).toBe(false);
  expect(data.document.config.dns.servers ?? []).toEqual([]);
  data.dnsFallback = true;
  await page.getByRole("button", { name: "Refresh discovery", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("No usable system DNS was discovered");
  await expect(page.getByLabel("Discovered upstream DNS")).toContainText("8.8.8.8:53");
  await page.getByRole("button", { name: "Custom servers", exact: true }).click();
  const servers = page.getByRole("textbox", { name: "Upstream DNS servers", exact: true });
  await expect(servers).toContainText("8.8.8.8:53");
  await servers.fill("192.168.40.53");
  await page.getByRole("button", { name: "Host · this PC", exact: true }).click();
  await expect(page.getByLabel("LAN listener address", { exact: true })).not.toBeVisible();
  await expect(servers).toHaveValue("192.168.40.53");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => data.document.config.dns.mode).toBe("host");
  expect(data.document.config.dns.system).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("@compat health combines ports in Overview and pins a verified selection with one click", async ({
  page,
}) => {
  const data = await fixture(page);
  data.state.data_state = "running";
  data.state.state = "running";
  const actions: string[] = [];
  const entry = {
    id: 1,
    generation: 2,
    domain: "service.example",
    scope: "",
    status: "attention",
    reason: "web_unreachable",
    expires: new Date(Date.now() + 240000).toISOString(),
    first: new Date().toISOString(),
    last: new Date().toISOString(),
    count: 2,
    suggestions: { "443": "Local HTTP" },
    results: [
      {
        protocol: "tcp",
        port: 80,
        source: "probe",
        outbound: "direct",
        status: "failed",
        stage: "connect",
        duration_ms: 3000,
        time: new Date().toISOString(),
      },
      {
        protocol: "tcp",
        port: 443,
        source: "probe",
        outbound: "direct",
        status: "failed",
        stage: "connect",
        duration_ms: 3000,
        time: new Date().toISOString(),
      },
    ],
  };
  await page.route("**/api/v1/connection-health*", async (route) => {
    const body = route.request().postDataJSON();
    if (body) {
      actions.push(body.action);
      if (body.action === "pin") {
        entry.status = "history";
        return route.fulfill({
          contentType: "application/json",
          body: JSON.stringify({ ...data.document, applied: true }),
        });
      }
      if (body.action === "handled") entry.status = "history";
    }
    return route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        status: "running",
        auto_enabled: false,
        entries: [entry],
        total: 1,
        dropped: 0,
      }),
    });
  });
  await page.goto("/#/traffic?view=overview");
  const health = page.getByRole("region", { name: "Connection health" });
  await expect(health.getByRole("button", { name: "service.example", exact: true })).toBeVisible();
  await expect(health.getByRole("columnheader", { name: "Port status", exact: true })).toHaveCount(
    1,
  );
  await health.getByRole("button", { name: "Pin as manual rule", exact: true }).click();
  await expect.poll(() => actions).toEqual(["pin"]);
  await expect(health.getByRole("button", { name: "service.example", exact: true })).toHaveCount(0);
  await health.getByRole("button", { name: "History", exact: true }).click();
  await expect(health.getByRole("button", { name: "service.example", exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("@compat comfortable changes typography and offline errors stay out of page flow", async ({
  page,
}) => {
  const data = await fixture(page);
  await page.goto("/#/settings?section=interface");
  const bodySize = () => page.evaluate(() => getComputedStyle(document.documentElement).fontSize);
  const before = await bodySize();
  await page.getByLabel("Density", { exact: true }).selectOption("comfortable");
  await expect.poll(bodySize).not.toBe(before);
  await page.reload();
  await expect.poll(bodySize).toBe("15px");
  const main = page.locator("main");
  const top = (await main.boundingBox())!.y;
  data.offline = true;
  await expect(page.locator(".errorToast")).toBeVisible({ timeout: 15000 });
  await expect(page.locator('main [role="alert"]')).toHaveCount(0);
  expect((await main.boundingBox())!.y).toBe(top);
  await expect(page.locator(".errorToast")).toHaveCount(0, { timeout: 12000 });
  await page.getByRole("button", { name: "Errors 1", exact: true }).click();
  await expect(page.getByRole("region", { name: "Error history" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Error history" })).toContainText(
    "Cannot reach this KONE host",
  );
});
