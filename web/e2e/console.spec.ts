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
  await expect(dialog.getByRole("alert")).toBeVisible();
  await dialog.getByRole("alert").getByText("Technical details").click();
  await expect(dialog.getByText("Host check failed")).toBeVisible();
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
  data.readiness = { ...data.readiness, ready: true, blockers: [], checks: [] };
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
  await dialog.getByLabel("Routing policy").selectOption("proxy-first");
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
  await page.getByLabel("Optional preset…", { exact: true }).selectOption("telegram");
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
  await expect(page.getByRole("heading", { name: "Traffic paths" })).toBeVisible();
  await expect(page.getByRole("switch", { name: "Enable proxy" })).toBeDisabled();
  data.authenticated = false;
  await expect(page.getByRole("heading", { name: "Open your network workspace" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Traffic paths" })).toHaveCount(0);
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
    page.getByRole("heading", { name: "Connection diagnostics", exact: true }),
  ).toBeVisible();
  await expect(page.getByLabel("Optional preset…")).toHaveValue("");
  await expect(page.getByLabel("Target · domain or IP:port", { exact: true })).toHaveValue("");
  const summaries = page.locator("summary").filter({ hasText: target });
  await expect(summaries).toHaveCount(3);
  await expect(summaries.nth(2)).toContainText("Pending");
  await expect(summaries.nth(1)).toHaveAttribute("aria-busy", "true");
  await expect(summaries.nth(0).locator("..")).not.toHaveAttribute("open");
  await summaries.nth(0).click();
  await expect(summaries.nth(0).locator("..")).toHaveAttribute("open", "");
  await expect(summaries.nth(1).locator("..")).not.toHaveAttribute("open");
  await page
    .getByLabel("Target · domain or IP:port", { exact: true })
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
  await expect(summaries.nth(1)).toContainText("12 ms");
  await expect(summaries.nth(2)).toContainText("Not run");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
