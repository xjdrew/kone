import { test, expect } from "@playwright/test";
import { spawn } from "node:child_process";
import { access, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

// Authentication URLs and credential-entry fields must not enter traces or
// screenshots. The ordinary fixture tests retain their normal diagnostics.
test.use({ trace: "off", screenshot: "off", video: "off" });

async function within(promise, milliseconds) {
  let timer;
  try { return await Promise.race([promise, new Promise((resolve) => { timer = setTimeout(() => resolve(null), milliseconds); })]); }
  finally { clearTimeout(timer); }
}
const redact = (value) => String(value)
  .replace(/(#token=)[^\s&]+/g, "$1REDACTED")
  .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/g, "$1REDACTED@");

async function startManager(binary, directory) {
  const child = spawn(binary, ["-manage", "-no-browser", "-no-tray", "-listen", "127.0.0.1:0", "-data-dir", directory], {
    cwd: directory,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "", diagnostics = "", settled = false;
  let accept, reject;
  const ready = new Promise((resolve, fail) => { accept = resolve; reject = fail; });
  const timer = setTimeout(() => reject(new Error(`Real manager startup timed out: ${redact(diagnostics)}`)), 12000);
  const done = new Promise((resolve) => {
    child.once("error", () => { settled = true; reject(new Error("Cannot launch the real management test binary")); resolve({ code: null, signal: "spawn-error" }); });
    child.once("exit", (code, signal) => { settled = true; reject(new Error(`Real manager stopped before readiness (${code ?? signal})`)); resolve({ code, signal }); });
  });
  child.stderr.on("data", (chunk) => { diagnostics = (diagnostics + chunk.toString()).slice(-8192); });
  child.stdout.on("data", (chunk) => {
    output = (output + chunk.toString()).slice(-16384);
    const match = output.match(/KONE management \(capture paused\): (http:\/\/127\.0\.0\.1:\d+\/(?:#token=[a-f0-9]{64})?)\r?\n/);
    if (match) accept(match[1]);
  });
  let stopping;
  const stop = () => stopping ||= (async () => {
    if (!settled) child.kill("SIGTERM");
    const outcome = await within(done, 8000);
    if (!outcome) {
      child.kill("SIGKILL"); // Only this owned child; forced cleanup remains a test failure.
      await within(done, 2000);
      throw new Error("Real manager did not stop gracefully after SIGTERM");
    }
    if (outcome.code !== 0 || outcome.signal) throw new Error(`Real manager did not exit cleanly (${outcome.code ?? outcome.signal}): ${redact(diagnostics)}`);
  })();
  try {
    const url = new URL(await ready);
    return { url, stop, pid: child.pid, done };
  } catch (error) {
    await stop().catch(() => {});
    throw error;
  } finally { clearTimeout(timer); }
}

async function networkFingerprint() {
  const digest = (value) => createHash("sha256").update(value).digest("hex");
  return {
    interfaces: (await readdir("/sys/class/net")).sort(),
    routes: digest(await readFile("/proc/net/route")),
    dns: digest(await readFile("/etc/resolv.conf")),
  };
}

async function assertNoCaptureJournal(directory) {
  try {
    await access(join(directory, "capture.json"));
    throw new Error("Management-only browser journey unexpectedly created a capture journal");
  } catch (error) { if (error.code !== "ENOENT") throw error; }
}

async function openManagement(browser, manager, ownedContexts) {
  const context = await browser.newContext();
  ownedContexts.push(context);
  const page = await context.newPage();
  const forbidden = [], states = [], pending = new Set();
  const allowed = new Set(["POST /api/v1/session", "POST /api/v1/auth/password", "POST /api/v1/config/validate", "PUT /api/v1/config"]);
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request(), url = new URL(request.url());
    const key = `${request.method()} ${url.pathname}`;
    if (url.searchParams.has("token") || (request.method() !== "GET" && !allowed.has(key))) {
      forbidden.push(key); // No headers, request bodies or credentials in diagnostics.
      return route.abort("blockedbyclient");
    }
    return route.continue(); // Every allowed response comes from the genuine Go server.
  });
  page.on("response", (response) => {
    if (new URL(response.url()).pathname !== "/api/v1/state" || !response.ok()) return;
    const task = response.json().then((state) => states.push({ state: state.state, data_state: state.data_state, running_version: state.running_version }));
    pending.add(task);
    task.finally(() => pending.delete(task)).catch(() => {});
  });
  // Install the actual one-use URL fragment before the first application script,
  // without putting a credential in Playwright's navigation-step URL or traces.
  await context.addInitScript(({ origin, fragment }) => {
    if (location.origin === origin && !sessionStorage.getItem("real-bootstrap-installed")) {
      sessionStorage.setItem("real-bootstrap-installed", "1");
      history.replaceState(null, "", `/${fragment}`);
    }
  }, { origin: manager.url.origin, fragment: manager.url.hash });
  await page.goto(manager.url.origin + "/");
  const secretInput = page.locator("#setup-password, #login-password").first();
  await expect(secretInput).toBeVisible();
  if (await page.locator("#setup-password").isVisible()) {
    await page.locator("#setup-password").fill("browser-fixture-management-password");
    await page.locator("#setup-password-confirm").fill("browser-fixture-management-password");
    await page.getByRole("button", { name: "设置管理密码", exact: true }).click();
  } else {
    await page.locator("#login-password").fill("browser-fixture-management-password");
    await page.getByRole("button", { name: "登录管理", exact: true }).click();
  }
  await expect(page.getByRole("heading", { name: "首页", exact: true })).toBeVisible();
  await expect(page).toHaveURL(/(?:\/|#home)$/);
  const cookies = await context.cookies(manager.url.origin);
  const session = cookies.find((cookie) => cookie.name === "kone_session");
  expect(Boolean(session?.httpOnly)).toBe(true);
  expect(session?.sameSite).toBe("Strict");
  expect(await page.evaluate(() => document.cookie.includes("kone_session"))).toBe(false);
  const assertPaused = async () => {
    const state = await page.evaluate(async () => {
      const response = await fetch("/api/v1/state", { credentials: "same-origin" });
      if (!response.ok) throw new Error("Real cookie session cannot read manager state");
      const value = await response.json();
      return { state: value.state, data_state: value.data_state, running_version: value.running_version };
    });
    states.push(state);
    await Promise.all([...pending]);
    expect(forbidden).toEqual([]);
    expect(states.length).toBeGreaterThan(0);
    for (const observed of states) expect(observed).toEqual({ state: "paused", data_state: "paused", running_version: 0 });
  };
  return { context, page, assertPaused };
}

test("@real genuine management cookie, save, reload and restart stay capture-paused", async ({ browser }) => {
  test.setTimeout(60000);
  const binary = process.env.KONE_MANAGEMENT_TEST_BINARY;
  if (process.env.CI && process.platform === "linux") expect(Boolean(binary), "CI must supply the real management binary").toBe(true);
  test.skip(process.platform !== "linux" || !binary, "requires opt-in Linux CI binary; never executes a local Windows Go program");
  // Defense in depth: an unexpected UI action cannot gain host CAP_NET_ADMIN.
  const capabilities = (await readFile("/proc/self/status", "utf8")).match(/^CapEff:\s*([0-9a-f]+)$/mi);
  expect(Boolean(capabilities)).toBe(true);
  expect((BigInt(`0x${capabilities[1]}`) & (1n << 12n)) === 0n).toBe(true);
  const originalNetwork = await networkFingerprint();
  const directory = await mkdtemp(join(tmpdir(), "kone-real-browser-"));
  const managers = [], contexts = [];
  let failure;
  try {
    let manager = await startManager(binary, directory);
    managers.push(manager);
    let ui = await openManagement(browser, manager, contexts);
    await ui.assertPaused();
    await ui.page.locator(".nav-link[data-page=diagnostics]").click();
    await expect(ui.page.getByRole("heading", { name: "运行日志", exact: true })).toBeVisible();
    const logs = await ui.page.evaluate(async () => {
      const response = await fetch("/api/v1/logs?limit=100&min_level=info", { credentials: "same-origin" });
      const value = await response.json();
      return { ok: response.ok, records: Array.isArray(value.records), cursor: typeof value.next_cursor, helperConnected: value.helper?.connected };
    });
    expect(logs).toEqual({ ok: true, records: true, cursor: "string", helperConnected: false });
    await ui.assertPaused();
    await ui.page.locator(".nav-link[data-page=outbounds]").click();
    await ui.page.getByRole("button", { name: "＋ 添加代理", exact: true }).click();
    await ui.page.locator("#outbound-name-0").fill("BrowserReal");
    await ui.page.locator("#outbound-url-0").fill("http://127.0.0.1:18080");
    await ui.page.locator("#outbound-credentials-0").selectOption("replace");
    await ui.page.locator("#outbound-username-0").fill("browser-fixture-user");
    await ui.page.locator("#outbound-password-0").fill("not-a-real-proxy-password");
    await ui.page.getByRole("button", { name: "保存", exact: true }).click();
    await ui.page.locator("#outbound-save-untested").click();
    await expect(ui.page.locator("#page-notice")).toContainText("已保存");
    await ui.assertPaused();
    await ui.page.locator(".nav-link[data-page=rules]").click();
    await ui.page.getByRole("button", { name: "＋ 添加精确域名", exact: true }).click();
    await ui.page.locator("#rule-pattern-0").fill("saved-browser.example");
    await ui.page.locator("#rule-outbound-0").selectOption("BrowserReal");
    await ui.page.locator("#rule-protocol-0").selectOption("tcp");
    await ui.page.locator("#rule-ports-0").fill("443");
    await ui.page.getByRole("button", { name: "保存", exact: true }).click();
    await expect(ui.page.locator("#page-notice")).toContainText("已保存");
    await ui.page.reload();
    await ui.page.locator('[data-rule-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
    await expect(ui.page.locator("#rule-pattern-0")).toHaveValue("saved-browser.example");
    await expect(ui.page.locator("#rule-outbound-0")).toHaveValue("BrowserReal");
    await ui.page.getByRole("button", { name: "取消编辑", exact: true }).click();
    const verifySaved = async () => {
      await ui.page.locator(".nav-link[data-page=outbounds]").click();
      await expect(ui.page.locator("#outbound-name-0")).toHaveCount(0);
      await ui.page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
      await expect(ui.page.locator("#outbound-name-0")).toHaveValue("BrowserReal");
      const value = await ui.page.locator("#outbound-url-0").inputValue();
      expect(value.includes("REDACTED")).toBe(true);
      expect(value.includes("browser-fixture-user") || value.includes("not-a-real-proxy-password")).toBe(false);
      await expect(ui.page.locator("#outbound-password-0")).toHaveCount(0);
      await ui.page.getByRole("button", { name: "取消编辑", exact: true }).click();
      await ui.assertPaused();
      await assertNoCaptureJournal(directory);
      const persisted = JSON.parse(await readFile(join(directory, "settings.json"), "utf8"));
      // Only boolean evidence leaves this scope; never dump credential-bearing
      // files or include their values in failed assertion diagnostics.
      expect(typeof persisted.toml === "string" && persisted.toml.includes("browser-fixture-user")).toBe(true);
      expect(typeof persisted.toml === "string" && persisted.toml.includes("not-a-real-proxy-password")).toBe(true);
      const descendants = await readFile(`/proc/${manager.pid}/task/${manager.pid}/children`, "utf8");
      expect(descendants.trim()).toBe("");
    };
    await verifySaved();
    await ui.context.close();
    await manager.stop();
    manager = await startManager(binary, directory);
    managers.push(manager);
    ui = await openManagement(browser, manager, contexts);
    await verifySaved();
    await ui.page.locator(".nav-link[data-page=rules]").click();
    await ui.page.locator('[data-rule-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
    await expect(ui.page.locator("#rule-pattern-0")).toHaveValue("saved-browser.example");
    await expect(ui.page.locator("#rule-outbound-0")).toHaveValue("BrowserReal");
    await expect(ui.page.locator("#rule-protocol-0")).toHaveValue("tcp");
    await expect(ui.page.locator("#rule-ports-0")).toHaveValue("443");
    await ui.assertPaused();
  } catch (error) { failure = error; }
  finally {
    for (const context of contexts) await context.close().catch(() => {});
    for (const manager of managers) {
      try { await manager.stop(); } catch (error) { failure ||= error; }
    }
    try {
      await assertNoCaptureJournal(directory);
      expect(await networkFingerprint()).toEqual(originalNetwork);
    } catch (error) { failure ||= error; }
    await rm(directory, { recursive: true, force: true });
  }
  if (failure) throw failure;
});
