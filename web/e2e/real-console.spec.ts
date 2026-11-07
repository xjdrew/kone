import { test, expect } from "@playwright/test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startManager, networkFingerprint, assertNoCaptureJournal } from "./real-manager.mjs";

// These journeys enter synthetic credentials. Keep traces and screenshots off.
test.use({ trace: "off", screenshot: "off", video: "off" });
test("@real management credentials, policy edits and process restart remain capture-paused", async ({
  browser,
}) => {
  const binary = process.env.KONE_MANAGEMENT_TEST_BINARY;
  if (!binary) throw new Error("Run just ci test-web-e2e to build the genuine manager fixture");
  const directory = await mkdtemp(join(tmpdir(), "kone-react-real-"));
  const before = await networkFingerprint();
  let manager = await startManager(binary, directory);
  const context = await browser.newContext();
  const page = await context.newPage();
  const forbidden: string[] = [];
  await context.addInitScript(() => {
    localStorage.setItem("kone.locale", "en");
  });
  await page.route("**/api/v1/lifecycle/**", (route) => {
    forbidden.push(route.request().url());
    return route.abort();
  });
  try {
    await page.goto(manager.url.origin + "/");
    await expect(page.getByRole("heading", { name: "Traffic paths" })).toBeVisible();
    await expect(page.getByRole("switch", { name: "Enable proxy" })).toBeEnabled();
    await page.getByRole("link", { name: "Policy", exact: true }).click();
    await page.getByRole("link", { name: "Outbounds", exact: true }).click();
    await page.getByRole("button", { name: "Add outbound", exact: true }).first().click();
    let dialog = page.getByRole("dialog");
    await dialog.getByLabel("Name", { exact: true }).fill("Fixture proxy");
    await dialog.getByLabel("Address", { exact: true }).fill("127.0.0.1");
    await dialog.getByLabel("Port", { exact: true }).fill("7078");
    await dialog.getByLabel("Credentials", { exact: true }).selectOption("replace");
    await dialog.getByLabel("Username", { exact: true }).fill("fixture-user");
    await dialog.getByLabel("Password / key", { exact: true }).fill("fixture-proxy-password");
    await dialog.getByRole("button", { name: "Save", exact: true }).click();
    await expect(dialog).not.toBeVisible();
    await page.getByRole("button", { name: "Fixture proxy", exact: true }).click();
    dialog = page.getByRole("dialog");
    await expect(dialog.getByLabel("Credentials", { exact: true })).toHaveValue("preserve");
    await expect(dialog.getByLabel("Password / key", { exact: true })).toHaveCount(0);
    await dialog.getByLabel("Name", { exact: true }).fill("Office");
    await dialog.getByRole("button", { name: "Save", exact: true }).click();
    await expect(dialog).not.toBeVisible();
    await page.getByRole("link", { name: "Rules", exact: true }).click();
    await page.getByRole("button", { name: "Add rule", exact: true }).first().click();
    dialog = page.getByRole("dialog");
    await dialog.getByLabel("Match type").selectOption("IP-CIDR");
    await dialog.getByLabel("Domain / address / country").fill("149.154.167.50/32");
    await dialog.getByLabel("Protocol", { exact: true }).selectOption("tcp");
    await dialog.getByLabel("Ports", { exact: true }).fill("443");
    await dialog.getByLabel("Outbound", { exact: true }).selectOption("Office");
    await dialog.getByRole("button", { name: "Save", exact: true }).click();
    await expect(dialog).not.toBeVisible();
    await expect(
      page.getByRole("button", { name: "149.154.167.50/32", exact: true }),
    ).toBeVisible();
    await page.getByRole("link", { name: "Settings", exact: true }).click();
    await page.getByRole("link", { name: "Access", exact: true }).click();
    await page.getByLabel("New password", { exact: true }).fill("fixture-management-password");
    await page.getByLabel("Confirm password", { exact: true }).fill("fixture-management-password");
    await page.getByRole("button", { name: "Set management password", exact: true }).click();
    await expect(page.getByRole("button", { name: "Change password", exact: true })).toBeVisible();
    await page.reload();
    await expect(page.getByRole("heading", { name: "Settings", exact: true })).toBeVisible();
    const saved = await page.evaluate(async () => {
      const state = await (await fetch("/api/v1/state")).json();
      const doc = await (await fetch("/api/v1/config")).json();
      return {
        paused: state.data_state === "paused",
        version: doc.version,
        name: doc.config.outbounds[0].name,
        credential: doc.credential_state.Office.configured,
        redacted: !JSON.stringify(doc).includes("fixture-proxy-password"),
      };
    });
    expect(saved).toMatchObject({ paused: true, name: "Office", credential: true, redacted: true });
    await assertNoCaptureJournal(directory);
    await manager.stop();
    manager = await startManager(binary, directory);
    await page.goto(manager.url.origin + "/#/policy");
    await expect(
      page.getByRole("button", { name: "149.154.167.50/32", exact: true }),
    ).toBeVisible();
    const restarted = await page.evaluate(async () => {
      const state = await (await fetch("/api/v1/state")).json();
      const doc = await (await fetch("/api/v1/config")).json();
      return {
        paused: state.data_state === "paused",
        version: doc.version,
        outbound: doc.config.rules[0].outbound,
        credential: doc.credential_state.Office.configured,
      };
    });
    expect(restarted).toEqual({
      paused: true,
      version: saved.version,
      outbound: "Office",
      credential: true,
    });
    expect(forbidden).toHaveLength(0);
    await assertNoCaptureJournal(directory);
    expect(await networkFingerprint()).toEqual(before);
  } finally {
    await context.close();
    await manager.stop();
    await rm(directory, { recursive: true, force: true });
  }
});
