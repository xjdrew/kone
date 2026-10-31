import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";
const chrome =
  process.env.KONE_BROWSER_PATH ||
  (process.platform === "win32" &&
  existsSync("C:/Program Files/Google/Chrome/Application/chrome.exe")
    ? "C:/Program Files/Google/Chrome/Application/chrome.exe"
    : undefined);
export default defineConfig({
  testDir: "./e2e",
  testMatch: "**/*.spec.js",
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  expect: { timeout: 7000 },
  reporter: [
    ["list"],
    ["html", { open: "never", outputFolder: "playwright-report" }],
    ["json", { outputFile: "test-results/results.json" }],
  ],
  use: {
    baseURL: "http://127.0.0.1:4173",
    headless: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium-1440x900",
      use: {
        browserName: "chromium",
        viewport: { width: 1440, height: 900 },
        launchOptions: chrome ? { executablePath: chrome } : {},
      },
    },
    {
      name: "webkit-touch-390x844",
      grep: /@compat/,
      use: {
        browserName: "webkit",
        viewport: { width: 390, height: 844 },
        hasTouch: true,
        isMobile: true,
      },
    },
    {
      name: "firefox-touch-390x844",
      grep: /@compat/,
      use: {
        browserName: "firefox",
        viewport: { width: 390, height: 844 },
        hasTouch: true,
      },
    },
  ],
  webServer: {
    command: "node e2e/server.mjs",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
  },
});
