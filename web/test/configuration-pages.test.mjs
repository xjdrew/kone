import { test } from "node:test";
import assert from "node:assert/strict";
import { createConfigurationPages, outboundAddress, currentHealth } from "../src/configuration-pages.js";

test("health expires even when the user has not refreshed the status page", () => {
  const now = Date.parse("2026-11-01T12:00:00Z");
  assert.equal(currentHealth({ status: "healthy", expires_at: "2026-11-01T12:01:00Z" }, now), true);
  for (const value of [{ status: "healthy", expires_at: "2026-11-01T11:59:59Z" }, { status: "healthy" }, { status: "healthy", expires_at: "invalid" }, { status: "healthy", expires_at: "2026-11-01T12:01:00Z", stale: true }, { status: "unhealthy", expires_at: "2026-11-01T12:01:00Z" }])
    assert.equal(currentHealth(value, now), false);
});

test("configuration summaries never expose proxy userinfo or path secrets", () => {
  assert.equal(outboundAddress("socks5://alice:private-password@127.0.0.1:1080/private?token=hidden"), "socks5://127.0.0.1:1080");
  assert.equal(outboundAddress("ss://opaque-credential@proxy.example:443"), "ss://proxy.example:443");
  assert.equal(outboundAddress("not a URL"), "地址尚未配置");
});

test("all configuration landing pages show saved resources without editable forms", () => {
  const h = (tag, attrs, ...children) => ({ tag, attrs, children: children.flat(Infinity).filter(Boolean) });
  const noop = () => {};
  const model = {
    config: { version: 3, inbound: { name: "Saved inbound", enabled: true }, config: { core: {}, dns: {}, general: {}, outbounds: [{ id: "proxy-1", name: "Saved proxy", url: "http://alice:hidden@127.0.0.1:8080" }], rules: [{ type: "FINAL", outbound: "direct" }] } },
    draft: { outbounds: [{ name: "Unsaved proxy", url: "http://secret:secret@draft.invalid" }] },
    state: { running_version: 2, capture_locked: true }, outboundHealth: [], sessions: [], lan: {}, geoip: {}, online: true,
  };
  const ui = {
    model, h, card: (title, description, ...children) => h("section", {}, title, description, ...children),
    note: text => h("p", {}, text), button: (text, onclick, kind, disabled) => h("button", { onclick, disabled }, text),
    badge: text => h("span", {}, text), detailPairs: pairs => h("dl", {}, ...pairs.flat()), empty: text => h("p", {}, text), readonlyNote: () => null, time: String,
    canManage: () => true, runtime: () => "running", stateLabel: () => "正在接管", edit: noop, addOutbound: noop, addRule: noop, deleteOutbound: noop, deleteRule: noop, moveRule: noop, outboundDetails: noop, testOutbound: noop, refreshHealth: noop, preflight: noop, simulateRules: noop,
    dnsObservations: () => [h("section", {}, "DNS observations")], settingsObservations: () => [h("section", {}, "Settings status")],
  };
  const views = createConfigurationPages(ui);
  const collect = (nodes, result = []) => {
    for (const node of nodes.flat(Infinity)) {
      if (node && typeof node === "object") { result.push(node); collect(node.children || [], result); }
    }
    return result;
  };
  for (const [page, render] of Object.entries(views)) {
    const nodes = render();
    assert.ok(!collect(nodes).some(node => ["form", "input", "textarea", "select"].includes(node.tag)), `${page} must open forms only after an edit action`);
    const text = JSON.stringify(nodes);
    assert.doesNotMatch(text, /Unsaved proxy|private-password|alice:hidden|secret:secret/);
    if (page === "outbounds") assert.match(text, /Saved proxy/);
  }
  const inboundEdit = collect(views.inbounds()).find(node => node.tag === "button" && node.children.includes("编辑入站"));
  assert.equal(inboundEdit.attrs.disabled, true, "an active TUN cannot be edited from the landing page");
  model.config.capture_locked = true;
  model.state.capture_locked = false;
  ui.runtime = () => "paused";
  const paused = createConfigurationPages(ui);
  const afterPause = collect(paused.inbounds()).find(node => node.tag === "button" && node.children.includes("编辑入站"));
  assert.equal(afterPause.attrs.disabled, false, "fresh paused state overrides the stale document's lock flag");
});
