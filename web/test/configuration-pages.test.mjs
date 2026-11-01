import { test } from "node:test";
import assert from "node:assert/strict";
import { createConfigurationPages, outboundAddress, currentHealth, needsDirectConfirmation } from "../src/configuration-pages.js";

const element = (tag, attrs = {}, ...children) => ({ tag, attrs, children: children.flat(Infinity).filter(Boolean), getAttribute: name => attrs[name] });
const descendants = (nodes) => (Array.isArray(nodes) ? nodes : [nodes]).flatMap(node => node && typeof node === "object" ? [node, ...descendants(node.children || [])] : []);

function settingsHarness() {
  const model = {
    state: { version: "v1.2.3" }, config: { version: 7, config: { general: { "log-level": "warn" } } },
    draft: { general: { "log-level": "debug" } }, lan: {}, sessions: [], online: true, authBusy: false, busy: false,
  };
  const ui = {
    model, h: element, card: (title, description, ...children) => element("section", { "data-card-title": title }, ...children),
    note: text => element("p", {}, text), button: (text, onclick, kind, disabled, attrs = {}) => element("button", { onclick, disabled, ...attrs }, text),
    detailPairs: () => null, readonlyNote: () => null, runtime: () => "paused", canManage: () => true,
    settingsDetail: section => element("section", { "data-settings-detail": section }, element("input", { id: `${section}-field` })),
  };
  return { model, ui, render: () => createConfigurationPages(ui).settings() };
}

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

test("reset is available for inactive settings and leaves residual cleanup to the host", () => {
  const { model, ui, render } = settingsHarness();
  let state = "paused";
  ui.runtime = () => state;
  const reset = () => descendants(render()).find(node => node.attrs["data-settings-action"] === "reset");
  assert.equal(reset().attrs.disabled, false);
  state = "invalid_config";
  model.state.config_error = "Saved settings are damaged";
  assert.equal(reset().attrs.disabled, false, "reset can repair damaged settings without capture");
  for (state of ["running", "starting", "pausing", "stopping", "degraded", "preflight"]) {
    assert.equal(reset().attrs.disabled, true, state);
  }
  state = "paused";
  for (const boundary of ["capture_locked", "remote_session"]) {
    model.state[boundary] = true;
    assert.equal(reset().attrs.disabled, true, boundary);
    model.state[boundary] = false;
  }
  model.recovery = { required: true };
  assert.equal(reset().attrs.disabled, false, "the host automatically handles safe residual records");
  ui.canManage = () => false;
  assert.equal(reset().attrs.disabled, true, "read-only sessions cannot reset settings");
  assert.equal(descendants(render()).find(node => node.attrs["data-settings-action"] === "logout").attrs.disabled, false, "read-only sessions can sign out");
});

test("settings root has grouped navigation with About first and dangerous actions last", () => {
  const { render } = settingsHarness();
  const nodes = descendants(render());
  assert.equal(nodes.filter(node => Object.hasOwn(node.attrs, "data-settings-root")).length, 1);
  assert.deepEqual(nodes.filter(node => node.attrs["data-settings-group"]).map(node => node.attrs["data-settings-group"]), ["about", "application", "security", "maintenance", "actions"]);
  const links = nodes.filter(node => node.attrs["data-settings-link"]);
  assert.deepEqual(links.map(node => node.attrs["data-settings-link"]), ["about", "logs", "geoip", "lan", "account", "configuration", "privacy", "network"]);
  for (const link of links) assert.equal(link.attrs.href, `#settings/${link.attrs["data-settings-link"]}`);
  assert.deepEqual(nodes.filter(node => node.attrs["data-settings-action"]).map(node => node.attrs["data-settings-action"]), ["reset", "logout"]);
  assert.ok(!nodes.some(node => ["form", "input", "select", "textarea"].includes(node.tag)), "the root menu contains no configuration forms");
  const text = JSON.stringify(render());
  assert.match(text, /v1\.2\.3/);
  assert.match(text, /WARN/);
  assert.doesNotMatch(text, /DEBUG/);
});

test("settings detail renders only the selected subpage while retaining read-only navigation", () => {
  const { model, ui, render } = settingsHarness();
  ui.canManage = () => false;
  assert.equal(descendants(render()).filter(node => node.tag === "a").length, 8);
  for (const section of ["about", "logs", "geoip", "lan", "account", "configuration", "privacy", "network"]) {
    model.settingsSection = section;
    const nodes = descendants(render());
    assert.deepEqual(nodes.filter(node => node.attrs["data-settings-detail"]).map(node => node.attrs["data-settings-detail"]), [section]);
    assert.ok(!nodes.some(node => Object.hasOwn(node.attrs, "data-settings-root")));
  }
});

test("only first-time direct-only rules require the short capture confirmation", () => {
  const now = Date.parse("2026-11-01T12:00:00Z");
  const document = rules => ({ config: { rules } });
  assert.equal(needsDirectConfirmation(document([]), now), true);
  assert.equal(needsDirectConfirmation(document([{ outbound: "direct" }, { outbound: "reject" }]), now), true);
  assert.equal(needsDirectConfirmation({ ...document([]), direct_only_confirmed: true }, now), false);
  assert.equal(needsDirectConfirmation(document([{ outbound: "office" }]), now), false);
  assert.equal(needsDirectConfirmation(document([{ outbound: "office", "expires-at": "2026-11-01T11:59:59Z" }]), now), true);
  assert.equal(needsDirectConfirmation(document([{ outbound: "office", "expires-at": "2026-11-01T12:01:00Z" }]), now), false);
});
