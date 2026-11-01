import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  request,
  bootstrap,
  ApiError,
  targetWithPort,
  flowQueryChunks,
  normalizeTraffic,
  exactRuleTarget,
  explainError,
} from "../src/api.js";
const originalFetch = globalThis.fetch;

test("disabled TUN errors explain the required saved inbound setting", async () => {
  const message = "enable the TUN inbound before starting capture";
  globalThis.fetch = async () => new Response(JSON.stringify({ error: { message } }), { status: 400 });
  await assert.rejects(request("/lifecycle/start", "POST", {}), /入站.*TUN.*保存/);
  assert.equal(explainError("other failure"), "other failure");
});

test("rule shortcuts retain exact domain, address, port and known transport scope", () => {
  assert.deepEqual(exactRuleTarget("Example.COM.:443", "udp"), {
    type: "DOMAIN", pattern: "example.com", protocol: "udp", ports: [443], source: "one-click",
  });
  assert.deepEqual(exactRuleTarget("192.0.2.9:8443", "tcp"), {
    type: "IP-CIDR", pattern: "192.0.2.9/32", protocol: "tcp", ports: [8443], source: "one-click",
  });
  assert.deepEqual(exactRuleTarget("[fd7a:203::2]:53", "udp"), {
    type: "IP-CIDR6", pattern: "fd7a:203::2/128", protocol: "udp", ports: [53], source: "one-click",
  });
  assert.deepEqual(exactRuleTarget("fd7a:203::2"), {
    type: "IP-CIDR6", pattern: "fd7a:203::2/128", source: "one-click",
  });
  assert.equal(exactRuleTarget("example.com", "unknown").protocol, undefined);
  assert.equal(exactRuleTarget("example.com").ports, undefined);
});

test("retained traffic preserves its actual observation time without inventing freshness", () => {
  const timestamp = "2026-11-01T00:00:01Z";
  const snapshot = normalizeTraffic({
    traffic: { frozen: true, timestamp, records: [], totals: { active: 2 } },
    sankey: { frozen: true },
  });
  assert.equal(snapshot.frozen, true);
  assert.equal(snapshot.at, timestamp);
  assert.equal(snapshot.stats.active, 2);
  assert.equal(normalizeTraffic({ frozen: true }).at, "");
  assert.equal(normalizeTraffic({ traffic: {}, sankey: { frozen: true } }).frozen, true);
  assert.equal(normalizeTraffic({}).frozen, false);
});
afterEach(() => {
  globalThis.fetch = originalFetch;
  delete globalThis.location;
  delete globalThis.history;
});

test("diagnostic target formatting preserves explicit ports and brackets IPv6 literals", () => {
  assert.equal(targetWithPort("example.com", 443), "example.com:443");
  assert.equal(targetWithPort("example.com:8443", 443), "example.com:8443");
  assert.equal(targetWithPort("fd7a:203::2", 443), "[fd7a:203::2]:443");
  assert.equal(targetWithPort("[fd7a:203::2]", 443), "[fd7a:203::2]:443");
  assert.equal(targetWithPort("[fd7a:203::2]:8443", 443), "[fd7a:203::2]:8443");
});

test("large graph drilldown stays bounded while preserving exact sampled membership", () => {
  const ids = Array.from(
    { length: 1200 },
    (_, i) => `session-12345678901234567890-${i}`,
  );
  const paths = Array.from(
    { length: 800 },
    (_, i) => `path-12345678901234567890-${i}`,
  );
  const queries = flowQueryChunks(
    { anchor: "s:1200", since: "start", until: "end" },
    paths,
    ids,
  );
  assert.equal(queries.length, 12);
  assert.deepEqual(
    queries.flatMap((query) => query.flow_ids.split(",")),
    ids,
  );
  for (const query of queries) {
    assert.equal(query.anchor, "s:1200");
    assert.equal(query.since, "start");
    assert.ok(new URLSearchParams(query).toString().length < 8000);
  }
});

test("bootstrap removes URL token before exchange and uses cookie/CSRF after exchange", async () => {
  globalThis.location = { hash: "#token=once-only", pathname: "/", search: "" };
  let removed = false;
  const calls = [];
  globalThis.history = {
    replaceState: (_state, _title, url) => {
      assert.equal(url, "/#home");
      removed = true;
    },
  };
  globalThis.fetch = async (path, options) => {
    assert.equal(removed, true);
    calls.push({ path, ...options });
    return new Response(
      JSON.stringify(
        path.endsWith("/session")
          ? { csrf_token: "csrf-test" }
          : { role: "admin" },
      ),
      { status: 200 },
    );
  };
  await bootstrap();
  await request("/config/apply", "POST", {});
  assert.equal(calls[0].headers.Authorization, "Bearer once-only");
  assert.equal(calls[1].headers.Authorization, undefined);
  assert.equal(calls[2].headers.Authorization, undefined);
  assert.equal(calls[2].headers["X-CSRF-Token"], "csrf-test");
  assert.equal(calls[2].credentials, "same-origin");
  assert.ok(calls[2].headers["X-Request-ID"]);
});

test("write version conflicts remain explicit and never automatically retry", async () => {
  let count = 0;
  globalThis.fetch = async () => {
    count++;
    return new Response(
      JSON.stringify({
        error: { code: "version_conflict", message: "Version conflict" },
      }),
      { status: 409 },
    );
  };
  await assert.rejects(
    request("/config", "PUT", {}),
    (error) =>
      error instanceof ApiError &&
      error.status === 409 &&
      error.details.code === "version_conflict",
  );
  assert.equal(count, 1);
});

test("first-time bootstrap keeps only setup authorization and never reads management data", async () => {
  globalThis.location = { hash: "#token=initial-setup-only", pathname: "/", search: "" };
  globalThis.history = { replaceState: () => {} };
  const calls = [];
  globalThis.fetch = async (path, options) => {
    calls.push({ path, ...options });
    assert.equal(path, "/api/v1/session");
    return new Response(JSON.stringify({ role: "setup", setup_required: true, csrf_token: "setup-csrf" }), { status: 200 });
  };
  const result = await bootstrap();
  assert.equal(result.setup_required, true);
  assert.equal(result.authenticated, false);
  assert.equal(result.setup_authorized, true);
  assert.equal(calls.length, 1);
  globalThis.fetch = async (_path, options) => {
    assert.equal(options.headers.Authorization, undefined);
    assert.equal(options.headers["X-CSRF-Token"], "setup-csrf");
    return new Response(JSON.stringify({ role: "admin" }), { status: 200 });
  };
  await request("/auth/password", "POST", { password: "fixture-password", confirm_password: "fixture-password" });
});

test("diagnostic bootstrap strips credentials before exchange and only navigates", async () => {
  globalThis.location = { hash: "#token=diagnostic-one-use&page=diagnostics", pathname: "/", search: "" };
  const calls = [];
  globalThis.history = {
    replaceState: (_state, _title, target) => {
      assert.equal(target, "/#diagnostics");
      globalThis.location.hash = "#diagnostics";
    },
  };
  globalThis.fetch = async (path, options) => {
    assert.equal(globalThis.location.hash, "#diagnostics");
    calls.push({ path, ...options });
    return new Response(JSON.stringify({ role: "admin", csrf_token: "diagnostic-csrf" }), { status: 200 });
  };
  await bootstrap();
  assert.deepEqual(calls.map(({ path, method }) => [path, method]), [["/api/v1/session", "POST"], ["/api/v1/state", "GET"]]);
  assert.equal(JSON.parse(calls[0].body).token, "diagnostic-one-use");
  assert.equal(calls[1].headers.Authorization, undefined);
  assert.ok(calls.every(({ path }) => !path.includes("token=") && !path.includes("diagnostics")));
});

test("bootstrap page parameters use an explicit home/diagnostics whitelist", async () => {
  for (const page of ["settings", "https://example.com", "javascript:alert(1)", "diagnostics?probe=1", "DIAGNOSTICS"]) {
    globalThis.location = { hash: `#token=once&page=${encodeURIComponent(page)}`, pathname: "/", search: "" };
    let scrubbed = false;
    globalThis.history = { replaceState: (_state, _title, target) => { assert.equal(target, "/#home"); scrubbed = true; } };
    globalThis.fetch = async () => { assert.equal(scrubbed, true); return new Response(JSON.stringify({ role: "admin" }), { status: 200 }); };
    await bootstrap();
  }
});

test("an expired bootstrap token cannot override a later pairing session cookie", async () => {
  globalThis.location = { hash: "#token=expired", pathname: "/", search: "" };
  globalThis.history = { replaceState: () => {} };
  const calls = [];
  globalThis.fetch = async (path, options) => {
    calls.push(options.headers);
    return new Response(
      JSON.stringify(
        path.endsWith("/session")
          ? { error: { message: "Expired" } }
          : { role: "read" },
      ),
      { status: path.endsWith("/session") ? 401 : 200 },
    );
  };
  await assert.rejects(bootstrap());
  await request("/state");
  assert.equal(calls[0].Authorization, "Bearer expired");
  assert.equal(calls[1].Authorization, undefined);
});

test("a timed-out mutation reports uncertainty without resubmitting", async () => {
  let count = 0;
  globalThis.fetch = async (_path, options) => {
    count++;
    return new Promise((_resolve, reject) =>
      options.signal.addEventListener("abort", () =>
        reject(new DOMException("Aborted", "AbortError")),
      ),
    );
  };
  await assert.rejects(
    request("/lifecycle/start", "POST", {}, { timeout: 5 }),
    (error) => error instanceof ApiError && error.details.uncertain === true,
  );
  assert.equal(count, 1);
});

test("redacted TOML export is read as text while API errors stay structured", async () => {
  globalThis.fetch = async () =>
    new Response('[core]\nstack="system"\n', { status: 200 });
  assert.equal(
    await request("/export", "GET", undefined, { responseType: "text" }),
    '[core]\nstack="system"\n',
  );
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ error: { message: "Not authorized" } }), {
      status: 403,
    });
  await assert.rejects(
    request("/export", "GET", undefined, { responseType: "text" }),
    (error) => error.message === "Not authorized",
  );
});
