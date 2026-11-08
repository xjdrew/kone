import { afterEach, describe, expect, test } from "bun:test";
import {
  addPreciseRule,
  exactRule,
  groupFlows,
  renamedOutbound,
  saveRequest,
  targetHost,
  flowTarget,
  pathDrill,
} from "../src/domain";
import {
  readDiagnosticHistory,
  rememberDiagnostic,
  diagnosticElapsed,
} from "../src/diagnostic-history";
import { diagnosticRequest } from "../src/diagnostic-request";
import { graphLayout } from "../src/graph-layout";
import { ApiError, clearSession, request, setSession } from "../src/api/client";
import { configuration, documentFixture, flowFixture, graphFixture } from "./factories";
import english from "../../pkg/locale/catalog/en.json";
import chinese from "../../pkg/locale/catalog/zh.json";
import { canEnable } from "../src/readiness";
import type { Readiness, ReadinessCheck } from "../src/model";

test("default direct routing needs no consent, but cannot bypass real blockers", () => {
  const permissions: ReadinessCheck = {
    id: "permissions",
    code: "privileges",
    severity: "error",
    status: "error",
    message: "CAP_NET_ADMIN is required",
    page: "settings",
  };
  const report: Readiness = {
    ready: true,
    direct_only: true,
    direct_only_confirmed: false,
    checks: [],
    blockers: [],
    warnings: [],
  };
  expect(canEnable(report)).toBe(true);
  expect(canEnable({ ...report, direct_only: false })).toBe(true);
  expect(canEnable({ ...report, ready: false, blockers: [permissions] })).toBe(false);
  expect(canEnable({ ...report, ready: false })).toBe(false);
  expect(canEnable({ ...report, blockers: [permissions] })).toBe(false);
});

describe("precise routing edits", () => {
  test("Telegram is one IPv4 TCP port, and the probe never sends TLS", () => {
    expect(exactRule("149.154.167.50:443", "tcp")).toMatchObject({
      type: "IP-CIDR",
      pattern: "149.154.167.50/32",
      protocol: "tcp",
      ports: [443],
    });
    expect(diagnosticRequest("149.154.167.50:443", "Local HTTP", "tcp", true, "", "")).toEqual({
      target: "149.154.167.50:443",
      outbounds: ["direct", "Local HTTP"],
      protocol: "tcp",
      tls: false,
    });
    expect(diagnosticRequest("www.google.com:443", "Local HTTP", "tcp", true, "", "").tls).toBe(
      true,
    );
  });
  test("DNS evidence does not invent transport scope; IPv6 remains one address", () => {
    const rule = exactRule("Example.COM.");
    expect(rule.pattern).toBe("example.com");
    expect(rule.protocol).toBeUndefined();
    expect(rule.ports).toBeUndefined();
    expect(exactRule("[2001:0db8:0:0::1]:8443", "udp")).toMatchObject({
      type: "IP-CIDR6",
      pattern: "2001:db8::1/128",
      protocol: "udp",
      ports: [8443],
    });
    expect(targetHost("2001:db8::443").port).toBeUndefined();
  });
  test("one-click rules retain FINAL and do not overwrite a different expiry", () => {
    const config = configuration(),
      rule = exactRule("149.154.167.50:443", "tcp");
    const next = addPreciseRule(config, rule);
    expect(next.rules.at(-1)?.type).toBe("FINAL");
    expect(config.rules).toHaveLength(2);
    const duplicate = addPreciseRule(next, { ...rule, outbound: "Local HTTP" });
    expect(duplicate.rules).toHaveLength(3);
    expect(duplicate.rules[0].id).toBe(rule.id);
    const temporary = { ...exactRule("example.com"), "expires-at": "2026-11-08T00:00:00Z" };
    const again = addPreciseRule(addPreciseRule(config, temporary), exactRule("example.com"));
    expect(again.rules).toHaveLength(4);
  });
  test("renames update references atomically; credentials are explicit preservation", () => {
    const doc = documentFixture();
    const config = renamedOutbound(doc.config, "Local HTTP", "Office");
    expect(config.rules[0].outbound).toBe("Office");
    expect(doc.config.rules[0].outbound).toBe("Local HTTP");
    expect(saveRequest(doc, doc.config)).toMatchObject({
      base_version: 7,
      credential_actions: { "Local HTTP": { action: "preserve" } },
    });
  });
});
test("target grouping normalizes addresses and retains individual ports and zero-byte failures", () => {
  const flows = [
    flowFixture({ domain: "Example.COM.", target: "example.com:443" }),
    flowFixture({
      id: "other-port",
      domain: "example.com",
      target: "example.com:8443",
      protocol: "udp",
      upload: 0,
      download: 0,
      status: "failed",
    }),
    flowFixture({ id: "other-domain", domain: "other.example" }),
    flowFixture({ id: "v6-a", domain: "", target: "[2001:0db8::1]:443" }),
    flowFixture({ id: "v6-b", domain: "", target: "[2001:db8::1]:80" }),
  ];
  const groups = groupFlows(flows);
  expect(groups).toHaveLength(3);
  expect(groups[0].flows).toHaveLength(2);
  expect(groups[0].failed).toBe(1);
  expect(groups[0].flows[1].protocol).toBe("udp");
  expect(groups[2].flows).toHaveLength(2);
});
test("Sankey geometry conserves width across columns and omits zero-byte edges", () => {
  const graph = graphFixture();
  graph.links.push({
    id: "zero",
    source: "in",
    target: "rule",
    value: 0,
    path_ids: ["failed-path"],
  });
  const layout = graphLayout(graph);
  expect(new Set(layout.nodes.map((node) => node.height)).size).toBe(1);
  expect(layout.links).toHaveLength(3);
  expect(layout.links.every((link) => link.path_ids[0] === "path-1")).toBe(true);
});
test("Other drill-down retains the original path IDs, flow IDs and observation window", () => {
  const path = graphFixture().paths[0];
  const result = pathDrill(
    [
      {
        ...path,
        id: "other",
        other: true,
        filter: {
          ...path.filter,
          path_ids: ["original-a", "original-b"],
          flow_ids: ["flow-1", "flow-2"],
        },
      },
    ],
    "anchor-1",
  );
  expect(result).toMatchObject({
    path_ids: "original-a,original-b",
    flow_ids: "flow-1,flow-2",
    anchor: "anchor-1",
    window_start: path.filter.since,
    window_end: path.filter.until,
  });
});
test("actions use DNS evidence or the restored address, never invent a Fake-IP rule", () => {
  expect(
    flowTarget(
      flowFixture({ target: "10.192.0.9:8443", fake_ip: "10.192.0.9", domain: "Example.COM." }),
    ),
  ).toBe("example.com:8443");
  expect(
    flowTarget(
      flowFixture({
        target: "10.192.0.9:443",
        fake_ip: "10.192.0.9",
        domain: "",
        real_destination: "",
      }),
    ),
  ).toBe("");
});
test("offline catalogs have the same messages and interpolation parameters", () => {
  expect(Object.keys(english.messages).sort()).toEqual(Object.keys(chinese.messages).sort());
  for (const key of Object.keys(english.messages) as (keyof typeof english.messages)[]) {
    expect(chinese.messages[key]).not.toBe("");
    expect(english.messages[key].match(/\{\{[^}]+\}\}/g)).toEqual(
      chinese.messages[key].match(/\{\{[^}]+\}\}/g),
    );
  }
});
const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
  clearSession();
});
test("writes send CSRF and operation identity; conflicts retain machine-readable details", async () => {
  setSession({ csrf_token: "test-csrf" });
  let sent: RequestInit | undefined;
  globalThis.fetch = (async (_url: unknown, options: RequestInit) => {
    sent = options;
    return Response.json(
      { error: { code: "version_conflict", details: "changed" } },
      { status: 409 },
    );
  }) as unknown as typeof fetch;
  await expect(
    request("/config", { method: "PUT", body: {}, requestId: "one-action" }),
  ).rejects.toMatchObject({ code: "version_conflict", status: 409 });
  expect(new Headers(sent?.headers).get("X-CSRF-Token")).toBe("test-csrf");
  expect(new Headers(sent?.headers).get("Idempotency-Key")).toBe("one-action");
});
test("a response from a revoked session cannot restore its token or data", async () => {
  let finish!: (value: Response) => void;
  globalThis.fetch = (() =>
    new Promise<Response>((resolve) => {
      finish = resolve;
    })) as unknown as typeof fetch;
  const pending = request("/state");
  clearSession();
  finish(Response.json({ csrf_token: "old-secret", host: "private" }));
  await expect(pending).rejects.toMatchObject({ code: "session_changed" });
});
test("uncertain write timeout is distinguished from a rejected operation", async () => {
  globalThis.fetch = ((_url: unknown, options: RequestInit) =>
    new Promise<Response>((_resolve, reject) => {
      options.signal?.addEventListener("abort", () =>
        reject(new DOMException("Aborted", "AbortError")),
      );
    })) as unknown as typeof fetch;
  let error: unknown;
  try {
    await request("/config", { method: "PUT", body: {}, timeout: 2 });
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(ApiError);
  expect(error).toMatchObject({ code: "timeout", uncertain: true });
});

test("diagnostic history keeps 20 recent unique targets and round-trips test parameters", () => {
  let history = readDiagnosticHistory(null);
  expect(history).toHaveLength(2);
  expect(history[1]?.tls).toBe(false);
  for (let index = 0; index < 25; index++)
    history = rememberDiagnostic(history, {
      mode: "connection",
      target: `host${index}.example:443`,
      tls: true,
    });
  expect(history).toHaveLength(20);
  expect(history[0]?.target).toBe("host24.example:443");
  history = rememberDiagnostic(history, {
    mode: "connection",
    target: " HOST20.EXAMPLE.:0443 ",
    tls: false,
  });
  expect(history).toHaveLength(20);
  expect(history[0]).toMatchObject({ target: "host20.example:443", tls: false });
  expect(history.filter((entry) => entry.target === "host20.example:443")).toHaveLength(1);
  history = rememberDiagnostic(history, {
    mode: "dns",
    target: "Internal.EXAMPLE.",
    tls: false,
    dnsName: "Internal.EXAMPLE.",
    dnsType: "AAAA",
  });
  expect(readDiagnosticHistory(JSON.stringify(history))).toEqual(history);
  expect(readDiagnosticHistory("[]")).toEqual([]);
  expect(readDiagnosticHistory("broken")).toHaveLength(2);
  expect(readDiagnosticHistory('[{"mode":"dns","target":"secret@host:53","tls":false}]')).toEqual(
    [],
  );
  expect(
    readDiagnosticHistory(
      JSON.stringify([
        { mode: "dns", target: "192.168.1.1:53", tls: false, dnsName: "example.com", dnsType: "A" },
      ]),
    ),
  ).toEqual([]);
  for (const [input, expected] of [
    ["example.com", "example.com:80"],
    ["192.0.2.1", "192.0.2.1:80"],
    ["::1", "[::1]:80"],
    ["[::1]:8443", "[::1]:8443"],
    ["2001:db8:0:1:2:3:4:5", "[2001:db8:0:1:2:3:4:5]:80"],
    ["example.com:", "example.com:"],
    ["example.com:bad", "example.com:bad"],
    ["[::1", "[::1"],
    ["example.com:0", "example.com:0"],
    ["[::1]:0", "[::1]:0"],
  ])
    expect(diagnosticRequest(input!, "direct", "tcp", false, "", "").target).toBe(expected);
  expect(diagnosticElapsed(0)).toBe("<1 ms");
  expect(diagnosticElapsed(125)).toBe("125 ms");
  expect(diagnosticElapsed(undefined)).toBe("—");
});
