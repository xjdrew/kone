import type { Page } from "@playwright/test";
import { documentFixture, stateFixture, trafficFixture } from "../test/factories";
import type {
  Config,
  Operation,
  PolicyRequest,
  Readiness,
  RemoteAccess,
  SaveRequest,
} from "../src/model";

export async function fixture(page: Page, options: { readonly?: boolean; remote?: boolean } = {}) {
  const data = {
    document: documentFixture(),
    state: stateFixture(),
    operations: [] as Operation[],
    authenticated: !options.remote,
    conflict: false,
    dnsFallback: false,
    accessFailure: false,
    access: {
      enabled: false,
      https: true,
      transport: "https",
      trust_required: false,
      urls: [],
      interfaces: [
        { address: "192.168.40.2", interface: "eth0" },
        { address: "10.8.0.2", interface: "vpn0" },
      ],
    } as RemoteAccess,
    offline: false,
    readiness: {
      ready: true,
      direct_only: false,
      direct_only_confirmed: true,
      checks: [],
      blockers: [],
      warnings: [],
    } as Readiness,
    requests: [] as { method: string; path: string; search: string; body: unknown }[],
  };
  if (options.readonly) data.state.role = "read";
  if (options.remote) {
    data.state.local_access = false;
    data.state.remote_session = true;
  }
  await page.addInitScript(() => {
    localStorage.setItem("kone.locale", "en");
  });
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request(),
      url = new URL(req.url()),
      path = url.pathname.replace("/api/v1", ""),
      method = req.method();
    const body = req.postData() ? req.postDataJSON() : undefined;
    data.requests.push({ method, path, search: url.search, body });
    const respond = (value: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });
    if (data.offline) return route.abort();
    if (path === "/auth")
      return respond({
        local_access: data.state.local_access,
        local_session: data.authenticated,
        password_configured: data.state.password_configured,
      });
    if (path === "/session") {
      data.authenticated = true;
      return respond({ csrf_token: "fixture-csrf" });
    }
    if (!data.authenticated) return respond({ error: { code: "unauthorized" } }, 401);
    if (method !== "GET" && data.state.role === "read")
      return respond({ error: { code: "read_only" } }, 403);
    if (method !== "GET" && req.headers()["x-csrf-token"] !== "fixture-csrf")
      return respond({ error: { code: "csrf" } }, 403);
    if (path === "/state") return respond(data.state);
    if (path === "/config" && method === "GET") return respond(data.document);
    if (path === "/config" && method === "PUT") {
      const input = body as SaveRequest;
      if (data.conflict || input.base_version !== data.document.version)
        return respond(
          { error: { code: "version_conflict", details: "Another editor saved a revision" } },
          409,
        );
      data.document = {
        ...data.document,
        version: data.document.version + 1,
        config: input.config,
        inbound: input.inbound,
      };
      data.state.saved_version = data.document.version;
      return respond(data.document);
    }
    if (path === "/policy" && method === "GET")
      return respond({
        mode: data.document.config.policy?.mode ?? "direct-first",
        outbound: data.document.config.rules.at(-1)?.outbound,
        explicit: true,
        version: data.document.version,
        ipv4_only: true,
        udp_exception: false,
        interface: "eth0",
        interfaces: ["eth0", "wlan0"],
        ipv6_available: false,
        protection: [
          { prefix: "127.0.0.0/8", kind: "loopback" },
          { prefix: "::1/128", kind: "loopback" },
          { prefix: "192.168.40.2/32", interface: "eth0", kind: "host" },
          { prefix: "127.0.0.1:7078", kind: "proxy_endpoint" },
          { prefix: "192.168.40.1:53", kind: "dns_transport" },
        ],
      });
    if (path === "/policy/preview" || (path === "/policy" && method === "PUT")) {
      const input = body as PolicyRequest;
      if (input.base_version !== data.document.version || data.conflict)
        return respond({ error: { code: "version_conflict" } }, 409);
      const config: Config = structuredClone(data.document.config);
      config.policy = { mode: input.mode };
      config.core["auto-route"] = input.mode === "proxy-first";
      config.rules[config.rules.length - 1].outbound =
        input.mode === "proxy-first" ? input.outbound : "direct";
      if (path === "/policy/preview")
        return respond({
          valid: true,
          restart_required: true,
          issues: [],
          config,
          base_version: input.base_version,
          mode: input.mode,
          udp: "direct_exception",
          protection: [{ prefix: "127.0.0.0/8", kind: "loopback" }],
          added_rules: input.mode === "proxy-first" ? 4 : 0,
          preserved_rules: config.rules.length - 1,
        });
      data.document = { ...data.document, config, version: data.document.version + 1 };
      data.state.saved_version = data.document.version;
      return respond(data.document);
    }
    if (path === "/traffic") return respond(trafficFixture());
    if (path === "/flows") return respond(trafficFixture().traffic);
    if (path.startsWith("/flows/"))
      return respond(trafficFixture().traffic.records.find((flow) => path.endsWith(flow.id)));
    if (path === "/dns")
      return respond({
        status: { capacity: 512, dropped: 0 },
        queries: [
          {
            id: "dns-1",
            name: "www.google.com",
            type: "A",
            time: "2026-11-07T09:30:00Z",
            source: "application",
            scope: "default",
            transport: "udp",
            upstream: "192.168.1.1:53",
            status: "success",
            duration_ms: 2.3,
            cache: "hit",
            version: 7,
            real_addresses: ["142.250.71.14"],
            virtual_addresses: ["10.192.0.4"],
          },
        ],
      });
    if (path === "/dns/configuration")
      return respond({
        running: data.state.state === "running",
        defaults: {
          servers: data.dnsFallback
            ? ["8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"]
            : ["192.168.40.1:53"],
          source: data.dnsFallback ? "public_fallback" : "system",
          public_fallback: data.dnsFallback,
          warnings: [],
        },
        status: {
          mode: data.document.config.dns.mode || "host",
          system_requested: true,
          system_active: data.state.state === "running",
          listen_address: "10.192.0.1:53",
        },
        interfaces: data.access.interfaces,
      });
    if (path === "/diagnostics/dns" && method === "POST") {
      const input = body as { name: string; type: string };
      const operation: Operation = {
        id: `op-${data.operations.length + 1}`,
        kind: "diagnostics",
        target: input.name,
        outbounds: ["system", "kone"],
        protocol: "dns",
        status: "succeeded",
        stage: "complete",
        started_at: "2026-11-07T09:30:00Z",
        result: {
          results: ["system", "kone"].map((source) => ({
            target: input.name,
            outbound: source,
            protocol: "dns",
            dns_type: input.type,
            status: "answered",
            stage: "dns",
            duration_ms: source === "system" ? 12 : 0,
            scope: source === "system" ? "system" : "saved_configuration",
            dns_answers: [source === "system" ? "2001:db8::1" : "example.com. 30 IN AAAA fd00::4"],
            dns_virtual_addresses: source === "kone" ? ["fd00::4"] : [],
          })),
        },
      };
      data.operations.unshift(operation);
      return respond(operation, 202);
    }
    if (path === "/diagnostics" && method === "POST") {
      const input = body as {
        target: string;
        outbounds: string[];
        protocol: string;
        tls: boolean;
        dns_name?: string;
        dns_type?: string;
      };
      const operation: Operation = {
        id: `op-${data.operations.length + 1}`,
        kind: "diagnostic",
        target: input.target,
        outbounds: input.outbounds,
        protocol: input.protocol,
        status: "succeeded",
        stage: "complete",
        started_at: "2026-11-07T09:30:00Z",
        result: {
          results: input.outbounds.map((outbound) => ({
            target: input.target,
            outbound,
            protocol: input.protocol,
            dns_name: input.dns_name ?? "",
            dns_type: input.dns_type ?? "",
            status: outbound === "direct" ? "failed" : "reachable",
            stage: "connect",
            duration_ms: 4,
            message: "Fixture connection result",
          })),
          automatic_rule: false,
        },
      };
      data.operations.unshift(operation);
      return respond(operation, 202);
    }
    if (path === "/operations") return respond({ operations: data.operations });
    if (path.startsWith("/operations/"))
      return respond(data.operations.find((operation) => path.endsWith(operation.id)));
    if (path === "/outbounds/health") return respond({ statuses: [] });
    if (path === "/logs")
      return respond({
        records: [
          {
            id: "9007199254740993",
            time: "2026-11-07T09:30:00Z",
            level: "INFO",
            source: "management",
            message: "Capture paused",
            attrs: {},
          },
        ],
        next_cursor: "9007199254740993",
        oldest_cursor: "9007199254740993",
        dropped: 0,
        gap: false,
        has_more: false,
        capacity: 1000,
        bytes: 120,
      });
    if (path === "/readiness") return respond(data.readiness);
    if (path === "/sessions") return respond({ sessions: [] });
    if (path === "/auth/password") {
      data.state.password_configured = true;
      return respond({ csrf_token: "fixture-csrf" });
    }
    if (path === "/access/lan") {
      if (method === "POST") {
        if (data.accessFailure) return respond({ error: { code: "access_bind" } }, 400);
        const input = body as { enabled: boolean; address: string; https: boolean };
        const scheme = input.https ? "https" : "http";
        data.access = {
          ...data.access,
          enabled: input.enabled,
          listen_address: input.address,
          https: input.https,
          transport: scheme,
          trust_required: input.https && input.enabled,
          fingerprint: input.https ? "a1b2c3d4".repeat(8) : undefined,
          urls: input.enabled
            ? [scheme + "://" + input.address.replace("0.0.0.0", "192.168.40.2")]
            : [],
        };
      }
      return respond(data.access);
    }
    if (path === "/access/certificate")
      return route.fulfill({
        status: 200,
        contentType: "application/x-pem-file",
        body: "fixture-ca",
      });
    if (path === "/geoip")
      return respond({
        saved: { provider: "builtin", version: "fixture", sha256: "0".repeat(64) },
      });
    if (path.startsWith("/lifecycle/")) {
      data.state.state = data.state.data_state = path.endsWith("start") ? "running" : "paused";
      return respond({
        id: "lifecycle",
        kind: path.slice(11),
        status: "succeeded",
        stage: "complete",
        started_at: "2026-11-07T09:30:00Z",
      });
    }
    return respond({ error: { code: "not_found", details: `${method} ${path}` } }, 404);
  });
  return data;
}
