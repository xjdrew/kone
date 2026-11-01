import { test, expect } from "@playwright/test";
import { createHash } from "node:crypto";

const start = "2026-11-01T00:00:00Z";
const end = "2026-11-01T00:00:01Z";
function fixture() {
  const records = [
    {
      id: "flow-a",
      session_id: "traffic-session",
      config_version: 1,
      inbound: "tun-main",
      protocol: "tcp",
      source: "192.168.50.2:50000",
      destination: "198.18.0.2:443",
      target: "example.com:443",
      domain: "example.com",
      domain_source: "fake-ip",
      fake_ip: "198.18.0.2",
      process_status: "remote",
      rule_id: "rule-1",
      rule_name: "example.com",
      expected_outbound: "Proxy A",
      effective_outbound: "Proxy A",
      status: "active",
      started_at: start,
      upload: 1000,
      download: 3000,
    },
    {
      id: "flow-b",
      session_id: "traffic-session",
      config_version: 1,
      inbound: "tun-main",
      protocol: "udp",
      source: "192.168.50.3:50001",
      destination: "192.168.50.1:123",
      target: "192.168.50.1:123",
      process_status: "remote",
      rule_id: "default",
      rule_name: "默认直连",
      expected_outbound: "direct",
      effective_outbound: "direct",
      status: "active",
      started_at: start,
      upload: 100,
      download: 100,
    },
    {
      id: "flow-f",
      session_id: "traffic-session",
      config_version: 1,
      inbound: "tun-main",
      protocol: "udp",
      source: "192.168.50.2:50002",
      target: "unsupported.example:443",
      destination: "198.18.0.3:443",
      domain: "unsupported.example",
      expected_outbound: "Proxy A",
      effective_outbound: "",
      status: "failed",
      stage: "capability",
      error: "Proxy A does not support UDP; fallback is not configured",
      started_at: start,
      ended_at: end,
      upload: 0,
      download: 0,
    },
  ];
  const config = {
    version: 1,
    credential_state: { "Proxy A": { configured: true } },
    inbound: { id: "tun-main", name: "家庭网关", enabled: true },
    config: {
      general: {
        "log-level": "info",
        "log-format": "text",
      },
      core: {
        network: "10.192.0.1/16",
        stack: "system",
        tun: "",
        "auto-route": false,
        "outbound-interface": "",
      },
      dns: {
        servers: [],
        "listen-port": 53,
        ttl: 600,
        "read-timeout": 5,
        "write-timeout": 5,
        "packet-size": 4096,
        "history-limit": 512,
        "history-retention": 3600,
        "cache-limit": 1024,
      },
      outbounds: [
        {
          id: "outbound-id-1",
          enabled: true,
          name: "Proxy A",
          url: "http://REDACTED:REDACTED@127.0.0.1:18080",
        },
      ],
      rules: [
        {
          id: "rule-1",
          type: "DOMAIN",
          pattern: "example.com",
          outbound: "Proxy A",
        },
        { type: "FINAL", outbound: "direct" },
      ],
    },
  };
  return {
    records,
    config,
    role: "admin",
    offline: false,
    conflict: false,
    empty: false,
    requests: [],
    writes: [],
    expired: false,
    state: "paused",
    lanState: { enabled: false, transport: "https", trust_required: true },
    authorizedSessions: [{ id: "phone-1", role: "read", expires: end }],
    geoState: { saved: { version: "builtin", source: "legacy bundled dataset", license: "bundled notices", sha256: "a".repeat(64), ranges: 0, builtin: true }, restart_required: false },
    logRecords: [
      { id: "1", time: start, level: "INFO", source: "management", message: "Management service ready", attrs: { state: "ready" } },
      { id: "2", time: start, level: "ERROR", source: "helper", message: "TUN startup failed", attrs: { stage: "start", endpoint: "http://REDACTED@proxy.invalid" } },
    ],
  };
}

function outboundTestSnapshot(data) {
  const { outbound, body, version } = data.outboundOperation;
  const stage = data.testStage || "complete";
  const completed = stage === "complete";
  const connected = stage !== "connect" && !(completed && data.healthFailure);
  const tcpReady = ["target_tls", "complete"].includes(stage) && !data.healthFailure;
  const protocol = outbound.url.split(":", 1)[0];
  const tcpUnverified = protocol === "ss" && body.tls === false;
  const udpStatus = data.udpStatus || (["http", "https"].includes(protocol) ? "unsupported" : "unknown");
  return {
    id: outbound.id || "draft", name: outbound.name || "draft", status: completed ? data.healthFailure ? "unhealthy" : tcpUnverified ? "unknown" : "healthy" : "testing",
    stage: completed && data.healthFailure ? "connect" : stage, message: data.healthFailure && completed ? "Proxy connection refused" : completed ? "TLS verified for this target" : `Testing ${stage}`,
    target: body.target || "example.com:443", tls: body.tls !== false, config_version: version,
    configuration_id: "fixture-health", operation_id: "outbound-test-1", scope: "explicit TCP/TLS target; UDP response not tested",
    duration_ms: completed ? 240 : 0, ...(connected ? { connect_latency_ms: data.connectLatency ?? 12 } : {}),
    host: { address: new URL(outbound.url).host, status: connected ? "healthy" : completed ? "failed" : "testing", message: connected ? "Proxy endpoint TCP connected" : "Connecting to proxy endpoint" },
    protocols: {
      tcp: { status: tcpUnverified ? "unknown" : tcpReady ? "healthy" : completed ? "failed" : "testing", tested: completed || tcpReady, message: tcpUnverified ? "Shadowsocks transport has no target acknowledgement without TLS" : tcpReady ? "Target TCP tunnel established" : "Waiting for TCP tunnel" },
      tls: { status: body.tls === false ? "unknown" : completed && !data.healthFailure ? "healthy" : stage === "target_tls" ? "testing" : "unknown", tested: completed && !data.healthFailure && body.tls !== false, message: body.tls === false ? "TLS was not selected" : "Target TLS verification" },
      udp: { status: udpStatus, tested: false, evidence: udpStatus === "unsupported" ? "protocol" : "none", message: udpStatus === "unsupported" ? "This proxy implementation does not forward UDP" : "No UDP response was tested" },
    },
    progress: { stage: completed && data.healthFailure ? "connect" : stage, completed: completed ? data.healthFailure ? 0 : 3 : stage === "connect" ? 0 : stage === "proxy_handshake" ? 1 : 2, total: 3 },
    ...(completed ? { checked_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60000).toISOString() } : {}),
  };
}

async function mount(page, options = {}) {
  const data = Object.assign(fixture(), options);
  if (data.directOnly) data.config.config.rules = [{ type: "FINAL", outbound: "direct" }];
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.slice("/api/v1".length);
    const method = request.method();
    data.requests.push({
      path,
      method,
      query: Object.fromEntries(url.searchParams),
      headers: request.headers(),
      body: request.postDataJSON(),
    });
    if (data.delay)
      await new Promise((resolve) => setTimeout(resolve, data.delay));
    if (data.offline) return route.abort("connectionfailed");
    const respond = (body, status = 200) =>
      route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(body),
      });
    const body = request.postDataJSON();
    if (path === "/session" && body?.token && data.deferBootstrap) {
      const deferred = data.deferBootstrap;
      data.deferBootstrap = null;
      deferred.started = true;
      await deferred.promise;
    }
    if (path === "/auth") return respond({ setup_required: Boolean(data.requireSetup), setup_authorized: Boolean(data.setupSession), password_required: !data.requireSetup, authenticated: data.loggedIn !== false, ...(data.setupSession ? { csrf_token: "setup-csrf" } : {}) });
    if (path === "/auth/password") {
      if (method === "POST" && !data.setupSession) return respond({ error: { message: "local setup proof required" } }, 403);
      if (method === "PUT" && data.loggedIn === false) return respond({ error: { message: "Password required" } }, 401);
      if (method === "PUT" && (data.role !== "admin" || body.current_password !== (data.managementPassword || "mock-owner-password"))) return respond({ error: { message: "Current management password is incorrect" } }, 403);
      if (!body.password || body.password !== body.confirm_password) return respond({ error: { message: "password mismatch" } }, 400);
      data.requireSetup = false;
      data.requirePassword = true;
      data.loggedIn = true;
      data.setupSession = false;
      data.managementPassword = body.password;
      return respond({ role: data.role, csrf_token: "test-csrf", setup_required: false });
    }
    if (path === "/session/logout") { data.loggedIn = false; return respond({ logged_out: true }); }
    if (path === "/session") {
      if (data.requireSetup && body.token) { data.setupSession = true; return respond({ role: "setup", csrf_token: "setup-csrf", setup_required: true }); }
      if (body.pairing_code) {
        if (body.pairing_code !== data.pairingCode) return respond({ error: { message: "Password or authorization is invalid" } }, 401);
        data.role = data.pairingRole || data.role;
      } else if (data.requirePassword && body.password !== data.managementPassword) return respond({ error: { message: "Password or authorization is invalid" } }, 401);
      data.loggedIn = true;
      return respond({
        role: data.role,
        remote_session: Boolean(data.remoteSession),
        csrf_token: "test-csrf",
        session_id: "test-session",
      });
    }
    if (data.loggedIn === false) return respond({ error: { code: data.setupSession ? "setup_required" : "unauthorized", message: data.setupSession ? "Set the management password first" : "Password required" } }, data.setupSession ? 403 : 401);
    if (path === "/state" && data.deferState) {
      const deferred = data.deferState;
      data.deferState = null;
      deferred.started = true;
      await deferred.promise;
    }
    if (options.unauthorized)
      return respond({ error: { message: "Authorization expired" } }, 401);
    if (method !== "GET") {
      data.writes.push({ path, body });
      if (data.role === "read")
        return respond(
          { error: { message: "This session is read-only" } },
          403,
        );
    }
    if (path === "/state")
      return respond({
        csrf_token: "test-csrf",
        state: data.state,
        data_state: data.state,
        capture_locked: Boolean(data.captureLocked) || ["running", "starting", "stopping"].includes(data.state),
        recovery_required: Boolean(data.recoveryRequired),
        config_error: data.configError || "",
        last_error: data.lastError || "",
        control_state: "ready",
        host: "Gateway · 测试主机",
        role: data.role,
        remote_session: Boolean(data.remoteSession),
        capabilities: {
          stacks: ["system", "gvisor", "mixed"],
          tcp: true,
          udp_direct: true,
          proxy_udp_schemes: ["socks5", "ss"],
          ipv6: Boolean(data.ipv6),
          system_dns: Boolean(data.systemDNS),
        },
        version: "test-version",
        session_id: "test-session",
        saved_version: data.config.version,
        running_version: 1,
      });
    if (path === "/config" && method === "GET") {
      if (data.deferConfig) {
        const deferred = data.deferConfig;
        data.deferConfig = null;
        deferred.started = true;
        await deferred.promise;
      }
      return respond({ ...data.config, capture_locked: ["running", "starting", "stopping"].includes(data.state) });
    }
    if (path === "/readiness") return respond(data.readiness || {
      ready: !data.disabledTUN && (!data.directOnly || Boolean(data.config.direct_only_confirmed)),
      direct_only: Boolean(data.directOnly),
      direct_only_confirmed: Boolean(data.config.direct_only_confirmed),
      saved_version: data.config.version,
      checks: [],
      blockers: [...(data.disabledTUN ? [{ id: "inbound", code: "inbound_disabled", status: "failed", severity: "error", message: "请先在入站启用 TUN 入口并保存。", page: "inbounds", field: "enabled", action: "edit_inbound" }] : []), ...(data.directOnly && !data.config.direct_only_confirmed ? [{ id: "direct_only_confirmation", code: "direct_only_confirmation", status: "error", severity: "error", message: "请明确确认仅直连接管。", page: "outbounds", field: "direct_only_confirmed", action: "confirm_direct" }] : [])],
      warnings: [],
    });
    if (path === "/outbounds/health") {
      if (data.outboundOperation && !data.outboundOperation.body.draft) data.health = [outboundTestSnapshot(data)];
      return respond({ statuses: data.health || [], time: end });
    }
    if (path === "/outbounds/test") {
      const outbound = body.draft || data.config.config.outbounds.find((outbound) => outbound.id === body.outbound_id);
      data.outboundOperation = { outbound: structuredClone(outbound), body, version: data.config.version };
      if (data.asyncHealth) data.testStage = "connect";
      const result = outboundTestSnapshot(data);
      if (!body.draft) data.health = [result];
      return respond({ id: "outbound-test-1", status: data.asyncHealth ? "running" : "succeeded", stage: result.stage, result }, 202);
    }
    if (path === "/operations/outbound-test-1") {
      const result = outboundTestSnapshot(data);
      if (!data.outboundOperation.body.draft) data.health = [result];
      return respond({ id: "outbound-test-1", status: (data.testStage || "complete") === "complete" ? "succeeded" : "running", stage: result.stage, result });
    }
    if (path === "/config/validate") return respond(data.validationFailure ? { valid: false, restart_required: false, issues: [{ code: "outbound", severity: "error", message: data.validationFailure }] } : { valid: true, restart_required: false, issues: [] });
    if (path === "/config/import/validate")
      return respond({
        valid: true,
        restart_required: true,
        candidate_document: data.config,
      });
    if (path === "/config/import") {
      data.config.version++;
      return respond(data.config);
    }
    if (path === "/config/defaults") {
      if (data.resetError) return respond({ error: { message: data.resetError } }, 409);
      if (data.captureLocked || ["running", "starting", "degraded", "pausing", "stopping", "preflight"].includes(data.state)) return respond({ error: { message: "Pause capture and finish recovery before resetting configuration" } }, 409);
      if (body.base_version !== data.config.version) return respond({ error: { message: "Version conflict" } }, 409);
      data.config.version++;
      data.config.inbound.enabled = true;
      data.config.config.rules = [];
      data.config.config.outbounds = [];
      data.config.direct_only_confirmed = false;
      data.config.credential_state = {};
      data.configError = "";
      data.recoveryRequired = false;
      data.lastError = "";
      data.state = "paused";
      return respond(data.config);
    }
    if (path === "/config" && method === "PUT") {
      if (data.conflict || body.base_version !== data.config.version)
        return respond({ error: { message: "Version conflict" } }, 409);
      const config = structuredClone(body.config);
      const credentialState = {};
      data.outboundSequence ||= Math.max(0, ...data.config.config.outbounds.map((outbound) => Number(outbound.id?.match(/^outbound-id-(\d+)$/)?.[1]) || 0)) + 1;
      for (const outbound of config.outbounds || []) {
        outbound.id ||= `outbound-id-${data.outboundSequence++}`;
        const action = body.credential_actions?.[outbound.name] || { action: "preserve", original_name: outbound.name };
        const original = action.original_name || outbound.name;
        const configured = action.action === "replace" || action.action !== "clear" && Boolean(data.config.credential_state?.[original]?.configured);
        credentialState[outbound.name] = { configured };
        const schemeEnd = outbound.url.indexOf("://") + 3;
        const rest = outbound.url.slice(schemeEnd);
        const authority = rest.split(/[/?#]/, 1)[0];
        const address = authority.slice(authority.lastIndexOf("@") + 1);
        outbound.url = `${outbound.url.slice(0, schemeEnd)}${configured ? "REDACTED:REDACTED@" : ""}${address}${rest.slice(authority.length)}`;
      }
      if (data.outboundOperation) {
        const old = data.config.config.outbounds.find((outbound) => outbound.id === data.outboundOperation.outbound.id);
        const next = config.outbounds.find((outbound) => outbound.id === data.outboundOperation.outbound.id);
        const authentication = next && body.credential_actions?.[next.name];
        if (!old || !next || old.url !== next.url || old.enabled !== next.enabled || old["udp-fallback"] !== next["udp-fallback"] || authentication?.action === "replace" || JSON.stringify(data.config.config.core) !== JSON.stringify(config.core) || JSON.stringify(data.config.config.dns) !== JSON.stringify(config.dns)) {
          data.outboundOperation = null;
          data.health = [];
        } else data.outboundOperation.outbound.name = next.name;
      }
      data.config = {
        version: data.config.version + 1,
        config,
        inbound: body.inbound,
        credential_state: credentialState,
        direct_only_confirmed: body.direct_only_confirmed ?? data.config.direct_only_confirmed,
      };
      return respond({ ...data.config, applied: data.state === "running" && !data.applyError, apply_error: data.applyError || "" });
    }
    if (path === "/config/apply") return respond({ status: "completed" });
    if (path === "/config/undo") return respond(data.config);
    if (path === "/traffic" || path === "/flows") {
      if (data.telemetryUnavailable) return respond({ error: { message: "data source unavailable during startup" } }, 503);
      let records = data.empty ? [] : data.records;
      if (url.searchParams.get("protocol"))
        records = records.filter(
          (record) => record.protocol === url.searchParams.get("protocol"),
        );
      if (url.searchParams.get("flow_ids"))
        records = records.filter((record) =>
          url.searchParams.get("flow_ids").split(",").includes(record.id),
        );
      if (path === "/flows" && data.expired)
        return respond({ error: { message: "Original detail expired" } }, 410);
      const totals = {
        upload: records.reduce((sum, r) => sum + r.upload, 0),
        download: records.reduce((sum, r) => sum + r.download, 0),
        upload_rate: records.length ? 250 : 0,
        download_rate: records.length ? 650 : 0,
        active: records.filter((r) => r.status === "active").length,
        failed: records.filter((r) => r.status === "failed").length,
        rejected: 0,
      };
      const traffic = {
        frozen: Boolean(data.frozen),
        records,
        totals,
        timestamp: end,
        session_id: "traffic-session",
        anchor: "traffic-session:3",
        dropped_details: 0,
        recording: true,
        capacity: 4096,
        total: records.length,
      };
      const offset = url.searchParams.get("cursor")
        ? records.findIndex(
            (record) => record.id === url.searchParams.get("cursor"),
          ) + 1
        : 0;
      const limit = Math.min(500, Number(url.searchParams.get("limit")) || 100);
      traffic.records = records.slice(offset, offset + limit);
      if (offset + limit < records.length)
        traffic.next_cursor = traffic.records.at(-1).id;
      if (path === "/flows") return respond(traffic);
      const metric = url.searchParams.get("metric");
      const cumulative = metric === "cumulative";
      let paths = records
        .filter((r) => r.upload + r.download > 0)
        .map((r) => ({
          id: `path-${r.id}`,
          config_version: r.config_version,
          inbound: r.inbound,
          rule_id: r.rule_id,
          rule_name: r.rule_name,
          effective_outbound: r.effective_outbound,
          target: r.target,
          upload: r.upload,
          download: r.download,
          value: cumulative
            ? r.upload + r.download
            : metric === "upload"
              ? r.upload / 4
              : metric === "download"
                ? r.download / 4
                : (r.upload + r.download) / 4,
          connections: 1,
          filter: {
            anchor: traffic.anchor,
            path_ids: [`path-${r.id}`],
            flow_ids: [r.id],
            since: start,
            until: end,
          },
        }));
      if (data.aggregateAll && paths.length)
        paths = [
          {
            ...paths[0],
            id: "path-all",
            target: "Other",
            other: true,
            value: paths.reduce((sum, path) => sum + path.value, 0),
            upload: paths.reduce((sum, path) => sum + path.upload, 0),
            download: paths.reduce((sum, path) => sum + path.download, 0),
            connections: paths.length,
            filter: {
              anchor: traffic.anchor,
              path_ids: ["path-all"],
              flow_ids: records.map((record) => record.id),
              since: start,
              until: end,
            },
          },
        ];
      return respond({
        traffic,
        sankey: {
          frozen: Boolean(data.frozen),
          session_id: traffic.session_id,
          timestamp: end,
          scope: "business",
          metric,
          unit: cumulative ? "B" : "B/s",
          window_start: start,
          window_end: end,
          anchor: traffic.anchor,
          paths,
          failures: totals.failed,
          total: paths.reduce((sum, p) => sum + p.value, 0),
        },
      });
    }
    if (path === "/dns")
      return respond({
        status: {
          automatic: true,
          system_source: "test-system-scope",
          search_domains: ["corp.example"],
          warnings: data.autoScopes
            ? ["Per-application VPN policy is not reproduced"]
            : [],
          rules: data.autoScopes
            ? [
                {
                  suffix: "corp.example",
                  servers: ["192.168.50.1:53"],
                  interface: "eth0",
                  automatic: true,
                  exact: false,
                },
              ]
            : [],
          servers: ["192.168.50.1:53"],
          tcp: true,
          history_dropped: 0,
        },
        queries: [
          {
            id: "q-1",
            time: end,
            name: "example.com.",
            type: "A",
            scope: "dns",
            transport: "udp",
            upstream: "192.168.50.1:53",
            upstream_transport: "udp",
            status: "NOERROR",
            cache: "miss",
            duration_ms: 4,
            virtual_addresses: ["198.18.0.2"],
            real_addresses: [],
          },
        ],
      });
    if (path === "/diagnostics" && method === "GET")
      return respond({ operations: [] });
    if (path === "/logs") {
      if (data.logsUnavailable) return respond({ error: { message: "logs temporarily unavailable" } }, 503);
      let records = data.logRecords;
      const levels = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
      records = records.filter((record) => (!url.searchParams.has("after") || BigInt(record.id) > BigInt(url.searchParams.get("after"))) &&
        levels[record.level] >= (levels[(url.searchParams.get("min_level") || "info").toUpperCase()] || 0) &&
        (!url.searchParams.get("source") || record.source === url.searchParams.get("source")));
      return respond({ records, next_cursor: data.logRecords.at(-1)?.id || "0", dropped: 0, gap: false, has_more: false, capacity: 1000, helper: { connected: data.state === "running" } });
    }
    if (path === "/diagnostics")
      return respond({ id: "diag-1", status: "running" }, 202);
    if (path === "/sessions")
      return respond({
        sessions: data.authorizedSessions,
      });
    if (/^\/sessions\/[^/]+\/revoke$/.test(path)) {
      data.authorizedSessions = data.authorizedSessions.filter((session) => session.id !== decodeURIComponent(path.split("/")[2]));
      return respond({ revoked: true });
    }
    if (path === "/access/lan") {
      if (method === "POST") data.lanState = { ...data.lanState, enabled: body.enabled, ...(body.address ? { address: body.address, url: `https://${body.address}`, fingerprint: "fixture-certificate-fingerprint" } : {}) };
      return respond(data.lanState);
    }
    if (path === "/recovery")
      return respond({ required: Boolean(data.recoveryRequired), ownership: data.recoveryRequired ? "owned" : "none", items: [] });
    if (path === "/geoip" && method === "PUT") {
      data.geoState = {
        saved: {
          ...body,
          sha256: request.headers()["x-content-sha256"],
          ranges: body.ranges.length,
        },
        restart_required: false,
      };
      data.geoCorrupt = false;
      return respond(data.geoState);
    }
    if (path === "/geoip/rollback") {
      data.geoState = {
        saved: {
          version: "recovered-v1",
          source: "verified previous dataset",
          license: "CC0-1.0",
          sha256: "b".repeat(64),
          ranges: 1,
        },
      };
      data.geoCorrupt = false;
      return respond(data.geoState);
    }
    if (path === "/geoip" && data.geoCorrupt)
      return respond(
        {
          error: { code: "geoip", message: "Saved active dataset is corrupt" },
        },
        400,
      );
    if (path === "/geoip") return respond(data.geoState);
    if (path === "/pairing")
      return respond({ code: "12345678", role: body.role, expires: end });
    if (path === "/rules/simulate")
      return respond({
        outbound: "Proxy A",
        rule: "rule-1",
        protocol: "tcp",
        source: "saved-config",
      });
    if (path === "/lifecycle/preflight")
      if (data.disabledTUN) return respond({ error: { message: "enable the TUN inbound before starting capture" } }, 400);
    if (path === "/lifecycle/preflight")
      return respond({
        valid: true,
        ok: true,
        checks: [{ name: "configuration", ok: true }],
      });
    if (path.startsWith("/lifecycle/")) {
      if (path === "/lifecycle/start") {
        if (data.startError) return respond({ error: data.startError }, data.startErrorStatus || 400);
        if (data.disabledTUN) return respond({ error: { code: "inbound_disabled", message: "enable the TUN inbound before starting capture" } }, 400);
        if (data.directOnly && !data.config.direct_only_confirmed) return respond({ error: { code: "direct_only_confirmation", message: "Confirm direct-only capture explicitly, or select a proxy outbound in the rules" } }, 409);
        data.recoveryRequired = false;
        data.lastError = "";
      }
      data.state = path.endsWith("pause") ? "paused" : "running";
      const messages = path.endsWith("start") ? ["Starting traffic capture", "Traffic capture ready"] : path.endsWith("pause") ? ["Traffic capture paused"] : [];
      for (const message of messages) data.logRecords.push({ id: String(BigInt(data.logRecords.at(-1)?.id || "0") + 1n), time: new Date().toISOString(), level: "INFO", source: "management", message, attrs: { state: data.state } });
      return respond({ status: "completed", message: "Operation completed" });
    }
    if (path === "/privacy/clear") {
      data.records = [];
      return respond({ cleared: true, network_changed: false });
    }
    if (path === "/export")
      return route.fulfill({
        contentType: "application/toml",
        body: '[core]\nstack = "system"\n',
      });
    return respond(
      { error: { message: `Unimplemented test route: ${path}` } },
      404,
    );
  });
  const bootstrapPage = options.bootstrapPage;
  await page.goto(options.noBootstrap ? "/#home" : "/#token=local-test-only" + (bootstrapPage ? `&page=${encodeURIComponent(bootstrapPage)}` : ""));
  if (options.authScreen) {
    await expect(page.getByRole("heading", { name: options.authScreen, exact: true })).toBeVisible();
    await expectManagementShellHidden(page);
    return data;
  }
  await expect(
    page.getByRole("heading", { name: bootstrapPage === "diagnostics" ? "诊断" : "首页", exact: true }),
  ).toBeVisible();
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  return data;
}

const managementShellSelectors = ["#sidebar", ".topbar", ".workspace-footer", "#nav-backdrop", ".skip-link", "#connection-banner", "#toast-region"];

async function expectManagementShellHidden(page) {
  for (const selector of managementShellSelectors) await expect(page.locator(selector)).toBeHidden();
  await expect(page.locator("#lifecycle-toggle")).toBeHidden();
  const viewport = page.viewportSize();
  const bounds = await page.locator("#main").boundingBox();
  expect(bounds.x).toBeCloseTo(0, 0);
  expect(bounds.y).toBeCloseTo(0, 0);
  expect(bounds.width).toBeCloseTo(viewport.width, 0);
  expect(bounds.height).toBeGreaterThanOrEqual(viewport.height);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width);
}

async function expectManagementShellVisible(page) {
  await expect(page.locator("body")).not.toHaveClass(/auth-(?:pending|screen)/);
  await expect(page.locator(".topbar")).toBeVisible();
  await expect(page.locator(".workspace-footer")).toBeVisible();
  await expect(page.locator("#lifecycle-toggle")).toBeVisible();
}

async function expectKeyboardOutsideManagementShell(page) {
  for (let index = 0; index < 8; index++) {
    await page.keyboard.press("Tab");
    const backgroundFocus = await page.evaluate((selectors) => document.activeElement?.closest(selectors.join(","))?.outerHTML || null, managementShellSelectors);
    expect(backgroundFocus).toBeNull();
  }
}

async function expectNoDialogPlaceholders(page) {
  const placeholders = await page.locator("#detail-content").evaluate((content) => [...content.childNodes]
    .filter((node) => node.nodeType === Node.TEXT_NODE)
    .map((node) => node.textContent.trim())
    .filter((text) => text === "null" || text === "0"));
  expect(placeholders).toEqual([]);
}

async function navigate(page, name) {
  if (
    (await page.locator("#menu-toggle").isVisible()) &&
    !(await page.locator("#sidebar").getAttribute("class")).includes("open")
  )
    await page.locator("#menu-toggle").click();
  await page.locator(`.nav-link[data-page=${name}]`).click();
}

async function navigateSettings(page, section) {
  await navigate(page, "settings");
  await page.locator(`[data-settings-link="${section}"]`).click();
  await expect(page.locator(`[data-settings-detail="${section}"]`)).toBeVisible();
}

async function saveOutbound(page) {
  await page.locator("[data-editor-save]").click();
}

async function dismissOutboundTestSuggestion(page) {
  await expect(page.locator("[data-outbound-test-suggestion]")).toBeVisible();
  await page.getByRole("button", { name: "稍后", exact: true }).click();
}

async function confirmReferencedOutboundRename(page) {
  await expect(page.getByRole("heading", { name: "确认保存变更", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "确认保存", exact: true }).click();
}

for (const firstVisit of ["password", "setup"]) {
  test(`@compat delayed ${firstVisit} authorization never paints the management interface`, async ({ page }, testInfo) => {
    await page.addInitScript((selectors) => {
      window.authShellFlashes = [];
      window.monitorAuthShell = true;
      const sample = () => {
        if (window.monitorAuthShell) {
          const visible = selectors.filter((selector) => {
            const element = document.querySelector(selector);
            if (!element) return false;
            const style = getComputedStyle(element);
            return element.getClientRects().length > 0 && style.display !== "none" && style.visibility !== "hidden";
          });
          if (visible.length) window.authShellFlashes.push(visible);
        }
        requestAnimationFrame(sample);
      };
      requestAnimationFrame(sample);
    }, managementShellSelectors);
    let release;
    const deferred = { started: false, promise: new Promise((resolve) => { release = resolve; }) };
    const pending = mount(page, {
      requireSetup: firstVisit === "setup", requirePassword: firstVisit === "password", loggedIn: false,
      managementPassword: "mock-owner-password", deferBootstrap: deferred,
      authScreen: firstVisit === "setup" ? "设置管理密码" : "登录 KONE 管理",
    });
    try {
      await expect.poll(() => deferred.started).toBe(true);
      await expect(page.locator("body")).toHaveClass(/auth-pending/);
      await expect(page.locator("#main .loading-state")).toBeVisible();
      await expectManagementShellHidden(page);
      await expectKeyboardOutsideManagementShell(page);
      await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      await page.screenshot({ path: testInfo.outputPath(`pending-${firstVisit}-authorization.png`), animations: "disabled" });
      release();
      const data = await pending;
      await expect(page.locator("body")).toHaveClass(/auth-screen/);
      await page.screenshot({ path: testInfo.outputPath(`${firstVisit}-first-visit-login-only.png`), animations: "disabled" });
      await page.evaluate(() => { window.monitorAuthShell = false; });
      expect(await page.evaluate(() => window.authShellFlashes)).toEqual([]);
      expect(data.requests.some((request) => ["/config", "/logs", "/traffic"].includes(request.path))).toBe(false);
    } finally {
      release();
      await pending;
    }
  });
}

test("@compat password login occupies the whole viewport until successful authentication", async ({ page }, testInfo) => {
  const data = await mount(page, { noBootstrap: true, requirePassword: true, managementPassword: "mock-owner-password", loggedIn: false, authScreen: "登录 KONE 管理" });
  await expect(page.locator("body")).toHaveClass(/auth-screen/);
  await expectKeyboardOutsideManagementShell(page);
  await page.screenshot({ path: testInfo.outputPath("password-login-only.png"), animations: "disabled" });
  await page.locator("#login-password").fill("incorrect-password");
  await page.getByRole("button", { name: "登录管理", exact: true }).click();
  await expect(page.locator("#auth-error")).toContainText("Password or authorization is invalid");
  await expectManagementShellHidden(page);
  await expectKeyboardOutsideManagementShell(page);
  await page.locator("#login-password").fill("mock-owner-password");
  let release;
  const deferred = { started: false, promise: new Promise((resolve) => { release = resolve; }) };
  data.deferConfig = deferred;
  try {
    await page.getByRole("button", { name: "登录管理", exact: true }).click();
    await expect.poll(() => deferred.started).toBe(true);
    await expect(page.locator("body")).toHaveClass(/auth-pending/);
    await expectManagementShellHidden(page);
    await expectKeyboardOutsideManagementShell(page);
  } finally { release(); }
  await expect(page.getByRole("heading", { name: "首页", exact: true })).toBeVisible();
  await expectManagementShellVisible(page);
  expect(data.writes.some((write) => write.path.startsWith("/lifecycle/"))).toBe(false);
});

test("@compat pairing login keeps management hidden and restores only the authorized session", async ({ page }, testInfo) => {
  const data = await mount(page, { noBootstrap: true, requirePassword: true, managementPassword: "mock-owner-password", loggedIn: false, pairingCode: "12345678", pairingRole: "read", authScreen: "登录 KONE 管理" });
  await page.getByRole("button", { name: "使用配对代码", exact: true }).click();
  await expect(page.getByRole("heading", { name: "使用配对代码连接", exact: true })).toBeVisible();
  await expectManagementShellHidden(page);
  await page.screenshot({ path: testInfo.outputPath("pairing-login-only.png"), animations: "disabled" });
  await page.locator("#pairing-code").fill("12345678");
  await page.getByRole("button", { name: "授权并连接", exact: true }).click();
  await expect(page.getByRole("heading", { name: "首页", exact: true })).toBeVisible();
  await expectManagementShellVisible(page);
  await expect(page.locator("#session-role")).toContainText("只读");
  await expect(page.locator("#lifecycle-toggle")).toBeDisabled();
  expect(data.writes).toEqual([]);
});

for (const transition of ["logout", "expired"]) {
  test(`@compat mobile open navigation cannot leak management after ${transition}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 390, height: 844 });
    const data = await mount(page);
    data.requirePassword = true;
    data.managementPassword = "mock-owner-password";
    await navigate(page, "settings");
    await page.locator("#toast-region").evaluate((region) => { region.textContent = "Previous management notification"; });
    await page.locator("#menu-toggle").click();
    await expect(page.locator("#sidebar")).toHaveClass(/open/);
    await expect(page.locator("#nav-backdrop")).toBeVisible();
    if (transition === "logout") {
      // Exercise the handler while a stale menu overlay is still present.
      await page.getByRole("button", { name: "退出登录", exact: true }).dispatchEvent("click");
    } else {
      data.loggedIn = false;
      await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    }
    await expect(page.locator("#login-password")).toBeVisible();
    await expectManagementShellHidden(page);
    await expect(page.locator("#sidebar")).not.toHaveClass(/open/);
    await expect(page.locator("#menu-toggle")).toHaveAttribute("aria-expanded", "false");
    await page.screenshot({ path: testInfo.outputPath(`mobile-${transition}-login-only.png`), animations: "disabled" });
    await page.locator("#login-password").fill("mock-owner-password");
    await page.getByRole("button", { name: "登录管理", exact: true }).click();
    await expect(page.getByRole("heading", { name: "设置", exact: true })).toBeVisible();
    await expectManagementShellVisible(page);
    await expect(page.locator("#nav-backdrop")).toBeHidden();
    expect(data.writes.some((write) => write.path.startsWith("/lifecycle/"))).toBe(false);
  });
}

test("@compat first-time password setup requires matching inputs and remains capture-paused", async ({ page }) => {
  const data = await mount(page, { requireSetup: true, loggedIn: false, authScreen: "设置管理密码" });
  await page.reload();
  await expect(page.locator("#setup-password")).toBeVisible();
  await expectManagementShellHidden(page);
  expect(data.requests.some((request) => ["/config", "/logs", "/traffic"].includes(request.path))).toBe(false);
  await page.locator("#setup-password").fill("mock-owner-password");
  await page.locator("#setup-password-confirm").fill("different-password");
  await page.getByRole("button", { name: "设置管理密码", exact: true }).click();
  await expect(page.locator("#auth-error")).toContainText("两次输入的密码不一致");
  expect(data.requests.some((request) => request.path === "/auth/password")).toBe(false);
  await page.locator("#setup-password-confirm").fill("mock-owner-password");
  await page.getByRole("button", { name: "设置管理密码", exact: true }).click();
  await expect(page.getByRole("heading", { name: "首页", exact: true })).toBeVisible();
  await expectManagementShellVisible(page);
  expect(data.requests.find((request) => request.path === "/auth/password")?.headers["x-csrf-token"]).toBe("setup-csrf");
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  expect(data.writes.some((write) => write.path.startsWith("/lifecycle/"))).toBe(false);
  await navigate(page, "settings");
  await page.getByRole("button", { name: "退出登录", exact: true }).click();
  await expect(page.locator("#login-password")).toBeVisible();
  await expectManagementShellHidden(page);
  await expect(page.locator("#login-password")).toHaveValue("");
  await page.locator("#login-password").fill("wrong-password");
  await page.getByRole("button", { name: "登录管理", exact: true }).click();
  await expect(page.locator("#auth-error")).toContainText("Password or authorization is invalid");
  await page.locator("#login-password").fill("mock-owner-password");
  await page.getByRole("button", { name: "登录管理", exact: true }).click();
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  await expectManagementShellVisible(page);
});

test("@compat public first visit cannot seize password setup without the local tray proof", async ({ page }) => {
  const data = await mount(page, { requireSetup: true, loggedIn: false, noBootstrap: true, authScreen: "设置管理密码" });
  await expect(page.getByText(/请从这台主机的 KONE 托盘重新打开管理页/)).toBeVisible();
  await expect(page.locator("#setup-password")).toHaveCount(0);
  expect(data.writes).toEqual([]);
});

test("@compat settings show grouped navigation with About first and account actions at the bottom", async ({ page }, testInfo) => {
  const data = await mount(page);
  for (const name of ["home", "connections", "inbounds", "outbounds", "rules", "dns", "diagnostics", "settings"]) {
    await navigate(page, name);
    await expect(page.getByRole("button", { name: "刷新", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "退出登录", exact: true })).toHaveCount(name === "settings" ? 1 : 0);
  }
  const root = page.locator("[data-settings-root]");
  await expect(root).toBeVisible();
  expect(await root.locator("[data-settings-group]").evaluateAll((groups) => groups.map((group) => group.getAttribute("data-settings-group")))).toEqual(["about", "application", "security", "maintenance", "actions"]);
  expect(await root.locator("[data-settings-link]").evaluateAll((links) => links.map((link) => link.getAttribute("data-settings-link")))).toEqual(["about", "logs", "geoip", "lan", "account", "configuration", "privacy", "network"]);
  for (const [group, labels] of [["application", ["应用设置", "日志设置", "GeoIP 数据"]], ["security", ["访问与安全", "手机与平板访问", "管理密码"]], ["maintenance", ["数据维护", "配置管理", "记录与隐私", "网络维护"]]]) {
    for (const label of labels) await expect(root.locator(`[data-settings-group="${group}"]`)).toContainText(label);
  }
  expect(await root.locator("[data-settings-action]").evaluateAll((actions) => actions.map((action) => action.getAttribute("data-settings-action")))).toEqual(["reset", "logout"]);
  await expect(root.locator("form, input, select, textarea")).toHaveCount(0);
  await expect(page.locator("[data-settings-detail]")).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("settings-ios-menu.png"), fullPage: true, animations: "disabled" });
  expect(data.writes).toEqual([]);
});

test("@compat settings subpages support direct links, the Back button and browser history", async ({ page }, testInfo) => {
  const data = await mount(page);
  await page.goto("/#settings/logs");
  await expect(page.locator('[data-settings-detail="logs"]')).toBeVisible();
  await expect(page.getByRole("heading", { name: "日志设置", exact: true })).toBeVisible();
  await expect(page.locator(".nav-link[data-page=settings]")).toHaveClass(/active/);
  await expect(page.locator("#log-level")).toHaveValue("info");
  await expect(page.locator("#editor-dialog")).not.toBeVisible();
  await page.locator("[data-settings-back]").click();
  await expect(page.locator("[data-settings-root]")).toBeVisible();
  await expect(page).toHaveURL(/#settings$/);
  await page.goBack();
  await expect(page.locator('[data-settings-detail="logs"]')).toBeVisible();
  await page.goForward();
  await expect(page.locator("[data-settings-root]")).toBeVisible();
  await page.locator('[data-settings-link="about"]').click();
  await expect(page.locator('[data-settings-detail="about"]')).toContainText("test-version");
  await expect(page.locator('[data-settings-detail="about"]')).toContainText("GPL-3.0-or-later");
  await page.screenshot({ path: testInfo.outputPath("settings-about-subpage.png"), animations: "disabled" });
  expect(data.writes).toEqual([]);
});

test("@compat log settings edit inline, cancel restores saved values and save retains unrelated configuration", async ({ page }, testInfo) => {
  const data = await mount(page);
  await navigateSettings(page, "logs");
  await page.locator("#log-level").selectOption("debug");
  await expect(page.locator("[data-settings-save]")).toBeEnabled();
  expect(data.writes).toEqual([]);
  await page.locator("[data-settings-cancel]").click();
  await expect(page.locator("#log-level")).toHaveValue("info");
  await expect(page.locator("[data-settings-save]")).toBeDisabled();
  await page.locator("#log-level").selectOption("warn");
  await page.locator("#log-format").selectOption("json");
  await page.screenshot({ path: testInfo.outputPath("settings-logs-inline.png"), animations: "disabled" });
  await expect(page.locator("#editor-dialog")).not.toBeVisible();
  await page.locator("[data-settings-save]").click();
  await expect.poll(() => data.writes.find((write) => write.path === "/config")?.body.config.general).toEqual({ "log-level": "warn", "log-format": "json" });
  expect(data.config.config.outbounds[0].name).toBe("Proxy A");
  expect(data.config.config.rules[0].outbound).toBe("Proxy A");
  await expect(page.locator("[data-settings-save]")).toBeDisabled();
  await page.locator("[data-settings-back]").click();
  await expect(page.locator('[data-settings-link="logs"]')).toContainText("WARN");
  expect(data.writes.some((write) => write.path.startsWith("/lifecycle/"))).toBe(false);
});

for (const destination of ["back", "history", "navigation"]) {
  test(`@compat unsaved inline log settings can stay or be discarded when leaving through ${destination}`, async ({ page }) => {
    const data = await mount(page);
    await navigateSettings(page, "logs");
    await page.locator("#log-level").selectOption("debug");
    const leave = async () => {
      if (destination === "back") await page.locator("[data-settings-back]").click();
      else if (destination === "history") await page.goBack();
      else await navigate(page, "dns");
    };
    await leave();
    await expect(page.locator("#detail-dialog").getByRole("heading", { name: "放弃未保存的修改？", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "继续编辑", exact: true }).click();
    await expect(page.locator('[data-settings-detail="logs"]')).toBeVisible();
    await expect(page.locator("#log-level")).toHaveValue("debug");
    expect(data.writes).toEqual([]);
    await leave();
    await page.getByRole("button", { name: "放弃修改并离开", exact: true }).click();
    if (destination === "navigation") await expect(page.getByRole("heading", { name: "DNS", exact: true })).toBeVisible();
    else await expect(page.locator("[data-settings-root]")).toBeVisible();
    await navigateSettings(page, "logs");
    await expect(page.locator("#log-level")).toHaveValue("info");
    expect(data.writes).toEqual([]);
  });
}

test("password subpage protects unfinished input when leaving and clears it after discard", async ({ page }) => {
  const data = await mount(page);
  await navigateSettings(page, "account");
  await page.locator("#current-password").fill("mock-owner-password");
  await page.locator("#new-password").fill("unfinished-password");
  await page.locator("[data-settings-back]").click();
  await page.getByRole("button", { name: "继续编辑", exact: true }).click();
  await expect(page.locator("#new-password")).toHaveValue("unfinished-password");
  await page.locator("[data-settings-back]").click();
  await page.getByRole("button", { name: "放弃修改并离开", exact: true }).click();
  await page.locator('[data-settings-link="account"]').click();
  await expect(page.locator("#current-password")).toHaveValue("");
  await expect(page.locator("#new-password")).toHaveValue("");
  expect(data.requests.some((request) => request.path === "/auth/password")).toBe(false);
});

test("@compat a delayed log-settings request cannot rebuild a later password subpage or erase its input", async ({ page }) => {
  const data = await mount(page);
  await navigate(page, "settings");
  let release;
  const deferred = { started: false, promise: new Promise((resolve) => { release = resolve; }) };
  data.deferConfig = deferred;
  try {
    await page.locator('[data-settings-link="logs"]').click();
    await expect.poll(() => deferred.started).toBe(true);
    await page.locator('[data-settings-link="account"]').click();
    await expect(page.locator('[data-settings-detail="account"]')).toBeVisible();
    await page.locator("#current-password").fill("mock-owner-password");
    await page.locator("#new-password").fill("unfinished-password");
    const response = page.waitForResponse((result) => new URL(result.url()).pathname === "/api/v1/config" && result.ok());
    release();
    await response;
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await expect(page.locator('[data-settings-detail="account"]')).toBeVisible();
    await expect(page.locator("#current-password")).toHaveValue("mock-owner-password");
    await expect(page.locator("#new-password")).toHaveValue("unfinished-password");
    expect(data.writes).toEqual([]);
  } finally { release(); }
});

test("@compat cancelling log edits finishes its reload before allowing navigation to a new form", async ({ page }) => {
  const data = await mount(page);
  await navigateSettings(page, "logs");
  await page.locator("#log-level").selectOption("debug");
  let release;
  const deferred = { started: false, promise: new Promise((resolve) => { release = resolve; }) };
  data.deferConfig = deferred;
  try {
    await page.locator("[data-settings-cancel]").click();
    await expect.poll(() => deferred.started).toBe(true);
    await expect(page.locator("[data-settings-back]")).toBeDisabled();
    await navigate(page, "dns");
    await expect(page).toHaveURL(/#settings\/logs$/);
    await expect(page.locator('[data-settings-detail="logs"]')).toBeVisible();
    const response = page.waitForResponse((result) => new URL(result.url()).pathname === "/api/v1/config" && result.ok());
    release();
    await response;
    await expect(page.locator("#log-level")).toHaveValue("info");
    await expect(page.locator("[data-settings-back]")).toBeEnabled();
    await navigateSettings(page, "account");
    await page.locator("#new-password").fill("new-form-input");
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await expect(page.locator("#new-password")).toHaveValue("new-form-input");
    expect(data.writes).toEqual([]);
  } finally { release(); }
});

test("@compat closing an unsaved-settings confirmation with Escape or the close button allows another attempt", async ({ page }) => {
  const data = await mount(page);
  await navigateSettings(page, "logs");
  await page.locator("#log-level").selectOption("debug");
  await page.locator("[data-settings-back]").click();
  await expect(page.getByRole("heading", { name: "放弃未保存的修改？", exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator("#detail-dialog")).not.toBeVisible();
  await expect(page.locator("#log-level")).toHaveValue("debug");
  await page.locator("[data-settings-back]").click();
  await expect(page.getByRole("heading", { name: "放弃未保存的修改？", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "关闭详情", exact: true }).click();
  await page.locator("[data-settings-back]").click();
  await expect(page.getByRole("heading", { name: "放弃未保存的修改？", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "放弃修改并离开", exact: true }).click();
  await expect(page.locator("[data-settings-root]")).toBeVisible();
  expect(data.writes).toEqual([]);
});

test("@compat settings subpages remain within a 320px viewport", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 320, height: 760 });
  const data = await mount(page);
  for (const section of ["about", "logs", "geoip", "lan", "account", "configuration", "privacy", "network"]) {
    await navigateSettings(page, section);
    await expect(page.locator("[data-settings-back]")).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth), section).toBeLessThanOrEqual(320);
    await expect(page.locator("#editor-dialog")).not.toBeVisible();
  }
  await page.locator("[data-settings-back]").click();
  await page.screenshot({ path: testInfo.outputPath("settings-menu-320px.png"), fullPage: true, animations: "disabled" });
  expect(data.writes).toEqual([]);
});

test("capture transitions lock the inline log and GeoIP forms without losing an existing draft", async ({ page }) => {
  const data = await mount(page);
  await navigateSettings(page, "logs");
  await page.locator("#log-level").selectOption("debug");
  data.state = "running";
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await expect(page.locator("#log-level")).toBeDisabled();
  await expect(page.locator("[data-settings-save]")).toBeDisabled();
  await expect(page.locator("#log-level")).toHaveValue("debug");
  data.state = "paused";
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await expect(page.locator("#log-level")).toBeEnabled();
  await expect(page.locator("#log-level")).toHaveValue("debug");
  await page.locator("[data-settings-cancel]").click();
  data.state = "running";
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await navigateSettings(page, "geoip");
  await expect(page.locator("#geoip-file")).toBeDisabled();
  await expect(page.locator("#geoip-expected")).toBeDisabled();
  expect(data.writes).toEqual([]);
});

test("settings retain read-only and remote ownership boundaries on their subpages", async ({ page }) => {
  const data = await mount(page, { role: "read" });
  await navigateSettings(page, "logs");
  await expect(page.locator("#log-level")).toBeDisabled();
  await expect(page.locator("[data-settings-save]")).toBeDisabled();
  await navigateSettings(page, "account");
  await expect(page.locator("#current-password")).toBeDisabled();
  await expect(page.getByRole("button", { name: "确认修改密码", exact: true })).toBeDisabled();
  await navigateSettings(page, "privacy");
  await expect(page.getByRole("button", { name: "导出脱敏配置", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "清空连接与 DNS 记录及本机解析缓存", exact: true })).toBeDisabled();
  data.role = "admin";
  data.remoteSession = true;
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await navigateSettings(page, "lan");
  await expect(page.locator("#lan-address")).toBeDisabled();
  await expect(page.getByRole("button", { name: "开启局域网访问", exact: true })).toBeDisabled();
  expect(data.writes).toEqual([]);
});

test("LAN subpage enables access, creates a scoped code, revokes a device and disables access", async ({ page }) => {
  const data = await mount(page);
  await navigateSettings(page, "lan");
  await page.locator("#lan-address").fill("192.168.50.1:9243");
  await page.getByRole("button", { name: "开启局域网访问", exact: true }).click();
  await expect.poll(() => data.writes.find((write) => write.path === "/access/lan")?.body).toEqual({ enabled: true, address: "192.168.50.1:9243" });
  await expect(page.locator("#detail-dialog").getByRole("heading", { name: "局域网访问", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "关闭详情", exact: true }).click();
  await expect(page.locator('[data-settings-detail="lan"]')).toContainText("fixture-certificate-fingerprint");
  await expect(page.getByRole("link", { name: "下载本地主机证书", exact: true })).toHaveAttribute("href", "/api/v1/access/certificate");
  await page.getByRole("button", { name: "创建只读授权码", exact: true }).click();
  await expect(page.locator("#detail-dialog")).toContainText("12345678");
  expect(data.writes.find((write) => write.path === "/pairing")?.body).toEqual({ role: "read" });
  await page.getByRole("button", { name: "关闭详情", exact: true }).click();
  await page.getByRole("button", { name: "撤销", exact: true }).click();
  await expect.poll(() => data.authorizedSessions.length).toBe(0);
  await expect(page.locator('[data-settings-detail="lan"]')).toContainText("尚无其他授权会话");
  await page.getByRole("button", { name: "关闭局域网访问", exact: true }).click();
  await expect.poll(() => data.lanState.enabled).toBe(false);
  await expect(page.getByRole("button", { name: "创建只读授权码", exact: true })).toBeDisabled();
  expect(data.writes.some((write) => write.path.startsWith("/lifecycle/"))).toBe(false);
});

test("privacy subpage exports redacted configuration and clears observations only after confirmation", async ({ page }) => {
  const data = await mount(page);
  await navigateSettings(page, "privacy");
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "导出脱敏配置", exact: true }).click();
  expect((await download).suggestedFilename()).toMatch(/^kone-redacted-.*\.toml$/);
  expect(data.requests.some((request) => request.path === "/export" && request.method === "GET")).toBe(true);
  await page.getByRole("button", { name: "清空连接与 DNS 记录及本机解析缓存", exact: true }).click();
  await page.locator("#detail-dialog").getByRole("button", { name: "取消", exact: true }).click();
  expect(data.writes).toEqual([]);
  await page.getByRole("button", { name: "清空连接与 DNS 记录及本机解析缓存", exact: true }).click();
  await page.getByRole("button", { name: "确认清空", exact: true }).click();
  await expect.poll(() => data.records.length).toBe(0);
  await navigate(page, "home");
  await expect(page.getByText("尚无可绘制的业务流量", { exact: true })).toBeVisible();
  expect(data.writes).toEqual([{ path: "/privacy/clear", body: {} }]);
});

test("@compat change password validates confirmation, verifies the current password and keeps capture paused", async ({ page }, testInfo) => {
  const data = await mount(page, { managementPassword: "mock-owner-password" });
  await navigateSettings(page, "account");
  await expect(page.locator("#detail-dialog")).not.toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("change-password.png"), animations: "disabled" });
  await page.locator("#current-password").fill("wrong-owner-password");
  await page.locator("#new-password").fill("replacement-owner-password");
  await page.locator("#confirm-new-password").fill("does-not-match");
  await page.getByRole("button", { name: "确认修改密码", exact: true }).click();
  await expect(page.locator('[data-settings-detail="account"]')).toContainText("两次输入");
  expect(data.requests.filter((request) => request.path === "/auth/password")).toHaveLength(0);
  await page.locator("#confirm-new-password").fill("replacement-owner-password");
  await page.getByRole("button", { name: "确认修改密码", exact: true }).click();
  await expect(page.locator('[data-settings-detail="account"]')).toContainText("当前管理密码不正确");
  await page.locator("#current-password").fill("mock-owner-password");
  await page.getByRole("button", { name: "确认修改密码", exact: true }).click();
  await expect(page.locator("#detail-dialog")).not.toBeVisible();
  const changes = data.requests.filter((request) => request.path === "/auth/password");
  expect(changes.at(-1)).toMatchObject({ method: "PUT", body: { current_password: "mock-owner-password", password: "replacement-owner-password", confirm_password: "replacement-owner-password" } });
  await expect(page.locator('[data-settings-detail="account"]')).toBeVisible();
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  await page.locator("[data-settings-back]").click();
  await page.getByRole("button", { name: "退出登录", exact: true }).click();
  await expect(page.locator("#login-password")).toHaveValue("");
  await page.locator("#login-password").fill("mock-owner-password");
  await page.getByRole("button", { name: "登录管理", exact: true }).click();
  await expect(page.locator("#auth-error")).toContainText("Password or authorization is invalid");
  await page.locator("#login-password").fill("replacement-owner-password");
  await page.getByRole("button", { name: "登录管理", exact: true }).click();
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  expect(data.writes.some((write) => write.path.startsWith("/lifecycle/"))).toBe(false);
});

test("@compat reset all configuration requires confirmation and leaves capture stopped", async ({ page }) => {
  const data = await mount(page);
  await navigate(page, "settings");
  await page.getByRole("button", { name: "重置所有配置", exact: true }).click();
  await page.locator("#detail-dialog").getByRole("button", { name: "取消", exact: true }).click();
  expect(data.writes.some((write) => write.path === "/config/defaults")).toBe(false);
  await page.getByRole("button", { name: "重置所有配置", exact: true }).click();
  await page.getByRole("button", { name: "确认重置所有配置", exact: true }).click();
  await expect.poll(() => data.writes.filter((write) => write.path === "/config/defaults").length).toBe(1);
  expect(data.writes.find((write) => write.path === "/config/defaults").body).toEqual({ base_version: 1 });
  await expect(page.locator("#page-notice")).toContainText("默认");
  await navigate(page, "outbounds");
  await expect(page.getByText("尚未配置代理", { exact: true })).toBeVisible();
  await navigate(page, "inbounds");
  await expect(page.locator('[data-card-title="TUN 接管入口"]')).toContainText("已启用");
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  expect(data.writes.some((write) => write.path.startsWith("/lifecycle/"))).toBe(false);
});

test("reset failures preserve the saved settings and surface the server reason", async ({ page }) => {
  const data = await mount(page, { resetError: "Configuration version changed; reload settings" });
  await navigate(page, "settings");
  await page.getByRole("button", { name: "重置所有配置", exact: true }).click();
  await page.getByRole("button", { name: "确认重置所有配置", exact: true }).click();
  await expect(page.getByText("Configuration version changed; reload settings", { exact: false })).toBeVisible();
  expect(data.config.version).toBe(1);
  await page.locator("#detail-dialog").getByRole("button", { name: "取消", exact: true }).click();
  await navigate(page, "outbounds");
  await expect(page.locator('[data-outbound-row="0"]')).toContainText("Proxy A");
});

test("capture starting after reset confirmation still prevents configuration loss", async ({ page }) => {
  const data = await mount(page);
  await navigate(page, "settings");
  await page.getByRole("button", { name: "重置所有配置", exact: true }).click();
  data.state = "running";
  await page.getByRole("button", { name: "确认重置所有配置", exact: true }).click();
  await expect(page.locator("#detail-dialog")).toContainText("Pause capture and finish recovery before resetting configuration");
  expect(data.config.version).toBe(1);
  expect(data.config.config.outbounds[0].name).toBe("Proxy A");
  expect(data.writes.some((write) => write.path.startsWith("/lifecycle/"))).toBe(false);
});

test("inactive invalid configuration can be repaired by resetting all settings", async ({ page }) => {
  const data = await mount(page);
  data.state = "invalid_config";
  data.configError = "Saved configuration contains an invalid outbound";
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await navigate(page, "settings");
  await expect(page.getByRole("button", { name: "重置所有配置", exact: true })).toBeEnabled();
  await page.getByRole("button", { name: "重置所有配置", exact: true }).click();
  await page.getByRole("button", { name: "确认重置所有配置", exact: true }).click();
  await expect(page.locator("#page-notice")).toContainText("所有配置已恢复默认");
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  expect(data.configError).toBe("");
  expect(data.config.config.outbounds).toEqual([]);
  expect(data.writes.some((write) => write.path.startsWith("/lifecycle/"))).toBe(false);
});

for (const previousState of ["recovery_required", "recovery_failed", "pending_recovery"]) {
  test(`inactive ${previousState} does not prevent resetting configuration`, async ({ page }) => {
    const data = await mount(page);
    if (previousState !== "pending_recovery") data.state = previousState;
    data.recoveryRequired = true;
    await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    await navigate(page, "settings");
    await expect(page.getByRole("button", { name: "重置所有配置", exact: true })).toBeEnabled();
    await page.getByRole("button", { name: "重置所有配置", exact: true }).click();
    await page.getByRole("button", { name: "确认重置所有配置", exact: true }).click();
    await expect(page.locator("#page-notice")).toContainText("所有配置已恢复默认");
    expect(data.recoveryRequired).toBe(false);
    expect(data.writes.some((write) => write.path === "/lifecycle/recover")).toBe(false);
    expect(data.writes.some((write) => write.path === "/lifecycle/start")).toBe(false);
  });
}

for (const condition of ["running", "starting", "degraded", "pausing", "stopping", "preflight", "capture_locked"]) {
  test(`reset configuration is blocked while ${condition}`, async ({ page }) => {
    const data = await mount(page);
    if (condition === "capture_locked") data.captureLocked = true;
    else data.state = condition;
    await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    await navigate(page, "settings");
    await expect(page.getByRole("button", { name: "重置所有配置", exact: true })).toBeDisabled();
    expect(data.writes.some((write) => write.path === "/config/defaults")).toBe(false);
  });
}

test("read-only sessions cannot change the password or reset configuration", async ({ page }) => {
  const data = await mount(page, { role: "read" });
  await navigate(page, "settings");
  await expect(page.getByRole("button", { name: "重置所有配置", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "退出登录", exact: true })).toBeEnabled();
  await page.locator('[data-settings-link="account"]').click();
  await expect(page.getByRole("button", { name: "确认修改密码", exact: true })).toBeDisabled();
  expect(data.writes).toEqual([]);
});

test("@compat capture starts with one click without advisory readiness dialogs", async ({ page }) => {
  const data = await mount(page, { readiness: {
    ready: false, saved_version: 1, checks: [], changes: ["Add capture routes"],
    blockers: [{ id: "recovery", code: "recovery", severity: "error", message: "Old recovery journal", page: "settings" }],
    warnings: [{ id: "capture_scope", code: "capture_scope", severity: "warning", page: "inbounds" }, { id: "outbound_health", code: "outbound_health", severity: "warning", page: "outbounds" }],
    recovery: { required: true, can_clear: true, ownership: "owned", items: [{ kind: "journal", status: "owned", message: "Old journal can be cleared" }] },
  } });
  await page.locator("#lifecycle-toggle").click();
  await expect(page.locator("#runtime-status")).toContainText("正在接管");
  await expect(page.locator("#detail-dialog")).not.toBeVisible();
  expect(data.requests.some((request) => request.path === "/readiness")).toBe(false);
  expect(data.writes).toEqual([{ path: "/lifecycle/start", body: {} }]);
});

for (const previousState of ["recovery_required", "recovery_failed"]) {
  test(`capture starts from an inactive ${previousState} journal without a manual recovery step`, async ({ page }) => {
    const data = await mount(page);
    data.state = previousState;
    data.recoveryRequired = true;
    data.lastError = "Previous capture stopped before reporting completion";
    await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    await expect(page.locator("#runtime-status")).toContainText("尚未接管");
    await navigateSettings(page, "network");
    const recovery = page.locator('[data-settings-detail="network"]');
    await expect(recovery).toContainText("接管停止后会自动恢复网络");
    await expect(recovery).not.toContainText("所有权判断");
    await expect(recovery).not.toContainText("下一步");
    await page.locator("#lifecycle-toggle").click();
    await expect(page.locator("#runtime-status")).toContainText("正在接管");
    await expect(page.locator("#detail-dialog")).not.toBeVisible();
    expect(data.recoveryRequired).toBe(false);
    expect(data.writes).toEqual([{ path: "/lifecycle/start", body: {} }]);
    expect(data.requests.some((request) => request.path === "/readiness")).toBe(false);
  });
}

for (const [code, message] of [
  ["configuration", "规则 2 引用了不存在的出站 Missing Proxy。"],
  ["preflight", "TUN 设备被另一个程序占用，请先关闭该程序。"],
]) {
  test(`capture startup shows the backend ${code} failure directly`, async ({ page }) => {
    const data = await mount(page, { startError: { code, message } });
    await page.locator("#lifecycle-toggle").click();
    await expect(page.locator("#page-notice")).toContainText(message);
    await expect(page.locator("#detail-dialog")).not.toBeVisible();
    await expect(page.locator("#runtime-status")).toContainText("已暂停");
    expect(data.writes).toEqual([{ path: "/lifecycle/start", body: {} }]);
    expect(data.requests.some((request) => request.path === "/readiness")).toBe(false);
  });
}

test("@compat a late authenticated state response cannot restore a logged-out console", async ({ page }) => {
  const data = await mount(page);
  data.requirePassword = true;
  data.managementPassword = "mock-owner-password";
  await navigate(page, "settings");
  let release;
  const deferred = { started: false, promise: new Promise((resolve) => { release = resolve; }) };
  data.deferState = deferred;
  try {
    await expect.poll(() => deferred.started).toBe(true);
    await page.getByRole("button", { name: "退出登录", exact: true }).click();
    await expect(page.locator("#login-password")).toBeVisible();
    const lateState = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/state" && response.ok());
    release();
    await lateState;
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await expect(page.locator("#login-password")).toBeVisible();
    await expectManagementShellHidden(page);
    await expect(page.locator("#main .sankey-svg")).toHaveCount(0);
    expect(data.writes.some((write) => write.path.startsWith("/lifecycle/"))).toBe(false);
  } finally { release(); }
});

test("@compat direct-only capture uses one short confirmation and remembers the choice", async ({ page }, testInfo) => {
  const data = await mount(page, { directOnly: true });
  await page.locator("#lifecycle-toggle").click();
  await expect(page.getByRole("heading", { name: "启用直连接管", exact: true })).toBeVisible();
  await expect(page.locator("#detail-dialog")).toContainText("当前规则仅使用直连或拒绝，不经过代理。");
  await expect(page.locator("#detail-dialog").getByRole("checkbox")).toHaveCount(0);
  await expect(page.locator("#detail-dialog")).not.toContainText("系统变更");
  await expect(page.locator("#detail-dialog")).not.toContainText("恢复");
  await expect(page.locator("#detail-dialog")).not.toContainText("null");
  await expectNoDialogPlaceholders(page);
  await page.screenshot({ path: testInfo.outputPath("direct-only-simple-confirmation.png"), animations: "disabled" });
  expect(data.writes).toEqual([]);
  await page.locator("#detail-dialog").getByRole("button", { name: "取消", exact: true }).click();
  expect(data.writes).toEqual([]);
  await page.locator("#lifecycle-toggle").click();
  await page.getByRole("button", { name: "确认启用接管", exact: true }).click();
  await expect(page.locator("#runtime-status")).toContainText("正在接管");
  await expect(page.locator("#detail-dialog")).not.toBeVisible();
  expect(data.writes.find((write) => write.path === "/config")?.body.direct_only_confirmed).toBe(true);
  expect(data.writes.filter((write) => write.path === "/lifecycle/start")).toHaveLength(1);
  data.state = "paused";
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  await page.locator("#lifecycle-toggle").click();
  await expect(page.locator("#runtime-status")).toContainText("正在接管");
  await expect(page.locator("#detail-dialog")).not.toBeVisible();
  expect(data.writes.filter((write) => write.path === "/lifecycle/start")).toHaveLength(2);
  expect(data.writes.filter((write) => write.path === "/config")).toHaveLength(1);
  expect(data.requests.some((request) => request.path === "/readiness")).toBe(false);
});

test("direct-only confirmation preserves saved settings while an editor contains an unsaved draft", async ({ page }) => {
  const data = await mount(page, { directOnly: true });
  const saved = structuredClone(data.config.config);
  await navigate(page, "outbounds");
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await page.locator("#outbound-name-0").fill("Unsaved proxy draft");
  await page.locator("#lifecycle-toggle").dispatchEvent("click");
  await page.getByRole("button", { name: "确认启用接管", exact: true }).click();
  await expect(page.locator("#runtime-status")).toContainText("正在接管");
  const confirmation = data.writes.find((write) => write.path === "/config");
  expect(confirmation.body.config).toEqual(saved);
  expect(confirmation.body.direct_only_confirmed).toBe(true);
  expect(data.config.config.outbounds[0].name).toBe("Proxy A");
});

test("dialogs without footer actions do not display placeholder values", async ({ page }) => {
  await mount(page, { bootstrapPage: "diagnostics" });
  await page.getByRole("button", { name: "新建诊断", exact: true }).click();
  await expect(page.locator("#detail-dialog").getByRole("heading", { name: "新建诊断", exact: true })).toBeVisible();
  await expectNoDialogPlaceholders(page);
});

test("@compat configuration pages start as saved-state displays and cancel discards edits", async ({ page }, testInfo) => {
  const data = await mount(page);
  for (const name of ["inbounds", "outbounds", "rules", "dns", "settings"]) {
    await navigate(page, name);
    await expect(page.locator("#main [data-save]")).toHaveCount(0);
    await expect(page.locator("#main .editor-item")).toHaveCount(0);
  }
  await navigate(page, "outbounds");
  await expect(page.locator('[data-outbound-row="0"]')).toContainText("Proxy A");
  await page.screenshot({ path: testInfo.outputPath("outbounds-list.png"), animations: "disabled" });
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await page.screenshot({ path: testInfo.outputPath("outbound-editor.png"), animations: "disabled" });
  await page.locator("#outbound-name-0").fill("discard this name");
  await page.locator("[data-editor-cancel]").click();
  await expect(page.locator("[data-outbound-editor]")).toHaveCount(0);
  await expect(page.locator("#editor-dialog")).not.toBeVisible();
  await expect(page.locator('[data-outbound-row="0"]')).toContainText("Proxy A");
  expect(data.writes).toEqual([]);
});

test("@compat running capture locks TUN while rule edits save and hot-apply", async ({ page }) => {
  const data = await mount(page);
  data.state = "running";
  await expect(page.locator("#runtime-status")).toContainText("正在接管");
  await navigate(page, "inbounds");
  await expect(page.getByRole("button", { name: "编辑入站", exact: true })).toBeDisabled();
  await navigate(page, "rules");
  await page.locator('[data-rule-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await page.locator("#rule-pattern-0").fill("updated.example");
  await page.getByRole("button", { name: "保存", exact: true }).click();
  await expect(page.locator("#editor-dialog")).not.toBeVisible();
  await expect(page.locator('[data-rule-row="0"]')).toContainText("updated.example");
  await expect(page.locator("#page-notice")).toContainText("已保存并热应用");
  expect(data.writes.some((write) => write.path.startsWith("/lifecycle/") || write.path === "/config/apply")).toBe(false);
});

for (const [section, kind, field] of [["inbounds", "inbounds", "#inbound-tun"], ["rules", "rule", "#rule-protocol-0"], ["dns", "dns", "#dns-port"]]) {
  test(`@compat ${section} editors keep advanced controls folded and cancel without saving`, async ({ page }) => {
    const data = await mount(page);
    await navigate(page, section);
    if (kind === "inbounds") await page.getByRole("button", { name: "编辑入站", exact: true }).click();
    else if (kind === "dns") await page.getByRole("button", { name: "编辑 DNS 设置", exact: true }).click();
    else await page.locator('[data-rule-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
    const advanced = page.locator(`[data-editor-advanced="${kind}"]`);
    await expect(advanced).toHaveJSProperty("open", false);
    await expect(page.locator(field)).toBeHidden();
    await expect(page.locator("[data-editor-save]")).toHaveText("保存");
    await expect(page.locator("[data-editor-cancel]")).toHaveText("取消");
    await expect(page.getByRole("button", { name: "校验与预览", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "保存并应用", exact: true })).toHaveCount(0);
    await advanced.locator(":scope > summary").click();
    await expect(page.locator(field)).toBeVisible();
    if (kind === "inbounds") await page.locator(field).fill("kone-fixture-device");
    else if (kind === "rule") await page.locator(field).selectOption("udp");
    else await page.locator(field).fill("5353");
    await page.locator("[data-editor-cancel]").click();
    await expect(page.locator("#editor-dialog")).not.toBeVisible();
    expect(data.writes).toEqual([]);
  });
}

for (const [protocol, port] of [["http", "80"], ["https", "443"], ["socks5", "1080"], ["ss", "8388"]]) {
  test(`@compat ${protocol} proxies save structured endpoint fields without starting a connection`, async ({ page }, testInfo) => {
    const data = await mount(page);
    await navigate(page, "outbounds");
    await page.getByRole("button", { name: "＋ 添加代理", exact: true }).click();
    await expect(page.locator('[data-outbound-editor="1"]')).toBeVisible();
    await expect(page.locator("#editor-dialog")).not.toBeVisible();
    await page.locator("#outbound-protocol-1").selectOption(protocol);
    await page.locator("#outbound-host-1").fill("proxy.example");
    await page.locator("#outbound-port-1").fill(port);
    if (protocol === "ss") {
      await page.locator("#outbound-method-1").selectOption("aes-128-gcm");
      await page.locator("#outbound-password-1").fill("fixture-ss-secret");
    }
    await expect(page.locator("#outbound-name-1")).not.toHaveValue("");
    await expect(page.locator("#outbound-url-1")).toHaveCount(0);
    await expect(page.locator("#outbound-udp-1")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "校验与预览", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "保存并应用", exact: true })).toHaveCount(0);
    if (protocol === "http") await page.screenshot({ path: testInfo.outputPath("outbound-structured-editor.png"), animations: "disabled" });
    const name = await page.locator("#outbound-name-1").inputValue();
    await saveOutbound(page);
    await expect(page.locator("[data-outbound-test-suggestion]")).toBeVisible();
    if (protocol === "http") await page.screenshot({ path: testInfo.outputPath("outbound-saved-test-suggestion.png"), animations: "disabled" });
    expect(data.requests.some((request) => request.path === "/outbounds/test")).toBe(false);
    const saved = data.writes.find((write) => write.path === "/config");
    expect(saved.body.config.outbounds.at(-1)).toMatchObject({ name, url: `${protocol}://proxy.example:${port}`, "udp-fallback": "direct" });
    expect(saved.body.credential_actions[name]).toMatchObject(protocol === "ss" ? { action: "replace", username: "aes-128-gcm", password: "fixture-ss-secret" } : { action: "clear" });
    expect(data.writes.findIndex((write) => write.path === "/config/validate")).toBeLessThan(data.writes.indexOf(saved));
    await dismissOutboundTestSuggestion(page);
    await expect(page.locator('[data-outbound-row="1"]')).toContainText(name);
    await expect(page.locator('[data-outbound-row="1"]')).toContainText(/未测试|待测试/);
    expect(data.requests.some((request) => request.path === "/outbounds/test")).toBe(false);
  });
}

test("@compat default outbound names remain unique and a custom name survives changing protocol", async ({ page }) => {
  const initial = fixture();
  initial.config.config.outbounds.push({ id: "outbound-id-2", name: "HTTP 代理", url: "http://127.0.0.1:8081" }, { id: "outbound-id-3", name: "HTTP 代理 2", url: "http://127.0.0.1:8082" });
  const data = await mount(page, { config: initial.config });
  await navigate(page, "outbounds");
  await page.getByRole("button", { name: "＋ 添加代理", exact: true }).click();
  await expect(page.locator("#outbound-name-3")).toHaveValue("HTTP 代理 3");
  await page.locator("#outbound-name-3").fill("Office custom name");
  await page.locator("#outbound-protocol-3").selectOption("https");
  await expect(page.locator("#outbound-name-3")).toHaveValue("Office custom name");
  await page.locator("[data-editor-cancel]").click();
  await expect(page.locator('[data-outbound-row="3"]')).toHaveCount(0);
  expect(data.writes).toEqual([]);
});

test("@compat the structured outbound editor fits a 320px viewport", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 320, height: 760 });
  const data = await mount(page);
  await navigate(page, "outbounds");
  await page.getByRole("button", { name: "＋ 添加代理", exact: true }).click();
  await expect(page.locator('[data-outbound-editor="1"]')).toBeVisible();
  await expect(page.locator("#outbound-host-1")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
  await page.screenshot({ path: testInfo.outputPath("outbound-editor-320px.png"), fullPage: true, animations: "disabled" });
  await page.locator("[data-editor-cancel]").click();
  expect(data.writes).toEqual([]);
});

test("outbound edit deep links retain stable identity and automatic validation keeps the failed form", async ({ page }) => {
  const data = await mount(page, { validationFailure: "代理地址无法解析，请检查服务器地址。" });
  await page.goto("/#outbounds/edit/outbound-id-1");
  await expect(page.locator('[data-outbound-editor="0"]')).toBeVisible();
  await expect(page.locator("#outbound-host-0")).toHaveValue("127.0.0.1");
  await expect(page.locator("#outbound-username-0")).toHaveValue("");
  await expect(page.locator("#outbound-password-0")).toHaveValue("");
  await page.locator("#outbound-name-0").fill("Keep this draft");
  await saveOutbound(page);
  await expect(page.locator("#page-notice")).toContainText("代理地址无法解析");
  await expect(page.locator("#outbound-name-0")).toHaveValue("Keep this draft");
  await expect(page).toHaveURL(/#outbounds\/edit\/outbound-id-1$/);
  expect(data.writes.some((write) => write.path === "/config")).toBe(false);
  expect(data.requests.some((request) => request.path === "/outbounds/test")).toBe(false);
});

for (const previousExit of ["cancel", "save"]) {
  test(`@compat same-hash history after outbound ${previousExit} still guards a later dirty Back`, async ({ page }) => {
    const data = await mount(page);
    await navigate(page, "outbounds");
    await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
    if (previousExit === "cancel") await page.locator("[data-editor-cancel]").click();
    else {
      await page.locator("#outbound-name-0").fill("Saved proxy");
      await saveOutbound(page);
      await confirmReferencedOutboundRename(page);
      await dismissOutboundTestSuggestion(page);
    }
    await expect(page).toHaveURL(/#outbounds$/);
    await page.evaluate(() => new Promise((resolve) => {
      window.addEventListener("popstate", () => resolve(), { once: true });
      history.back();
    }));
    await expect(page).toHaveURL(/#outbounds$/);
    const savedName = data.config.config.outbounds[0].name;
    const savedWrites = data.writes.filter((write) => write.path === "/config").length;
    await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
    await page.locator("#outbound-name-0").fill("Unsaved after same-hash Back");
    await page.goBack();
    await expect(page.getByRole("heading", { name: "放弃未保存的修改？", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "放弃修改并离开", exact: true }).click();
    await expect(page.locator('[data-outbound-row="0"]')).toContainText(savedName);
    await expect(page.locator("[data-outbound-editor]")).toHaveCount(0);
    expect(data.writes.filter((write) => write.path === "/config")).toHaveLength(savedWrites);
  });
}

test("partial outbound credentials stay in the form and explicit clearing removes the saved authentication", async ({ page }) => {
  const data = await mount(page);
  await navigate(page, "outbounds");
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await page.locator("#outbound-username-0").fill("changed-user-only");
  await saveOutbound(page);
  await expect(page.locator("#page-notice")).toContainText("用户名和密码");
  await expect(page.locator("#outbound-username-0")).toHaveValue("changed-user-only");
  expect(data.writes.some((write) => write.path === "/config")).toBe(false);
  await page.locator("#outbound-clear-auth-0").check();
  await saveOutbound(page);
  await dismissOutboundTestSuggestion(page);
  expect(data.writes.find((write) => write.path === "/config").body.credential_actions["Proxy A"]).toMatchObject({ action: "clear", original_name: "Proxy A" });
  expect(data.config.config.outbounds[0].url).not.toContain("@");
  expect(data.config.credential_state["Proxy A"].configured).toBe(false);
  expect(data.requests.some((request) => request.path === "/outbounds/test")).toBe(false);
});

test("testing an outbound draft is explicit, preserves stored credentials and invalidates evidence after edits", async ({ page }) => {
  const data = await mount(page, { asyncHealth: true });
  const saved = structuredClone(data.config);
  await navigate(page, "outbounds");
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await page.locator("#outbound-username-0").fill("draft-user");
  await page.locator("#outbound-password-0").fill("draft-password");
  await page.locator("[data-outbound-draft-test]").click();
  const panel = page.locator("[data-outbound-draft-panel]");
  await expect(panel).toBeVisible();
  await expect(panel.locator("[data-outbound-test-progress]")).toContainText(/连接|connect/);
  const probe = data.writes.find((write) => write.path === "/outbounds/test");
  expect(probe.body).toMatchObject({ base_version: 1, draft: { id: "outbound-id-1", name: "Proxy A" }, credential_action: { action: "replace", username: "draft-user", password: "draft-password" } });
  expect(data.config).toEqual(saved);
  expect(data.writes.some((write) => write.path === "/config")).toBe(false);
  data.testStage = "complete";
  await expect(panel.locator('[data-outbound-protocol="udp"]')).toContainText(/不支持|unsupported/);
  await expect(page.locator("#outbound-udp-0")).toBeVisible();
  await page.locator("#outbound-host-0").fill("different-proxy.example");
  await expect(page.locator("#outbound-udp-0")).toBeHidden();
  await page.locator("[data-editor-cancel]").click();
  expect(data.config).toEqual(saved);
  await expect(page.locator('[data-outbound-row="0"]')).toContainText(/未测试|待测试/);
});

test("@compat explicit outbound tests show live stages, real connect latency and protocol evidence", async ({ page }, testInfo) => {
  const data = await mount(page, { asyncHealth: true });
  await navigate(page, "outbounds");
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "测试", exact: true }).click();
  const panel = page.locator('[data-outbound-test-panel="0"]');
  const latency = page.locator('[data-outbound-row="0"] [data-outbound-connect-latency]');
  await expect(panel).toBeVisible();
  await expect(panel.locator("[data-outbound-test-progress]")).toContainText(/连接|connect/);
  await expect(page.locator('[data-outbound-row="0"]')).toContainText("测试中");
  data.testStage = "proxy_handshake";
  await expect(panel.locator("[data-outbound-test-progress]")).toContainText(/握手|代理协议|proxy_handshake/);
  await expect(latency).toContainText(/12\s*ms/);
  data.testStage = "target_tls";
  await expect(panel.locator("[data-outbound-test-progress]")).toContainText(/TLS|tls/);
  data.testStage = "complete";
  await expect(panel.locator('[data-outbound-protocol="tcp"]')).toContainText(/通过|成功|可用|healthy/);
  await expect(panel.locator('[data-outbound-protocol="tls"]')).toContainText(/通过|成功|可用|healthy/);
  await expect(panel.locator('[data-outbound-protocol="udp"]')).toContainText(/不支持|unsupported/);
  await expect(latency).toContainText(/12\s*ms/);
  await expect(latency).not.toContainText("240");
  await expect(page.locator('[data-outbound-row="0"]')).toContainText(/可用|成功/);
  await page.screenshot({ path: testInfo.outputPath("outbound-live-test-results.png"), fullPage: true, animations: "disabled" });
  expect(data.writes.filter((write) => write.path === "/outbounds/test")).toHaveLength(1);
  expect(data.writes.some((write) => write.path === "/config")).toBe(false);
});

test("saving a proxy suggests a test and starts it only when the user chooses Test connection", async ({ page }) => {
  const data = await mount(page);
  await navigate(page, "outbounds");
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await page.locator("#outbound-name-0").fill("Office probe");
  await saveOutbound(page);
  await confirmReferencedOutboundRename(page);
  await expect(page.locator("[data-outbound-test-suggestion]")).toBeVisible();
  expect(data.requests.some((request) => request.path === "/outbounds/test")).toBe(false);
  await page.getByRole("button", { name: "测试连接", exact: true }).click();
  await expect(page.locator('[data-outbound-test-panel="0"]')).toBeVisible();
  await expect.poll(() => data.writes.filter((write) => write.path === "/outbounds/test").length).toBe(1);
  expect(data.writes.find((write) => write.path === "/outbounds/test").body).toMatchObject({ outbound_id: "outbound-id-1", base_version: 2 });
});

test("a measured zero millisecond connect latency is displayed as a measurement", async ({ page }) => {
  await mount(page, { connectLatency: 0 });
  await navigate(page, "outbounds");
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "测试", exact: true }).click();
  await expect(page.locator("[data-outbound-connect-latency]")).toContainText(/0\s*ms/);
  await expect(page.locator("[data-outbound-connect-latency]")).not.toContainText(/未测试|未知/);
});

test("Shadowsocks transport success without target verification stays unverified", async ({ page }) => {
  const initial = fixture();
  initial.config.config.outbounds[0].url = "ss://REDACTED:REDACTED@127.0.0.1:8388";
  const data = await mount(page, { config: initial.config });
  await navigate(page, "outbounds");
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "测试", exact: true }).click();
  await page.locator("[data-outbound-test-options] > summary").click();
  await page.locator("#outbound-test-tls").uncheck();
  await page.getByRole("button", { name: "重新测试", exact: true }).click();
  await expect.poll(() => data.writes.filter((write) => write.path === "/outbounds/test").length).toBe(2);
  await expect(page.locator('[data-outbound-protocol="tcp"]')).toContainText(/未验证|未知/);
  await expect(page.locator('[data-outbound-protocol="udp"]')).toContainText(/未验证|未知/);
  await expect(page.locator('[data-outbound-row="0"] .outbound-status-line')).not.toContainText(/成功|可用/);
});

test("UDP fallback appears only after an explicit unsupported result and an unknown result stays unverified", async ({ page }) => {
  const data = await mount(page);
  await navigate(page, "outbounds");
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await expect(page.locator("#outbound-udp-0")).toHaveCount(0);
  await page.locator("[data-editor-cancel]").click();
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "测试", exact: true }).click();
  await expect(page.locator('[data-outbound-protocol="udp"]')).toContainText(/不支持|unsupported/);
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await expect(page.locator("#outbound-udp-0")).toBeVisible();
  await page.locator('[data-editor-advanced="outbound"] > summary').click();
  await page.locator("#outbound-enabled-0").uncheck();
  await expect(page.locator("#outbound-udp-0")).toBeHidden();
  await page.locator("[data-editor-cancel]").click();
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await expect(page.locator("#outbound-udp-0")).toBeVisible();
  await page.locator("#outbound-udp-0").selectOption("direct");
  await saveOutbound(page);
  await dismissOutboundTestSuggestion(page);
  expect(data.writes.find((write) => write.path === "/config").body.config.outbounds[0]["udp-fallback"]).toBe("direct");
  data.udpStatus = "unknown";
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "测试", exact: true }).click();
  await expect(page.locator('[data-outbound-protocol="udp"]')).toContainText(/未验证|未测试|未知|unknown/);
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await expect(page.locator("#outbound-udp-0")).toHaveCount(0);
});

test("@compat outbound testing is explicit, reports protocol failure and updates its list status", async ({ page }) => {
  const data = await mount(page, { healthFailure: true });
  await navigate(page, "outbounds");
  expect(data.writes).toEqual([]);
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "测试", exact: true }).click();
  await expect(page.locator('[data-outbound-test-panel="0"]')).toBeVisible();
  await expect(page.locator('[data-outbound-test-panel="0"]')).toContainText("Proxy connection refused");
  await page.locator("[data-outbound-test-options] > summary").click();
  await page.locator("#outbound-test-target").fill("target.example:8443");
  await page.getByRole("button", { name: "重新测试", exact: true }).click();
  await expect.poll(() => data.writes.filter((write) => write.path === "/outbounds/test").length).toBe(2);
  expect(data.writes.filter((write) => write.path === "/outbounds/test").at(-1)?.body).toMatchObject({ outbound_id: "outbound-id-1", target: "target.example:8443", tls: true });
  await expect(page.locator("#detail-dialog")).not.toBeVisible();
  await expect(page.locator('[data-outbound-row="0"]')).toContainText(/测试失败|失败/);
  expect(data.writes.some((write) => write.path === "/config" || write.path.startsWith("/lifecycle/"))).toBe(false);
});

test("@compat desktop diagnostic deep link opens diagnostics without starting a probe", async ({ page }) => {
  const data = await mount(page, { bootstrapPage: "diagnostics" });
  await expect(page).toHaveURL(/#diagnostics$/);
  await expect(page.locator("#diagnose-target")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "新建诊断", exact: true })).toBeVisible();
  await expect(page.locator(".nav-link[data-page=diagnostics]")).toHaveClass(/active/);
  expect(data.requests.some((request) => request.path === "/diagnostics" && request.method === "GET")).toBe(true);
  expect(data.requests.filter((request) => request.path === "/session")).toHaveLength(1);
  expect(data.writes).toHaveLength(0);
  expect(data.requests.every((request) => !Object.hasOwn(request.query, "token"))).toBe(true);
  expect(page.url()).not.toContain("local-test-only");
});

test("@compat uses embedded offline assets, removes token fragment, and renders native measured paths", async ({
  page,
}, testInfo) => {
  const external = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("http://127.0.0.1:4173/"))
      external.push(request.url());
  });
  const data = await mount(page);
  await expect(page).toHaveURL(/#home$/);
  await expect(page.locator(".sankey-node")).toHaveCount(7);
  await expect(
    page.locator(".sankey-node").filter({ hasText: "example.com:443" }),
  ).toBeVisible();
  expect(data.requests.find((r) => r.path === "/traffic").query.metric).toBe(
    "total",
  );
  expect(
    data.requests.find((r) => r.path === "/session").headers.authorization,
  ).toBe("Bearer local-test-only");
  expect(
    data.requests.find((r) => r.path === "/state").headers.authorization,
  ).toBeUndefined();
  expect(external).toEqual([]);
  const viewport = page.viewportSize();
  await page.screenshot({
    path: testInfo.outputPath(
      `home-${testInfo.project.use.browserName}-${viewport.width}x${viewport.height}.png`,
    ),
  });
});

test("@compat touch/keyboard Sankey drilldown preserves exact sample and returns to its selection", async ({
  page,
}, testInfo) => {
  const data = await mount(page);
  const node = page
    .locator(".sankey-node")
    .filter({ hasText: "example.com:443" });
  if (testInfo.project.use.hasTouch) await node.locator("rect").tap();
  else {
    await node.focus();
    await page.keyboard.press("Enter");
  }
  await expect(page.locator("#path-selection")).toContainText("1 条连接");
  await page.getByRole("button", { name: "查看连接", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "连接", exact: true }),
  ).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(1);
  const drill = data.requests.find((r) => r.path === "/flows");
  expect(drill.query).toMatchObject({
    anchor: "traffic-session:3",
    path_ids: "path-flow-a",
    flow_ids: "flow-a",
    since: start,
    until: end,
  });
  await page.getByRole("button", { name: "详情", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("fake-ip");
  await expect(page.getByRole("dialog")).toContainText("来自其他设备");
  await page.getByRole("button", { name: "关闭详情" }).click();
  await navigate(page, "home");
  await expect(page.locator("#path-selection")).toContainText(
    "example.com:443",
  );
});

test("expired graph details are reported without silently substituting live records", async ({
  page,
}) => {
  await mount(page, { expired: true });
  await page
    .locator(".sankey-node")
    .filter({ hasText: "example.com:443" })
    .click();
  await page.getByRole("button", { name: "查看连接", exact: true }).click();
  await expect(page.locator("#page-notice")).toContainText("已过期");
  await expect(
    page.getByRole("heading", { name: "首页", exact: true }),
  ).toBeVisible();
});

test("rename updates rule references atomically and explicitly preserves masked credentials", async ({
  page,
}) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=outbounds]").click();
  await expect(page.locator("#outbound-name-0")).toHaveCount(0);
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await page.locator("#outbound-name-0").fill("Office");
  await page.locator("#outbound-name-0").dispatchEvent("input");
  await saveOutbound(page);
  await confirmReferencedOutboundRename(page);
  await dismissOutboundTestSuggestion(page);
  await expect(page.locator("#page-notice")).toContainText("已保存");
  const save = data.writes.find((r) => r.path === "/config");
  expect(save.body.config.outbounds[0].name).toBe("Office");
  expect(save.body.config.outbounds[0].id).toBe("outbound-id-1");
  expect(save.body.config.rules[0].outbound).toBe("Office");
  expect(save.body.credential_actions.Office).toMatchObject({
    action: "preserve",
    original_name: "Proxy A",
  });
  expect(save.body.config.general["log-level"]).toBe("info");
  await expect(page.locator("#editor-dialog")).not.toBeVisible();
  await expect(page.locator('[data-outbound-row="0"]')).toContainText("Office");
});

test("version conflict retains draft and offers a persistent actionable message", async ({
  page,
}) => {
  await mount(page, { conflict: true });
  await page.locator(".nav-link[data-page=inbounds]").click();
  await page.getByRole("button", { name: "编辑入站", exact: true }).click();
  await page.locator("#inbound-name").fill("保留的草稿");
  await page.getByRole("button", { name: "保存", exact: true }).click();
  await expect(page.locator("#page-notice")).toContainText(
    "其他页面或文件修改",
  );
  await expect(page.locator("#inbound-name")).toHaveValue("保留的草稿");
  await expect(page.locator("[data-editor-save]")).toBeEnabled();
});

for (const externalChange of ["reorder", "delete"]) {
  test(`automatic refresh preserves a pristine outbound editor after external ${externalChange}`, async ({ page }) => {
    const initial = fixture();
    initial.config.config.outbounds.push({ id: "outbound-id-2", enabled: true, name: "Proxy B", url: "socks5://127.0.0.1:18081" });
    const data = await mount(page, { config: initial.config });
    await navigate(page, "outbounds");
    await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
    await expect(page.locator("#outbound-name-0")).toHaveValue("Proxy A");
    if (externalChange === "reorder") data.config.config.outbounds.reverse();
    else {
      data.config.config.outbounds.shift();
      data.config.config.rules = [{ type: "FINAL", outbound: "direct" }];
    }
    data.config.version = 2;
    await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    await expect(page.getByText(/已保存版本发生变化|已保存配置已变化/)).toBeVisible();
    await expect(page.locator("#outbound-name-0")).toHaveValue("Proxy A");
    await page.locator("#outbound-name-0").fill("Edited Proxy A");
    await saveOutbound(page);
    await confirmReferencedOutboundRename(page);
    await expect(page.locator("#page-notice")).toContainText("其他页面或文件修改");
    await expect(page.locator("#outbound-name-0")).toHaveValue("Edited Proxy A");
    const save = data.writes.find((write) => write.path === "/config");
    expect(save.body.base_version).toBe(1);
    expect(save.body.config.outbounds[0]).toMatchObject({ id: "outbound-id-1", name: "Edited Proxy A" });
    expect(save.body.credential_actions["Edited Proxy A"]).toMatchObject({ action: "preserve", original_name: "Proxy A" });
    expect(data.config.version).toBe(2);
    expect(data.config.config.outbounds[0].name).toBe("Proxy B");
  });
}

for (const first of ["username", "password"]) {
  test(`credential editor preserves both fields when ${first} is entered first`, async ({ page }) => {
    const data = await mount(page);
    await page.locator(".nav-link[data-page=outbounds]").click();
    await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
    const values = { username: "credential-fixture-user", password: "credential-fixture-password" };
    const second = first === "username" ? "password" : "username";
    await page.locator(`#outbound-${first}-0`).fill(values[first]);
    await page.locator(`#outbound-${second}-0`).fill(values[second]);
    await saveOutbound(page);
    await dismissOutboundTestSuggestion(page);
    await expect(page.locator("#page-notice")).toContainText("已保存");
    const credentials = data.writes.find((write) => write.path === "/config")?.body.credential_actions["Proxy A"];
    expect(credentials?.action === "replace").toBe(true);
    expect(credentials?.username === values.username).toBe(true);
    expect(credentials?.password === values.password).toBe(true);
  });
}

test("@compat readonly session sees every page but cannot save, diagnose, or start", async ({
  page,
}) => {
  const data = await mount(page, { role: "read" });
  await expect(page.locator("#lifecycle-toggle")).toBeDisabled();
  for (const name of [
    "connections",
    "inbounds",
    "outbounds",
    "rules",
    "dns",
    "diagnostics",
    "settings",
  ]) {
    await navigate(page, name);
    await expect(page.locator("#main h1")).toBeVisible();
  }
  expect(data.writes).toEqual([]);
  await page.locator('[data-settings-link="configuration"]').click();
  await expect(
    page.getByRole("button", { name: "应用已保存设置" }),
  ).toBeDisabled();
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
});

test("@compat mobile 320px all pages retain navigation, editing, and no body overflow", async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 320, height: 760 });
  await mount(page);
  for (const name of [
    "home",
    "connections",
    "inbounds",
    "outbounds",
    "rules",
    "dns",
    "diagnostics",
    "settings",
  ]) {
    await page.locator("#menu-toggle").click();
    await page.locator(`.nav-link[data-page=${name}]`).click();
    const title = {
      home: "首页",
      connections: "连接",
      inbounds: "入站",
      outbounds: "出站",
      rules: "规则",
      dns: "DNS",
      diagnostics: "诊断",
      settings: "设置",
    }[name];
    await expect(
      page.getByRole("heading", { name: title, exact: true }),
    ).toBeVisible();
    await expect(
      page.locator(".workspace-footer").getByRole("link", {
        name: "IP Geolocation by DB-IP",
      }),
    ).toBeVisible();
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth), {
        message: `Horizontal body overflow on ${name} at 320px`,
      })
      .toBeLessThanOrEqual(320);
  }
  await page.locator("#menu-toggle").click();
  await page.locator(".nav-link[data-page=home]").click();
  await expect(
    page.getByRole("heading", { name: "首页", exact: true }),
  ).toBeVisible();
  await expect(page.locator("#sidebar")).not.toHaveClass(/open/);
  await page.screenshot({
    path: testInfo.outputPath(
      `home-${testInfo.project.use.browserName}-320x760.png`,
    ),
    animations: "disabled",
  });
});

test("empty and disconnected states never imply traffic or current healthy operation", async ({
  page,
}) => {
  const data = await mount(page, { empty: true });
  await expect(page.getByText("尚无可绘制的业务流量")).toBeVisible();
  await expect(page.locator(".sankey-edge")).toHaveCount(0);
  data.offline = true;
  await expect(page.locator("#runtime-status")).toHaveText("状态未知");
  await expect(page.locator("#connection-banner")).toContainText(
    "管理连接中断",
  );
  await expect(page.locator("#lifecycle-toggle")).toBeDisabled();
});

test("@compat weak network recovery refreshes real state without repeating a mutation", async ({
  page,
}) => {
  const data = await mount(page);
  data.offline = true;
  await expect(page.locator("#runtime-status")).toHaveText("状态未知");
  await expect(page.locator("#lifecycle-toggle")).toBeDisabled();
  await expect(page.locator("#connection-banner")).toContainText(
    "管理连接中断",
  );
  data.offline = false;
  data.delay = 200;
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  await expect(page.locator("#connection-banner")).toBeHidden();
  await expect(page.locator("#lifecycle-toggle")).toBeEnabled();
  expect(data.writes).toEqual([]);
});

test("@compat unavailable capture telemetry keeps management and rules editable, then recovers", async ({ page }) => {
  const data = await mount(page);
  await navigate(page, "rules");
  const add = page.getByRole("button", { name: "＋ 添加精确域名", exact: true });
  await expect(add).toBeEnabled();
  data.state = "running";
  data.telemetryUnavailable = true;
  await expect(page.locator("#connection-banner")).toContainText("管理连接正常，流量数据暂不可用");
  await expect(page.locator("#runtime-status")).toContainText("正在接管");
  await expect(add).toBeEnabled();
  await navigate(page, "home");
  await expect(page.getByText(/数据暂不可用：这里是/)).toBeVisible();
  await expect(page.getByText(/接管已停止/)).toHaveCount(0);
  await expect(page.getByRole("button", { name: "上次采样速率", exact: true })).toBeVisible();
  await navigate(page, "rules");
  data.offline = true;
  await expect(page.locator("#runtime-status")).toHaveText("状态未知");
  await expect(add).toBeDisabled();
  data.offline = false;
  await expect(page.locator("#runtime-status")).toContainText("正在接管");
  await expect(add).toBeEnabled();
  data.telemetryUnavailable = false;
  await expect(page.locator("#connection-banner")).toBeHidden();
  expect(data.writes).toEqual([]);
});

test("@compat disabled TUN explains the saved inbound requirement without starting capture", async ({ page }) => {
  const data = await mount(page, { disabledTUN: true });
  await page.locator("#lifecycle-toggle").click();
  await expect(page.locator("#page-notice")).toContainText("启用 TUN 入口并保存");
  await expect(page.locator("#detail-dialog")).not.toBeVisible();
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  expect(data.writes).toEqual([{ path: "/lifecycle/start", body: {} }]);
  expect(data.requests.some((request) => request.path === "/readiness")).toBe(false);
});

test("@compat default INFO logs appear immediately and keep polling through capture start and pause", async ({ page }, testInfo) => {
  const data = await mount(page, { bootstrapPage: "diagnostics" });
  await expect(page.locator("#log-level")).toHaveValue("info");
  await expect(page.locator("#log-source")).toHaveValue("");
  await expect(page.locator("#runtime-logs")).toContainText("Management service ready");
  expect(data.writes).toEqual([]);
  await page.locator("#lifecycle-toggle").click();
  await expect(page.locator("#runtime-status")).toContainText("正在接管");
  await expect(page.locator("#runtime-logs")).toContainText("Starting traffic capture");
  await expect(page.locator("#runtime-logs")).toContainText("Traffic capture ready");
  await page.locator("#lifecycle-toggle").click();
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  if (await page.locator("#detail-dialog").isVisible()) await page.getByRole("button", { name: "关闭详情", exact: true }).click();
  await expect(page.locator("#runtime-logs")).toContainText("Traffic capture paused");
  await expect(page.locator("#runtime-logs")).toContainText("Management service ready");
  await expect(page.locator("#runtime-logs")).toContainText("Traffic capture ready");
  await page.screenshot({ path: testInfo.outputPath("automatic-capture-logs.png"), animations: "disabled" });
  expect(data.requests.filter((request) => request.path === "/logs").every((request) => request.query.min_level === "info")).toBe(true);
  expect(data.writes.filter((write) => write.path.startsWith("/lifecycle/")).map((write) => write.path)).toEqual(["/lifecycle/start", "/lifecycle/pause"]);
});

test("@compat runtime logs filter sources, pause polling and render fields as safe text", async ({ page }) => {
  const data = await mount(page, { bootstrapPage: "diagnostics" });
  await expect(page.getByRole("heading", { name: "运行日志", exact: true })).toBeVisible();
  await expect(page.locator("#runtime-logs")).toContainText("TUN startup failed");
  await page.locator("#log-source").selectOption("helper");
  await expect.poll(() => data.requests.filter((r) => r.path === "/logs").at(-1)?.query.source).toBe("helper");
  await page.getByRole("button", { name: "暂停日志刷新" }).click();
  data.logRecords = [{ id: "3", time: end, level: "ERROR", source: "helper", message: "<img src=x onerror=alert(1)>", attrs: { reason: "safe text" } }];
  await page.getByRole("button", { name: "刷新日志", exact: true }).click();
  await expect(page.locator("#runtime-logs")).toContainText("<img src=x onerror=alert(1)>");
  await expect(page.locator("#runtime-logs img")).toHaveCount(0);
  await page.locator("#runtime-logs details").first().locator("summary").click();
  await expect(page.locator("#runtime-logs pre").first()).toContainText("safe text");
  data.logsUnavailable = true;
  await page.getByRole("button", { name: "刷新日志", exact: true }).click();
  await expect(page.getByText("日志暂不可用：logs temporarily unavailable")).toBeVisible();
  await expect(page.locator("#runtime-status")).toContainText("已暂停");
  expect(data.writes).toEqual([]);
});

test("untrusted domain and error strings render as text, never executable markup", async ({
  page,
}) => {
  const data = fixture();
  data.records[0].target = "<img src=x onerror=alert(1)>:443";
  let dialogs = 0;
  page.on("dialog", (dialog) => {
    dialogs++;
    dialog.dismiss();
  });
  await mount(page, data);
  await page.locator(".nav-link[data-page=connections]").click();
  await expect(page.locator("tbody")).toContainText(
    "<img src=x onerror=alert(1)>:443",
  );
  expect(await page.locator("tbody img").count()).toBe(0);
  expect(dialogs).toBe(0);
});

test("diagnosis sends one explicit TCP target and never replays business payload", async ({
  page,
}) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=diagnostics]").click();
  await page.getByRole("button", { name: "新建诊断", exact: true }).click();
  await page.locator("#diagnose-target").fill("example.com");
  await page.locator("#diagnose-port").fill("8443");
  await page.getByRole("button", { name: "开始独立诊断" }).click();
  await expect(page.locator("#page-notice")).toContainText("独立诊断任务");
  const writes = data.writes.filter((r) => r.path === "/diagnostics");
  expect(writes).toHaveLength(1);
  expect(writes[0].body).toEqual({
    target: "example.com:8443",
    tls: false,
    outbounds: ["direct", "Proxy A"],
  });
});

test("automatic refresh never silently rebases a dirty draft onto a concurrent saved version", async ({
  page,
}) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=inbounds]").click();
  await page.getByRole("button", { name: "编辑入站", exact: true }).click();
  await page.locator("#inbound-name").fill("My draft");
  data.config.version = 2;
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await expect(page.locator("#inbound-name")).toHaveValue("My draft");
  await expect(
    page.locator("[data-editor-conflict]"),
  ).toContainText("当前草稿仍保留");
  await page.getByRole("button", { name: "保存", exact: true }).click();
  await expect
    .poll(
      () =>
        data.writes.find((write) => write.path === "/config")?.body
          .base_version,
    )
    .toBe(1);
});

test("TOML import validates before explicit confirmation and never starts capture", async ({
  page,
}) => {
  const data = await mount(page);
  await navigateSettings(page, "configuration");
  await page.getByRole("button", { name: "导入 TOML 设置" }).click();
  const toml = '[core]\nstack = "system"\n';
  await page.locator("#import-toml").fill(toml);
  await page.getByRole("button", { name: "校验导入", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("显式重启");
  expect(
    data.writes.filter((write) => write.path === "/config/import"),
  ).toHaveLength(0);
  await page.getByRole("button", { name: "确认保存导入" }).click();
  await expect(page.locator("#page-notice")).toContainText("尚未应用");
  expect(
    data.writes.filter((write) => write.path === "/config/import"),
  ).toHaveLength(1);
  expect(data.writes.find((write) => write.path === "/config/import").body).toEqual({ base_version: 1, toml });
  expect(
    data.writes.some((write) => write.path.startsWith("/lifecycle/")),
  ).toBe(false);
});

test("GeoIP requires an independent checksum and sends a raw bounded upload with both base identities", async ({
  page,
}) => {
  const data = await mount(page);
  await navigateSettings(page, "geoip");
  const attribution = page.locator('[data-settings-detail="geoip"]').getByRole("link", {
    name: "IP Geolocation by DB-IP",
  });
  await expect(attribution).toHaveAttribute("href", "https://db-ip.com");
  await expect(attribution).toHaveAttribute("rel", "noopener noreferrer");
  const content = JSON.stringify({
    format: 1,
    version: "test-v2",
    source: "https://provider.example.invalid/dataset",
    license: "CC0-1.0",
    license_url: "https://provider.example.invalid/license",
    published_at: start,
    ranges: [{ start: "192.0.2.0", end: "192.0.2.255", country: "CN" }],
  });
  const digest = createHash("sha256").update(content).digest("hex");
  await page.locator("#geoip-file").setInputFiles({
    name: "geoip.json",
    mimeType: "application/json",
    buffer: Buffer.from(content),
  });
  await page.locator("#geoip-expected").fill("0".repeat(64));
  await page.getByRole("button", { name: "校验并准备更新" }).click();
  await expect(page.locator("#page-notice")).toContainText(
    "SHA-256 与预期不一致",
  );
  expect(data.writes.filter((write) => write.path === "/geoip")).toHaveLength(
    0,
  );
  await page.locator("#geoip-expected").fill(digest);
  await page.getByRole("button", { name: "校验并准备更新" }).click();
  await page.getByRole("button", { name: "确认保存数据", exact: true }).click();
  await expect(page.locator("#page-notice")).toContainText("GeoIP 已保存");
  const upload = data.requests.find(
    (request) => request.path === "/geoip" && request.method === "PUT",
  );
  expect(upload.headers).toMatchObject({
    "if-match": "1",
    "x-content-sha256": digest,
    "x-geoip-base-sha256": "a".repeat(64),
    "x-csrf-token": "test-csrf",
  });
  expect(upload.body.version).toBe("test-v2");
  await expect(page.locator('[data-settings-detail="geoip"]')).toContainText("test-v2");
  await page.locator("[data-settings-back]").click();
  await expect(page.locator('[data-settings-link="geoip"]')).toContainText("test-v2");
  expect(
    data.writes.some((write) => write.path.startsWith("/lifecycle/")),
  ).toBe(false);
});

for (const width of [360, 390, 430, 768, 1024])
  test(`home graph and equivalent paths remain usable at ${width}px`, async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width, height: 844 });
    await mount(page);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await page.getByRole("button", { name: "放大图形", exact: true }).click();
    await expect(page.locator("#sankey")).toHaveClass(/zoomed/);
    await page.getByText("同口径路径列表", { exact: true }).click();
    await expect(
      page.getByRole("button", { name: "选择路径" }).first(),
    ).toBeVisible();
    if (width === 390) {
      await page.locator("#sankey").scrollIntoViewIfNeeded();
      await page.screenshot({
        path: testInfo.outputPath("mobile-graph-390.png"),
        animations: "disabled",
      });
    }
  });

test("all compiled stacks are runtime choices and saving never starts capture", async ({ page }) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=inbounds]").click();
  await page.getByRole("button", { name: "编辑入站", exact: true }).click();
  await page.locator('[data-editor-advanced="inbounds"] > summary').click();
  const stack = page.locator("#inbound-stack");
  await expect(stack).toHaveValue("system");
  await expect(stack.locator("option")).toHaveCount(3);
  await stack.selectOption("gvisor");
  await page.getByRole("button", { name: "保存", exact: true }).click();
  await expect.poll(() => data.writes.find((write) => write.path === "/config")?.body.config.core.stack).toBe("gvisor");
  expect(data.writes.some((write) => write.path.startsWith("/lifecycle/"))).toBe(false);
});

test("IPv6 is an explicit saved opt-in and unavailable platforms cannot enable it", async ({
  page,
}) => {
  const data = await mount(page, { ipv6: true });
  await page.locator(".nav-link[data-page=inbounds]").click();
  await page.getByRole("button", { name: "编辑入站", exact: true }).click();
  await page.locator('[data-editor-advanced="inbounds"] > summary').click();
  await page.locator("#inbound-ipv6-network").fill("fd7a:203::1/120");
  await page.locator("#inbound-outbound-interface").fill("eth0");
  await page.locator("#inbound-auto-route6").check();
  await page.getByRole("button", { name: "保存", exact: true }).click();
  await expect
    .poll(
      () =>
        data.writes.find((write) => write.path === "/config")?.body.config.core[
          "ipv6-network"
        ],
    )
    .toBe("fd7a:203::1/120");
  expect(
    data.writes.find((write) => write.path === "/config").body.config.core[
      "auto-route6"
    ],
  ).toBe(true);
  expect(
    data.writes.some((write) => write.path.startsWith("/lifecycle/")),
  ).toBe(false);
  data.ipv6 = false;
  data.config.config.core["ipv6-network"] = "";
  data.config.config.core["auto-route6"] = false;
  await page.reload();
  await page.getByRole("button", { name: "编辑入站", exact: true }).click();
  await page.locator('[data-editor-advanced="inbounds"] > summary').click();
  await expect(page.locator("#inbound-ipv6-network")).toBeDisabled();
  await expect(page.locator("#inbound-auto-route6")).toBeDisabled();
});

test("Other drilldown reads every original contributor in bounded requests and list pagination stays anchored", async ({
  page,
}) => {
  const original = fixture().records[0];
  const records = Array.from({ length: 250 }, (_, i) => ({
    ...original,
    id: `flow-${String(i).padStart(4, "0")}`,
  }));
  const data = await mount(page, { records, aggregateAll: true });
  await page.locator(".sankey-node").filter({ hasText: "其他目的" }).click();
  await page.getByRole("button", { name: "查看连接", exact: true }).click();
  await expect(page.locator(".search-summary")).toContainText("已载入 250 条");
  const reads = data.requests.filter((request) => request.path === "/flows");
  expect(reads).toHaveLength(3);
  expect(reads.flatMap((read) => read.query.flow_ids.split(","))).toEqual(
    records.map((record) => record.id),
  );
  expect(reads.every((read) => read.query.anchor === "traffic-session:3")).toBe(
    true,
  );
  await page.getByRole("button", { name: "切换实时", exact: true }).click();
  await expect(page.locator(".search-summary")).toContainText("已载入 100 条");
  await page.getByRole("button", { name: "固定快照并加载更早记录" }).click();
  await expect(page.locator(".search-summary")).toContainText("已载入 250 条");
  await expect(page.getByText("固定观察快照", { exact: false })).toBeVisible();
});

test("temporary domain rules and outbound disable are explicit saved drafts with stable identities", async ({
  page,
}) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=rules]").click();
  await page.locator('[data-rule-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await page.locator('[data-editor-advanced="rule"] > summary').click();
  await page.getByText("高级：规则有效期", { exact: true }).click();
  await page.locator("#rule-lifetime-0").selectOption("temporary");
  await expect(page.locator("#rule-expires-0")).toBeVisible();
  await page.getByRole("button", { name: "保存", exact: true }).click();
  await expect
    .poll(
      () =>
        data.writes.find((write) => write.path === "/config")?.body.config
          .rules[0]["expires-at"],
    )
    .toMatch(/^\d{4}-\d{2}-\d{2}T/);
  await page.locator(".nav-link[data-page=outbounds]").click();
  await page.locator('[data-outbound-row="0"]').getByRole("button", { name: "编辑", exact: true }).click();
  await page.locator('[data-editor-advanced="outbound"] > summary').click();
  await page.locator("#outbound-enabled-0").uncheck();
  await saveOutbound(page);
  await expect(page.locator("[data-outbound-test-suggestion]")).not.toBeVisible();
  await expect
    .poll(
      () =>
        data.writes.filter((write) => write.path === "/config").at(-1)?.body
          .config.outbounds[0].enabled,
    )
    .toBe(false);
  expect(
    data.writes.filter((write) => write.path === "/config").at(-1).body.config
      .outbounds[0].id,
  ).toBe("outbound-id-1");
  expect(
    data.writes.some((write) => write.path.startsWith("/lifecycle/")),
  ).toBe(false);
});

test("DNS system guidance saves explicit intent while automatic scopes remain read-only", async ({
  page,
}) => {
  const data = await mount(page, { systemDNS: true, autoScopes: true });
  await page.locator(".nav-link[data-page=dns]").click();
  await expect(page.getByText("系统解析范围", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "编辑 DNS 设置", exact: true }).click();
  await page.locator("#dns-system").check();
  await page.locator('[data-editor-advanced="dns"] > summary').click();
  await page.getByRole("button", { name: "＋ 添加解析规则" }).click();
  await page.locator("#dns-route-suffix-0").fill("private.example");
  await page.locator("#dns-route-servers-0").fill("192.168.50.1:53");
  await page.locator("#dns-route-interface-0").fill("eth0");
  await page.getByRole("button", { name: "保存", exact: true }).first().click();
  await expect
    .poll(
      () =>
        data.writes.find((write) => write.path === "/config")?.body.config.dns
          .system,
    )
    .toBe(true);
  const saved = data.writes.find((write) => write.path === "/config").body
    .config.dns;
  expect(saved.rules).toEqual([
    {
      suffix: "private.example",
      servers: ["192.168.50.1:53"],
      interface: "eth0",
    },
  ]);
  expect(JSON.stringify(saved)).not.toContain("automatic");
  expect(
    data.writes.some((write) => write.path.startsWith("/lifecycle/")),
  ).toBe(false);
});

test("corrupt GeoIP still permits explicit revalidation of the saved previous dataset", async ({
  page,
}) => {
  const data = await mount(page, { geoCorrupt: true });
  await navigateSettings(page, "geoip");
  await expect(
    page.locator('[data-settings-detail="geoip"]').getByText("Saved active dataset is corrupt", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "尝试恢复已保存上一版" }).click();
  await expect(page.locator("#detail-dialog")).toContainText(
    "不会猜测或自动替换成内置版",
  );
  expect(data.writes.some((write) => write.path === "/geoip/rollback")).toBe(
    false,
  );
  await page.getByRole("button", { name: "确认回退数据", exact: true }).click();
  await expect
    .poll(
      () => data.writes.find((write) => write.path === "/geoip/rollback")?.body,
    )
    .toEqual({ base_version: 1, base_sha256: "" });
  await expect(page.locator('[data-settings-detail="geoip"]')).toContainText("recovered-v1");
  await expect(page.locator('[data-settings-detail="geoip"]')).not.toContainText("Saved active dataset is corrupt");
  await expect(page.locator("#geoip-expected")).toBeEnabled();
});

test("initial transport failure keeps management signed out without invented observations", async ({
  page,
}) => {
  await page.route("**/api/v1/**", (route) => route.abort("connectionfailed"));
  await page.goto("/#home");
  await expectManagementShellHidden(page);
  await expect(page.locator(".metric-value")).toHaveCount(0);
  await expect(page.locator("#login-password")).toBeVisible();
  await expect(page.locator("#lifecycle-toggle")).toBeDisabled();
});

test("@compat retained capture observations never claim live sampling after repeated refresh", async ({ page }) => {
  const data = await mount(page, { frozen: true, state: "paused" });
  await expect(page.locator(".metric-label").filter({ hasText: "上次采样上传 / 下载" })).toBeVisible();
  await expect(page.locator(".metric-label").filter({ hasText: "上次采样活动连接" })).toBeVisible();
  await expect(page.getByText(/接管已停止：这里是/)).toContainText("不会继续实时更新");
  await expect(page.getByRole("button", {name: "上次采样速率", exact: true})).toBeVisible();
  const note = await page.getByText(/接管已停止：这里是/).textContent();
  await expect.poll(() => data.requests.filter((request) => request.path === "/traffic").length).toBeGreaterThan(1);
  await expect(page.getByText(/接管已停止：这里是/)).toHaveText(note);
  await expect(page.locator(".metric-label").filter({ hasText: "实时上传 / 下载" })).toHaveCount(0);
  await expect(page.getByRole("button", {name: "实时速率", exact: true})).toHaveCount(0);
});

test("observed UDP shortcuts retain transport and port, precede broad rules and never silently save", async ({ page }) => {
  const data = await mount(page);
  await page.getByRole("button", { name: "详情", exact: true }).first().click();
  await page.getByRole("dialog").getByRole("button", { name: "为此目标建规则" }).click();
  await expect(page.locator("#rule-pattern-0")).toHaveValue("unsupported.example");
  await expect(page.locator("#rule-protocol-0")).toHaveValue("udp");
  await expect(page.locator("#rule-ports-0")).toHaveValue("443");
  await expect(page.locator("#rule-pattern-1")).toHaveCount(0);
  expect(data.writes.some((write) => write.path === "/config")).toBe(false);
  await page.getByRole("button", { name: "保存", exact: true }).first().click();
  await expect.poll(() => data.writes.find((write) => write.path === "/config")?.body.config.rules[0]).toMatchObject({
    type: "DOMAIN", pattern: "unsupported.example", protocol: "udp", ports: [443], source: "one-click",
  });
  await page.locator(".nav-link[data-page=home]").click();
  await page.getByRole("button", { name: "详情", exact: true }).first().click();
  await page.getByRole("dialog").getByRole("button", { name: "为此目标建规则" }).click();
  await expect(page.locator("#editor-dialog")).not.toBeVisible();
  await expect(page.locator("[data-rule-row]")).toHaveCount(3);
  await expect(page.getByText(/没有重复添加/)).toBeVisible();
  expect(data.writes.filter((write) => write.path === "/config")).toHaveLength(1);
  expect(data.writes.some((write) => write.path.startsWith("/lifecycle/") || write.path === "/config/apply")).toBe(false);
});

test("routing simulation sends the selected protocol and destination port without probing", async ({ page }) => {
  const data = await mount(page);
  await page.locator(".nav-link[data-page=rules]").click();
  await page.getByRole("button", { name: "模拟规则匹配", exact: true }).click();
  await page.locator("#simulate-target").fill("example.com");
  await page.locator("#simulate-port").fill("8443");
  await page.getByRole("combobox", { name: "模拟协议" }).selectOption("udp");
  await page.getByRole("button", { name: "模拟匹配" }).click();
  await expect.poll(() => data.requests.find((request) => request.path === "/rules/simulate")?.body).toEqual({ target: "example.com:8443", protocol: "udp" });
  expect(data.writes.some((write) => write.path === "/diagnostics" || write.path === "/config")).toBe(false);
});
