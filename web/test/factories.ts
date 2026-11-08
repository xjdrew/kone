import type { Config, Document, Flow, RuntimeState, Sankey, TrafficResponse } from "../src/model";

export function configuration(): Config {
  return {
    general: { "log-level": "info", "log-format": "text" },
    core: {
      tun: "kone0",
      stack: "system",
      network: "10.192.0.1/16",
      "auto-route": false,
      "auto-route6": false,
      "ipv6-network": "",
      "outbound-interface": "eth0",
    },
    dns: {
      system: true,
      "listen-port": 53,
      ttl: 60,
      "packet-size": 4096,
      "read-timeout": 5,
      "write-timeout": 5,
      "history-limit": 512,
      "history-retention": 3600,
      "cache-limit": 1024,
    },
    geoip: { provider: "builtin" },
    outbounds: [
      {
        id: "proxy-a",
        name: "Local HTTP",
        url: "http://127.0.0.1:7078",
        enabled: true,
        "udp-fallback": "direct",
      },
    ],
    rules: [
      {
        id: "rule-google",
        type: "DOMAIN-SUFFIX",
        pattern: "google.com",
        outbound: "Local HTTP",
        source: "user",
      },
      { id: "final", type: "FINAL", outbound: "direct" },
    ],
  };
}
export function documentFixture(): Document {
  return {
    version: 7,
    running_version: 7,
    confirmed_version: 7,
    config: configuration(),
    inbound: { id: "tun-main", name: "TUN", enabled: true },
    credential_state: {},
    config_error: "",
    capture_locked: false,
    direct_only_confirmed: true,
  };
}
export function stateFixture(): RuntimeState {
  return {
    state: "paused",
    control_state: "ready",
    data_state: "paused",
    host: "kone-dev",
    role: "admin",
    remote_session: false,
    local_access: true,
    password_configured: false,
    session_id: "session-1",
    capabilities: ["tun"],
    version: "1.0.0",
    saved_version: 7,
    running_version: 7,
    confirmed_version: 7,
    last_error: "",
    config_error: "",
    time: "2026-11-07T09:30:00Z",
    csrf_token: "fixture-csrf",
    capture_locked: false,
  };
}
export function flowFixture(override: Partial<Flow> = {}): Flow {
  return {
    id: "flow-1",
    session_id: "run-1",
    config_version: 7,
    inbound: "TUN",
    protocol: "tcp",
    source: "10.192.0.4:54030",
    destination: "142.250.71.14:443",
    target: "www.google.com:443",
    domain: "www.google.com",
    rule_id: "rule-google",
    rule_name: "DOMAIN-SUFFIX google.com",
    rule_source: "user",
    rule_order: 1,
    expected_outbound: "Local HTTP",
    effective_outbound: "Local HTTP",
    status: "active",
    stage: "connected",
    started_at: "2026-11-07T09:29:40Z",
    updated_at: "2026-11-07T09:30:00Z",
    upload: 20480,
    download: 1048576,
    ...override,
  };
}
export function graphFixture(): Sankey {
  return {
    frozen: false,
    timestamp: "2026-11-07T09:30:00Z",
    metric: "total",
    total: 100,
    nodes: [
      { id: "in", label: "TUN", kind: "inbound", column: 0 },
      { id: "rule", label: "DOMAIN-SUFFIX google.com", kind: "rule", column: 1 },
      { id: "out", label: "Local HTTP", kind: "outbound", column: 2 },
      { id: "target", label: "www.google.com", kind: "target", column: 3 },
    ],
    links: [
      { id: "l1", source: "in", target: "rule", value: 100, path_ids: ["path-1"] },
      { id: "l2", source: "rule", target: "out", value: 100, path_ids: ["path-1"] },
      { id: "l3", source: "out", target: "target", value: 100, path_ids: ["path-1"] },
    ],
    paths: [
      {
        id: "path-1",
        inbound: "TUN",
        rule_id: "rule-google",
        rule_name: "DOMAIN-SUFFIX google.com",
        effective_outbound: "Local HTTP",
        target: "www.google.com",
        value: 100,
        connections: 1,
        failures: 0,
        other: false,
        filter: {
          anchor: "anchor-1",
          path_ids: ["path-1"],
          flow_ids: ["flow-1"],
          since: "2026-11-07T09:29:59Z",
          until: "2026-11-07T09:30:00Z",
        },
      },
    ],
    anchor: "anchor-1",
    truncated: false,
    anchor_expired: false,
  };
}
export function trafficFixture(): TrafficResponse {
  const records = [
    flowFixture(),
    flowFixture({
      id: "flow-2",
      domain: "",
      target: "149.154.167.50:443",
      destination: "149.154.167.50:443",
      status: "failed",
      stage: "connect",
      error: "connect timeout",
      rule_id: "final",
      rule_name: "FINAL",
      expected_outbound: "direct",
      effective_outbound: "direct",
      upload: 0,
      download: 0,
    }),
  ];
  return {
    traffic: {
      frozen: false,
      session_id: "run-1",
      timestamp: "2026-11-07T09:30:00Z",
      totals: {
        started: 2,
        active: 1,
        closed: 0,
        failed: 1,
        rejected: 0,
        canceled: 0,
        upload: 20480,
        download: 1048576,
        bytes: 1069056,
        upload_rate: 1536,
        download_rate: 245760,
      },
      records,
      total: 2,
      anchor: "anchor-1",
      capacity: 2048,
      dropped_details: 0,
      truncated: false,
      anchor_expired: false,
    },
    sankey: graphFixture(),
  };
}
