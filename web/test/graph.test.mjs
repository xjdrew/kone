import { test } from 'node:test';
import assert from 'node:assert/strict';
import { aggregatePaths, buildGraph, nativePaths, colorFor, bytes } from '../src/graph.js';
import { normalizeTraffic, normalizeFlow } from '../src/api.js';

const flow = (id, overrides = {}) => normalizeFlow({ id, inbound: 'tun-main', rule_id: 'rule-a', rule_name: '精确域名', protocol: 'tcp', expected_outbound: 'Proxy A', effective_outbound: 'Proxy A', target: 'example.com:443', upload: 60, download: 140, status: 'active', ...overrides });

test('Sankey preserves each observed path without joining unrelated dimensions', () => {
  const data = aggregatePaths([flow('a'), flow('b', { rule_id: 'rule-b', effective_outbound: 'direct', target: 'internal.example:80', upload: 10, download: 20 })]);
  const graph = buildGraph(data);
  assert.equal(data.total, 230);
  assert.equal(data.paths.length, 2);
  assert.equal(graph.edges.length, 6);
  for (const column of graph.columns) assert.equal(column.reduce((sum, node) => sum + node.value, 0), 230);
  const a = data.paths.find(path => path.flow_ids.includes('a'));
  assert.equal(a.nodes[2].label, 'Proxy A');
  assert.equal(a.nodes[3].label, 'example.com:443');
  assert.ok(!graph.edges.some(edge => edge.source === 'rule:rule-a' && edge.target === 'out:direct'));
});

test('zero-byte failures remain events without positive graph width', () => {
  const result = aggregatePaths([flow('failed', { status: 'failed', upload: 0, download: 0 }), flow('reject', { status: 'rejected', upload: 0, download: 0 })]);
  assert.equal(result.failed, 2);
  assert.equal(result.count, 2);
  assert.equal(result.total, 0);
  assert.deepEqual(result.paths, []);
});

test('Top N merging conserves traffic and exact member evidence under high cardinality', () => {
  const flows = Array.from({ length: 100 }, (_, i) => flow(`f-${i}`, { inbound: `tun-${i}`, rule_id: `rule-${i}`, effective_outbound: `proxy-${i}`, target: `host-${i}.example:443`, upload: i + 1, download: i + 2 }));
  const result = aggregatePaths(flows, { top: 3 });
  const graph = buildGraph(result);
  assert.equal(result.total, flows.reduce((sum, f) => sum + f.upload + f.download, 0));
  assert.deepEqual(new Set(result.paths.flatMap(path => path.flow_ids)), new Set(flows.map(f => f.id)));
  assert.ok(graph.columns.every(column => column.length <= 4));
  assert.ok(graph.nodes.every(node => node.height >= 0 && Number.isFinite(node.y)));
});

test('protocol filtering excludes DNS/control counters and keeps directional units separate', () => {
  const flows = [flow('tcp'), flow('udp', { protocol: 'udp', upload: 5 }), flow('dns', { category: 'dns', upload: 999999 })];
  assert.equal(aggregatePaths(flows, { direction: 'upload', protocol: 'udp' }).total, 5);
  assert.equal(aggregatePaths(flows, { direction: 'download', protocol: 'tcp' }).total, 140);
  assert.equal(aggregatePaths(flows, { metric: 'rate' }).total, 0, 'cumulative counters must not masquerade as speed');
});

test('native sampler weights are authoritative and retain immutable drilldown filters', () => {
  const filter = { anchor: 's:41', path_ids: ['p-a', 'p-b'], flow_ids: ['f-2'], since: '2026-11-01T00:00:00Z', until: '2026-11-01T00:00:01Z' };
  const snapshot = { unit: 'B/s', anchor: 's:41', window_start: filter.since, window_end: filter.until, failures: 1, paths: [{ id: 'other', inbound: 'tun-main', rule_id: 'rule-a', rule_name: '精确域名', effective_outbound: 'direct', target: 'Other', value: 1250, upload: 10000, download: 20000, connections: 2, other: true, filter }] };
  const result = nativePaths(snapshot);
  assert.equal(result.total, 1250);
  assert.equal(result.count, 2);
  assert.equal(result.paths[0].nodes[3].label, '其他目的');
  assert.deepEqual(result.paths[0].filter, filter);
  assert.equal(result.anchor, 's:41');
  assert.equal(nativePaths(snapshot, { metric: 'cumulative', direction: 'upload' }).total, 10000);
  assert.equal(nativePaths(null), null);
});

test('node ordering and outbound colors survive record order changes', () => {
  const data = [flow('a'), flow('b', { effective_outbound: 'direct', target: 'b.example' })];
  const first = buildGraph(aggregatePaths(data));
  const second = buildGraph(aggregatePaths([...data].reverse()));
  assert.deepEqual(first.columns.map(column => column.map(node => node.id)), second.columns.map(column => column.map(node => node.id)));
  assert.equal(colorFor('out:direct'), colorFor('out:direct'));
  assert.equal(bytes(1250, true), '1.3 KB/s');
});

test('API adapter maps native contracts without guessing real IP or process ownership', () => {
  const native = { id: 'f', target: 'example.com:443', destination: '198.18.0.2:443', domain: 'example.com', domain_source: 'fake-ip', fake_ip: '198.18.0.2', process_status: 'unknown', effective_outbound: 'proxy', upload: 12 };
  const result = normalizeTraffic({ traffic: { records: [native], totals: { active: 1 }, dropped_details: 3, timestamp: 'fixed' }, sankey: { paths: [] } });
  assert.equal(result.at, 'fixed');
  assert.equal(result.stats.active, 1);
  assert.equal(result.dropped, 3);
  assert.equal(result.flows[0].target, 'example.com:443');
  assert.equal(result.flows[0].real_ip, '');
  assert.equal(result.flows[0].upload_rate, 0);
  assert.equal(result.flows[0].virtual_ip, '198.18.0.2');
  assert.equal(result.flows[0].process_status, 'unknown');
  assert.deepEqual(result.sankey, { paths: [] });
});
