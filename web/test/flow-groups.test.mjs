import test from "node:test";
import assert from "node:assert/strict";
import { flowTarget, groupFlows } from "../src/flow-groups.js";

test("groups domains across ports and protocols, preserving every connection", () => {
 const flows = [
  { id: "1", target: "Example.COM.:443", protocol: "tcp", upload: 8, status: "active", started_at: "2026-01-01" },
  { id: "2", domain: "example.com", target: "10.0.0.1:80", protocol: "udp", upload: 4, download: 12, status: "failed", started_at: "2026-01-02" },
  { id: "3", target: "other.test:443", status: "closed", started_at: "2026-01-03" },
 ];
 const groups = groupFlows(flows);
 assert.equal(groups.length, 2);
 const group = groups[1];
 assert.equal(group.target, "example.com");
 assert.equal(group.flows.length, 2);
 assert.equal(group.upload, 12);
 assert.equal(group.download, 12);
 assert.equal(group.active, 1);
 assert.equal(group.failed, 1);
 assert.equal(group.latest.id, "2");
});
test("normalizes IPv6 and keeps unknown destinations separate", () => {
 assert.equal(flowTarget({ target: "[2001:0db8::1]:443" }), "2001:db8::1");
 assert.equal(flowTarget({ target: "2001:db8::1" }), "2001:db8::1");
 assert.equal(groupFlows([{id:"a"}, {id:"b"}]).length, 2);
});
