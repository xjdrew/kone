import { test } from "node:test";
import assert from "node:assert/strict";
import { outboundRuleReferences } from "../src/outbounds-page.js";

test("outbound references count saved rules including explicit FINAL and expired entries", () => {
  const rules = [
    { id: "first", type: "DOMAIN", pattern: "one.example", outbound: "direct" },
    { id: "expired", type: "DOMAIN-SUFFIX", pattern: "old.example", outbound: "direct", "expires-at": "2000-01-01T00:00:00Z" },
    { id: "proxy", type: "DOMAIN", pattern: "proxy.example", outbound: "Office" },
    { id: "case", type: "DOMAIN", pattern: "case.example", outbound: "office" },
    { id: "fallback", type: "FINAL", outbound: "direct" },
  ];
  const original = structuredClone(rules);
  assert.deepEqual(outboundRuleReferences(rules, "direct").map(rule => [rule.id, rule.order]), [["first", 1], ["expired", 2], ["fallback", 5]]);
  assert.deepEqual(outboundRuleReferences(rules, "Office").map(rule => rule.id), ["proxy"]);
  assert.deepEqual(outboundRuleReferences(rules, "office").map(rule => rule.id), ["case"]);
  assert.deepEqual(outboundRuleReferences(rules, "reject"), []);
  assert.deepEqual(rules, original, "counting references cannot mutate saved settings");
});

test("implicit FINAL does not create a saved reference and counts follow the latest saved rules", () => {
  assert.deepEqual(outboundRuleReferences([], "direct"), []);
  const rules = [{ type: "DOMAIN", outbound: "Old" }, { type: "FINAL", outbound: "reject" }];
  assert.equal(outboundRuleReferences(rules, "Old").length, 1);
  rules[0].outbound = "Renamed";
  assert.equal(outboundRuleReferences(rules, "Old").length, 0);
  assert.equal(outboundRuleReferences(rules, "Renamed").length, 1);
  rules.shift();
  assert.equal(outboundRuleReferences(rules, "Renamed").length, 0);
  assert.deepEqual(outboundRuleReferences(rules, "reject").map(rule => rule.order), [1]);
});
