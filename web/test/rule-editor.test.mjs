import { test } from "node:test";
import assert from "node:assert/strict";
import { ruleTypes, rulePatternInfo, validateRulePattern, countryOptions, classifyRuleDecision } from "../src/rule-editor.js";

test("ordinary rule types exclude FINAL and provide distinct format guidance", () => {
  assert.deepEqual(ruleTypes, ["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "GEOIP"]);
  const hints = ruleTypes.map(type => {
    const info = rulePatternInfo(type);
    for (const field of ["label", "placeholder", "hint"]) assert.ok(typeof info[field] === "string" && info[field].length > 0, `${type} ${field}`);
    return info.hint;
  });
  assert.equal(new Set(hints).size, ruleTypes.length, "each matching method explains its own format and scope");
});

for (const [type, valid, invalid] of [
  ["DOMAIN", ["example.com", "sub.example.com", "xn--bcher-kva.example"], ["", "https://example.com", "example.com:443", "example.com/path", "*.example.com", "bad domain"]],
  ["DOMAIN-SUFFIX", ["example.com", "sub.example.com"], ["", ".example.com", "*.example.com", "https://example.com", "example.com:443", "bad domain"]],
  ["DOMAIN-KEYWORD", ["video", ".example", "cdn-edge"], ["", "two words", "https://example.com", "*.example.com", "example/path"]],
  ["IP-CIDR", ["0.0.0.0/0", "192.0.2.9/32", "198.51.100.0/24"], ["", "192.0.2.1", "192.0.2.0/33", "300.0.0.0/24", "2001:db8::/32", "192.0.2.1/-1"]],
  ["IP-CIDR6", ["::/0", "::1/128", "2001:db8::/32", "2001:db8:0:1::1/64"], ["", "2001:db8::", "2001:db8::/129", "2001:db8:::1/64", "192.0.2.0/24", "::ffff:192.0.2.1/128"]],
  ["GEOIP", ["CN", "US", "HK", "TW", "AQ", "XK", "ZZ", "AA"], ["", "cn", "CHN", "China", "C1"]],
]) {
  test(`${type} accepts its own legal patterns and rejects incompatible formats`, () => {
    for (const value of valid) assert.equal(validateRulePattern(type, value), "", `${type}: ${value}`);
    for (const value of invalid) assert.ok(validateRulePattern(type, value).length > 0, `${type}: ${value}`);
  });
}

test("GeoIP countries are an offline complete unique list with readable Chinese names and codes", () => {
  const options = countryOptions();
  assert.equal(options.length, 250, "249 ISO territories and XK; ZZ does not match unmapped addresses");
  assert.equal(new Set(options.map(option => option.value)).size, options.length);
  for (const option of options) {
    assert.match(option.value, /^[A-Z]{2}$/);
    assert.ok(option.label.includes(option.value), option.value);
  }
  assert.match(options.find(option => option.value === "CN").label, /中国/);
  assert.match(options.find(option => option.value === "US").label, /美国/);
  assert.ok(!options.some(option => option.value === "ZZ"));
  assert.deepEqual(countryOptions("en").map(option => option.value).sort(), options.map(option => option.value).sort());
  const legacy = countryOptions("zh-CN", "AA");
  assert.equal(legacy.length, 251);
  assert.equal(legacy.filter(option => option.value === "AA").length, 1, "an existing non-ISO two-letter code remains selectable");
  assert.match(countryOptions("zh-CN", "ZZ").find(option => option.value === "ZZ").label, /旧配置/);
});

test("simulation classifications honor explicit types while supporting older saved decisions", () => {
  assert.equal(classifyRuleDecision({ rule_type: "DOMAIN", rule_id: "rule-1", rule_order: 1 }), "rule");
  assert.equal(classifyRuleDecision({ rule_type: "FINAL", rule_id: "stable-final", rule_order: 2 }), "final");
  assert.equal(classifyRuleDecision({ rule_type: "PROTECTED", rule_id: "protected:endpoint", protected: true }), "protected");
  assert.equal(classifyRuleDecision({ rule_id: "rule-1", rule_name: "DOMAIN example.com", rule_order: 1 }), "rule");
  assert.equal(classifyRuleDecision({ rule_id: "builtin:default", rule_name: "Default direct", rule_source: "builtin" }), "final");
  assert.equal(classifyRuleDecision({ rule_id: "legacy-final", rule_name: "FINAL" }), "final");
  assert.equal(classifyRuleDecision({ rule_id: "protected:endpoint", protected: true }), "protected");
});
