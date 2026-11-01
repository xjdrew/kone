import { test } from "node:test";
import assert from "node:assert/strict";
import { outboundProtocols, parseOutboundFields, buildOutboundURL, defaultOutboundName, outboundCredentialAction } from "../src/outbound-editor.js";

test("protocol fields parse endpoints without putting saved credentials into editable inputs", () => {
  assert.deepEqual(outboundProtocols.map(protocol => protocol.value), ["http", "https", "socks5", "ss"]);
  for (const [raw, protocol, host, port] of [
    ["http://alice:private-password@proxy.example:80/relay?mode=secure", "http", "proxy.example", "80"],
    ["https://REDACTED:REDACTED@proxy.example:443", "https", "proxy.example", "443"],
    ["socks5://alice:private-password@[2001:db8::1]:1080", "socks5", "2001:db8::1", "1080"],
    ["ss://aes-256-gcm:private-password@proxy.example:8388", "ss", "proxy.example", "8388"],
  ]) {
    const fields = parseOutboundFields(raw);
    assert.equal(fields.protocol, protocol);
    assert.equal(fields.host, host);
    assert.equal(fields.port, port);
    assert.equal(fields.username, "");
    assert.equal(fields.password, "");
    assert.doesNotMatch(JSON.stringify(fields), /alice|private-password|REDACTED/);
  }
  assert.equal(parseOutboundFields("ss://aes-256-gcm:secret@proxy.example:8388").method, "aes-256-gcm");
  assert.equal(parseOutboundFields("ss://YWVzLTI1Ni1nY206c2VjcmV0@proxy.example:8388").method, "");
});

test("building an endpoint retains explicit default ports, IPv6 brackets and existing advanced suffixes", () => {
  assert.equal(buildOutboundURL({ protocol: "http", host: "proxy.example", port: "80" }), "http://proxy.example:80");
  assert.equal(buildOutboundURL({ protocol: "https", host: "proxy.example", port: "443" }), "https://proxy.example:443");
  assert.equal(buildOutboundURL({ protocol: "socks5", host: "[2001:db8::1]", port: 1080 }), "socks5://[2001:db8::1]:1080");
  const raw = "https://REDACTED:REDACTED@old.example:443/relay?mode=secure#saved";
  const fields = parseOutboundFields(raw);
  assert.equal(buildOutboundURL(fields, raw), raw);
  assert.equal(buildOutboundURL({ ...fields, host: "new.example", clearAuthentication: true }, raw), "https://new.example:443/relay?mode=secure#saved");
  assert.equal(buildOutboundURL({ protocol: "http", host: "proxy.example", port: 8080, suffix: "/relay?mode=secure" }), "http://proxy.example:8080/relay?mode=secure");
});

test("invalid hosts and ports fail before a malformed proxy URL can be saved", () => {
  const fields = { protocol: "http", host: "proxy.example", port: 8080 };
  for (const host of ["", "http://proxy.example", "alice@proxy.example", "proxy.example/path", "proxy.example?token=x", "bad host", "proxy\\host", "proxy.example:8080", "[invalid]"])
    assert.throws(() => buildOutboundURL({ ...fields, host }), Error, host);
  for (const port of ["", 0, 65536, -1, "1.5", "abc", Infinity])
    assert.throws(() => buildOutboundURL({ ...fields, port }), Error, String(port));
  assert.throws(() => buildOutboundURL({ ...fields, protocol: "ftp" }), Error);
});

test("default proxy names are readable, protocol-specific and unique among saved names", () => {
  const first = defaultOutboundName("http", []);
  assert.equal(first, "HTTP 代理");
  assert.equal(defaultOutboundName("http", [first]), "HTTP 代理 2");
  assert.equal(defaultOutboundName("http", [first, "HTTP 代理 2", "HTTP 代理 3"]), "HTTP 代理 4");
  for (const protocol of ["https", "socks5", "ss"]) {
    const name = defaultOutboundName(protocol, []);
    assert.ok(name.trim());
    assert.notEqual(name, first);
    assert.notEqual(defaultOutboundName(protocol, [name]), name);
  }
});

test("authentication changes preserve identity, replace complete input and clear only when explicitly selected", () => {
  const fields = { protocol: "http", username: "", password: "" };
  const options = { configured: true, originalName: "Office" };
  assert.deepEqual(outboundCredentialAction(fields, options), { action: "preserve", original_name: "Office" });
  assert.deepEqual(outboundCredentialAction({ ...fields, username: "alice", password: "new-password" }, options), { action: "replace", original_name: "Office", username: "alice", password: "new-password" });
  assert.deepEqual(outboundCredentialAction({ ...fields, username: "ignored-user", password: "ignored-password", clearAuthentication: true }, options), { action: "clear", original_name: "Office" });
  assert.deepEqual(outboundCredentialAction(fields), { action: "clear", original_name: "" });
  assert.throws(() => outboundCredentialAction({ ...fields, username: "changed-user" }, options), /用户名和密码/);
  assert.throws(() => outboundCredentialAction({ ...fields, password: "changed-password" }, options), /用户名和密码/);
  assert.throws(() => outboundCredentialAction(fields, { ...options, endpointChanged: true }), /重新填写认证信息|清除认证/);
});

test("Shadowsocks preserves an unchanged saved method but requires complete replacement credentials", () => {
  const fields = { protocol: "ss", method: "", username: "", password: "" };
  const options = { configured: true, originalName: "Private proxy" };
  assert.deepEqual(outboundCredentialAction(fields, options), { action: "preserve", original_name: "Private proxy" });
  assert.throws(() => outboundCredentialAction(fields), /加密方法.*密码/);
  assert.throws(() => outboundCredentialAction({ ...fields, method: "aes-128-gcm", methodChanged: true }, options), /同时填写/);
  assert.throws(() => outboundCredentialAction({ ...fields, clearAuthentication: true }, options), /不能清除认证/);
  assert.deepEqual(outboundCredentialAction({ ...fields, method: "aes-128-gcm", methodChanged: true, password: "new-password" }, options), { action: "replace", original_name: "Private proxy", username: "aes-128-gcm", password: "new-password" });
  assert.throws(() => outboundCredentialAction({ ...fields, method: "unsupported-method", password: "new-password" }, options), /支持的 Shadowsocks/);
});
