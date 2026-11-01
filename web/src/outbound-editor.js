export const outboundProtocols = [
  { value: "http", label: "HTTP CONNECT" },
  { value: "https", label: "HTTPS CONNECT" },
  { value: "socks5", label: "SOCKS5" },
  { value: "ss", label: "Shadowsocks" },
];

const defaultPorts = { http: "8080", https: "443", socks5: "1080", ss: "8388" };
const methods = new Set(["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"]);

export function parseOutboundFields(raw = "") {
  try {
    const url = new URL(raw);
    const protocol = url.protocol.slice(0, -1).toLowerCase();
    const authority = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split(/[/?#]/)[0];
    const port = authority.match(/:(\d+)$/)?.[1] || defaultPorts[protocol] || "";
    const method = decodeURIComponent(url.username);
    return { protocol, host: url.hostname.replace(/^\[|\]$/g, ""), port, method: methods.has(method) ? method : "", suffix: raw.match(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*(.*)$/i)?.[1] || "", username: "", password: "" };
  } catch {
    return { protocol: "http", host: "", port: "8080", method: "aes-256-gcm", suffix: "", username: "", password: "" };
  }
}

export function buildOutboundURL(fields, originalRaw = "") {
  const protocol = fields.protocol;
  if (!outboundProtocols.some(value => value.value === protocol)) throw new Error("请选择支持的代理协议。");
  let host = String(fields.host || "").trim();
  if ((host.startsWith("[") || host.endsWith("]")) && (!host.startsWith("[") || !host.endsWith("]") || !host.includes(":"))) throw new Error("IPv6 地址的方括号格式不正确。");
  host = host.replace(/^\[|\]$/g, "");
  if (!host || /[\s/@?#\\]/.test(host)) throw new Error("请输入有效的代理服务器地址，不要包含协议、路径或认证信息。");
  const port = String(fields.port ?? "").trim();
  if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) throw new Error("代理端口必须是 1 到 65535 的整数。");
  try { new URL(`http://${host.includes(":") ? `[${host}]` : host}:1`); }
  catch { throw new Error("代理服务器地址格式不正确。"); }
  const original = parseOutboundFields(originalRaw);
  if (originalRaw && !fields.clearAuthentication && original.protocol === protocol && original.host === host && Number(original.port) === Number(port)) return originalRaw;
  const authority = originalRaw.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i)?.[1] || "";
  const userInfo = !fields.clearAuthentication && authority.includes("@") ? `${authority.slice(0, authority.lastIndexOf("@"))}@` : "";
  if (host.includes(":")) host = `[${host}]`;
  // URL.toString() drops :80 and :443; managed proxies require explicit ports.
  return `${protocol}://${userInfo}${host}:${Number(port)}${originalRaw ? original.suffix : fields.suffix || ""}`;
}

export function defaultOutboundName(protocol, names = []) {
  const base = `${({ http: "HTTP", https: "HTTPS", socks5: "SOCKS5", ss: "Shadowsocks" })[protocol] || "HTTP"} 代理`;
  const used = new Set(names);
  if (!used.has(base)) return base;
  let number = 2;
  while (used.has(`${base} ${number}`)) number++;
  return `${base} ${number}`;
}

export function outboundCredentialAction(fields, { configured = false, originalName = "", endpointChanged = false } = {}) {
  const base = { original_name: originalName };
  if (fields.clearAuthentication) {
    if (fields.protocol === "ss") throw new Error("Shadowsocks 需要加密方法和密码，不能清除认证。");
    return { ...base, action: "clear" };
  }
  const username = fields.protocol === "ss" ? fields.method || "" : fields.username || "";
  const password = fields.password || "";
  if (!password && !fields.username && !fields.methodChanged) {
    if (configured && endpointChanged) throw new Error("修改代理地址或协议后，请重新填写认证信息，或明确清除认证。");
    if (fields.protocol === "ss" && !configured) throw new Error("请选择 Shadowsocks 加密方法并填写密码。");
    return { ...base, action: configured ? "preserve" : "clear" };
  }
  if (fields.protocol === "ss" && !username) throw new Error("请选择加密方法，才能替换 Shadowsocks 密码。");
  if (!password || !username) throw new Error(fields.protocol === "ss" ? "修改加密方法时，请同时填写新的 Shadowsocks 密码。" : "请同时填写用户名和密码；留空两项会保留现有认证。");
  if (fields.protocol === "ss" && !methods.has(username)) throw new Error("请选择支持的 Shadowsocks 加密方法。");
  return { ...base, action: "replace", username, password };
}
