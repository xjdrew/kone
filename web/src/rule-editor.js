export const ruleTypes = ["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "GEOIP"];

const patternInfo = {
  DOMAIN: { label: "精确域名", placeholder: "example.com", hint: "只匹配这个域名，不包含子域名。填写域名，不含协议、端口、路径或通配符。" },
  "DOMAIN-SUFFIX": { label: "域名后缀", placeholder: "example.com", hint: "匹配 example.com 及其子域名，如 www.example.com；不会匹配 notexample.com。无需前导点，不支持通配符。" },
  "DOMAIN-KEYWORD": { label: "域名关键词", placeholder: "example", hint: "匹配域名中任意位置包含的文字，例如 example 也会匹配 notexample.com；不支持通配符。" },
  "IP-CIDR": { label: "IPv4 地址范围", placeholder: "192.0.2.0/24", hint: "使用 IPv4 地址/前缀长度，范围为 /0–/32；单个地址使用 /32。修改捕获路由可能需要暂停接管。" },
  "IP-CIDR6": { label: "IPv6 地址范围", placeholder: "2001:db8::/32", hint: "使用 IPv6 地址/前缀长度，范围为 /0–/128；单个地址使用 /128。需要先在入站启用 IPv6 网段。" },
  GEOIP: { label: "国家或地区", placeholder: "选择国家或地区", hint: "按目标 IP 在当前 GeoIP 数据中的归属匹配；不会联网查询，也不直接匹配域名。" },
};

export function rulePatternInfo(type) { return patternInfo[type] || patternInfo.DOMAIN; }

const isoCodes = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split(" ");
export function countryOptions(locale = "zh-CN", current = "") {
  let names;
  try { names = new Intl.DisplayNames([locale], { type: "region" }); } catch { /* Codes remain usable without Intl.DisplayNames. */ }
  const codes = [...isoCodes, "XK"];
  if (/^[A-Z]{2}$/.test(current) && !codes.includes(current)) codes.push(current);
  return codes.map(value => ({ value, label: !isoCodes.includes(value) && value !== "XK" ? `${value}（旧配置代码）` : `${names?.of(value) || value} (${value})` })).sort((a, b) => a.label.localeCompare(b.label, locale));
}

function ipv4(value) {
  const parts = value.split(".");
  return parts.length === 4 && parts.every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

export function validateRulePattern(type, raw) {
  if (type === "FINAL") return "";
  const value = String(raw ?? "");
  if (!value) return type === "GEOIP" ? "请选择国家或地区。" : "请填写匹配内容。";
  if (type === "GEOIP") return /^[A-Z]{2}$/.test(value) ? "" : "请选择有效的国家或地区代码。";
  if (type === "IP-CIDR" || type === "IP-CIDR6") {
    const [address, prefix, extra] = value.split("/");
    const max = type === "IP-CIDR" ? 32 : 128;
    if (extra !== undefined || !/^(0|[1-9]\d*)$/.test(prefix || "") || Number(prefix) > max)
      return `请输入地址/前缀长度，${type === "IP-CIDR" ? "IPv4" : "IPv6"} 前缀范围为 /0–/${max}。`;
    if (type === "IP-CIDR") return ipv4(address) ? "" : "IP-CIDR 需要有效的 IPv4 地址，例如 192.0.2.0/24。";
    try {
      if (!address.includes(":") || /[\s[\]%]/.test(address)) throw new Error();
      const normalized = new URL(`http://[${address}]/`).hostname;
      if (normalized.startsWith("[::ffff:")) return "请使用原生 IPv6 地址，IPv4 映射地址应改用 IP-CIDR。";
      return "";
    } catch { return "IP-CIDR6 需要有效的 IPv6 地址，例如 2001:db8::/32。"; }
  }
  if (!ruleTypes.includes(type)) return "请选择有效的匹配方式。";
  if (/[\s\x00-\x1f\x7f:/?#@*\\]/.test(value)) return "只填写域名或关键词，不含空白、协议、端口、路径或通配符。";
  if (type === "DOMAIN-KEYWORD") return "";
  if (value.startsWith(".")) return "无需前导点，请直接填写 example.com。";
  if (ipv4(value)) return "IP 地址请使用 IP-CIDR，单个 IPv4 地址使用 /32。";
  try {
    const normalized = new URL(`http://${value}`).hostname.replace(/\.$/, "");
    if (normalized.length > 253 || !normalized.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) throw new Error();
    return "";
  } catch { return "请输入有效域名，例如 example.com；不支持通配符。"; }
}

export function classifyRuleDecision(decision = {}) {
  if (decision.rule_type === "PROTECTED" || decision.protected || decision.rule_id?.startsWith("protected:")) return "protected";
  if (decision.rule_type === "FINAL" || decision.rule_id === "builtin:default" || decision.rule_name === "FINAL") return "final";
  return "rule";
}

export function ruleScope(rule = {}) {
  return `${rule.protocol ? rule.protocol.toUpperCase() : "TCP 与 UDP"} · ${rule.ports?.length ? `端口 ${rule.ports.join(", ")}` : "全部端口"}`;
}
