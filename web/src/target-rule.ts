import type { Config, Rule } from "./model";

export type RuleMatch = Pick<Rule, "type"> & { pattern: string };

export function normalizeRuleTarget(target: string) {
  if ([...target].some((char) => char.charCodeAt(0) > 127) && !/[\s/\\?#@]/.test(target.trim())) {
    try {
      return new URL(`http://${target.trim()}`).host;
    } catch {
      /* The API validates malformed targets. */
    }
  }
  return target;
}

export function normalizeMatchPattern(type: string, value: string) {
  let pattern = value.trim().toLowerCase();
  if (!type.startsWith("DOMAIN")) return pattern;
  if (!pattern || /[\s/:?#@*\\]/.test(pattern)) return "";
  // URL provides the browser's IDNA conversion; keep ASCII keywords literal.
  if ([...pattern].some((char) => char.charCodeAt(0) > 127)) {
    try {
      pattern = new URL(`http://${pattern}`).hostname;
    } catch {
      return "";
    }
  }
  return type === "DOMAIN-KEYWORD" ? pattern : pattern.replace(/\.$/, "");
}

export function ruleCoversHost(host: string, match: RuleMatch) {
  const { type, pattern } = match;
  if (!pattern) return false;
  if (type === "DOMAIN-SUFFIX") return host === pattern || host.endsWith(`.${pattern}`);
  if (type === "DOMAIN-KEYWORD") return host.includes(pattern);
  if (type === "DOMAIN") return host === pattern;
  return pattern === `${host}/${type === "IP-CIDR" ? 32 : 128}`;
}

export function matchingTargetRules(config: Config, match: RuleMatch) {
  return config.rules.filter(
    (rule) =>
      rule.type === match.type &&
      !rule["expires-at"] &&
      normalizeMatchPattern(rule.type, rule.pattern ?? "") === match.pattern,
  );
}
