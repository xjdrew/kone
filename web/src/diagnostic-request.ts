import { targetHost } from "./domain";

export function connectionTarget(value: string): string {
  const { host, port } = targetHost(value.trim());
  // Keep malformed explicit ports for API validation instead of replacing them.
  if (
    port !== undefined ||
    /^\[[^\]]+\]:/.test(value.trim()) ||
    (value.includes(":") && !value.includes("::"))
  )
    return value.trim();
  return `${host.includes(":") ? `[${host}]` : host}:80`;
}

export function diagnosticRequest(
  target: string,
  outbound: string,
  protocol: string,
  tls: boolean,
  dnsName: string,
  dnsType: string,
) {
  return {
    target: protocol === "tcp" ? connectionTarget(target) : target,
    outbounds: outbound && outbound !== "direct" ? ["direct", outbound] : ["direct"],
    protocol,
    tls: protocol === "tcp" && target !== "149.154.167.50:443" && tls,
    ...(protocol === "udp" ? { udp_mode: "dns", dns_name: dnsName, dns_type: dnsType } : {}),
  };
}
