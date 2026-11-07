export function diagnosticRequest(
  target: string,
  outbound: string,
  protocol: string,
  tls: boolean,
  dnsName: string,
  dnsType: string,
) {
  return {
    target,
    outbounds: outbound && outbound !== "direct" ? ["direct", outbound] : ["direct"],
    protocol,
    tls: protocol === "tcp" && target !== "149.154.167.50:443" && tls,
    ...(protocol === "udp" ? { udp_mode: "dns", dns_name: dnsName, dns_type: dnsType } : {}),
  };
}
