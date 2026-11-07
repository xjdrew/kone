package kone

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func RulePool(schema string) string {
	switch strings.ToUpper(schema) {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
		return "domain"
	case "IP-CIDR", "IP-CIDR6", "GEOIP":
		return "ip"
	case "PROTECTED":
		return "system"
	default:
		return "final"
	}
}

func (rule *Rule) layeredEntry(entry decisionRule, values []any, protocol string, port uint16) (RoutingDecision, bool) {
	now := time.Now()
	if rule.now != nil {
		now = rule.now()
	}
	if !entry.expires.IsZero() && !now.Before(entry.expires) {
		return RoutingDecision{}, false
	}
	if !slices.ContainsFunc(values, entry.pattern.Match) {
		return RoutingDecision{}, false
	}
	decision := entry.decision(protocol, port)
	decision.Pool, decision.Evidence, decision.DecisionSource = RulePool(entry.config.Schema), "complete", "user-rule"
	if decision.Pool == "final" {
		decision.DecisionSource = "base-final"
	}
	if protocol == "" && (entry.config.Protocol != "" || len(entry.config.Ports) > 0 || entry.config.ExpiresAt != "") {
		decision.Outbound, decision.CaptureOnly, decision.Evidence = CaptureOutbound, true, "flow_required"
		decision.Reason = "business protocol, port or expiry requires a captured flow"
		return decision, true
	}
	if entry.config.Protocol != "" && !strings.EqualFold(entry.config.Protocol, protocol) {
		return RoutingDecision{}, false
	}
	if len(entry.config.Ports) > 0 && !slices.Contains(entry.config.Ports, port) {
		return RoutingDecision{}, false
	}
	return decision, true
}

func (rule *Rule) layeredMatch(pool string, values []any, protocol string, port uint16) (RoutingDecision, bool) {
	for _, entry := range rule.decisions {
		if RulePool(entry.config.Schema) == pool {
			if result, ok := rule.layeredEntry(entry, values, protocol, port); ok {
				return result, true
			}
		}
	}
	return RoutingDecision{}, false
}

func layeredProtection(protocol string, port uint16) RoutingDecision {
	return RoutingDecision{Pool: "system", Evidence: "complete", DecisionSource: "system", RuleID: "protected:local", RuleType: "PROTECTED", RuleName: "Local host protection", RuleSource: "protected", Outbound: BuiltinDirect, Protocol: protocol, Port: port, Protected: true, Reason: "local_host"}
}

// relatedDNSEvidence accepts only the original owner and its bounded CNAME
// chain. Unrelated Answer/Additional records never influence routing or dialing.
func relatedDNSEvidence(domain string, msg *dns.Msg) ([]string, []netip.Addr, bool) {
	if msg == nil || msg.Rcode != dns.RcodeSuccess || msg.Truncated {
		return nil, nil, false
	}
	owner := normalizeDomain(domain)
	seen := map[string]bool{owner: true}
	aliases := []string{}
	for depth := 0; depth < 16; depth++ {
		next := ""
		for _, answer := range msg.Answer {
			if cname, ok := answer.(*dns.CNAME); ok && normalizeDomain(cname.Hdr.Name) == owner {
				candidate := normalizeDomain(cname.Target)
				if next != "" && next != candidate {
					return nil, nil, false
				}
				next = candidate
			}
		}
		if next == "" {
			break
		}
		if seen[next] || depth == 15 {
			return nil, nil, false
		}
		seen[next], owner = true, next
		aliases = append(aliases, next)
	}
	addresses := []netip.Addr{}
	for _, answer := range msg.Answer {
		if !seen[normalizeDomain(answer.Header().Name)] {
			continue
		}
		var ip net.IP
		switch value := answer.(type) {
		case *dns.A:
			if len(msg.Question) > 0 && msg.Question[0].Qtype == dns.TypeAAAA {
				continue
			}
			ip = value.A
		case *dns.AAAA:
			if len(msg.Question) > 0 && msg.Question[0].Qtype == dns.TypeA {
				continue
			}
			ip = value.AAAA
		}
		address, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		address = address.Unmap()
		if !slices.Contains(addresses, address) {
			addresses = append(addresses, address)
		}
		if len(addresses) > 64 {
			return nil, nil, false
		}
	}
	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	return aliases, addresses, true
}

func (rule *Rule) decideLayered(val any, msg *dns.Msg, protocol string, port uint16) (decision RoutingDecision) {
	protocol = strings.ToLower(protocol)
	domain := ""
	var addresses []netip.Addr
	switch value := val.(type) {
	case string:
		domain = normalizeDomain(value)
	case net.IP:
		if ip, ok := netip.AddrFromSlice(value); ok {
			addresses = []netip.Addr{ip.Unmap()}
		}
	case netip.Addr:
		addresses = []netip.Addr{value.Unmap()}
	}
	defer func() {
		decision.Domain = domain
		if rule.geoIP != nil {
			metadata := rule.geoIP.Metadata()
			decision.GeoIPVersion, decision.GeoIPSHA256 = metadata.Version, metadata.SHA256
		}
	}()
	if domain != "" && (rule.directDomains[domain] || protocol == "" && rule.endpointDNS[domain]) {
		decision = layeredProtection(protocol, port)
		decision.RuleID, decision.Reason = "protected:endpoint", "proxy endpoint bypass"
		return decision
	}
	var original RoutingDecision
	var matched bool
	if domain != "" {
		original, matched = rule.layeredMatch("domain", []any{domain}, protocol, port)
		if msg == nil && matched && (original.CaptureOnly || rule.OutboundType(original.Outbound) == OutboundReject) {
			return original
		}
		if msg == nil {
			return RoutingDecision{Pool: "pending", Evidence: "dns_required", CaptureOnly: true, Outbound: CaptureOutbound, Protocol: protocol, Port: port, Reason: "resolve the domain before checking target protection and IP rules"}
		}
		aliases, candidates, valid := relatedDNSEvidence(domain, msg)
		if !valid || len(candidates) == 0 {
			return RoutingDecision{Pool: "pending", Evidence: "dns_failed", Outbound: BuiltinReject, Protocol: protocol, Port: port, Reason: "required DNS address evidence is unavailable"}
		}
		addresses = candidates
		if !matched && len(aliases) > 0 {
			values := make([]any, len(aliases))
			for i, name := range aliases {
				values[i] = name
			}
			original, matched = rule.layeredMatch("domain", values, protocol, port)
		}
	}
	// Protection is per actual candidate, before any business pool. A protected
	// address cannot authorize another address from the same DNS response.
	for _, ip := range addresses {
		for _, prefix := range rule.retired {
			if prefix.Contains(ip) {
				return RoutingDecision{Pool: "system", Evidence: "complete", DecisionSource: "system", RuleID: "protected:retired-fake-ip", RuleType: "PROTECTED", RuleSource: "protected", Outbound: BuiltinReject, Protocol: protocol, Port: port, Protected: true, Reason: "retired Fake-IP has no active identity; resolve the domain again"}
			}
		}
	}
	protected := []string{}
	for _, ip := range addresses {
		if rule.protectedAddress(ip.String()) || rule.directDomains[ip.String()] {
			protected = append(protected, ip.String())
		}
	}
	if len(protected) > 0 {
		decision = layeredProtection(protocol, port)
		decision.Candidates = protected
		return decision
	}
	if matched {
		for _, ip := range addresses {
			original.Candidates = append(original.Candidates, ip.String())
		}
		return original
	}
	values := make([]any, len(addresses))
	for i, ip := range addresses {
		values[i] = net.IP(ip.AsSlice())
	}
	for _, entry := range rule.decisions {
		if RulePool(entry.config.Schema) != "ip" {
			continue
		}
		if candidate, ok := rule.layeredEntry(entry, values, protocol, port); ok {
			for i, value := range values {
				if entry.pattern.Match(value) {
					candidate.Candidates = append(candidate.Candidates, addresses[i].String())
				}
			}
			return candidate
		}
	}
	decision, matched = rule.layeredMatch("final", []any{domain}, protocol, port)
	if !matched {
		decision = RoutingDecision{Pool: "final", Evidence: "complete", DecisionSource: "base-final", RuleID: "builtin:default", RuleType: "FINAL", RuleSource: "builtin", RuleName: "Default direct", Outbound: BuiltinDirect, Protocol: protocol, Port: port, Reason: "no rule matched"}
	}
	for _, ip := range addresses {
		decision.Candidates = append(decision.Candidates, ip.String())
	}
	return decision
}
