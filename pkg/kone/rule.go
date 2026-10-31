//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"github.com/miekg/dns"
	"log/slog"
	"strings"
)

func normalizeDomain(domain string) string { return strings.TrimSuffix(strings.ToLower(domain), ".") }

// ProxyDNS uses the first non-direct answer policy and retains endpoint bypass.
func (rule *Rule) ProxyDNS(domain string, msg *dns.Msg) string {
	policy := rule.Proxy(domain)
	if rule.OutboundType(policy) != OutboundDirect || rule.directDomains[normalizeDomain(domain)] || msg == nil {
		return policy
	}
	for _, rr := range msg.Answer {
		switch answer := rr.(type) {
		case *dns.A:
			policy = rule.Proxy(answer.A)
		case *dns.CNAME:
			policy = rule.Proxy(normalizeDomain(answer.Target))
		default:
			continue
		}
		if rule.OutboundType(policy) != OutboundDirect {
			return policy
		}
	}
	return policy
}

type Rule struct {
	directDomains map[string]bool // always direct connect for proxy domain
	patterns      []Pattern
	outbounds     map[string]OutboundType
}

// An empty reference is the internal fallback/endpoint bypass, always direct.
// Configured names have no special meaning, including DIRECT and REJECT.
func (rule *Rule) OutboundType(name string) OutboundType {
	if name == "" {
		return OutboundDirect
	}
	return rule.outbounds[name]
}

func (rule *Rule) DirectDomain(domain string) {
	slog.Debug("Proxy endpoint bypass added", "domain", domain)
	rule.directDomains[normalizeDomain(domain)] = true
}

// match a proxy for target `val`
func (rule *Rule) Proxy(val interface{}) string {
	if domain, ok := val.(string); ok {
		if rule.directDomains[normalizeDomain(domain)] {
			slog.Debug("Routing rule matched", "target", val, "proxy", "DIRECT")
			return "" // internal direct endpoint bypass
		}
	}

	for _, pattern := range rule.patterns {
		if pattern.Match(val) {
			proxy := pattern.Proxy()
			slog.Debug("Routing rule matched", "target", val, "proxy", proxy)
			return proxy
		}
	}
	slog.Debug("Default routing policy selected", "target", val, "proxy", "")
	return "" // implicit direct when no rule matches
}

func NewRule(rcs []RuleConfig, outbounds []OutboundConfig) *Rule {
	rule := &Rule{
		directDomains: map[string]bool{},
		outbounds:     map[string]OutboundType{},
	}
	for _, o := range outbounds {
		rule.outbounds[o.Name] = o.Type
	}

	for _, rc := range rcs {
		if pattern := CreatePattern(rc); pattern != nil {
			rule.patterns = append(rule.patterns, pattern)
		}
	}
	return rule
}
