//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/miekg/dns"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/xjdrew/kone/pkg/geoip"
)

// CaptureOutbound is a DNS-only policy: reserve a Fake-IP so the subsequent
// flow can apply protocol/port selectors. It is never a dial target.
const CaptureOutbound = "@capture"

type RoutingDecision struct {
	ConfigVersion     uint64 `json:"config_version"`
	GeoIPVersion      string `json:"geoip_version"`
	GeoIPSHA256       string `json:"geoip_sha256"`
	RuleID            string `json:"rule_id"`
	RuleName          string `json:"rule_name"`
	RuleSource        string `json:"rule_source"`
	RuleOrder         int    `json:"rule_order"`
	Outbound          string `json:"outbound"`
	EffectiveOutbound string `json:"effective_outbound"`
	Fallback          bool   `json:"fallback"`
	Protocol          string `json:"protocol,omitempty"`
	Port              uint16 `json:"port,omitempty"`
	Protected         bool   `json:"protected"`
	CaptureOnly       bool   `json:"capture_only"`
	Reason            string `json:"reason"`
}

type decisionRule struct {
	config  RuleConfig
	pattern Pattern
	id      string
	order   int
}

func normalizeDomain(domain string) string { return strings.TrimSuffix(strings.ToLower(domain), ".") }

// ProxyDNS uses the first non-direct answer policy and retains endpoint bypass.
func (rule *Rule) ProxyDNS(domain string, msg *dns.Msg) string {
	return rule.DecideDNS(domain, msg, "", 0).Outbound
}

type Rule struct {
	directDomains map[string]bool // always direct connect for proxy domain
	patterns      []Pattern
	outbounds     map[string]OutboundType
	decisions     []decisionRule
	geoIP         *geoip.Database
}

// Built-in and configured targets share the same immutable routing registry.
func (rule *Rule) OutboundType(name string) OutboundType {
	if name == CaptureOutbound {
		return OutboundProxy
	}
	return rule.outbounds[name]
}

func (rule *Rule) DirectDomain(domain string) {
	slog.Debug("Proxy endpoint bypass added", "domain", domain)
	rule.directDomains[normalizeDomain(domain)] = true
}

// match a proxy for target `val`
func (rule *Rule) Proxy(val interface{}) string {
	return rule.Decide(val, "", 0).Outbound
}

// Decide is shared by simulation and the data plane. Empty protocol denotes
// a DNS envelope, not a TCP/UDP business connection.
func (rule *Rule) Decide(val any, protocol string, port uint16) (decision RoutingDecision) {
	defer func() {
		if rule.geoIP != nil {
			metadata := rule.geoIP.Metadata()
			decision.GeoIPVersion, decision.GeoIPSHA256 = metadata.Version, metadata.SHA256
		}
	}()
	protocol = strings.ToLower(protocol)
	var endpoint string
	switch value := val.(type) {
	case string:
		endpoint = normalizeDomain(value)
	case net.IP:
		endpoint = value.String()
	case netip.Addr:
		endpoint = value.Unmap().String()
	}
	if endpoint != "" {
		if rule.directDomains[endpoint] {
			return RoutingDecision{RuleID: "protected:endpoint", RuleName: "Proxy endpoint bypass", RuleSource: "protected", Outbound: BuiltinDirect, Protocol: protocol, Port: port, Protected: true, Reason: "proxy endpoint bypass"}
		}
	}
	for _, entry := range rule.decisions {
		if !entry.pattern.Match(val) {
			continue
		}
		conditional := entry.config.Protocol != "" || len(entry.config.Ports) > 0
		if protocol == "" && conditional {
			if rule.OutboundType(entry.config.Outbound) == OutboundDirect {
				continue
			}
			decision := entry.decision(protocol, port)
			decision.Outbound, decision.CaptureOnly, decision.Reason = CaptureOutbound, true, "protocol-scoped rule requires Fake-IP interception"
			return decision
		}
		if entry.config.Protocol != "" && !strings.EqualFold(entry.config.Protocol, protocol) {
			continue
		}
		if len(entry.config.Ports) > 0 {
			matched := false
			for _, candidate := range entry.config.Ports {
				if candidate == port {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		return entry.decision(protocol, port)
	}
	return RoutingDecision{RuleID: "builtin:default", RuleName: "Default direct", RuleSource: "builtin", Outbound: BuiltinDirect, Protocol: protocol, Port: port, Reason: "no rule matched"}
}

func (entry decisionRule) decision(protocol string, port uint16) RoutingDecision {
	source := entry.config.Source
	if source == "" {
		source = "config"
	}
	name := entry.config.Schema
	if entry.config.Pattern != "" {
		name += " " + entry.config.Pattern
	}
	return RoutingDecision{RuleID: entry.id, RuleName: name, RuleSource: source, RuleOrder: entry.order, Outbound: entry.config.Outbound, Protocol: protocol, Port: port, Reason: "ordered rule match"}
}

func (rule *Rule) Explain(val any, protocol string, port uint16) RoutingDecision {
	return rule.Decide(val, protocol, port)
}

func (rule *Rule) DecideDNS(domain string, msg *dns.Msg, protocol string, port uint16) RoutingDecision {
	decision := rule.Decide(domain, protocol, port)
	if rule.OutboundType(decision.Outbound) != OutboundDirect || decision.Protected || msg == nil {
		return decision
	}
	for _, answer := range msg.Answer {
		switch value := answer.(type) {
		case *dns.A:
			decision = rule.Decide(value.A, protocol, port)
		case *dns.AAAA:
			decision = rule.Decide(value.AAAA, protocol, port)
		case *dns.CNAME:
			decision = rule.Decide(normalizeDomain(value.Target), protocol, port)
		default:
			continue
		}
		if rule.OutboundType(decision.Outbound) != OutboundDirect {
			return decision
		}
	}
	return decision
}

func NewRule(rcs []RuleConfig, outbounds []OutboundConfig) *Rule {
	return NewRuleWithGeoIP(rcs, outbounds, geoip.Builtin())
}

func NewRuleWithGeoIP(rcs []RuleConfig, outbounds []OutboundConfig, database *geoip.Database) *Rule {
	if database == nil {
		database = geoip.Builtin()
	}
	rule := &Rule{
		directDomains: map[string]bool{},
		outbounds:     map[string]OutboundType{},
		geoIP:         database,
	}
	for _, o := range outbounds {
		rule.outbounds[o.Name] = OutboundProxy
	}
	for name, kind := range builtinOutbounds() {
		rule.outbounds[name] = kind
	}

	duplicates := map[string]int{}
	for index, rc := range rcs {
		pattern := CreatePattern(rc)
		if strings.EqualFold(rc.Schema, "GEOIP") {
			pattern = NewGEOIPPatternWithDatabase(rc.Outbound, rc.Pattern, database)
		}
		if pattern != nil {
			rule.patterns = append(rule.patterns, pattern)
			id := rc.ID
			if id == "" {
				key := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%v", strings.ToUpper(rc.Schema), normalizeDomain(rc.Pattern), rc.Outbound, strings.ToLower(rc.Protocol), rc.Ports)
				digest := sha256.Sum256([]byte(key))
				id = "rule-" + hex.EncodeToString(digest[:8])
				duplicates[id]++
				if duplicates[id] > 1 {
					id += fmt.Sprint("-", duplicates[id])
				}
			}
			rc.Ports = append([]uint16(nil), rc.Ports...)
			rule.decisions = append(rule.decisions, decisionRule{config: rc, pattern: pattern, id: id, order: index + 1})
		}
	}
	return rule
}
