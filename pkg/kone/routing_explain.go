package kone

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/xjdrew/kone/pkg/geoip"
)

func explainTarget(target, protocol string, port uint16) (any, string, uint16, error) {
	target = strings.TrimSpace(target)
	protocol = strings.ToLower(protocol)
	if protocol == "" {
		protocol = "tcp"
	}
	if protocol != "tcp" && protocol != "udp" {
		return nil, "", 0, errors.New("protocol must be tcp or udp")
	}
	// A separate port field overrides only an omitted port, never an explicit one.
	defaultPort := "80"
	if port != 0 {
		defaultPort = strconv.Itoa(int(port))
	}
	normalized, err := normalizeTargetPort(target, defaultPort)
	if err != nil {
		return nil, "", 0, err
	}
	host, raw, _ := net.SplitHostPort(normalized)
	parsed, _ := strconv.ParseUint(raw, 10, 16)
	if port != 0 && port != uint16(parsed) {
		return nil, "", 0, errors.New("invalid or conflicting target port")
	}
	target, port = host, uint16(parsed)
	if address, err := netip.ParseAddr(target); err == nil {
		return address.Unmap(), protocol, port, nil
	}
	return normalizeDomain(target), protocol, port, nil
}

func explainWithRule(rule *Rule, outbounds *Outbounds, target, protocol string, port uint16, ipv6Enabled ...bool) (RoutingDecision, error) {
	value, protocol, port, err := explainTarget(target, protocol, port)
	if err != nil {
		return RoutingDecision{}, err
	}
	if address, ok := value.(netip.Addr); ok && address.Is6() && (len(ipv6Enabled) == 0 || !ipv6Enabled[0]) {
		return RoutingDecision{}, errors.New("IPv6 interception is not configured")
	}
	decision := rule.Decide(value, protocol, port)
	if decision.CaptureOnly {
		decision.EffectiveOutbound = ""
		return decision, nil
	}
	decision.EffectiveOutbound = decision.Outbound
	if err := outbounds.CheckEnabled(decision.Outbound); err != nil {
		decision.Reason = err.Error()
		decision.EffectiveOutbound = ""
		return decision, err
	}
	if protocol == "udp" {
		effective, err := outbounds.UDPOutbound(decision.Outbound)
		if err != nil {
			decision.Reason = err.Error()
			decision.EffectiveOutbound = ""
			return decision, err
		}
		decision.EffectiveOutbound = effective
		decision.Fallback = effective != decision.Outbound
		if decision.Fallback {
			decision.Reason = "explicit UDP fallback"
		}
	}
	return decision, nil
}

// ExplainRouting is side-effect free and works while the data plane is paused.
// It shares rule matching, endpoint protection and UDP capability decisions
// with the actual flow handler; it never probes or resolves the target.
func ExplainRouting(config *KoneConfig, target, protocol string, port uint16) (RoutingDecision, error) {
	return ExplainRoutingWithGeoIP(config, geoip.Builtin(), target, protocol, port)
}

func ExplainRoutingWithGeoIP(config *KoneConfig, database *geoip.Database, target, protocol string, port uint16) (RoutingDecision, error) {
	if config == nil {
		return RoutingDecision{}, errors.New("config is nil")
	}
	if err := config.Validate(); err != nil {
		return RoutingDecision{}, err
	}
	outbounds, err := NewOutbounds(config.Outbounds)
	if err != nil {
		return RoutingDecision{}, err
	}
	rule := NewRuleWithGeoIP(config.Rule, config.Outbounds, database)
	rule.protectPolicy(config)
	outbounds.bypassEndpoints(rule)
	return explainWithRule(rule, outbounds, target, protocol, port, config.Core.IPv6Network != "")
}

func (one *One) ExplainDecision(target, protocol string, port uint16) (RoutingDecision, error) {
	snapshot := one.policy.Load()
	if snapshot == nil {
		return RoutingDecision{}, fmt.Errorf("engine policy is not initialized")
	}
	decision, err := explainWithRule(snapshot.rule, snapshot.outbounds, target, protocol, port, snapshot.cfg.Core.IPv6Network != "")
	if value, proto, p, parseErr := explainTarget(target, protocol, port); parseErr == nil {
		if domain, ok := value.(string); ok && proto == "tcp" {
			if message := one.health.dnsEvidence(domain, snapshot); message != nil {
				decision = snapshot.rule.DecideDNS(domain, message, proto, p)
				decision = one.health.route(domain, p, proto, decision, snapshot)
				decision.EffectiveOutbound = decision.Outbound
			}
		}
	}
	decision.ConfigVersion = snapshot.configurationVersion()
	return decision, err
}
