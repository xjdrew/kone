package kone

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// Policy records explicit template intent. The ordered rules remain the source
// of truth for the default outbound; older files retain their original behavior.
type PolicyConfig struct {
	PreferredProxyID string      `toml:"preferred-proxy-id,omitempty" json:"preferred_proxy_id"`
	Smart            SmartConfig `toml:"smart,omitempty" json:"smart"`
	RuleVersion      uint        `toml:"rule-version,omitempty" json:"rule_version"`
	Mode             string      `toml:"mode,omitempty" json:"mode"`
	IPv4Only         bool        `toml:"ipv4-only,omitempty" json:"ipv4_only"`
	UDPException     bool        `toml:"udp-exception,omitempty" json:"udp_exception"`
	LANDefaults      bool        `toml:"lan-defaults-initialized,omitempty" json:"lan_defaults_initialized,omitempty"`
}

type ProtectedNetwork struct {
	Prefix    string `json:"prefix"`
	Interface string `json:"interface,omitempty"`
	Kind      string `json:"kind"`
}

// PolicyMode never guesses that a conditional FINAL is a base policy.
func PolicyMode(cfg *KoneConfig) (mode, outbound string) {
	if cfg == nil {
		return "custom", ""
	}
	if len(cfg.Rule) == 0 {
		return "direct-first", BuiltinDirect
	}
	last := cfg.Rule[len(cfg.Rule)-1]
	if last.Schema != "FINAL" || last.Protocol != "" || len(last.Ports) != 0 || last.ExpiresAt != "" {
		return "custom", ""
	}
	if last.Outbound == BuiltinDirect {
		return "direct-first", last.Outbound
	}
	if last.Outbound != BuiltinReject {
		if cfg.Policy.Mode == "" && !cfg.Core.AutoRoute {
			return "custom", last.Outbound
		}
		return "proxy-first", last.Outbound
	}
	return "custom", last.Outbound
}

func (cfg *KoneConfig) ValidatePolicy() error {
	if cfg == nil {
		return nil
	}
	if cfg.Policy.RuleVersion > 2 {
		return errors.New("policy.rule-version must be 1 (legacy) or 2 (layered)")
	}
	if cfg.Policy.Smart.Enabled {
		mode, _ := PolicyMode(cfg)
		if cfg.Policy.RuleVersion != 2 || mode == "custom" {
			return errors.New("Smart requires layered rules and a standard base mode")
		}
	}
	seenCandidates := map[string]bool{}
	if len(cfg.Policy.Smart.Candidates) > 16 {
		return errors.New("Smart supports at most 16 candidate outbounds")
	}
	for _, id := range cfg.Policy.Smart.Candidates {
		if id == "" || seenCandidates[id] {
			return errors.New("Smart candidate IDs must be unique and nonempty")
		}
		seenCandidates[id] = true
		found := false
		for _, o := range cfg.Outbounds {
			if o.ID == id && o.IsEnabled() {
				found = true
			}
		}
		if !found {
			return errors.New("Smart candidate must reference an enabled outbound ID")
		}
	}
	if cfg.Policy.PreferredProxyID != "" {
		out, ok := preferredProxy(cfg)
		if !ok {
			return errors.New("preferred proxy must reference an enabled outbound ID")
		}
		mode, final := PolicyMode(cfg)
		if mode == "proxy-first" && out.Name != final {
			return errors.New("preferred proxy must agree with the global FINAL outbound")
		}
	}
	if cfg.Policy.Mode == "" || cfg.Policy.Mode == "custom" {
		return nil
	}
	mode, name := PolicyMode(cfg)
	if cfg.Policy.Mode != "direct-first" && cfg.Policy.Mode != "proxy-first" {
		return errors.New("policy.mode must be direct-first, proxy-first or custom")
	}
	if mode != cfg.Policy.Mode {
		return errors.New("policy mode must agree with the unconditional final rule")
	}
	if mode == "direct-first" {
		return nil
	}
	if !cfg.Core.AutoRoute || cfg.Core.OutboundInterface == "" {
		return errors.New("global proxy requires IPv4 capture and an outbound interface")
	}
	if !cfg.Policy.IPv4Only && ((cfg.Core.IPv6Network != "" && !cfg.Core.AutoRoute6) || (cfg.Core.IPv6Network == "" && DefaultIPv6Network() != "")) {
		return errors.New("global proxy requires IPv6 capture or an explicit IPv4-only scope")
	}
	for _, outbound := range cfg.Outbounds {
		if outbound.Name == name {
			if !outbound.IsEnabled() {
				return errors.New("the global proxy outbound is disabled")
			}
			u, _ := url.Parse(outbound.URL)
			if u != nil && (u.Scheme == "http" || u.Scheme == "https") && outbound.UDPFallback == BuiltinDirect && !cfg.Policy.UDPException {
				return errors.New("global proxy requires explicit acceptance of the UDP direct exception")
			}
			return nil
		}
	}
	return errors.New("the global proxy outbound does not exist")
}

func PolicyProtection(core CoreConfig) []ProtectedNetwork {
	result := []ProtectedNetwork{}
	for _, value := range []string{"127.0.0.0/8", "::1/128"} {
		result = append(result, ProtectedNetwork{Prefix: value, Kind: "loopback"})
	}
	seen := map[string]bool{}
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Name == core.Tun {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err != nil || isSyntheticPrefix(prefix, core) || prefix.Addr().IsLoopback() {
				continue
			}
			address := prefix.Addr().Unmap()
			if !seen[address.String()] {
				seen[address.String()] = true
				result = append(result, ProtectedNetwork{Prefix: netip.PrefixFrom(address, address.BitLen()).String(), Interface: iface.Name, Kind: "host"})
			}
		}
	}
	return result
}

// DefaultLANRules is a template, not a routing override. Once materialized,
// these rules are ordinary ordered rules and may be changed or removed.
func DefaultLANRules(core CoreConfig) []RuleConfig {
	values := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "fc00::/7", "fe80::/10", "ff00::/8"}
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Name == core.Tun {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err == nil && prefix.Bits() > 0 && prefix.Bits() < prefix.Addr().BitLen() && !isSyntheticPrefix(prefix, core) {
				values = append(values, prefix.Masked().String())
			}
		}
	}
	return lanRules(values)
}

func lanRules(values []string) []RuleConfig {
	prefixes := []netip.Prefix{}
	for _, value := range values {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if a.Bits() != b.Bits() {
			return a.Bits() - b.Bits()
		}
		return a.Addr().Compare(b.Addr())
	})
	kept := []netip.Prefix{}
	for _, prefix := range prefixes {
		if !slices.ContainsFunc(kept, func(parent netip.Prefix) bool {
			return parent.Contains(prefix.Addr()) && parent.Bits() <= prefix.Bits()
		}) {
			kept = append(kept, prefix)
		}
	}
	slices.SortFunc(kept, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	rules := make([]RuleConfig, 0, len(kept))
	for _, prefix := range kept {
		schema := "IP-CIDR"
		if prefix.Addr().Is6() {
			schema = "IP-CIDR6"
		}
		rules = append(rules, RuleConfig{ID: "rule-lan-" + strings.NewReplacer("/", "-", ":", "-").Replace(prefix.String()), Source: "policy-lan", Schema: schema, Pattern: prefix.String(), Outbound: BuiltinDirect})
	}
	return rules
}

func isSyntheticPrefix(prefix netip.Prefix, core CoreConfig) bool {
	for _, value := range []string{core.Network, core.IPv6Network} {
		if synthetic, err := netip.ParsePrefix(value); err == nil && synthetic.Masked() == prefix.Masked() {
			return true
		}
	}
	return false
}

func (rule *Rule) protectPolicy(cfg *KoneConfig) {
	rule.layered = cfg.Policy.RuleVersion == 2
	for _, value := range cfg.DNS.RetiredPools {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			rule.retired = append(rule.retired, prefix)
		}
	}
	for _, item := range PolicyProtection(cfg.Core) {
		if prefix, err := netip.ParsePrefix(item.Prefix); err == nil {
			rule.protected = append(rule.protected, prefix)
		}
	}
	for _, value := range []string{cfg.Core.Network, cfg.Core.IPv6Network} {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			rule.synthetic = append(rule.synthetic, prefix.Masked())
		}
	}
}

func (rule *Rule) protectedAddress(endpoint string) bool {
	ip, err := netip.ParseAddr(strings.Trim(endpoint, "[]"))
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range rule.synthetic {
		if prefix.Contains(ip) {
			return false // Fake-IP must first be restored to its DNS evidence.
		}
	}
	for _, prefix := range rule.protected {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
