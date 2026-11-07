package kone

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// Policy records explicit template intent. The ordered rules remain the source
// of truth for the default outbound; older files retain their original behavior.
type PolicyConfig struct {
	Mode         string `toml:"mode,omitempty" json:"mode"`
	IPv4Only     bool   `toml:"ipv4-only,omitempty" json:"ipv4_only"`
	UDPException bool   `toml:"udp-exception,omitempty" json:"udp_exception"`
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
	for _, value := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"} {
		result = append(result, ProtectedNetwork{Prefix: value, Kind: "local_network"})
	}
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Name == core.Tun {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err != nil || isSyntheticPrefix(prefix, core) {
				continue
			}
			result = append(result, ProtectedNetwork{Prefix: netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen()).String(), Interface: iface.Name, Kind: "host"})
			// Only connected routes, never a physical interface's default route.
			if prefix.Bits() > 0 && prefix.Bits() < prefix.Addr().BitLen() {
				result = append(result, ProtectedNetwork{Prefix: prefix.Masked().String(), Interface: iface.Name, Kind: "connected"})
			}
		}
	}
	return result
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
	if cfg.Policy.Mode == "" || cfg.Policy.Mode == "custom" {
		return
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
