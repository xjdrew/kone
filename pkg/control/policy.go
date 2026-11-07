package control

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"

	"github.com/xjdrew/kone/pkg/kone"
)

type policyRequest struct {
	BaseVersion   uint64 `json:"base_version"`
	Mode          string `json:"mode"`
	Outbound      string `json:"outbound"`
	Interface     string `json:"interface"`
	IPv4Only      bool   `json:"ipv4_only"`
	UDPException  bool   `json:"udp_exception"`
	RejectUDP     bool   `json:"reject_udp"`
	ConvertCustom bool   `json:"convert_custom"`
}

// Describe transport bypasses without resolving endpoints or exposing URL credentials.
func policyProtection(cfg *kone.KoneConfig) []kone.ProtectedNetwork {
	items := kone.PolicyProtection(cfg.Core)
	for _, outbound := range cfg.Outbounds {
		if endpoint, err := url.Parse(outbound.URL); err == nil && outbound.IsEnabled() {
			items = append(items, kone.ProtectedNetwork{Prefix: endpoint.Host, Kind: "proxy_endpoint"})
		}
	}
	for _, server := range cfg.DNS.Servers {
		items = append(items, kone.ProtectedNetwork{Prefix: server, Kind: "dns_transport"})
	}
	for _, route := range cfg.DNS.Rules {
		for _, server := range route.Servers {
			items = append(items, kone.ProtectedNetwork{Prefix: server, Interface: route.Interface, Kind: "dns_transport"})
		}
	}
	seen := map[kone.ProtectedNetwork]bool{}
	return slices.DeleteFunc(items, func(item kone.ProtectedNetwork) bool {
		duplicate := seen[item]
		seen[item] = true
		return duplicate
	})
}

func (c *Controller) policyState() map[string]any {
	c.mu.Lock()
	doc := cloneDocument(c.doc)
	c.mu.Unlock()
	mode, outbound := kone.PolicyMode(doc.Config)
	interfaces := []string{}
	all, _ := net.Interfaces()
	for _, iface := range all {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 && iface.Name != doc.Config.Core.Tun {
			interfaces = append(interfaces, iface.Name)
		}
	}
	return map[string]any{"mode": mode, "outbound": outbound, "explicit": doc.Config.Policy.Mode != "", "version": doc.Version, "ipv4_only": doc.Config.Policy.IPv4Only, "udp_exception": doc.Config.Policy.UDPException, "interface": doc.Config.Core.OutboundInterface, "interfaces": interfaces, "ipv6_available": kone.DefaultIPv6Network() != "", "protection": policyProtection(doc.Config)}
}

func preparePolicy(request policyRequest, current Document) (SaveRequest, error) {
	if request.BaseVersion != current.Version {
		return SaveRequest{}, ErrConflict
	}
	if request.Mode != "direct-first" && request.Mode != "proxy-first" {
		return SaveRequest{}, errors.New("select direct-first or proxy-first")
	}
	cfg := cloneDocument(current).Config
	if cfg == nil {
		return SaveRequest{}, errors.New("current policy configuration is invalid")
	}
	mode, _ := kone.PolicyMode(cfg)
	if mode == "custom" && !request.ConvertCustom {
		return SaveRequest{}, errors.New("explicitly confirm conversion of a custom final rule")
	}
	final := kone.RuleConfig{ID: "rule-default-policy", Source: "policy", Schema: "FINAL", Outbound: kone.BuiltinDirect}
	if len(cfg.Rule) > 0 && cfg.Rule[len(cfg.Rule)-1].Schema == "FINAL" {
		final.ID = cfg.Rule[len(cfg.Rule)-1].ID
		cfg.Rule = cfg.Rule[:len(cfg.Rule)-1]
	}
	cfg.Policy = kone.PolicyConfig{Mode: request.Mode, IPv4Only: request.IPv4Only, UDPException: request.UDPException, LANDefaults: cfg.Policy.LANDefaults}
	if request.Mode == "proxy-first" {
		final.Outbound = request.Outbound
		cfg.Core.AutoRoute = true
		cfg.Core.OutboundInterface = request.Interface
		if cfg.Core.IPv6Network == "" && !request.IPv4Only {
			cfg.Core.IPv6Network = kone.DefaultIPv6Network()
		}

		cfg.Core.AutoRoute6 = cfg.Core.IPv6Network != "" && !request.IPv4Only
		initializeLANRules(cfg)
		for i := range cfg.Outbounds {
			if cfg.Outbounds[i].Name == request.Outbound {
				u, _ := url.Parse(cfg.Outbounds[i].URL)
				cfg.Policy.UDPException = request.UDPException && u != nil && (u.Scheme == "http" || u.Scheme == "https") && cfg.Outbounds[i].UDPFallback == kone.BuiltinDirect
			}
			if cfg.Outbounds[i].Name == request.Outbound && request.RejectUDP {
				cfg.Outbounds[i].UDPFallback = kone.BuiltinReject
				cfg.Policy.UDPException = false
			}
		}
	} else {
		cfg.Core.AutoRoute, cfg.Core.AutoRoute6 = false, false
		cfg.Policy.IPv4Only, cfg.Policy.UDPException = false, false
	}
	cfg.Rule = append(cfg.Rule, final)
	if err := cfg.Validate(); err != nil {
		return SaveRequest{}, err
	}
	credentials := map[string]CredentialAction{}
	for _, outbound := range cfg.Outbounds {
		credentials[outbound.Name] = CredentialAction{Action: "preserve"}
	}
	return SaveRequest{BaseVersion: request.BaseVersion, Config: jsonConfig(cfg), Inbound: current.Inbound, CredentialActions: credentials}, nil
}

func (c *Controller) policyRoute(w http.ResponseWriter, r *http.Request, apply bool) {
	var request policyRequest
	if err := readJSON(w, r, &request); err != nil {
		apiError(w, 400, "policy_invalid", err.Error())
		return
	}
	c.mu.Lock()
	current := cloneDocument(c.doc)
	c.mu.Unlock()
	save, err := preparePolicy(request, current)
	if err != nil {
		status, code := http.StatusBadRequest, "policy_invalid"
		if errors.Is(err, ErrConflict) {
			status, code = http.StatusConflict, "version_conflict"
		}
		apiError(w, status, code, err.Error())
		return
	}
	if apply {
		result, err := c.Save(save)
		if err != nil {
			status, code := http.StatusBadRequest, "policy_invalid"
			if errors.Is(err, ErrConflict) {
				status, code = http.StatusConflict, "version_conflict"
			}
			if errors.Is(err, ErrCaptureLocked) {
				status, code = http.StatusConflict, "capture_locked"
			}
			apiError(w, status, code, safeMessage(err, current.Config))
			return
		}
		writeJSON(w, 200, result)
		return
	}
	validation, err := c.Validate(save)
	if err != nil {
		apiError(w, 400, "policy_invalid", safeMessage(err, current.Config))
		return
	}
	udp := "supported"
	for _, item := range current.Config.Outbounds {
		if item.Name == request.Outbound {
			u, _ := url.Parse(item.URL)
			if u != nil && (u.Scheme == "http" || u.Scheme == "https") {
				udp = "rejected"
				if request.UDPException && !request.RejectUDP && item.UDPFallback == kone.BuiltinDirect {
					udp = "direct_exception"
				}
			}
		}
	}
	validation["config"], validation["base_version"] = save.Config, save.BaseVersion
	validation["mode"], validation["udp"] = request.Mode, udp
	candidate, err := prepareDocument(save, current)
	if err != nil {
		apiError(w, 400, "policy_invalid", safeMessage(err, current.Config))
		return
	}
	validation["protection"] = policyProtection(candidate.Config)
	preserved := len(current.Config.Rule)
	if preserved > 0 && current.Config.Rule[preserved-1].Schema == "FINAL" {
		preserved--
	}
	validation["preserved_rules"] = preserved
	validation["added_rules"] = len(candidate.Config.Rule) - preserved - 1
	writeJSON(w, 200, validation)
}

func initializeLANRules(cfg *kone.KoneConfig) bool {
	if cfg.Policy.Mode != "proxy-first" || cfg.Policy.LANDefaults {
		return false
	}
	cfg.Policy.LANDefaults = true
	for _, rule := range kone.DefaultLANRules(cfg.Core) {
		if rule.Schema == "IP-CIDR6" && cfg.Core.IPv6Network == "" {
			continue
		}
		if slices.ContainsFunc(cfg.Rule, func(existing kone.RuleConfig) bool {
			return existing.Schema == rule.Schema && existing.Pattern == rule.Pattern && existing.Outbound == rule.Outbound && existing.Protocol == "" && len(existing.Ports) == 0 && existing.ExpiresAt == ""
		}) {
			continue
		}
		if slices.ContainsFunc(cfg.Rule, func(existing kone.RuleConfig) bool { return existing.ID == rule.ID }) {
			rule.ID = randomID("rule-lan")
		}
		cfg.Rule = append(cfg.Rule, rule)
	}
	return true
}
