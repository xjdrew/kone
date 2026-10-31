package kone

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"

	singtun "github.com/sagernet/sing-tun"
)

// SupportedStacks reports compile-time capabilities without opening a device.
func SupportedStacks() []string {
	if singtun.WithGVisor {
		return []string{"system", "mixed"}
	}
	return []string{"system"}
}

// DialDiagnostic uses exactly the engine's outbound binding and DNS policy.
// It creates no TUN, route or adapter changes and never replays an application request.
func (one *One) DialDiagnostic(ctx context.Context, outbound, target string) (net.Conn, error) {
	return one.dialDiagnosticSnapshot(ctx, one.policy.Load(), outbound, target)
}

func (one *One) dialDiagnosticSnapshot(ctx context.Context, s *runtimeSnapshot, outbound, target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, diagnosticError("configuration", errors.New("target must be host:port"))
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, diagnosticError("configuration", errors.New("invalid target port"))
	}
	if s == nil {
		return nil, diagnosticError("configuration", errors.New("engine policy is not initialized"))
	}
	if s.rule.OutboundType(outbound) == OutboundDirect {
		if _, err := netip.ParseAddr(host); err != nil {
			response, err := one.dns.ResolveContext(ctx, host)
			if err != nil {
				return nil, diagnosticError("dns", err)
			}
			record := &DomainRecord{}
			record.SetRealIP(response)
			if record.RealIP == nil {
				return nil, diagnosticError("dns", errors.New("domain has no IPv4 address"))
			}
			target = net.JoinHostPort(record.RealIP.String(), port)
		}
	}
	conn, err := s.outbounds.DialContext(ctx, outbound, target)
	if err != nil {
		stage := "connect"
		if s.rule.OutboundType(outbound) == OutboundReject || errors.Is(err, ErrRejected) {
			stage = "policy"
		}
		return nil, diagnosticError(stage, err)
	}
	return conn, nil
}

type PreflightIssue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}
type PreflightReport struct {
	Ready   bool             `json:"ready"`
	Issues  []PreflightIssue `json:"issues"`
	Changes []string         `json:"changes"`
}

// Preflight is read-only: it never reserves ports or creates drivers/routes.
func Preflight(ctx context.Context, cfg *KoneConfig) PreflightReport {
	r := PreflightReport{Ready: true, Issues: []PreflightIssue{}, Changes: []string{}}
	add := func(code, message string) {
		r.Ready = false
		r.Issues = append(r.Issues, PreflightIssue{code, "error", message})
	}
	if err := ctx.Err(); err != nil {
		add("canceled", err.Error())
		return r
	}
	if err := cfg.Validate(); err != nil {
		add("configuration", err.Error())
		return r
	}
	if err := validateIPv6Platform(cfg.Core); err != nil {
		add("ipv6_platform", err.Error())
		return r
	}
	if err := checkNetworkPrivileges(); err != nil {
		add("privileges", err.Error())
	}
	if cfg.Core.Tun != "" {
		if _, err := net.InterfaceByName(cfg.Core.Tun); err == nil {
			add("device_exists", "The selected TUN name is already in use")
		}
	}
	if cfg.Core.OutboundInterface != "" {
		if _, err := net.InterfaceByName(cfg.Core.OutboundInterface); err != nil {
			add("outbound_interface", "The physical outbound interface is unavailable")
		}
	}
	prefix, _ := netip.ParsePrefix(cfg.Core.Network)
	prefix6, _ := netip.ParsePrefix(cfg.Core.IPv6Network)
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		add("interfaces", "Cannot inspect local interface addresses")
	} else {
		for _, value := range addresses {
			p, e := netip.ParsePrefix(value.String())
			if e == nil && p.Addr().Is4() && (p.Contains(prefix.Addr()) || prefix.Contains(p.Addr())) {
				add("network_overlap", "The TUN network overlaps an existing interface")
				break
			}
			if e == nil && prefix6.IsValid() && p.Addr().Is6() && (p.Contains(prefix6.Addr()) || prefix6.Contains(p.Addr())) {
				add("ipv6_network_overlap", "The IPv6 TUN network overlaps an existing interface")
				break
			}
		}
	}
	r.Changes = append(r.Changes, "Create an owned TUN device and DNS listeners for "+cfg.Core.Network)
	if cfg.Core.AutoRoute {
		r.Changes = append(r.Changes, "Capture IPv4 through two /1 routes; retain existing more-specific and default routes")
	}
	if cfg.Core.IPv6Network != "" {
		r.Changes = append(r.Changes, "Create owned IPv6 addresses and UDP/TCP DNS listeners for "+cfg.Core.IPv6Network)
		if cfg.Core.AutoRoute6 {
			r.Changes = append(r.Changes, "Capture IPv6 through two /1 routes while retaining more-specific and default routes")
		}
		r.Issues = append(r.Issues, PreflightIssue{"dns_scope", "info", "DNS covers clients configured to use KONE; encrypted DNS can bypass domain interception"})
	} else {
		r.Issues = append(r.Issues, PreflightIssue{"dns_scope", "info", "DNS covers clients configured to use KONE; encrypted DNS and IPv6 traffic can bypass capture"})
	}
	return r
}
