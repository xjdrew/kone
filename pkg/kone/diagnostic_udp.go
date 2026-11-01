package kone

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DiagnosticOptions struct {
	Protocol      string `json:"protocol,omitempty"`
	TLS           bool   `json:"tls,omitempty"`
	UDPMode       string `json:"udp_mode,omitempty"`
	DNSName       string `json:"dns_name,omitempty"`
	DNSType       string `json:"dns_type,omitempty"`
	AddressFamily string `json:"address_family,omitempty"`
}

func (o DiagnosticOptions) Normalize() (DiagnosticOptions, error) {
	if o.Protocol == "" {
		o.Protocol = "tcp"
	}
	if o.Protocol == "tcp" {
		if o.UDPMode != "" || o.DNSName != "" || o.DNSType != "" || o.AddressFamily != "" {
			return o, errors.New("UDP diagnostic options require protocol udp")
		}
		return o, nil
	}
	if o.Protocol != "udp" || o.TLS {
		return o, errors.New("diagnostic protocol must be tcp or udp; TLS requires TCP")
	}
	if o.UDPMode == "" {
		o.UDPMode = "dns"
	}
	if o.UDPMode != "dns" {
		return o, errors.New("UDP diagnostics require a DNS server and DNS response validation")
	}
	if o.DNSName == "" {
		o.DNSName = "example.com"
	}
	o.DNSName = strings.ToLower(strings.TrimSuffix(o.DNSName, "."))
	if err := ValidateDiagnosticTarget(net.JoinHostPort(o.DNSName, "53")); err != nil {
		return o, errors.New("invalid diagnostic DNS query name")
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(o.DNSName)); !ok {
		return o, errors.New("invalid diagnostic DNS query name")
	}
	if o.DNSType == "" {
		o.DNSType = "A"
	}
	if o.DNSType != "A" && o.DNSType != "AAAA" {
		return o, errors.New("diagnostic DNS query type must be A or AAAA")
	}
	if o.AddressFamily == "" {
		o.AddressFamily = "auto"
	}
	if o.AddressFamily != "auto" && o.AddressFamily != "ipv4" && o.AddressFamily != "ipv6" {
		return o, errors.New("diagnostic address family must be auto, ipv4 or ipv6")
	}
	return o, nil
}

func (one *One) ProbeDiagnosticRequestVersion(ctx context.Context, outbound, target string, options DiagnosticOptions, version uint64) (DiagnosticResult, error) {
	options, err := options.Normalize()
	if err != nil {
		return DiagnosticResult{}, err
	}
	if options.Protocol == "tcp" {
		return one.ProbeDiagnosticVersion(ctx, outbound, target, options.TLS, version)
	}
	return one.probeUDPDiagnostic(ctx, outbound, target, options, version)
}

func (one *One) diagnosticUDPTarget(ctx context.Context, s *runtimeSnapshot, outbound, target string, o DiagnosticOptions) (string, error) {
	if err := s.outbounds.CheckEnabled(outbound); err != nil {
		return "", diagnosticError("policy", err)
	}
	if s.rule.OutboundType(outbound) == OutboundReject {
		return "", diagnosticError("policy", ErrRejected)
	}
	// This tests the requested proxy itself. Business-flow fallback is not
	// evidence that an HTTP proxy can transport UDP, even when explicitly set.
	if !s.outbounds.SupportsUDP(outbound) {
		return "", diagnosticError("capability", fmt.Errorf("outbound %q: %w; diagnostic fallback is disabled", outbound, ErrUDPUnsupported))
	}
	host, port, _ := net.SplitHostPort(target)
	check := func(address netip.Addr) error {
		if diagnosticVirtualAddress(s, address) {
			return diagnosticError("virtual_destination", errors.New("KONE virtual addresses cannot prove remote UDP reachability"))
		}
		if address.IsUnspecified() || address.IsMulticast() {
			return diagnosticError("configuration", errors.New("DNS server address cannot be unspecified or multicast"))
		}
		if o.AddressFamily == "ipv4" && !address.Unmap().Is4() || o.AddressFamily == "ipv6" && !address.Unmap().Is6() {
			return diagnosticError("configuration", errors.New("DNS server literal does not match the selected address family"))
		}
		return nil
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" && s.rule.OutboundType(outbound) != OutboundDirect {
			return "", diagnosticError("configuration", errors.New("proxy UDP destinations cannot carry an IPv6 interface zone"))
		}
		return target, check(address)
	}
	if s.rule.OutboundType(outbound) != OutboundDirect {
		if o.AddressFamily != "auto" {
			return "", diagnosticError("configuration", errors.New("use a server IP literal to select an address family with remote proxy DNS"))
		}
		return target, nil
	}
	kinds := []uint16{dns.TypeA, dns.TypeAAAA}
	if o.AddressFamily == "ipv4" {
		kinds = kinds[:1]
	}
	if o.AddressFamily == "ipv6" {
		kinds = kinds[1:]
	}
	var failures []error
	for _, kind := range kinds {
		response, err := one.dns.ResolveTypeContext(ctx, host, kind)
		if err != nil {
			failures = append(failures, err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		for _, answer := range response.Answer {
			var ip net.IP
			if a, ok := answer.(*dns.A); ok && kind == dns.TypeA {
				ip = a.A
			}
			if a, ok := answer.(*dns.AAAA); ok && kind == dns.TypeAAAA {
				ip = a.AAAA
			}
			address, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			address = address.Unmap()
			if err := check(address); err != nil {
				return "", err
			}
			return net.JoinHostPort(address.String(), port), nil
		}
	}
	return "", diagnosticError("dns", errors.Join(append([]error{errors.New("DNS server hostname has no usable address in the selected family")}, failures...)...))
}

func (one *One) probeUDPDiagnostic(parent context.Context, outbound, target string, o DiagnosticOptions, expectedVersion uint64) (result DiagnosticResult, err error) {
	start := time.Now()
	result = DiagnosticResult{Target: target, Outbound: outbound, Protocol: "udp", Stage: "configuration", Status: "failed", Time: start, Expires: start.Add(5 * time.Minute), Scope: "explicit UDP/DNS response test; not QUIC or application traffic", DNSName: o.DNSName, DNSType: o.DNSType, DNSPath: "not_attempted"}
	defer func() { result.DurationMS = time.Since(start).Milliseconds() }()
	if err := ValidateDiagnosticTarget(target); err != nil {
		result.Message = err.Error()
		return result, nil
	}
	snapshot := one.policy.Load()
	if snapshot == nil {
		return result, errors.New("engine policy is unavailable")
	}
	result.ConfigVersion = snapshot.configurationVersion()
	if expectedVersion != 0 && expectedVersion != result.ConfigVersion {
		result.Status = "not_applied"
		result.Message = "The saved configuration has not been applied to this running engine"
		return result, nil
	}
	one.mu.Lock()
	closed, started, runContext := one.closed, one.started, one.runContext
	one.mu.Unlock()
	if closed {
		return result, errors.New("engine is stopping or stopped")
	}
	if started {
		select {
		case <-one.ready:
		default:
			return result, errors.New("engine is not ready for diagnostics")
		}
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if runContext != nil {
		if runContext.Err() != nil {
			cancel()
		}
		stop := context.AfterFunc(runContext, cancel)
		defer stop()
	}
	fail := func(stage string, cause error) (DiagnosticResult, error) {
		if actual := DiagnosticStage(cause); actual != "" {
			stage = actual
		}
		result.Stage = stage
		result.Message = diagnosticMessage(cause, snapshot.cfg)
		var networkError net.Error
		if errors.Is(ctx.Err(), context.Canceled) {
			result.Status = "canceled"
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(cause, &networkError) && networkError.Timeout() {
			result.Status = "unknown"
		} else if stage == "capability" || stage == "virtual_destination" {
			result.Status = "unsupported"
		}
		return result, nil
	}
	address, err := one.diagnosticUDPTarget(ctx, snapshot, outbound, target, o)
	if err != nil {
		return fail("configuration", err)
	}
	host, _, _ := net.SplitHostPort(target)
	if _, err := netip.ParseAddr(host); err == nil {
		result.DNSPath = "literal_ip"
	} else if snapshot.rule.OutboundType(outbound) == OutboundDirect {
		result.DNSPath = "engine_dns_snapshot"
	} else {
		result.DNSPath = "proxy_remote_resolution"
	}
	stage := "connect"
	if snapshot.rule.OutboundType(outbound) == OutboundProxy {
		stage = "proxy_association"
		result.PeerKind = "proxy_endpoint"
	}
	conn, err := snapshot.outbounds.DialUDPContext(ctx, outbound, address)
	if err != nil {
		return fail(stage, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return fail("udp_write", err)
	}
	query := new(dns.Msg)
	kind := uint16(dns.TypeA)
	if o.DNSType == "AAAA" {
		kind = dns.TypeAAAA
	}
	query.SetQuestion(dns.Fqdn(o.DNSName), kind)
	query.SetEdns0(1232, false)
	payload, err := query.Pack()
	if err != nil {
		return fail("configuration", err)
	}
	n, err := conn.Write(payload)
	if err == nil && n != len(payload) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fail("udp_write", err)
	}
	buffer := make([]byte, 4096)
	for range 4 {
		n, err := conn.Read(buffer)
		if err != nil {
			return fail("udp_response", err)
		}
		response := new(dns.Msg)
		if response.Unpack(buffer[:n]) != nil || !response.Response || response.Opcode != dns.OpcodeQuery || response.Id != query.Id || len(response.Question) != 1 || response.Question[0].Qtype != kind || response.Question[0].Qclass != dns.ClassINET || !strings.EqualFold(response.Question[0].Name, query.Question[0].Name) {
			continue
		}
		result.Stage, result.Status, result.PeerKind = "udp_response", "reachable", "validated_dns_response"
		if snapshot.rule.OutboundType(outbound) == OutboundDirect && conn.RemoteAddr() != nil {
			result.RemoteAddress = conn.RemoteAddr().String()
		}
		result.DNSRCode = dns.RcodeToString[response.Rcode]
		if result.DNSRCode == "" {
			result.DNSRCode = fmt.Sprintf("RCODE_%d", response.Rcode)
		}
		result.DNSTruncated = response.Truncated
		result.Message = "A matching UDP/DNS response was received; DNS rcode/truncation is separate from application success; no TCP retry was performed"
		return result, nil
	}
	return fail("udp_response", errors.New("received four invalid or mismatched UDP/DNS responses; target reachability is unverified"))
}
