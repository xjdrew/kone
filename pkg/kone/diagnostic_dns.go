package kone

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
)

func dnsDiagnosticResult(source string, options DiagnosticOptions) DiagnosticResult {
	now := time.Now()
	return DiagnosticResult{Target: options.DNSName, Outbound: source, Protocol: "dns", DNSName: options.DNSName, DNSType: options.DNSType, Stage: "dns", Status: "failed", Time: now, Expires: now.Add(5 * time.Minute)}
}

// ProbeSystemDNS uses the host's current resolution path, including OS caches
// and hosts entries. It deliberately does not substitute KONE's pinned upstreams.
// If the OS is already guided to KONE, these two paths may have the same answer.
func ProbeSystemDNS(ctx context.Context, options DiagnosticOptions) (DiagnosticResult, error) {
	return probeSystemDNS(ctx, options, net.DefaultResolver.LookupIP)
}

func probeSystemDNS(ctx context.Context, options DiagnosticOptions, lookup func(context.Context, string, string) ([]net.IP, error)) (result DiagnosticResult, err error) {
	options, err = options.Normalize()
	if err != nil || options.Protocol != "dns" {
		return result, errors.New("system DNS comparison requires a valid DNS query")
	}
	result = dnsDiagnosticResult("system", options)
	result.Scope, result.DNSPath = "system", "system"
	defer func() { result.DurationMS = time.Since(result.Time).Milliseconds() }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	network := "ip4"
	if options.DNSType == "AAAA" {
		network = "ip6"
	}
	addresses, lookupErr := lookup(ctx, network, options.DNSName)
	if lookupErr != nil {
		result.Message = safeTrafficError(lookupErr)
		var dnsErr *net.DNSError
		if errors.As(lookupErr, &dnsErr) && dnsErr.IsNotFound {
			// LookupIP does not expose a DNS response code or TTL. Do not invent one.
			result.Status = "no_records"
		}
		return result, nil
	}
	for _, address := range addresses {
		result.DNSAnswers = append(result.DNSAnswers, address.String())
	}
	result.Status = "answered"
	if len(addresses) == 0 {
		result.Status = "no_records"
	}
	return result, nil
}

func (one *One) probeDNSQuery(ctx context.Context, source string, options DiagnosticOptions, version uint64) (result DiagnosticResult, err error) {
	if source == "system" {
		return ProbeSystemDNS(ctx, options)
	}
	result = dnsDiagnosticResult(source, options)
	defer func() { result.DurationMS = time.Since(result.Time).Milliseconds() }()
	if source != "kone" {
		return result, errors.New("DNS comparison source must be system or kone")
	}
	snapshot := one.policy.Load()
	if snapshot == nil || version != 0 && snapshot.configurationVersion() != version {
		result.Status, result.Stage = "not_applied", "configuration"
		return result, nil
	}
	one.mu.Lock()
	closed, started, runContext := one.closed, one.started, one.runContext
	one.mu.Unlock()
	if closed {
		return result, errors.New("engine is stopping or stopped")
	}
	result.ConfigVersion, result.DNSPath = snapshot.configurationVersion(), "kone"
	result.Scope = "saved_configuration"
	select {
	case <-one.ready:
		result.Scope = "running"
	default:
		if started {
			return result, errors.New("engine is not ready for diagnostics")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if runContext != nil {
		stop := context.AfterFunc(runContext, cancel)
		defer stop()
	}
	kind := uint16(dns.TypeA)
	if options.DNSType == "AAAA" {
		kind = dns.TypeAAAA
	}
	// Use the real client handler: routes, cache, domain policy and Fake-IP are
	// included. ResolveTypeContext alone would bypass client-facing policy.
	reply, queryErr := one.dns.HandleQuery(ctx, new(dns.Msg).SetQuestion(dns.Fqdn(options.DNSName), kind), "control", "diagnostic")
	if queryErr != nil {
		result.Message = diagnosticMessage(queryErr, snapshot.cfg)
		return result, nil
	}
	if one.policy.Load() != snapshot {
		result.Status, result.Stage = "stale", "configuration"
		return result, nil
	}
	result.DNSRCode, result.DNSTruncated = dns.RcodeToString[reply.Rcode], reply.Truncated
	for _, answer := range reply.Answer {
		result.DNSAnswers = append(result.DNSAnswers, answer.String())
	}
	for _, address := range dnsAddresses(reply) {
		ip := net.ParseIP(address)
		if one.dnsTable.Contains(ip) || one.dnsTable6 != nil && one.dnsTable6.Contains(ip) {
			result.DNSVirtualAddresses = append(result.DNSVirtualAddresses, address)
		}
	}
	if reply.Rcode == dns.RcodeSuccess {
		result.Status = "answered"
		if len(reply.Answer) == 0 {
			result.Status = "no_records"
		}
	} else if reply.Rcode == dns.RcodeNameError {
		result.Status = "no_records"
	}
	return result, nil
}
