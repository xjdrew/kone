package kone

import (
	"context"

	"github.com/miekg/dns"
)

// Keep a domain's selected policy effective when IPv6 interception is off.
// A real AAAA answer would let clients bypass its IPv4 Fake-IP through IPv6.
// NODATA leaves the A query available without changing host IPv6 or routes.
func (d *Dns) queryWithoutIPv6(ctx context.Context, s *runtimeSnapshot, request *dns.Msg) (*dns.Msg, error) {
	domain := normalizeDomain(request.Question[0].Name)
	if reply := clientDNSPolicyReply(ctx, s, request, s.rule.Proxy(domain), "ipv6-policy"); reply != nil {
		return reply, nil
	}
	reply, err := d.resolve(ctx, request)
	if err != nil || len(reply.Answer) == 0 {
		return reply, err
	}
	// CNAME/address evidence can select an earlier rule than the domain alone.
	// Use the same ordered decision as A/AAAA capture and the flow handler.
	if guarded := clientDNSPolicyReply(ctx, s, request, s.rule.ProxyDNS(domain, reply), "ipv6-policy"); guarded != nil {
		return guarded, nil
	}
	return reply, nil
}

func clientDNSPolicyReply(ctx context.Context, s *runtimeSnapshot, request *dns.Msg, policy, cache string) *dns.Msg {
	kind := s.rule.OutboundType(policy)
	if kind == OutboundDirect {
		return nil
	}
	reply := new(dns.Msg)
	reply.SetReply(request)
	reply.RecursionAvailable = true
	if kind == OutboundReject {
		reply.Rcode = dns.RcodeRefused
	}
	if meta, _ := ctx.Value(dnsMetaKey{}).(*dnsQueryMeta); meta != nil {
		meta.Cache = cache
	}
	return reply
}
