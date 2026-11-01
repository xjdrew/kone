package kone

import (
	"context"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func serviceBindingBaseName(name string, kind uint16) string {
	name = normalizeDomain(name)
	labels := strings.SplitN(name, ".", 3)
	if len(labels) != 3 || !strings.HasPrefix(labels[0], "_") || len(labels[0]) < 2 || !strings.HasPrefix(labels[1], "_") || len(labels[1]) < 2 {
		return name
	}
	if kind == dns.TypeHTTPS {
		port, err := strconv.ParseUint(labels[0][1:], 10, 16)
		if labels[1] != "_https" || err != nil || port == 0 {
			return name
		}
	}
	return labels[2]
}

// Service-binding hints and alternative endpoints can bypass both Fake-IP
// families before A/AAAA answers arrive. Keep selected domains on their normal
// A/AAAA policy path; direct and protected endpoints retain the original RRset.
func (d *Dns) queryServiceBinding(ctx context.Context, s *runtimeSnapshot, request *dns.Msg) (*dns.Msg, error) {
	owner := normalizeDomain(request.Question[0].Name)
	base := serviceBindingBaseName(owner, request.Question[0].Qtype)
	policy := func(response *dns.Msg) string {
		if owner == base {
			return s.rule.ProxyDNS(owner, response)
		}
		// Treat the normalized service name as domain evidence while retaining
		// explicit owner rules, protected endpoints and the original rule order.
		evidence := new(dns.Msg)
		if response != nil {
			evidence.Answer = append(evidence.Answer, response.Answer...)
		}
		evidence.Answer = append(evidence.Answer, &dns.CNAME{Target: dns.Fqdn(base)})
		return s.rule.ProxyDNS(owner, evidence)
	}
	if reply := clientDNSPolicyReply(ctx, s, request, policy(nil), "binding-policy"); reply != nil {
		return reply, nil
	}
	reply, err := d.resolve(ctx, request)
	if err != nil || len(reply.Answer) == 0 {
		return reply, err
	}
	if guarded := clientDNSPolicyReply(ctx, s, request, policy(reply), "binding-policy"); guarded != nil {
		return guarded, nil
	}
	return reply, nil
}
