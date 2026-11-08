package kone

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"net"
	"slices"
	"time"
)

func (d *Dns) queryLayered(ctx context.Context, s *runtimeSnapshot, request *dns.Msg) (*dns.Msg, error) {
	domain := normalizeDomain(request.Question[0].Name)
	table := d.one.dnsTable
	if request.Question[0].Qtype == dns.TypeAAAA {
		table = d.one.dnsTable6
	}
	decision := s.rule.DecideDNS(domain, nil, "", 0)
	var message *dns.Msg
	var err error
	if decision.Evidence == "dns_required" || decision.Protected {
		if table != nil {
			if record := table.Get(domain); record.resolutionFresh(time.Now()) {
				message = record.resolved.Copy()
				message.Id = request.Id
				message.Question = append([]dns.Question(nil), request.Question...)
				remaining := uint32(max(0, time.Until(record.resolvedExpires).Seconds()))
				for _, rr := range message.Answer {
					rr.Header().Ttl = min(rr.Header().Ttl, remaining)
				}
			}
		}
		if message == nil {
			message, err = d.resolve(ctx, request)
		}
		if err != nil || message == nil {
			return message, err
		}
		if message.Rcode != dns.RcodeSuccess || len(message.Answer) == 0 {
			return message, nil
		}
		decision = s.rule.DecideDNS(domain, message, "", 0)
	}
	if decision.Evidence == "dns_failed" {
		return nil, errors.New("required DNS routing evidence is unavailable")
	}
	if s.rule.OutboundType(decision.Outbound) == OutboundReject {
		return new(dns.Msg).SetRcode(request, dns.RcodeRefused), nil
	}
	// Keep explicit domain/IP decisions attached to an identity. In Global this
	// is essential even for direct exceptions: the real IP is captured again.
	capture := !decision.Protected && (d.one.health.dnsEvidence(domain, s) != nil || decision.CaptureOnly || s.rule.OutboundType(decision.Outbound) != OutboundDirect || decision.Pool == "domain" || decision.Pool == "ip" || s.cfg.Core.AutoRoute || s.cfg.Core.AutoRoute6)
	if meta, _ := ctx.Value(dnsMetaKey{}).(*dnsQueryMeta); meta != nil {
		meta.Routing = decision
		meta.Resolved = message
	}
	if !capture {
		if message == nil {
			return d.resolve(ctx, request)
		}
		// A system-protected candidate cannot authorize every address in a
		// mixed answer. Return only addresses selected by this decision.
		if decision.Protected && len(decision.Candidates) > 0 {
			message = message.Copy()
			message.Answer = slices.DeleteFunc(message.Answer, func(rr dns.RR) bool {
				var ip net.IP
				switch r := rr.(type) {
				case *dns.A:
					ip = r.A
				case *dns.AAAA:
					ip = r.AAAA
				default:
					return false
				}
				return !slices.Contains(decision.Candidates, ip.String())
			})
		}
		return message, nil
	}
	if table == nil {
		reply := new(dns.Msg).SetReply(request)
		reply.RecursionAvailable = true
		return reply, nil
	}
	record := table.Set(domain, decision.Outbound)
	if record == nil {
		return nil, errors.New("virtual IP ownership could not be allocated")
	}
	if message != nil {
		table.SetRealIP(domain, message)
	}
	if meta, _ := ctx.Value(dnsMetaKey{}).(*dnsQueryMeta); meta != nil {
		meta.Cache = "fake-ip"
		meta.Virtual = []string{record.IP.String()}
		meta.Real = dnsAddresses(message)
	}
	return record.Answer(request), nil
}
