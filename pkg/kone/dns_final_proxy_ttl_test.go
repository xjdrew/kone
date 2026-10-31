package kone

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestFinalProxyRefreshesExpiredAddressAndCNAMEDecisions(t *testing.T) {
	for _, kind := range []string{"A", "AAAA", "CNAME"} {
		for _, oldPolicy := range []string{BuiltinDirect, "office"} {
			for _, nextPolicy := range []string{"next", BuiltinReject} {
				for _, trigger := range []string{"DNS", "TCP", "UDP"} {
					t.Run(fmt.Sprintf("%s/%s-to-%s/%s", kind, oldPolicy, nextPolicy, trigger), func(t *testing.T) {
						oldIP, newIP, questionType := "203.0.113.9", "198.51.100.9", uint16(dns.TypeA)
						oldMatch := RuleConfig{Schema: "IP-CIDR", Pattern: "203.0.113.0/24", Outbound: oldPolicy}
						newMatch := RuleConfig{Schema: "IP-CIDR", Pattern: "198.51.100.0/24", Outbound: nextPolicy}
						if kind == "AAAA" {
							oldIP, newIP, questionType = "2001:db8:1::9", "2001:db8:2::9", dns.TypeAAAA
							oldMatch.Schema, oldMatch.Pattern = "IP-CIDR6", "2001:db8:1::/64"
							newMatch.Schema, newMatch.Pattern = "IP-CIDR6", "2001:db8:2::/64"
						} else if kind == "CNAME" {
							oldMatch.Schema, oldMatch.Pattern = "DOMAIN", "old.cdn.example"
							newMatch.Schema, newMatch.Pattern = "DOMAIN", "new.cdn.example"
						}
						answer := func(request *dns.Msg, changed bool) *dns.Msg {
							message := new(dns.Msg)
							message.SetReply(request)
							address, name := oldIP, request.Question[0].Name
							if changed {
								address = newIP
							}
							if kind == "CNAME" {
								target := "old.cdn.example."
								if changed {
									target = "new.cdn.example."
								}
								message.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: target}}
								name = target
							}
							header := dns.RR_Header{Name: name, Rrtype: questionType, Class: dns.ClassINET, Ttl: 60}
							if questionType == dns.TypeAAAA {
								message.Answer = append(message.Answer, &dns.AAAA{Hdr: header, AAAA: net.ParseIP(address)})
							} else {
								message.Answer = append(message.Answer, &dns.A{Hdr: header, A: net.ParseIP(address)})
							}
							return message
						}
						var queries atomic.Int32
						handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) { queries.Add(1); w.WriteMsg(answer(request, true)) })
						upstream := startDNSListeners(t, handler, handler)
						one := dnsEngine(t, upstream)
						cfg := one.Snapshot().Config
						cfg.Outbounds = []OutboundConfig{{Name: "office", URL: "socks5://127.0.0.1:1"}, {Name: "next", URL: "socks5://127.0.0.1:2"}}
						if questionType == dns.TypeAAAA {
							cfg.Core.IPv6Network = "fd7a:203::1/120"
							one.initIPv6(cfg.Core)
						}
						cfg.Rule = []RuleConfig{oldMatch, newMatch, {Schema: "FINAL", Outbound: "office"}}
						snapshot := *one.policy.Load()
						snapshot.cfg, snapshot.rule = cfg, NewRule(cfg.Rule, cfg.Outbounds)
						var err error
						snapshot.outbounds, err = NewOutbounds(cfg.Outbounds)
						require.NoError(t, err)
						one.policy.Store(&snapshot)
						table := one.dnsTable
						if questionType == dns.TypeAAAA {
							table = one.dnsTable6
						}
						request := new(dns.Msg)
						request.SetQuestion("rotating.example.", questionType)
						record := table.Set("rotating.example", "office")
						// An earlier explicit direct/UDP fallback may have populated
						// real DNS evidence even though the domain-only default proxies.
						table.SetRealIP(record.Hostname, answer(request, false))
						destination := M.SocksaddrFromNet(&net.TCPAddr{IP: record.IP, Port: 443})
						old, err := one.flows.resolveDestination(context.Background(), &snapshot, destination, trigger == "UDP", nil)
						require.NoError(t, err)
						defer old.release()
						require.Equal(t, oldPolicy, old.outbound)
						oldAddress := old.address
						expireRealResolution(t, one, table, record.Hostname)
						if trigger == "DNS" {
							response, err := one.dns.HandleQuery(context.Background(), request, "udp", "client")
							require.NoError(t, err)
							if nextPolicy == BuiltinReject {
								require.Equal(t, dns.RcodeRefused, response.Rcode)
							} else {
								require.Equal(t, []string{record.IP.String()}, dnsAddresses(response))
							}
						} else {
							current, err := one.flows.resolveDestination(context.Background(), &snapshot, destination, trigger == "UDP", nil)
							if current.release != nil {
								defer current.release()
							}
							if nextPolicy == BuiltinReject {
								require.ErrorIs(t, err, ErrRejected)
							} else {
								require.NoError(t, err)
								require.Equal(t, "rotating.example:443", current.address)
							}
							require.Equal(t, nextPolicy, current.outbound)
						}
						require.Equal(t, int32(1), queries.Load())
						updated := table.GetByIP(record.IP)
						require.Equal(t, newIP, updated.RealIP.String())
						require.Equal(t, record.Hostname, updated.Hostname)
						require.Equal(t, oldAddress, old.address, "already established flow keeps its chosen target")
						require.Equal(t, oldPolicy, old.outbound)
					})
				}
			}
		}
	}
}

func TestExpiredRealEvidenceCannotBypassDomainRefusal(t *testing.T) {
	var queries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) { queries.Add(1); replyA(w, request, "192.0.2.9") })
	upstream := startDNSListeners(t, handler, handler)
	one := dnsEngine(t, upstream)
	record := one.dnsTable.Set("blocked.example", BuiltinDirect)
	one.dnsTable.SetRealIP(record.Hostname, &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Ttl: 60}, A: net.ParseIP("192.0.2.9")}}})
	snapshot := *one.policy.Load()
	snapshot.rule = NewRule([]RuleConfig{{Schema: "DOMAIN", Pattern: record.Hostname, Outbound: BuiltinReject}}, nil)
	snapshot.rule.DirectDomain("192.0.2.9")
	one.policy.Store(&snapshot)
	expireRealResolution(t, one, one.dnsTable, record.Hostname)
	request := new(dns.Msg)
	request.SetQuestion(record.Hostname+".", dns.TypeA)
	response, err := one.dns.HandleQuery(context.Background(), request, "udp", "client")
	require.NoError(t, err)
	require.Equal(t, dns.RcodeRefused, response.Rcode)
	_, _, err = one.flows.destination(context.Background(), &snapshot, M.SocksaddrFromNet(&net.TCPAddr{IP: record.IP, Port: 443}), false)
	require.ErrorIs(t, err, ErrRejected)
	require.Zero(t, queries.Load(), "current domain refusal neither uses expired evidence nor speculatively resolves it")
	require.False(t, one.dnsTable.Get(record.Hostname).resolutionFresh(time.Now()))
}
