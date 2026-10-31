package kone

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func expireRealResolution(t *testing.T, one *One, table *DnsTable, host string) {
	t.Helper()
	table.recordsLock.Lock()
	table.records[host].resolvedExpires = time.Time{}
	table.recordsLock.Unlock()
	one.ClearDNSCache()
	require.False(t, table.Get(host).resolutionFresh(time.Now()), "touching a Fake-IP must not renew the real DNS TTL")
}

func TestDNSRealResolutionExpiryReevaluatesPolicyAndKeepsMappings(t *testing.T) {
	for _, kind := range []string{"A", "AAAA", "CNAME"} {
		for _, trigger := range []string{"DNS", "new flow"} {
			t.Run(kind+"/"+trigger, func(t *testing.T) {
				var phase atomic.Int32
				var queries atomic.Int32
				oldIP, newIP := "203.0.113.9", "192.0.2.9"
				questionType := uint16(dns.TypeA)
				if kind == "AAAA" {
					oldIP, newIP, questionType = "2001:db8:1::9", "2001:db8:2::9", dns.TypeAAAA
				}
				handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
					queries.Add(1)
					message := new(dns.Msg)
					message.SetReply(request)
					address, target := oldIP, "old.cdn.example."
					if phase.Load() > 0 {
						address, target = newIP, "new.cdn.example."
					}
					name := request.Question[0].Name
					if kind == "CNAME" {
						message.Answer = append(message.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: target})
						name = target
					}
					header := dns.RR_Header{Name: name, Rrtype: questionType, Class: dns.ClassINET, Ttl: 60}
					if questionType == dns.TypeAAAA {
						message.Answer = append(message.Answer, &dns.AAAA{Hdr: header, AAAA: net.ParseIP(address)})
					} else {
						message.Answer = append(message.Answer, &dns.A{Hdr: header, A: net.ParseIP(address)})
					}
					w.WriteMsg(message)
				})
				upstream := startDNSListeners(t, handler, handler)
				one := dnsEngine(t, upstream)
				cfg := one.Snapshot().Config
				cfg.Outbounds = []OutboundConfig{{Name: "office", URL: "http://127.0.0.1:1"}}
				match := RuleConfig{Schema: "IP-CIDR", Pattern: "203.0.113.0/24", Outbound: "office"}
				if kind == "AAAA" {
					cfg.Core.IPv6Network = "fd7a:203::1/120"
					one.initIPv6(cfg.Core)
					match.Schema, match.Pattern = "IP-CIDR6", "2001:db8:1::/64"
				} else if kind == "CNAME" {
					match.Schema, match.Pattern = "DOMAIN", "old.cdn.example"
				}
				cfg.Rule = []RuleConfig{match, {Schema: "FINAL", Outbound: BuiltinDirect}}
				snapshot := *one.policy.Load()
				snapshot.cfg, snapshot.rule = cfg, NewRule(cfg.Rule, cfg.Outbounds)
				outbounds, err := NewOutbounds(cfg.Outbounds)
				require.NoError(t, err)
				snapshot.outbounds = outbounds
				one.policy.Store(&snapshot)
				request := new(dns.Msg)
				request.SetQuestion("rotating.example.", questionType)
				first, err := one.dns.HandleQuery(context.Background(), request, "udp", "client")
				require.NoError(t, err)
				fake := net.ParseIP(dnsAddresses(first)[0])
				table := one.tableForAddress(M.SocksaddrFromNet(&net.TCPAddr{IP: fake}).Addr)
				require.True(t, table.IsLocalIP(fake))
				oldRecord := table.Get("rotating.example")
				require.Equal(t, oldIP, oldRecord.RealIP.String())
				destination := M.SocksaddrFromNet(&net.TCPAddr{IP: fake, Port: 443})
				oldFlow, err := one.flows.resolveDestination(context.Background(), &snapshot, destination, false, nil)
				require.NoError(t, err)
				defer oldFlow.release()
				require.Equal(t, "office", oldFlow.outbound)
				phase.Store(1)
				expireRealResolution(t, one, table, "rotating.example")
				if trigger == "DNS" {
					response, err := one.dns.HandleQuery(context.Background(), request, "tcp", "client")
					require.NoError(t, err)
					require.Equal(t, []string{newIP}, dnsAddresses(response))
				} else {
					newFlow, err := one.flows.resolveDestination(context.Background(), &snapshot, destination, false, nil)
					require.NoError(t, err)
					defer newFlow.release()
					require.Equal(t, BuiltinDirect, newFlow.outbound)
					require.Equal(t, net.JoinHostPort(newIP, "443"), newFlow.address)
				}
				updated := table.GetByIP(fake)
				require.Equal(t, "rotating.example", updated.Hostname)
				require.Equal(t, fake.String(), updated.IP.String())
				require.Equal(t, newIP, updated.RealIP.String())
				require.Equal(t, oldIP, oldRecord.RealIP.String(), "old record snapshots retain their own real DNS answer")
				require.Equal(t, "office", oldFlow.outbound, "an established flow retains its chosen route")
				require.Equal(t, "rotating.example:443", oldFlow.address)
				require.Equal(t, int32(2), queries.Load())
			})
		}
	}
}

func TestDirectFlowRealAddressExpiresWithoutChangingExistingTarget(t *testing.T) {
	var fail atomic.Bool
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		if fail.Load() {
			message := new(dns.Msg)
			message.SetRcode(request, dns.RcodeServerFailure)
			w.WriteMsg(message)
			return
		}
		replyA(w, request, "192.0.2.20")
	})
	upstream := startDNSListeners(t, handler, handler)
	one := dnsEngine(t, upstream)
	record := one.dnsTable.Set("direct.example", BuiltinDirect)
	one.dnsTable.SetRealIP(record.Hostname, &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Ttl: 60}, A: net.ParseIP("192.0.2.10")}}})
	destination := M.SocksaddrFromNet(&net.TCPAddr{IP: record.IP, Port: 443})
	old, err := one.flows.resolveDestination(context.Background(), one.policy.Load(), destination, false, nil)
	require.NoError(t, err)
	defer old.release()
	require.Equal(t, "192.0.2.10:443", old.address)
	expireRealResolution(t, one, one.dnsTable, record.Hostname)
	current, err := one.flows.resolveDestination(context.Background(), one.policy.Load(), destination, false, nil)
	require.NoError(t, err)
	defer current.release()
	require.Equal(t, "192.0.2.20:443", current.address)
	require.Equal(t, "192.0.2.10:443", old.address)
	refresh := one.dnsTable.Get(record.Hostname)
	require.True(t, refresh.resolutionFresh(time.Now()))
	negative := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	refresh.SetRealIP(negative)
	require.Nil(t, refresh.RealIP, "a negative replacement must never preserve an old real address")
	fail.Store(true)
	expireRealResolution(t, one, one.dnsTable, record.Hostname)
	failed, err := one.flows.resolveDestination(context.Background(), one.policy.Load(), destination, false, nil)
	if failed.release != nil {
		defer failed.release()
	}
	require.Error(t, err)
	require.False(t, strings.Contains(failed.address, "192.0.2.20"), "failed refresh must not reuse expired destination data")
	require.Equal(t, record.IP.String(), one.dnsTable.Get(record.Hostname).IP.String())
}
