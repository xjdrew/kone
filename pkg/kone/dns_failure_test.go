package kone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/proxy"
)

type dnsCapturedReply struct {
	dns.ResponseWriter
	address net.Addr
	message *dns.Msg
}

func (w *dnsCapturedReply) RemoteAddr() net.Addr { return w.address }
func (w *dnsCapturedReply) WriteMsg(message *dns.Msg) error {
	w.message = message.Copy()
	return nil
}

func TestDNSUpstreamFailureStagesAndClientResponses(t *testing.T) {
	for _, failure := range []string{"truncated-tcp", "refused", "disconnected"} {
		t.Run(failure, func(t *testing.T) {
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
				if failure == "disconnected" {
					w.Close()
					return
				}
				response := new(dns.Msg)
				response.SetReply(request)
				if failure == "truncated-tcp" {
					response.Truncated = true
				} else {
					response.Rcode = dns.RcodeRefused
				}
				w.WriteMsg(response)
			})
			upstream := startDNSListeners(t, handler, handler)
			one := dnsEngine(t, upstream)
			if failure == "disconnected" {
				one.dns.forceTCP = true
			}
			request := new(dns.Msg)
			request.SetQuestion("failure.example.", dns.TypeTXT)
			writer := &dnsCapturedReply{address: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}}
			one.dns.ServeDNS(writer, request)
			require.Equal(t, dns.RcodeServerFailure, writer.message.Rcode)
			events := one.DNSQueries()
			require.Len(t, events, 1)
			require.Equal(t, "tcp", events[0].Transport)
			require.Equal(t, upstream, events[0].Upstream)
			require.Equal(t, "loopback", events[0].ResolverInterface)
			require.NotEmpty(t, events[0].Error)
			if failure == "truncated-tcp" {
				require.Contains(t, events[0].Error, "truncated DNS response after TCP retry")
				require.Equal(t, "tcp", events[0].UpstreamTransport)
			}
			require.Empty(t, one.dns.cache.entries, "failed responses must not be cached")
		})
	}
}

func TestDNSInputValidationEDNSBoundsAndUnavailablePool(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{strings.Repeat("a", 250), strings.Repeat("b", 250), strings.Repeat("c", 250)}}}
		w.WriteMsg(response)
	})
	upstream := startDNSListeners(t, handler, handler)
	one := dnsEngine(t, upstream)
	writer := &dnsCapturedReply{address: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}}
	one.dns.ServeDNS(writer, nil)
	require.Nil(t, writer.message)
	invalid := &dns.Msg{Question: []dns.Question{{Name: "one.example.", Qtype: dns.TypeA}, {Name: "two.example.", Qtype: dns.TypeA}}}
	one.dns.ServeDNS(writer, invalid)
	require.Equal(t, dns.RcodeFormatError, writer.message.Rcode)
	_, err := one.dns.HandleQuery(context.Background(), invalid, "udp", "client")
	require.ErrorContains(t, err, "exactly one question")
	request := new(dns.Msg)
	request.SetQuestion("large.example.", dns.TypeTXT)
	request.SetEdns0(128, false)
	one.dns.ServeDNS(writer, request)
	require.True(t, writer.message.Truncated)
	require.LessOrEqual(t, writer.message.Len(), 512, "small advertised EDNS buffer must remain bounded at the DNS minimum")
	request.Extra = nil
	request.Question[0].Qtype = 65400
	_, err = one.dns.HandleQuery(context.Background(), request, "udp", "client")
	require.NoError(t, err)
	require.Equal(t, "65400", one.DNSQueries()[0].Type)
	address, subnet, _ := net.ParseCIDR("192.0.2.1/30")
	one.dnsTable = NewDnsTable(address, subnet)
	one.dnsTable.Set("occupied.example", "office")
	snapshot := *one.policy.Load()
	snapshot.rule = NewRule([]RuleConfig{{Schema: "FINAL", Outbound: "office"}}, []OutboundConfig{{Name: "office", URL: "http://127.0.0.1:1"}})
	one.policy.Store(&snapshot)
	request.SetQuestion("pool-full.example.", dns.TypeA)
	_, err = one.dns.HandleQuery(context.Background(), request, "udp", "client")
	require.ErrorContains(t, err, "virtual IP pool exhausted")
	request.SetQuestion("unconfigured.example.", dns.TypeAAAA)
	_, err = one.dns.doIPv4Query(request)
	require.NoError(t, err, "an unconfigured address family passes through to real DNS")
	one.dns.nameservers = nil
	request.SetQuestion("no-upstream.example.", dns.TypeTXT)
	_, err = one.dns.resolve(context.Background(), request)
	require.ErrorIs(t, err, ErrResolve)
}

func TestProxyEndpointExclusiveScopeEmptyAndUnreachableAnswers(t *testing.T) {
	for _, empty := range []bool{true, false} {
		t.Run(fmt.Sprint("empty=", empty), func(t *testing.T) {
			var queries atomic.Int32
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
				queries.Add(1)
				if !empty && request.Question[0].Qtype == dns.TypeA {
					replyA(w, request, "127.0.0.1")
					return
				}
				response := new(dns.Msg)
				response.SetReply(request)
				response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "no-address.corp."}}
				w.WriteMsg(response)
			})
			upstream := startDNSListeners(t, handler, handler)
			one := dnsEngine(t, "127.0.0.1:1")
			one.dns.routes = []DNSRouteConfig{{Suffix: "corp", Servers: []string{upstream}}}
			closed, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			_, port, _ := net.SplitHostPort(closed.Addr().String())
			closed.Close()
			_, err = one.endpointDialer(&net.Dialer{Timeout: time.Second})(context.Background(), "tcp", "proxy.corp:"+port)
			require.Error(t, err)
			var staged *proxy.StageError
			if empty {
				require.ErrorAs(t, err, &staged)
				require.Equal(t, proxy.StageDNS, staged.Stage)
				require.Equal(t, int32(2), queries.Load(), "NODATA may check AAAA only within the same private scope")
			} else {
				require.False(t, errors.As(err, &staged), "a resolved endpoint connection failure must not become a DNS failure")
				require.Equal(t, int32(1), queries.Load(), "a failed connection must not try an unrelated resolver/family")
			}
		})
	}
}

func TestDNSByteBudgetReplacementAndIdleHistoryPruning(t *testing.T) {
	cache := newDNSResponseCache(1000)
	now := time.Now()
	response := &dns.Msg{Answer: []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "large.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: strings.Fields(strings.Repeat(strings.Repeat("x", 255)+" ", 200))}}}
	for i := range 200 {
		cache.put(fmt.Sprint(i), response, now.Add(time.Duration(i)*time.Nanosecond))
	}
	require.Nil(t, cache.get("0", 1, now))
	require.NotNil(t, cache.get("199", 1, now))
	require.LessOrEqual(t, cache.bytes, 8<<20)
	previous := cache.bytes
	small := response.Copy()
	small.Answer[0].(*dns.TXT).Txt = []string{"small"}
	cache.put("199", small, now)
	require.Less(t, cache.bytes, previous)
	history := newDNSHistory(2, time.Second)
	history.add(DNSQueryEvent{Time: now, Name: "expired.example"})
	history.prune(now.Add(2 * time.Second))
	require.Empty(t, history.entries[0].Name, "idle maintenance must release expired observations without a reader")
}

func TestDNSSystemCaptureRejectsRecursiveAndOverflowedScopes(t *testing.T) {
	cfg := defaultConfig().DNS
	cfg.System = true
	observed := DNSSystemContext{
		StubServers:    []string{"127.0.0.53:53"},
		DefaultServers: []string{"127.0.0.53:53", "192.0.2.53:53"},
		Scopes:         []DNSSystemScope{{Suffix: "private.example", Servers: []string{"127.0.0.54:53"}}},
	}
	merged := mergeSystemDNSContext(cfg, observed, nil)
	require.Equal(t, []string{"192.0.2.53:53"}, merged.Servers)
	require.True(t, merged.Rules[0].Unavailable, "captured system DNS cannot recursively delegate private names to an unverified local stub")
	one := dnsEngine(t, "127.0.0.1:1")
	one.dns.routes = merged.Rules
	question := new(dns.Msg)
	question.SetQuestion("db.private.example.", dns.TypeA)
	_, err := one.dns.resolve(context.Background(), question)
	require.ErrorContains(t, err, "unverified loopback scope resolver")
	for i := range 64 {
		cfg.Rules = append(cfg.Rules, DNSRouteConfig{Suffix: fmt.Sprintf("manual-%d.example", i), Servers: []string{"192.0.2.53:53"}})
	}
	merged = mergeSystemDNSContext(cfg, observed, nil)
	require.True(t, merged.SystemContext.RequireManual, "an exhausted rule budget must stop capture instead of dropping private scopes")
	cfg.Rules = nil
	observed.Scopes = []DNSSystemScope{{Suffix: "bad suffix"}, {Suffix: "private.example", Servers: []string{"192.0.2.53:53"}}, {Suffix: "private.example", Servers: []string{"192.0.2.53:53"}, Unavailable: true, Reason: "VPN transport unavailable"}}
	observed.SearchDomains = make([]string, 40)
	observed.Warnings = make([]string, 20)
	merged = mergeSystemDNSContext(cfg, observed, nil)
	require.Len(t, merged.SystemContext.SearchDomains, 32)
	require.Len(t, merged.SystemContext.Warnings, 16)
	require.Len(t, merged.Rules, 1)
	require.True(t, merged.Rules[0].Unavailable)
	require.Equal(t, "VPN transport unavailable", merged.Rules[0].Reason)
	observed.Scopes[1].Servers[0] = "203.0.113.53:53"
	require.Equal(t, "192.0.2.53:53", merged.Rules[0].Servers[0], "observed network snapshots must be independently owned")
}
