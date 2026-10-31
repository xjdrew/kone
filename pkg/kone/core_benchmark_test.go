package kone

import (
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func BenchmarkRuleDecision(b *testing.B) {
	rule := NewRule([]RuleConfig{{Schema: "DOMAIN-SUFFIX", Pattern: "example.com", Outbound: BuiltinReject}, {Schema: "GEOIP", Pattern: "CN", Outbound: BuiltinReject}, {Schema: "FINAL", Outbound: BuiltinDirect}}, nil)
	for _, value := range []any{"www.example.com", netip.MustParseAddr("114.114.114.114"), netip.MustParseAddr("8.8.8.8")} {
		b.Run(valueString(value), func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				var decision RoutingDecision
				for pb.Next() {
					decision = rule.Decide(value, "tcp", 443)
				}
				runtime.KeepAlive(decision)
			})
		})
	}
}

func valueString(value any) string {
	if address, ok := value.(netip.Addr); ok {
		return address.String()
	}
	return value.(string)
}

func BenchmarkDNSResponseCache(b *testing.B) {
	request := new(dns.Msg)
	request.SetQuestion("cached.example.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "cached.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: net.IPv4(192, 0, 2, 1)}}
	cache := newDNSResponseCache(1024)
	now := time.Now()
	key := dnsCacheKey(request, "")
	cache.put(key, response, now)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		message := cache.get(key, uint16(i), now)
		runtime.KeepAlive(message)
	}
}
