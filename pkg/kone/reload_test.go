package kone

import (
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func testEngine(t *testing.T) *One {
	t.Helper()
	cfg := parseTestConfig(t, `
[[outbounds]]
name='A'
url='http://Proxy.Example.com:8080'
[[outbounds]]
name='B'
url='socks5://127.0.0.1:1080'
[[rules]]
type='FINAL'
outbound='A'
`)
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	return one
}

func TestReloadPreservesProxyBypass(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	require.NoError(t, one.Reload(one.Snapshot().Config))
	require.Equal(t, BuiltinDirect, one.policy.Load().rule.Proxy("PROXY.EXAMPLE.COM."))
	require.Equal(t, BuiltinDirect, one.policy.Load().rule.Proxy("127.0.0.1"))
	require.Equal(t, "A", one.policy.Load().rule.Proxy("other.example.com"))
}

func TestReloadUpdatesCachedPolicyAndPreservesAddress(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	record := one.dnsTable.Set("example.com", "A")
	one.dnsTable.SetNonProxyDomain("direct.example", 600)
	cfg := one.Snapshot().Config
	cfg.Rule[0].Outbound = "B"
	require.NoError(t, one.Reload(cfg))
	_, records := one.DNSSnapshot()
	got := records[record.Hostname]
	require.Equal(t, "B", got.Proxy)
	require.True(t, record.IP.Equal(got.IP))
	require.False(t, one.dnsTable.IsNonProxyDomain("direct.example"))
	// Caller mutations do not alter the active snapshot.
	cfg.Rule[0].Outbound = "reject"
	require.Equal(t, "B", one.policy.Load().rule.Proxy("example.com"))
}

func TestReloadFailureLeavesPolicyIntact(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	one.dnsTable.Set("example.com", "A")
	cases := []struct {
		name   string
		change func(*KoneConfig)
	}{
		{"core", func(c *KoneConfig) { c.Core.TcpListenPort = 83 }},
		{"logging", func(c *KoneConfig) { c.General.LogLevel = "debug" }},
		{"route", func(c *KoneConfig) { c.Rule = []RuleConfig{{Schema: "IP-CIDR", Pattern: "8.8.8.0/24", Outbound: "A"}} }},
		{"invalid", func(c *KoneConfig) { c.Rule[0].Outbound = "Missing" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := one.Snapshot().Config
			tc.change(cfg)
			require.Error(t, one.Reload(cfg))
			require.Equal(t, "A", one.policy.Load().rule.Proxy("example.com"))
			require.Equal(t, "A", policyFor(one, "example.com"))
		})
	}
}

type flowConn struct {
	net.Conn
	remote net.Addr
}

func (c flowConn) RemoteAddr() net.Addr { return c.remote }

func TestCachedVirtualAddressCanBecomeDirect(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	record := one.dnsTable.Set("example.com", "A")
	answer := &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("203.0.113.10")}}}
	one.dnsTable.SetRealIP(record.Hostname, answer)
	cfg := one.Snapshot().Config
	cfg.Rule[0].Outbound = "direct"
	require.NoError(t, one.Reload(cfg))
	relay := NewTCPRelay(one, cfg.Core)
	_, port := relay.nat.allocSession(net.IPv4(192, 168, 1, 2), record.IP, 50000, 443)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	var data ConnData
	addr, policy := relay.realRemoteHost(flowConn{Conn: left, remote: &net.TCPAddr{IP: record.IP, Port: int(port)}}, &data)
	require.Equal(t, "203.0.113.10:443", addr)
	require.Equal(t, "direct", policy)
	require.Equal(t, "example.com", data.Dst)
}

func TestConcurrentReloadAndDNS(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	cfg := one.Snapshot().Config
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if err := one.Reload(cfg); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			r := new(dns.Msg)
			r.SetQuestion("example.com.", dns.TypeA)
			_, err := one.dns.doIPv4Query(r)
			if err != nil {
				t.Error(err)
				return
			}
			one.dnsTable.Snapshot()
		}
	}()
	wg.Wait()
}

func TestReloadReevaluatesCachedCNAMEAndIPRules(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	record := one.dnsTable.Set("origin.example", "A")
	one.dnsTable.SetRealIP(record.Hostname, &dns.Msg{Answer: []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "origin.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "cdn.example."},
		&dns.A{Hdr: dns.RR_Header{Name: "cdn.example.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("203.0.113.1")},
	}})
	cfg := one.Snapshot().Config
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN", Pattern: "cdn.example", Outbound: "B"}, {Schema: "FINAL", Outbound: "direct"}}
	require.NoError(t, one.Reload(cfg))
	require.Equal(t, "B", policyFor(one, record.Hostname))
	require.True(t, record.IP.Equal(one.dnsTable.Get(record.Hostname).IP))
}

func policyFor(one *One, domain string) string {
	_, records := one.DNSSnapshot()
	return records[domain].Proxy
}
