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
[proxies]
A='http://Proxy.Example.com:8080'
B='socks5://127.0.0.1:1080'
[[rules]]
type='FINAL'
proxy='A'
`)
	ip, subnet, err := net.ParseCIDR(cfg.Core.Network)
	require.NoError(t, err)
	p, err := NewProxies(cfg.Proxy)
	require.NoError(t, err)
	one := &One{ip: ip.To4(), subnet: subnet, cfg: cloneConfig(cfg), rule: NewRule(cfg.Rule), proxies: p, dnsTable: NewDnsTable(ip, subnet)}
	p.bypassEndpoints(one.rule)
	one.dns, err = NewDns(one, cfg.Core)
	require.NoError(t, err)
	return one
}

func TestReloadPreservesProxyBypass(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	require.NoError(t, one.Reload(cloneConfig(one.cfg)))
	require.Equal(t, "DIRECT", one.rule.Proxy("PROXY.EXAMPLE.COM."))
	require.Equal(t, "DIRECT", one.rule.Proxy("127.0.0.1"))
	require.Equal(t, "A", one.rule.Proxy("other.example.com"))
}

func TestReloadUpdatesCachedPolicyAndPreservesAddress(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	record := one.dnsTable.Set("example.com", "A")
	one.dnsTable.SetNonProxyDomain("direct.example", 600)
	cfg := cloneConfig(one.cfg)
	cfg.Rule[0].Proxy = "B"
	require.NoError(t, one.Reload(cfg))
	got := one.dnsTable.GetByIP(record.IP)
	require.Equal(t, "B", got.Proxy)
	require.True(t, record.IP.Equal(got.IP))
	require.False(t, one.dnsTable.IsNonProxyDomain("direct.example"))
	// Caller mutations do not alter the active snapshot.
	cfg.Rule[0].Proxy = "REJECT"
	require.Equal(t, "B", one.rule.Proxy("example.com"))
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
		{"proxy", func(c *KoneConfig) { c.Proxy["A"] = "http://new.example:8080" }},
		{"route", func(c *KoneConfig) { c.Rule = []RuleConfig{{Schema: "IP-CIDR", Pattern: "8.8.8.0/24", Proxy: "A"}} }},
		{"invalid", func(c *KoneConfig) { c.Rule[0].Proxy = "Missing" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cloneConfig(one.cfg)
			tc.change(cfg)
			require.Error(t, one.Reload(cfg))
			require.Equal(t, "A", one.rule.Proxy("example.com"))
			require.Equal(t, "A", one.dnsTable.Get("example.com").Proxy)
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
	cfg := cloneConfig(one.cfg)
	cfg.Rule[0].Proxy = "DIRECT"
	require.NoError(t, one.Reload(cfg))
	relay := NewTCPRelay(one, cfg.Core)
	_, port := relay.nat.allocSession(net.IPv4(192, 168, 1, 2), record.IP, 50000, 443)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	var data ConnData
	addr, policy := relay.realRemoteHost(flowConn{Conn: left, remote: &net.TCPAddr{IP: record.IP, Port: int(port)}}, &data)
	require.Equal(t, "203.0.113.10:443", addr)
	require.Equal(t, "DIRECT", policy)
	require.Equal(t, "example.com", data.Dst)
}

func TestConcurrentReloadAndDNS(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	cfg := cloneConfig(one.cfg)
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
			one.policyMu.RLock()
			r := new(dns.Msg)
			r.SetQuestion("example.com.", dns.TypeA)
			_, err := one.dns.doIPv4Query(r)
			one.policyMu.RUnlock()
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
	cfg := cloneConfig(one.cfg)
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN", Pattern: "cdn.example", Proxy: "B"}, {Schema: "FINAL", Proxy: "DIRECT"}}
	require.NoError(t, one.Reload(cfg))
	require.Equal(t, "B", one.dnsTable.Get(record.Hostname).Proxy)
	require.True(t, record.IP.Equal(one.dnsTable.Get(record.Hostname).IP))
}
