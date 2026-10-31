package kone

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func syntheticIPv6Engine(t *testing.T) *One {
	t.Helper()
	cleanProxyEnv(t)
	one := testEngine(t)
	snapshot := *one.policy.Load()
	snapshot.cfg = cloneConfig(snapshot.cfg)
	snapshot.cfg.Core.IPv6Network = "fd7a:203::1/120"
	one.policy.Store(&snapshot)
	one.initIPv6(snapshot.cfg.Core)
	one.dns.ipv6 = one.dns.ipv6Servers(snapshot.cfg.DNS)
	return one
}

func TestIPv6ConfigurationBoundsAndPlatformAdmission(t *testing.T) {
	cleanProxyEnv(t)
	configuration, err := ParseConfig([]byte("[core]\nipv6-network='fd7a:203::1/120'\n[[rules]]\ntype='IP-CIDR6'\npattern='2001:db8::/64'\noutbound='reject'"))
	require.NoError(t, err)
	require.Equal(t, "fd7a:203::1/120", configuration.Core.IPv6Network)
	if runtime.GOOS != "linux" {
		_, err := FromConfig(configuration)
		require.ErrorContains(t, err, "only on Linux")
	}
	for _, network := range []string{"2001:db8::1/64", "fd7a:203::/64", "fd7a:203::1/63", "fd7a:203::1/121", "192.0.2.1/24"} {
		_, err := ParseConfig([]byte("[core]\nipv6-network='" + network + "'"))
		require.Error(t, err)
	}
	for _, text := range []string{
		"[core]\nauto-route6=true",
		"[core]\nipv6-network='fd7a:203::1/120'\nauto-route6=true",
		"[core]\nipv6-network='fd7a:203::1/120'\n[dns]\nservers=['fd7a:203::53']",
		"[core]\nipv6-network='fd7a:203::1/120'\n[[rules]]\ntype='IP-CIDR6'\npattern='192.0.2.0/24'\noutbound='direct'",
	} {
		_, err := ParseConfig([]byte(text))
		require.Error(t, err, text)
	}
	options := deviceOptions(configuration.Core)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix(configuration.Core.IPv6Network)}, options.Inet6Address)
	require.Len(t, options.Inet4Address, 1)
	require.True(t, options.EXP_ExternalConfiguration)
}

func TestIPv6PoolBoundsAndPinnedAAAARecords(t *testing.T) {
	ip, subnet, _ := net.ParseCIDR("fd7a:203::1/120")
	table := NewDnsTable(ip, subnet)
	table.ipPool.reserve(netip.MustParseAddr("fd7a:203::2"))
	require.Equal(t, 255, table.ipPool.Capacity())
	record := table.Set("same.example", "office")
	require.NotNil(t, record)
	require.Nil(t, record.IP.To4())
	request := new(dns.Msg)
	request.SetQuestion("same.example.", dns.TypeAAAA)
	answer := record.Answer(request)
	require.Equal(t, record.IP.String(), answer.Answer[0].(*dns.AAAA).AAAA.String())
	answer.Answer[0].(*dns.AAAA).AAAA[0] = 0
	require.Equal(t, record.IP.String(), table.Get("same.example").IP.String())
	response := &dns.Msg{Answer: []dns.RR{&dns.A{A: net.IPv4(192, 0, 2, 1)}, &dns.AAAA{AAAA: net.ParseIP("2001:db8::9")}}}
	table.SetRealIP(record.Hostname, response)
	require.Equal(t, "2001:db8::9", table.Get(record.Hostname).RealIP.String())
	release := table.Pin(record.Hostname)
	table.recordsLock.Lock()
	table.records[record.Hostname].Expires = time.Time{}
	table.recordsLock.Unlock()
	for i := 0; i < 30; i++ {
		table.Set(string(rune('a'+i))+".example", "office")
	}
	table.clearExpiredDomain(time.Now())
	require.NotNil(t, table.Get(record.Hostname))
	release()
	release()
	table.recordsLock.Lock()
	table.records[record.Hostname].Expires = time.Time{}
	table.recordsLock.Unlock()
	table.clearExpiredDomain(time.Now())
	require.Nil(t, table.Get(record.Hostname))
	pool := NewDnsIPPool(netip.MustParsePrefix("fd7a:204::1/120"))
	pool.reserve(netip.MustParseAddr("fd7a:204::2"))
	for range 253 {
		address := pool.Alloc("same")
		require.True(t, address.Is6())
		require.True(t, pool.Contains(address))
	}
	require.False(t, pool.Alloc("full").IsValid())
	require.False(t, pool.Contains(netip.MustParseAddr("fd7a:205::1")))
	require.False(t, pool.Contains(netip.MustParseAddr("192.0.2.1")))
	require.Equal(t, DnsIPPoolMaxSpace, NewDnsIPPool(netip.MustParsePrefix("fd7a:204::1/64")).Capacity())
}

func TestAAAAFakeIPPolicyAndFamilyCorrectFlowResolution(t *testing.T) {
	one := syntheticIPv6Engine(t)
	request := new(dns.Msg)
	request.SetQuestion("dual.example.", dns.TypeAAAA)
	response, err := one.dns.HandleQuery(context.Background(), request, "udp", "[::1]:1234")
	require.NoError(t, err)
	ip := response.Answer[0].(*dns.AAAA).AAAA
	require.Equal(t, []string{ip.String()}, one.DNSQueries()[0].VirtualAddresses)
	require.True(t, one.DNSStatus().IPv6)
	record := one.dnsTable6.GetByIP(ip)
	require.NotNil(t, record)
	request.SetQuestion("dual.example.", dns.TypeA)
	_, err = one.dns.HandleQuery(context.Background(), request, "udp", "client")
	require.NoError(t, err)
	require.Len(t, one.domainRecords(), 2, "A/AAAA mappings remain independently stable")
	destination := M.SocksaddrFromNet(&net.UDPAddr{IP: ip, Port: 443})
	_, _, err = one.flows.destination(context.Background(), one.policy.Load(), destination, true)
	require.ErrorIs(t, err, ErrUDPUnsupported, "unsupported UDP must be rejected before real AAAA resolution")
	cfg := one.Snapshot().Config
	cfg.Rule[0].Outbound = "B"
	require.NoError(t, one.Reload(cfg))
	address, outbound, err := one.flows.destination(context.Background(), one.policy.Load(), destination, true)
	require.NoError(t, err)
	require.Equal(t, "dual.example:443", address)
	require.Equal(t, "B", outbound)
	one.dnsTable6.SetRealIP("dual.example", &dns.Msg{Answer: []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Ttl: 60}, AAAA: net.ParseIP("2001:db8::9")}}})
	cfg.Rule[0].Outbound = BuiltinDirect
	require.NoError(t, one.Reload(cfg))
	address, outbound, err = one.flows.destination(context.Background(), one.policy.Load(), destination, true)
	require.NoError(t, err)
	require.Equal(t, "[2001:db8::9]:443", address)
	require.Equal(t, BuiltinDirect, outbound)
	p := one.policy.Load().outbounds
	p.dial = func(_ context.Context, network, addr string) (net.Conn, error) {
		require.Equal(t, "udp6", network)
		require.Equal(t, address, addr)
		return nil, errors.New("IPv6 direct marker")
	}
	_, err = p.DialUDPContext(context.Background(), BuiltinDirect, address)
	require.ErrorContains(t, err, "IPv6 direct marker")
	cfg.Rule[0].Outbound = BuiltinReject
	require.NoError(t, one.Reload(cfg))
	request.SetQuestion("dual.example.", dns.TypeAAAA)
	response, err = one.dns.HandleQuery(context.Background(), request, "tcp", "[::1]:1234")
	require.NoError(t, err)
	require.Equal(t, dns.RcodeRefused, response.Rcode)
}

func TestIPCIDR6RuleAndAAAAAnswerUseSameDecision(t *testing.T) {
	rule := NewRule([]RuleConfig{{Schema: "IP-CIDR6", Pattern: "2001:db8::/64", Outbound: BuiltinReject}, {Schema: "FINAL", Outbound: BuiltinDirect}}, nil)
	require.Equal(t, BuiltinReject, rule.Decide(netip.MustParseAddr("2001:db8::9"), "udp", 443).Outbound)
	require.Equal(t, BuiltinDirect, rule.Decide(netip.MustParseAddr("2001:db8:1::9"), "tcp", 443).Outbound)
	message := &dns.Msg{Answer: []dns.RR{&dns.AAAA{AAAA: net.ParseIP("2001:db8::9")}}}
	require.Equal(t, BuiltinReject, rule.DecideDNS("same.example", message, "tcp", 443).Outbound)
	one := syntheticIPv6Engine(t)
	decision, err := one.ExplainDecision("[2001:db8::9]:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, "A", decision.Outbound)
}
