package kone

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pelletier/go-toml/v2"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestDNSDefaultsUseSystemOnceAndSurviveReload(t *testing.T) {
	cleanProxyEnv(t)
	cfg, err := ParseConfig([]byte("[[rules]]\ntype='FINAL'\noutbound='direct'"))
	require.NoError(t, err)
	require.Empty(t, cfg.DNS.Servers)
	require.Equal(t, uint16(53), cfg.DNS.ListenPort)
	reads := 0
	servers := []string{"192.0.2.53"}
	one, err := FromConfig(cfg, func(one *One) error {
		one.readSystemDNS = func() ([]string, error) { reads++; return servers, nil }
		one.readSystemDNSContext = func() (DNSSystemContext, error) { return DNSSystemContext{}, nil }
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.53:53"}, one.dns.nameservers)
	require.Empty(t, one.Snapshot().Config.DNS.Servers)
	servers[0] = "10.192.0.1" // simulate system DNS now pointing at our TUN
	updated, err := ParseConfig(cfg.source)
	require.NoError(t, err)
	require.NoError(t, one.Reload(updated))
	require.Equal(t, 1, reads)
	require.Equal(t, []string{"192.0.2.53:53"}, one.dns.nameservers)
	changed := one.Snapshot().Config
	changed.DNS.TTL++
	require.ErrorContains(t, one.Reload(changed), "require restart")
	require.Equal(t, uint64(2), one.Snapshot().Version)
}

func TestEffectiveDNSConfigErrorsAndExplicitOverride(t *testing.T) {
	readerError := errors.New("system DNS unavailable")
	for _, tc := range []struct {
		servers []string
		err     error
		want    string
	}{{nil, readerError, "system DNS unavailable"}, {nil, nil, "no system DNS"}, {[]string{"invalid"}, nil, "dns.servers[1]"}} {
		_, err := effectiveDNSConfig(defaultConfig().DNS, func() ([]string, error) { return tc.servers, tc.err })
		require.ErrorContains(t, err, tc.want)
	}
	cfg := defaultConfig().DNS
	cfg.Servers = []string{"2001:db8::53"}
	effective, err := effectiveDNSConfig(cfg, func() ([]string, error) { t.Fatal("explicit DNS must not read system settings"); return nil, nil })
	require.NoError(t, err)
	require.Equal(t, []string{"[2001:db8::53]:53"}, effective.Servers)
	require.Equal(t, []string{"2001:db8::53"}, cfg.Servers)
	cleanProxyEnv(t)
	for _, reply := range [][]string{nil, {"10.192.0.1"}} {
		_, err := FromConfig(defaultConfig(), func(one *One) error { one.readSystemDNS = func() ([]string, error) { return reply, nil }; return nil })
		require.Error(t, err)
	}
}

func TestBuiltInOutboundsNeedNoConfiguration(t *testing.T) {
	cleanProxyEnv(t)
	cfg, err := ParseConfig([]byte(`
[[rules]]
type='FINAL'
outbound='direct'
`))
	require.NoError(t, err)
	rule := NewRule(cfg.Rule, cfg.Outbounds)
	require.Empty(t, cfg.Outbounds)
	require.Equal(t, BuiltinDirect, rule.Proxy("example.com"))
	require.Equal(t, OutboundDirect, rule.OutboundType(BuiltinDirect))
	require.Equal(t, OutboundReject, rule.OutboundType(BuiltinReject))
	p, err := NewOutbounds(cfg.Outbounds)
	require.NoError(t, err)
	var dialed []string
	p.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		return nil, errors.New("dial stopped")
	}
	_, err = p.Dial(BuiltinDirect, "192.0.2.1:80")
	require.ErrorContains(t, err, "dial stopped")
	require.Equal(t, []string{"192.0.2.1:80"}, dialed)
	_, err = p.Dial(BuiltinReject, "192.0.2.2:80")
	require.ErrorContains(t, err, "rejected")
	_, err = p.Dial("missing", "192.0.2.2:80")
	require.ErrorContains(t, err, "unknown outbound")
	_, err = p.Dial("", "192.0.2.3:80")
	require.ErrorContains(t, err, "unknown outbound")
	require.Equal(t, []string{"192.0.2.1:80"}, dialed)
	implicit := NewRule(nil, nil)
	require.Equal(t, BuiltinDirect, implicit.Proxy("unmatched.example"))
	data, err := cfg.RedactedTOML()
	require.NoError(t, err)
	reparsed, err := ParseConfig(data)
	require.NoError(t, err)
	require.Empty(t, reparsed.Outbounds, "built-ins must not become file configuration")
	_, err = NewOutbounds([]OutboundConfig{{Name: "direct", URL: "http://127.0.0.1:8080"}})
	require.Error(t, err)
}

func TestEnvironmentOutboundOverrideAndConflict(t *testing.T) {
	cleanProxyEnv(t)
	t.Setenv(HTTP_PROXY, "http://127.0.0.1:8888")
	cfg := parseTestConfig(t, "[[outbounds]]\nname='http_proxy'\nurl='http://127.0.0.1:8080'")
	require.Equal(t, "http://127.0.0.1:8888", outboundByName(cfg, HTTP_PROXY).URL)
	_, err := ParseConfig([]byte("[[outbounds]]\nname='http_proxy'\ntype='direct'"))
	require.ErrorContains(t, err, "unknown configuration key")
	_, err = ParseConfig([]byte("[[outbounds]]\nname='http_proxy'\nurl='http://user:secret@127.0.0.1:bad'"))
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secret")
}

func TestReloadBuiltInTargetsAndCIDRProtection(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	old := one.policy.Load()
	cfg := one.Snapshot().Config
	cfg.Rule[0].Outbound = BuiltinDirect
	require.NoError(t, one.Reload(cfg))
	require.Equal(t, OutboundDirect, one.policy.Load().rule.OutboundType(one.policy.Load().rule.Proxy("example.com")))
	require.Equal(t, OutboundProxy, old.rule.OutboundType("A"))
	cfg.Rule = []RuleConfig{{Schema: "IP-CIDR", Pattern: "192.0.2.0/24", Outbound: BuiltinDirect}}
	routed, err := FromConfig(cfg)
	require.NoError(t, err)
	updated := routed.Snapshot().Config
	updated.Rule[0].Outbound = "A"
	require.ErrorContains(t, routed.Reload(updated), "require restart")
	require.Equal(t, uint64(1), routed.Snapshot().Version)
}

func TestReloadWithOnlyBuiltInOutbounds(t *testing.T) {
	cleanProxyEnv(t)
	cfg := parseTestConfig(t, "[[rules]]\ntype='FINAL'\noutbound='direct'")
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	old := one.policy.Load()
	updated := one.Snapshot().Config
	updated.Rule[0].Outbound = BuiltinReject
	require.NoError(t, one.Reload(updated))
	require.Empty(t, one.Snapshot().Config.Outbounds)
	require.Equal(t, BuiltinDirect, old.rule.Proxy("example.com"))
	require.Equal(t, BuiltinReject, one.policy.Load().rule.Proxy("example.com"))
	_, err = one.policy.Load().outbounds.Dial(BuiltinReject, "192.0.2.1:80")
	require.ErrorContains(t, err, "rejected")
	updated = one.Snapshot().Config
	updated.Rule = nil
	require.NoError(t, one.Reload(updated))
	require.Equal(t, BuiltinDirect, one.policy.Load().rule.Proxy("example.com"))
	require.Empty(t, one.Snapshot().Config.Outbounds)
}

func TestBuiltInRejectAppliesAfterCNAMEAndIPResolution(t *testing.T) {
	cleanProxyEnv(t)
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	ready := make(chan struct{})
	server := &dns.Server{PacketConn: conn, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 10}, Target: "blocked.example."},
			&dns.A{Hdr: dns.RR_Header{Name: "blocked.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.IPv4(192, 0, 2, 9)},
		}
		w.WriteMsg(reply)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("DNS test server did not start")
	}
	defer func() { require.NoError(t, server.Shutdown()); require.NoError(t, <-done) }()
	for _, rule := range []RuleConfig{
		{Schema: "DOMAIN", Pattern: "blocked.example", Outbound: BuiltinReject},
		{Schema: "IP-CIDR", Pattern: "192.0.2.0/24", Outbound: BuiltinReject},
	} {
		cfg := parseTestConfig(t, "")
		cfg.Rule = []RuleConfig{rule, {Schema: "FINAL", Outbound: "direct"}}
		cfg.DNS.Servers = []string{conn.LocalAddr().String()}
		one, err := FromConfig(cfg)
		require.NoError(t, err)
		request := new(dns.Msg)
		request.SetQuestion("origin.example.", dns.TypeA)
		reply, err := one.dns.doIPv4Query(request)
		require.NoError(t, err)
		require.Equal(t, dns.RcodeRefused, reply.Rcode)
		require.Empty(t, reply.Answer)
		require.Nil(t, one.dnsTable.Get("origin.example"))
		// A cached Fake-IP from an earlier proxy rule can need its first
		// real lookup after reload. Newly discovered CNAME/IP rejection must
		// also stop the UDP flow before any destination socket is created.
		record := one.dnsTable.Set("origin.example", BuiltinDirect)
		_, _, err = one.flows.destination(context.Background(), one.policy.Load(), M.SocksaddrFromNet(&net.UDPAddr{IP: record.IP, Port: 443}), true)
		require.ErrorIs(t, err, ErrRejected)
	}
}

func TestExampleDocumentsEveryConfigurationField(t *testing.T) {
	cleanProxyEnv(t)
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "kone.example.toml"))
	require.NoError(t, err)
	cfg, err := ParseConfig(data)
	require.NoError(t, err)
	require.Empty(t, cfg.DNS.Servers, "example must use system DNS by default")
	require.Equal(t, "system", cfg.Core.Stack)
	// Enable commented defaults to validate their spelling, types, and values.
	option := regexp.MustCompile(`^#\s*(\[\[?[a-z][a-z0-9.-]*\]\]?|[a-z][a-z0-9-]*\s*=.*)$`)
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if match := option.FindStringSubmatch(strings.TrimSpace(line)); match != nil {
			lines[i] = match[1]
		}
	}
	all := []byte(strings.Join(lines, "\n"))
	_, err = ParseConfig(all)
	require.NoError(t, err)
	var document map[string]any
	require.NoError(t, toml.Unmarshal(all, &document))
	for _, item := range []struct {
		section string
		schema  reflect.Type
		array   bool
	}{
		{"general", reflect.TypeFor[GeneralConfig](), false},
		{"core", reflect.TypeFor[CoreConfig](), false},
		{"dns", reflect.TypeFor[DNSConfig](), false},
		{"outbounds", reflect.TypeFor[OutboundConfig](), true},
		{"rules", reflect.TypeFor[RuleConfig](), true},
	} {
		value := document[item.section]
		if item.array {
			value = value.([]any)[0]
		}
		fields := value.(map[string]any)
		for i := 0; i < item.schema.NumField(); i++ {
			key := strings.Split(item.schema.Field(i).Tag.Get("toml"), ",")[0]
			if key == "-" {
				continue
			}
			require.Contains(t, fields, key, "%s.%s missing from complete example", item.section, key)
		}
	}
}
