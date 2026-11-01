package kone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/dnsconfig"
)

func TestResolvedDNSContextPreservesLinkDomainsAndSecurityBoundary(t *testing.T) {
	context := parseResolvedDNSContext([]byte("Global: 192.0.2.53\nLink 2 (eth0): 192.0.2.54\nLink 5 (vpn0): 10.0.0.53"), []byte("Global: global.test\nLink 2 (eth0): home.test\nLink 5 (vpn0): ~corp.test ~."), []byte("Global: no\nLink 2 (eth0): no\nLink 5 (vpn0): yes"), []byte("Link 2 (eth0): yes\nLink 5 (vpn0): no"))
	require.Equal(t, "systemd-resolved", context.Source)
	require.Contains(t, context.SearchDomains, "home.test")
	require.Contains(t, context.DefaultServers, "192.0.2.53:53")
	require.NotContains(t, context.DefaultServers, "10.0.0.53:53")
	var private DNSSystemScope
	for _, scope := range context.Scopes {
		if scope.Suffix == "corp.test" {
			private = scope
		}
	}
	require.Equal(t, "vpn0", private.Interface)
	require.True(t, private.Unavailable, "encrypted scope must never be downgraded to plaintext UDP")
	context.StubServers = []string{"127.0.0.53:53"}
	cfg := mergeSystemDNSContext(defaultConfig().DNS, context, nil)
	for _, route := range cfg.Rules {
		require.False(t, route.Unavailable)
		require.Equal(t, context.StubServers, route.Servers)
		require.Empty(t, route.Interface)
	}
	cfg = defaultConfig().DNS
	cfg.System = true
	cfg = mergeSystemDNSContext(cfg, context, nil)
	require.Equal(t, context.DefaultServers, cfg.Servers, "system capture must not recursively use its own system stub")
	copy := cloneDNSSystemContext(context)
	copy.Scopes[0].Servers[0] = "changed"
	require.NotEqual(t, "changed", context.Scopes[0].Servers[0])
}

func TestWindowsDNSContextNRPTExactNamesAndAdapterScopes(t *testing.T) {
	context, err := parseWindowsDNSContext([]byte(`{"links":[{"name":"VPN","index":5,"suffix":"corp.test","servers":["10.0.0.53"]}],"search":["corp.test"],"routes":[{"prefix":"0.0.0.0/0","interface":"Ethernet","metric":25},{"prefix":"10.0.0.0/8","interface":"VPN","metric":10}],"nrpt":[{"namespaces":["host.corp.test"],"servers":["10.0.0.53"],"secure":false},{"namespaces":[".secure.test"],"servers":["10.0.0.53"],"secure":true}]}`))
	require.NoError(t, err)
	require.Len(t, context.Scopes, 3)
	require.Equal(t, "VPN", context.Scopes[0].Interface)
	require.True(t, context.Scopes[1].Exact)
	require.False(t, context.Scopes[1].Unavailable)
	require.True(t, context.Scopes[2].Unavailable)
	require.Contains(t, context.SearchDomains, "corp.test")
	_, err = parseWindowsDNSContext([]byte("invalid"))
	require.Error(t, err)
	context, err = parseWindowsDNSContext([]byte(`{"links":[{"name":"VPN","suffix":"corp.test","servers":[]}],"nrpt":[{"namespaces":[".orphan.test"],"servers":["10.0.0.53"]}]}`))
	require.NoError(t, err)
	require.True(t, context.Scopes[0].Unavailable)
	require.True(t, context.Scopes[1].Unavailable)
}

func TestWindowsDNSContextExcludesOwnedResolverFromAutomaticUpstreams(t *testing.T) {
	observed, err := parseWindowsDNSContext([]byte(`{"owned_excluded":true,"default_servers":["192.0.2.53"],"links":[],"nrpt":[]}`))
	require.NoError(t, err)
	cfg := defaultConfig().DNS
	cfg.Servers = []string{"10.207.0.1:53"}
	merged := mergeSystemDNSContext(cfg, observed, nil)
	require.Equal(t, []string{"192.0.2.53:53"}, merged.Servers)
	require.NotContains(t, merged.Servers, "10.207.0.1:53")
	observed, err = parseWindowsDNSContext([]byte(`{"owned_excluded":true,"default_servers":[],"links":[],"nrpt":[]}`))
	require.NoError(t, err)
	require.True(t, observed.RequireManual)
	require.NotEmpty(t, observed.Warnings)
	merged = mergeSystemDNSContext(cfg, observed, nil)
	require.Empty(t, merged.Servers, "an unavailable original resolver must not silently reuse KONE")
}

func TestDarwinDNSContextScopesPortsAndMulticastBoundary(t *testing.T) {
	context, err := parseDarwinDNSContext([]byte("DNS configuration\nresolver #1\n  search domain[0] : home.test\n  nameserver[0] : 192.0.2.53\n  if_index : 2 (en0)\nresolver #2\n  domain : corp.test\n  nameserver[0] : 10.0.0.53\n  port : 5353\n  if_index : 7 (utun3)\n  flags : Scoped, Request A records\nresolver #3\n  domain : local\n  options : mdns\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.53:53"}, context.DefaultServers)
	require.Contains(t, context.SearchDomains, "home.test")
	require.Len(t, context.Scopes, 2)
	require.Equal(t, "utun3", context.Scopes[0].Interface)
	require.Equal(t, []string{"10.0.0.53:5353"}, context.Scopes[0].Servers)
	require.True(t, context.Scopes[1].Unavailable, "mDNS must not leak to default unicast resolvers")
	_, err = parseDarwinDNSContext([]byte("no DNS context"))
	require.Error(t, err)
}

func TestSystemDNSMergeManualPrecedenceAndKnownFailureNoFallback(t *testing.T) {
	cleanProxyEnv(t)
	observed := DNSSystemContext{Source: "fixture", SearchDomains: []string{"corp.test"}, Scopes: []DNSSystemScope{{Suffix: "corp.test", Servers: []string{"192.0.2.53:53"}}, {Suffix: "secure.test", Unavailable: true, Reason: "secure resolver unavailable"}}}
	cfg := defaultConfig().DNS
	cfg.Servers = []string{"127.0.0.1:1"}
	cfg.Rules = []DNSRouteConfig{{Suffix: "test", Servers: []string{"192.0.2.1:53"}}}
	merged := mergeSystemDNSContext(cfg, observed, errors.New("incomplete"))
	one := testEngine(t)
	one.dns.routes = merged.Rules
	servers, route := one.dns.selectResolvers("db.corp.test")
	require.Equal(t, "test", route, "explicit manual rules override automatic scopes")
	require.Equal(t, []string{"192.0.2.1:53"}, servers)
	one.dns.routes = merged.Rules[1:]
	request := new(dns.Msg)
	request.SetQuestion("db.secure.test.", dns.TypeAAAA)
	_, err := one.dns.resolve(context.Background(), request)
	require.ErrorContains(t, err, "secure resolver unavailable")
	require.NotEmpty(t, merged.SystemContext.Warnings)
	root := observed
	root.StubServers = []string{"127.0.0.53:53"}
	cfg.System = true
	merged = mergeSystemDNSContext(cfg, root, nil)
	require.True(t, merged.SystemContext.RequireManual)
}

func TestExactSystemDNSNamesDoNotExpandAndAmbiguityFailsClosed(t *testing.T) {
	one := testEngine(t)
	one.dns.routes = []DNSRouteConfig{{Suffix: "corp.test", Servers: []string{"192.0.2.1:53"}, Automatic: true}, {Suffix: "corp.test", Servers: []string{"192.0.2.2:53"}, Automatic: true, Exact: true}}
	servers, _ := one.dns.selectResolvers("corp.test")
	require.Equal(t, []string{"192.0.2.2:53"}, servers)
	servers, _ = one.dns.selectResolvers("sub.corp.test")
	require.Equal(t, []string{"192.0.2.1:53"}, servers)
	observed := DNSSystemContext{Scopes: []DNSSystemScope{{Suffix: "corp.test", Servers: []string{"192.0.2.1:53"}, Interface: "a"}, {Suffix: "corp.test", Servers: []string{"192.0.2.2:53"}, Interface: "b"}}}
	merged := mergeSystemDNSContext(defaultConfig().DNS, observed, nil)
	require.Len(t, merged.Rules, 1)
	require.True(t, merged.Rules[0].Unavailable)
	observed.Scopes = nil
	for i := 0; i < 70; i++ {
		observed.Scopes = append(observed.Scopes, DNSSystemScope{Suffix: fmt.Sprintf("scope%d.test", i), Servers: []string{"192.0.2.1:53"}})
	}
	merged = mergeSystemDNSContext(defaultConfig().DNS, observed, nil)
	require.Len(t, merged.Rules, 64)
	require.True(t, merged.Rules[63].Unavailable)
	require.Equal(t, ".", merged.Rules[63].Suffix)
}

func TestDNSDiscoveryOutputAndCommandBounds(t *testing.T) {
	var output dnsLimitedOutput
	_, err := output.Write([]byte("small"))
	require.NoError(t, err)
	_, err = output.Write([]byte(strings.Repeat("x", 1<<20)))
	require.Error(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = readDNSCommand(ctx, "kone-missing-dns-command")
	require.Error(t, err)
	t.Setenv("KONE_DNS_CONTEXT_HELPER", "1")
	data, err := readDNSCommand(context.Background(), os.Args[0], "-test.run=^TestDNSContextCommandHelper$")
	require.NoError(t, err)
	require.Contains(t, string(data), "DNS context helper")
	ctx, cancel = context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	_, err = readDNSCommand(ctx, os.Args[0], "-test.run=^TestDNSContextCommandHelper$")
	require.Error(t, err)
}

func TestDNSContextCommandHelper(t *testing.T) {
	if os.Getenv("KONE_DNS_CONTEXT_HELPER") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, "DNS context helper")
}

func TestDNSSystemContextPlatformDispatchIsReadOnlyAndDeterministic(t *testing.T) {
	for _, platform := range []string{"linux", "windows", "darwin", "unsupported"} {
		for _, failure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", platform, failure), func(t *testing.T) {
				read := func(ctx context.Context, name string, args ...string) ([]byte, error) {
					deadline, ok := ctx.Deadline()
					require.True(t, ok)
					require.LessOrEqual(t, time.Until(deadline), 4*time.Second)
					if failure {
						return nil, errors.New("injected discovery failure")
					}
					switch name {
					case "resolvectl":
						require.Len(t, args, 1)
						switch args[0] {
						case "domain":
							return []byte("Link 2 (eth0): ~corp.test"), nil
						case "dns":
							return []byte("Link 2 (eth0): 192.0.2.53"), nil
						case "dnsovertls":
							return []byte("Global: no\nLink 2 (eth0): no"), nil
						case "default-route":
							return []byte("Link 2 (eth0): yes"), nil
						}
					case "powershell":
						require.Contains(t, strings.Join(args, " "), "Get-DnsClientNrptPolicy -Effective")
						return []byte(`{"links":[],"nrpt":[],"routes":[],"search":[]}`), nil
					case "scutil":
						require.Equal(t, []string{"--dns"}, args)
						return []byte("resolver #1\nnameserver[0] : 192.0.2.53\n"), nil
					}
					return nil, errors.New("unexpected discovery command")
				}
				observed, err := readDNSSystemContextFor(platform, &dnsconfig.DnsConfig{Servers: []string{"127.0.0.53:53"}, Search: []string{"home.test"}, UseTCP: true}, read, nil)
				if failure || platform == "unsupported" {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
				require.NotEmpty(t, observed.Source)
				if platform == "linux" && !failure {
					require.Equal(t, []string{"127.0.0.53:53"}, observed.StubServers)
					require.True(t, observed.UseTCP)
					require.Len(t, observed.Scopes, 1)
				}
			})
		}
	}
}

func TestDNSSystemContextReadOnlySmoke(t *testing.T) {
	observed, _ := readDNSSystemContext()
	require.NotEmpty(t, observed.Source)
}

func TestDNSRuleInterfaceValidationAndRuntimeCapability(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	cfg := one.Snapshot().Config.DNS
	cfg.Rules = []DNSRouteConfig{{Suffix: "corp.test", Servers: []string{"127.0.0.1:53"}, Interface: "kone-no-such-dns-interface"}}
	_, err := NewDns(one, cfg)
	require.ErrorContains(t, err, "interface is unavailable")
	cfg.Rules[0].Automatic = true
	d, err := NewDns(one, cfg)
	require.NoError(t, err)
	require.True(t, d.routes[0].Unavailable)
	request := new(dns.Msg)
	request.SetQuestion("db.corp.test.", dns.TypeA)
	_, err = d.resolve(context.Background(), request)
	require.ErrorContains(t, err, "exclusive system DNS scope unavailable")
	cfg.SystemContext.RequireManual = true
	_, err = NewDns(one, cfg)
	require.ErrorContains(t, err, "requires explicit")
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	device := ""
	for _, item := range interfaces {
		if item.Flags&net.FlagLoopback != 0 && item.Flags&net.FlagUp != 0 {
			device = item.Name
			break
		}
	}
	if device == "" {
		t.Skip("no loopback interface available")
	}
	private := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { replyA(w, r, "192.0.2.9") })
	address := startDNSListeners(t, private, private)
	cfg.SystemContext.RequireManual = false
	cfg.Rules = []DNSRouteConfig{{Suffix: "corp.test", Servers: []string{address}, Interface: device}}
	d, err = NewDns(one, cfg)
	require.NoError(t, err)
	_, err = d.ResolveContext(context.Background(), "db.corp.test")
	require.NoError(t, err)
	require.Equal(t, "loopback", d.Queries()[0].ResolverInterface)
	require.Equal(t, device, d.routeClients[dnsRouteKey(cfg.Rules[0])].device)
}

func TestSystemDNSUseTCPNeverSendsUDP(t *testing.T) {
	udp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		t.Error("system use-tcp must not send UDP")
		replyA(w, r, "192.0.2.1")
	})
	tcp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { replyA(w, r, "192.0.2.2") })
	address := startDNSListeners(t, udp, tcp)
	one := dnsEngine(t, address)
	one.dns.forceTCP = true
	answer, err := one.dns.ResolveContext(context.Background(), "tcp.example")
	require.NoError(t, err)
	require.Equal(t, "192.0.2.2", answer.Answer[0].(*dns.A).A.String())
	require.Equal(t, "tcp", one.DNSQueries()[0].UpstreamTransport)
}
