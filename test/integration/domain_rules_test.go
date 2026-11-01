package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/kone"
)

func domainRuleDNSListeners(t *testing.T, handler dns.Handler) map[string]string {
	t.Helper()
	addresses := map[string]string{}
	for _, transport := range []string{"udp", "tcp"} {
		ready := make(chan struct{})
		server := &dns.Server{Net: transport, Handler: handler, NotifyStartedFunc: func() { close(ready) }}
		var err error
		if transport == "udp" {
			server.PacketConn, err = net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			addresses[transport] = server.PacketConn.LocalAddr().String()
		} else {
			server.Listener, err = net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			addresses[transport] = server.Listener.Addr().String()
		}
		done := make(chan error, 1)
		go func() { done <- server.ActivateAndServe() }()
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("loopback DNS listener did not start")
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			require.NoError(t, server.ShutdownContext(ctx))
			require.NoError(t, <-done)
		})
	}
	return addresses
}

func TestDomainRuleDNSPreventsIPv6BypassOverUDPAndTCP(t *testing.T) {
	// Use real DNS wire requests and engine policy, without starting capture or
	// creating any system device, route, DNS setting or external connection.
	upstream := domainRuleDNSListeners(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		if request.Question[0].Qtype == dns.TypeHTTPS || request.Question[0].Qtype == dns.TypeSVCB {
			binding := dns.SVCB{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: request.Question[0].Qtype, Class: dns.ClassINET, Ttl: 60}, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("192.0.2.9")}}, &dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2001:db8::9")}}}}
			if request.Question[0].Qtype == dns.TypeHTTPS {
				reply.Answer = []dns.RR{&dns.HTTPS{SVCB: binding}}
			} else {
				reply.Answer = []dns.RR{&binding}
			}
			reply.Extra = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::9")}}
		} else if request.Question[0].Qtype == dns.TypeAAAA {
			reply.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::9")}}
		} else {
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.9")}}
		}
		w.WriteMsg(reply)
	}))
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4-only", true: "IPv6-enabled"}[ipv6], func(t *testing.T) {
			cfg := kone.DefaultConfig()
			cfg.DNS.Servers = []string{upstream["udp"]}
			cfg.DNS.System = false
			cfg.Outbounds = []kone.OutboundConfig{{Name: "broken", URL: "http://127.0.0.1:1"}}
			cfg.Rule = []kone.RuleConfig{
				{Schema: "DOMAIN", Pattern: "captured.example", Outbound: "broken"},
				{Schema: "DOMAIN", Pattern: "selective.example", Protocol: "tcp", Ports: []uint16{443}, Outbound: "broken"},
				{Schema: "DOMAIN", Pattern: "blocked.example", Outbound: kone.BuiltinReject},
				{Schema: "FINAL", Outbound: kone.BuiltinDirect},
			}
			if ipv6 {
				cfg.Core.IPv6Network = "fd7a:203::1/120"
			}
			engine, err := kone.FromConfig(cfg)
			require.NoError(t, err)
			defer engine.Close()
			resolver, err := kone.NewDns(engine, cfg.DNS)
			require.NoError(t, err)
			listeners := domainRuleDNSListeners(t, resolver)
			for _, transport := range []string{"udp", "tcp"} {
				query := func(name string, kind uint16) *dns.Msg {
					request := new(dns.Msg)
					request.SetQuestion(dns.Fqdn(name), kind)
					response, _, err := (&dns.Client{Net: transport, Timeout: time.Second}).Exchange(request, listeners[transport])
					require.NoError(t, err)
					return response
				}
				for _, name := range []string{"captured.example", "selective.example"} {
					reply := query(name, dns.TypeAAAA)
					require.Equal(t, dns.RcodeSuccess, reply.Rcode)
					if ipv6 {
						require.Len(t, reply.Answer, 1)
						_, subnet, _ := net.ParseCIDR(cfg.Core.IPv6Network)
						require.True(t, subnet.Contains(reply.Answer[0].(*dns.AAAA).AAAA))
					} else {
						require.Empty(t, reply.Answer, "a broken proxy never permits a real AAAA bypass")
					}
					reply = query(name, dns.TypeA)
					require.Len(t, reply.Answer, 1)
					_, subnet, _ := net.ParseCIDR(cfg.Core.Network)
					require.True(t, subnet.Contains(reply.Answer[0].(*dns.A).A))
				}
				for _, binding := range []struct {
					name string
					kind uint16
				}{
					{"captured.example", dns.TypeHTTPS}, {"_8443._https.captured.example", dns.TypeHTTPS},
					{"_sip._tcp.captured.example", dns.TypeSVCB}, {"selective.example", dns.TypeHTTPS},
				} {
					reply := query(binding.name, binding.kind)
					require.Equal(t, dns.RcodeSuccess, reply.Rcode)
					require.Empty(t, reply.Answer, "service hints cannot bypass Fake-IP with either capture family")
					require.Empty(t, reply.Extra)
				}
				require.Equal(t, dns.RcodeRefused, query("blocked.example", dns.TypeHTTPS).Rcode)
				binding := query("direct.example", dns.TypeHTTPS)
				require.IsType(t, &dns.HTTPS{}, binding.Answer[0])
				require.NotEmpty(t, binding.Extra, "direct service binding records stay intact")
				require.Equal(t, dns.RcodeRefused, query("blocked.example", dns.TypeAAAA).Rcode)
				reply := query("direct.example", dns.TypeAAAA)
				require.Equal(t, "2001:db8::9", reply.Answer[0].(*dns.AAAA).AAAA.String())
			}
			require.Equal(t, cfg.Core.IPv6Network, engine.Snapshot().Config.Core.IPv6Network)
			require.False(t, engine.Snapshot().Config.Core.AutoRoute6)
		})
	}
}

func TestSavedDomainRuleDefaultsAndSimulationIdentifyFinalOverHTTP(t *testing.T) {
	c, err := control.New(control.Options{Directory: t.TempDir()})
	require.NoError(t, err)
	defer c.Close()
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := server.Client()
	// Real Argon2id setup can be slow with race/coverage instrumentation.
	client.Timeout = 15 * time.Second
	var cookie *http.Cookie
	csrf := ""
	call := func(method, path string, value any) map[string]any {
		var body io.Reader
		if value != nil {
			data, err := json.Marshal(value)
			require.NoError(t, err)
			body = bytes.NewReader(data)
		}
		request, err := http.NewRequest(method, server.URL+"/api/v1/"+path, body)
		require.NoError(t, err)
		if cookie != nil {
			request.AddCookie(cookie)
			request.Header.Set("X-CSRF-Token", csrf)
		}
		response, err := client.Do(request)
		require.NoError(t, err)
		defer response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode)
		if cookies := response.Cookies(); len(cookies) > 0 {
			cookie = cookies[0]
		}
		var result map[string]any
		require.NoError(t, json.NewDecoder(response.Body).Decode(&result))
		if token, ok := result["csrf_token"].(string); ok {
			csrf = token
		}
		return result
	}
	call("POST", "session", map[string]any{"token": c.BootstrapToken()})
	call("POST", "auth/password", map[string]any{"password": "domain-rules-owner", "confirm_password": "domain-rules-owner"})
	client.Timeout = 3 * time.Second
	doc := call("GET", "config", nil)
	config := doc["config"].(map[string]any)
	config["outbounds"] = []map[string]any{{"name": "office", "url": "http://127.0.0.1:8080"}}
	config["rules"] = []map[string]any{{"id": "explicit-final", "type": "FINAL", "outbound": "reject"}}
	doc = call("PUT", "config", map[string]any{"base_version": doc["version"], "config": config, "inbound": doc["inbound"]})
	added := call("POST", "rules/exact", map[string]any{"base_version": doc["version"], "target": "example.com", "outbound": "office"})
	doc = call("GET", "config", nil)
	rules := doc["config"].(map[string]any)["rules"].([]any)
	require.Empty(t, rules[0].(map[string]any)["protocol"])
	require.Empty(t, rules[0].(map[string]any)["ports"])
	for _, protocol := range []string{"tcp", "udp"} {
		for _, port := range []uint16{53, 80, 443} {
			matched := call("POST", "rules/simulate", map[string]any{"target": "example.com", "protocol": protocol, "port": port})
			require.Equal(t, added["rule_id"], matched["rule_id"])
			require.Equal(t, "DOMAIN", matched["rule_type"])
			require.Equal(t, float64(1), matched["rule_order"])
			require.Equal(t, "office", matched["outbound"])
		}
	}
	fallback := call("POST", "rules/simulate", map[string]any{"target": "unmatched.example", "protocol": "tcp", "port": 443})
	require.Equal(t, "explicit-final", fallback["rule_id"])
	require.Equal(t, "FINAL", fallback["rule_type"])
	require.Equal(t, "FINAL", fallback["rule_name"])
	require.Equal(t, float64(2), fallback["rule_order"])
	protected := call("POST", "rules/simulate", map[string]any{"target": "127.0.0.1", "protocol": "tcp", "port": 443})
	require.Equal(t, "PROTECTED", protected["rule_type"])
	require.Equal(t, true, protected["protected"])
	config = doc["config"].(map[string]any)
	config["rules"] = rules[:1]
	call("PUT", "config", map[string]any{"base_version": doc["version"], "config": config, "inbound": doc["inbound"]})
	fallback = call("POST", "rules/simulate", map[string]any{"target": "unmatched.example", "protocol": "tcp", "port": 443})
	require.Equal(t, "builtin:default", fallback["rule_id"])
	require.Equal(t, "FINAL", fallback["rule_type"])
	require.Equal(t, "Default direct", fallback["rule_name"])
	require.Equal(t, float64(0), fallback["rule_order"])
	doc = call("GET", "config", nil)
	config = doc["config"].(map[string]any)
	config["rules"] = append(config["rules"].([]any), map[string]any{"id": "legacy-final", "type": "FINAL", "protocol": "udp", "ports": []int{53}, "outbound": "reject"})
	call("PUT", "config", map[string]any{"base_version": doc["version"], "config": config, "inbound": doc["inbound"]})
	fallback = call("POST", "rules/simulate", map[string]any{"target": "unmatched.example", "protocol": "udp", "port": 53})
	require.Equal(t, "legacy-final", fallback["rule_id"])
	require.Equal(t, "FINAL", fallback["rule_type"])
	require.Equal(t, "reject", fallback["outbound"])
	fallback = call("POST", "rules/simulate", map[string]any{"target": "unmatched.example", "protocol": "tcp", "port": 443})
	require.Equal(t, "builtin:default", fallback["rule_id"], "imported conditional FINAL keeps its old scope")
	require.Equal(t, "paused", c.State().State)
	require.Empty(t, c.Operations(), "rule simulation never opens a diagnostic connection")
}
