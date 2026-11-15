package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestSystemDNSLayeredPersistentIdentityAndPinnedProxyTarget(t *testing.T) {
	cfg := systemConfig(t)
	cfg.Policy.RuleVersion = 2
	cfg.DNS.PersistentFakeIP = true
	cfg.DNS.RetiredPools = []string{"10.209.0.0/24"}
	upstream := domainRuleDNSListeners(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg).SetReply(r)
		for _, ip := range []string{"203.0.113.9", "198.51.100.9"} {
			reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)})
		}
		_ = w.WriteMsg(reply)
	}))
	targets := make(chan string, 8)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targets <- r.Host
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		request, err := http.ReadRequest(buf.Reader)
		if err != nil {
			return
		}
		request.Body.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\npinned")
	}))
	defer proxy.Close()
	cfg.DNS.Servers = []string{upstream["udp"]}
	cfg.Outbounds = []kone.OutboundConfig{{Name: "office", URL: proxy.URL}}
	cfg.Rule = []kone.RuleConfig{{ID: "selected-ip", Schema: "IP-CIDR", Pattern: "198.51.100.9/32", Outbound: "office"}, {Schema: "FINAL", Outbound: "direct"}}
	directory := filepath.Join(t.TempDir(), "ownership")
	identities := map[string]string{}
	for run := range 2 {
		one, err := kone.FromConfig(cfg, kone.WithFakeIPDirectory(directory))
		require.NoError(t, err)
		ctx, stop := context.WithCancel(t.Context())
		t.Cleanup(func() { stop(); one.Close() })
		done := make(chan error, 1)
		go func() { done <- one.Run(ctx) }()
		select {
		case <-one.Ready():
		case err := <-done:
			t.Fatalf("start: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("ready timeout")
		}
		names := []string{"site-120.example", "site-201.example"}
		if run == 1 {
			names[0], names[1] = names[1], names[0]
		}
		for _, name := range names {
			reply, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(new(dns.Msg).SetQuestion(name+".", dns.TypeA), fmt.Sprintf("10.203.0.1:%d", cfg.DNS.ListenPort))
			require.NoError(t, err)
			require.Len(t, reply.Answer, 1)
			fake := reply.Answer[0].(*dns.A).A.String()
			if run == 0 {
				identities[name] = fake
			} else {
				require.Equal(t, identities[name], fake)
			}
			client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 3 * time.Second}
			response, err := client.Get("http://" + net.JoinHostPort(fake, "80") + "/")
			require.NoError(t, err)
			data, err := io.ReadAll(response.Body)
			response.Body.Close()
			require.NoError(t, err)
			require.Equal(t, "pinned", string(data))
			require.Equal(t, "198.51.100.9:80", <-targets)
		}
		stop()
		require.NoError(t, systemWait(t, done))
		require.NoError(t, one.Close())
		noSystemInterface(t, cfg)
	}
	require.NotEqual(t, identities["site-120.example"], identities["site-201.example"])
}
