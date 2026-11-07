package integration

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestSystemLifecycleLiveCIDRRoutes(t *testing.T) {
	cfg := ipv6SystemConfig(t) // Requires the CI-owned isolated network namespace.
	proxy := localConnectProxy(t, "live-route")
	cfg.Outbounds = []kone.OutboundConfig{{Name: "live", URL: proxy.URL}}
	one, cancel, done := systemStart(t, cfg)
	defer func() { cancel(); require.NoError(t, systemWait(t, done)); noSystemInterface(t, cfg) }()
	updated := one.Snapshot().Config
	updated.Rule = []kone.RuleConfig{
		{Schema: "IP-CIDR", Pattern: "203.0.113.0/24", Outbound: "live"},
		{Schema: "IP-CIDR6", Pattern: "2001:db8:123::/64", Outbound: "reject"},
	}
	require.NoError(t, one.Reload(updated))
	require.Contains(t, systemCommand(t, "route", "show", "dev", cfg.Core.Tun), "203.0.113.0/24")
	require.Contains(t, systemCommand(t, "-6", "route", "show", "dev", cfg.Core.Tun), "2001:db8:123::/64")
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("http://203.0.113.10/")
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, "live-route", string(body))
	updated.Rule = nil
	require.NoError(t, one.Reload(updated))
	require.Eventually(t, func() bool {
		return !strings.Contains(systemCommand(t, "route", "show", "dev", cfg.Core.Tun), "203.0.113.0/24")
	}, 3*time.Second, 20*time.Millisecond)
	require.NotContains(t, systemCommand(t, "-6", "route", "show", "dev", cfg.Core.Tun), "2001:db8:123::/64")
}

// Global capture must route raw IP traffic through the selected default; no
// client proxy configuration or public endpoint is involved in this fixture.
func TestSystemLifecycleGlobalPolicyAndPausedTransition(t *testing.T) {
	cfg := ipv6SystemConfig(t)
	upstream := localConnectProxy(t, "global-policy")
	cfg.Policy = kone.PolicyConfig{Mode: "proxy-first"}
	cfg.Core.AutoRoute, cfg.Core.AutoRoute6 = true, true
	cfg.Outbounds = []kone.OutboundConfig{{Name: "global", URL: upstream.URL}}
	cfg.Rule = []kone.RuleConfig{{Schema: "FINAL", Outbound: "global"}}
	one, cancel, done := systemStart(t, cfg)
	defer func() { cancel(); require.NoError(t, systemWait(t, done)); noSystemInterface(t, cfg) }()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for _, target := range []string{"http://203.0.113.10/", "http://[2001:db8:123::10]/"} {
		response, err := client.Get(target)
		require.NoError(t, err, target)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		require.NoError(t, err)
		require.Equal(t, "global-policy", string(body))
	}
	next := one.Snapshot().Config
	next.Policy.Mode = "direct-first"
	next.Rule[0].Outbound = "direct"
	require.Error(t, one.Reload(next), "changing the protection/capture plan must require a pause")
	require.Equal(t, "proxy-first", one.Snapshot().Config.Policy.Mode)
}
