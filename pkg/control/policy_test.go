package control

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestPolicyPreviewApplyConflictAndPausedMigration(t *testing.T) {
	c := testController(t, Options{})
	cfg := currentRequest(c)
	cfg.Config["outbounds"] = []map[string]any{{"name": "upstream", "url": "http://127.0.0.1:7078", "udp-fallback": "direct"}}
	cfg.Config["rules"] = []map[string]any{{"id": "exception", "type": "DOMAIN", "pattern": "internal.example", "outbound": "direct"}, {"id": "fallback", "type": "FINAL", "outbound": "direct"}}
	_, err := c.Save(cfg)
	require.NoError(t, err)
	token := owner(t, c)
	input := policyRequest{BaseVersion: c.doc.Version, Mode: "proxy-first", Outbound: "upstream", Interface: "test-uplink", IPv4Only: true}
	require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/policy/preview", input).Code)
	input.UDPException = true
	state := request(t, c, token, "GET", "/api/v1/policy", nil)
	require.Equal(t, 200, state.Code)
	var policy map[string]any
	require.NoError(t, json.Unmarshal(state.Body.Bytes(), &policy))
	require.Equal(t, "direct-first", policy["mode"])
	preview := request(t, c, token, "POST", "/api/v1/policy/preview", input)
	require.Equal(t, 200, preview.Code, preview.Body.String())
	require.Equal(t, input.BaseVersion, c.doc.Version, "preview cannot save or enable capture")
	require.Equal(t, "paused", c.State().DataState)
	var plan map[string]any
	require.NoError(t, json.Unmarshal(preview.Body.Bytes(), &plan))
	require.Equal(t, "direct_exception", plan["udp"])
	require.Equal(t, 200, request(t, c, token, "PUT", "/api/v1/policy", input).Code)
	require.Equal(t, "paused", c.State().DataState)
	require.Equal(t, "proxy-first", c.doc.Config.Policy.Mode)
	require.True(t, c.doc.Config.Core.AutoRoute)
	require.Equal(t, "exception", c.doc.Config.Rule[0].ID)
	require.Equal(t, "fallback", c.doc.Config.Rule[1].ID)
	require.Equal(t, "upstream", c.doc.Config.Rule[1].Outbound)
	require.Equal(t, 409, request(t, c, token, "PUT", "/api/v1/policy", input).Code)
	input.BaseVersion = c.doc.Version
	input.RejectUDP = true
	preview = request(t, c, token, "POST", "/api/v1/policy/preview", input)
	require.Equal(t, 200, preview.Code)
	require.NoError(t, json.Unmarshal(preview.Body.Bytes(), &plan))
	require.Equal(t, "rejected", plan["udp"])
	require.Equal(t, "direct", c.doc.Config.Outbounds[0].UDPFallback, "preview cannot alter a shared outbound")
	require.Equal(t, 200, request(t, c, token, "PUT", "/api/v1/policy", input).Code)
	require.Equal(t, "reject", c.doc.Config.Outbounds[0].UDPFallback)
	require.False(t, c.doc.Config.Policy.UDPException)
	input.BaseVersion = c.doc.Version
	input.Mode = "direct-first"
	require.Equal(t, 200, request(t, c, token, "PUT", "/api/v1/policy", input).Code)
	require.False(t, c.doc.Config.Core.AutoRoute)
	require.Equal(t, "exception", c.doc.Config.Rule[0].ID)
	require.Equal(t, kone.BuiltinDirect, c.doc.Config.Rule[1].Outbound)
}

func TestPolicyRejectsMalformedIntentWithoutMutation(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	before := cloneDocument(c.doc)
	for _, input := range []any{
		map[string]any{"unknown": true},
		policyRequest{BaseVersion: before.Version, Mode: "invalid"},
		policyRequest{BaseVersion: before.Version, Mode: "proxy-first", Outbound: "missing", Interface: "eth0", IPv4Only: true},
	} {
		require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/policy/preview", input).Code)
		require.Equal(t, before.Version, c.doc.Version)
		require.Equal(t, "paused", c.State().DataState)
	}
	_, err := preparePolicy(policyRequest{BaseVersion: 1, Mode: "direct-first"}, Document{Version: 1})
	require.ErrorContains(t, err, "invalid")
}

func TestPolicyProtectionDescribesTransportsWithoutCredentialsOrQueries(t *testing.T) {
	cfg := kone.DefaultConfig()
	cfg.Outbounds = []kone.OutboundConfig{{Name: "private", URL: "http://username:secret@proxy.example:7078"}}
	cfg.DNS.Servers = []string{"192.168.1.1:53"}
	cfg.DNS.Rules = []kone.DNSRouteConfig{{Suffix: "corp.example", Servers: []string{"10.8.0.1:53"}, Interface: "vpn0"}}
	items := policyProtection(cfg)
	require.Contains(t, items, kone.ProtectedNetwork{Prefix: "proxy.example:7078", Kind: "proxy_endpoint"})
	require.Contains(t, items, kone.ProtectedNetwork{Prefix: "10.8.0.1:53", Interface: "vpn0", Kind: "dns_transport"})
	encoded, err := json.Marshal(items)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "secret")
	require.NotContains(t, string(encoded), "username")
	for _, item := range items {
		require.NotEqual(t, "local_network", item.Kind, "legacy profiles must not claim protections they do not apply")
	}
	cfg.Policy.Mode = "custom"
	require.Equal(t, items, policyProtection(cfg))
	cfg.Policy.Mode = "direct-first"
	require.Contains(t, policyProtection(cfg), kone.ProtectedNetwork{Prefix: "127.0.0.0/8", Kind: "local_network"})
}

func TestPolicyCustomConversionAndNativeUDPScope(t *testing.T) {
	c := testController(t, Options{})
	current := cloneDocument(c.doc)
	current.Config.Policy.Mode = "" // Existing profiles have no policy metadata.
	current.Config.Rule = []kone.RuleConfig{{ID: "custom", Schema: "FINAL", Outbound: "direct", Protocol: "tcp", Ports: []uint16{443}}}
	input := policyRequest{BaseVersion: current.Version, Mode: "direct-first"}
	_, err := preparePolicy(input, current)
	require.ErrorContains(t, err, "explicitly confirm")
	input.ConvertCustom = true
	save, err := preparePolicy(input, current)
	require.NoError(t, err)
	next, err := prepareDocument(save, current)
	require.NoError(t, err)
	require.Equal(t, "custom", next.Config.Rule[0].ID)
	require.Empty(t, next.Config.Rule[0].Protocol)
	require.Empty(t, next.Config.Rule[0].Ports)
	current.Config.Outbounds = []kone.OutboundConfig{{Name: "socks", URL: "socks5://127.0.0.1:1080", UDPFallback: "direct"}}
	input.Mode, input.Outbound, input.Interface, input.IPv4Only = "proxy-first", "socks", "test-uplink", true
	_, err = preparePolicy(input, current)
	require.NoError(t, err, "native UDP does not use the configured TCP-only fallback")
}
