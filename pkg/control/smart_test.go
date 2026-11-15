package control

import (
	"context"
	"errors"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
	"testing"
	"time"
)

type smartMemoryEngine struct {
	*memoryEngine
	evidence    kone.SmartSuggestion
	calls       int
	dataError   error
	actionError error
	failCall    int
}

func (e *smartMemoryEngine) SmartData() (kone.SmartState, error) {
	if e.dataError != nil {
		return kone.SmartState{}, e.dataError
	}
	return kone.SmartState{Enabled: true, Status: "observing", Suggestions: []kone.SmartSuggestion{e.evidence}}, nil
}
func (e *smartMemoryEngine) SmartAction(r kone.SmartAction) (kone.SmartActionResult, error) {
	e.calls++
	if e.actionError != nil && (e.failCall == 0 || e.calls == e.failCall) {
		return kone.SmartActionResult{}, e.actionError
	}
	return kone.SmartActionResult{Suggestion: &e.evidence}, nil
}
func TestSmartPreviewAcceptanceIsVersionedAndKeepsUserRules(t *testing.T) {
	engine := &smartMemoryEngine{memoryEngine: newMemoryEngine()}
	c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) { return engine, nil }})
	cfg := currentRequest(c)
	policy := cfg.Config["policy"].(map[string]any)
	policy["smart"] = map[string]any{"enabled": true}
	cfg.Config["outbounds"] = []map[string]any{{"id": "office-id", "name": "office", "url": "socks5://127.0.0.1:1080"}}
	cfg.Config["rules"] = []map[string]any{{"id": "manual", "type": "DOMAIN", "pattern": "manual.example", "outbound": "direct"}, {"id": "final", "type": "FINAL", "outbound": "direct"}}
	_, err := c.Save(cfg)
	require.NoError(t, err)
	enable(t, c)
	require.NoError(t, c.Start(context.Background()))
	token := owner(t, c)
	version := c.doc.Version
	engine.evidence = kone.SmartSuggestion{ID: "evidence", Domain: "service.example", Status: "ready", Action: "proxy", OutboundID: "office-id", ConfigVersion: version, Port: 443, Protocol: "tcp+tls", ExpiresAt: time.Now().Add(time.Minute)}
	preview := request(t, c, token, "POST", "/api/v1/smart", kone.SmartAction{Action: "preview", ID: "evidence", Version: version})
	require.Equal(t, 200, preview.Code, preview.Body.String())
	require.Equal(t, version, c.doc.Version)
	accepted := request(t, c, token, "POST", "/api/v1/smart", kone.SmartAction{Action: "accept", ID: "evidence", Version: version})
	require.Equal(t, 200, accepted.Code, accepted.Body.String())
	require.Equal(t, version+1, c.doc.Version)
	require.Equal(t, 3, engine.calls)
	rules := c.doc.Config.Rule
	require.Len(t, rules, 3)
	require.Equal(t, "manual", rules[0].ID)
	require.Equal(t, "service.example", rules[1].Pattern)
	require.Equal(t, []uint16{443}, rules[1].Ports)
	require.Equal(t, "tcp", rules[1].Protocol)
	require.Equal(t, "office", rules[1].Outbound)
	require.Equal(t, "final", rules[2].ID)
	repeated := request(t, c, token, "POST", "/api/v1/smart", kone.SmartAction{Action: "accept", ID: "evidence", Version: version})
	require.Equal(t, 409, repeated.Code)
	cfg = currentRequest(c)
	cfg.Config["policy"].(map[string]any)["smart"] = map[string]any{"enabled": false}
	_, err = c.Save(cfg)
	require.NoError(t, err)
	require.Equal(t, rules, c.doc.Config.Rule)
}
func TestLayeredMigrationKeepsLegacyOrderUntilConfirmed(t *testing.T) {
	cfg := kone.DefaultConfig()
	cfg.Policy.Mode = "direct-first"
	cfg.Rule = []kone.RuleConfig{{ID: "ip", Source: "user", Schema: "IP-CIDR", Pattern: "8.8.8.8/32", Outbound: "direct"}, {ID: "domain", Source: "user", Schema: "DOMAIN", Pattern: "service.example", Outbound: "reject"}, {ID: "final", Schema: "FINAL", Outbound: "direct"}}
	current := Document{Version: 7, Config: cfg}
	input := policyRequest{BaseVersion: 7, Mode: "direct-first"}
	save, err := preparePolicy(input, current)
	require.NoError(t, err)
	prepared, err := prepareDocument(save, current)
	require.NoError(t, err)
	require.Zero(t, prepared.Config.Policy.RuleVersion)
	require.Equal(t, cfg.Core.Network, prepared.Config.Core.Network)
	input.UpgradeRules = true
	save, err = preparePolicy(input, current)
	require.NoError(t, err)
	prepared, err = prepareDocument(save, current)
	require.NoError(t, err)
	require.Equal(t, uint(2), prepared.Config.Policy.RuleVersion)
	require.True(t, prepared.Config.DNS.PersistentFakeIP)
	require.NotEqual(t, cfg.Core.Network, prepared.Config.Core.Network)
	require.NotEmpty(t, prepared.Config.DNS.RetiredPools)
	require.Equal(t, cfg.Rule[:2], prepared.Config.Rule[:2])
	require.Len(t, crossPoolChanges(cfg.Rule), 1)
	require.Zero(t, current.Config.Policy.RuleVersion)
}

func TestSmartHTTPRejectsUnavailableStaleAndInvalidEvidenceWithoutSaving(t *testing.T) {
	engine := &smartMemoryEngine{memoryEngine: newMemoryEngine()}
	c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) { return engine, nil }})
	token := owner(t, c)
	paused := request(t, c, token, "GET", "/api/v1/smart", nil)
	require.Equal(t, 200, paused.Code)
	require.Contains(t, paused.Body.String(), `"status":"paused"`)
	require.Equal(t, 409, request(t, c, token, "POST", "/api/v1/smart", kone.SmartAction{Action: "clear"}).Code)
	cfg := currentRequest(c)
	cfg.Config["policy"].(map[string]any)["smart"] = map[string]any{"enabled": true}
	_, err := c.Save(cfg)
	require.NoError(t, err)
	enable(t, c)
	require.NoError(t, c.Start(t.Context()))
	version := c.doc.Version
	valid := kone.SmartSuggestion{ID: "evidence", Domain: "service.example", Status: "ready", Action: "direct", ConfigVersion: version, Port: 443, Protocol: "tcp+tls"}
	engine.evidence = valid
	require.Equal(t, 200, request(t, c, token, "GET", "/api/v1/smart", nil).Code)
	engine.dataError = errors.New("owner unavailable")
	require.Equal(t, 503, request(t, c, token, "GET", "/api/v1/smart", nil).Code)
	engine.dataError = nil
	require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/smart", "not an object").Code)
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/smart", kone.SmartAction{Action: "clear"}).Code)
	for _, scenario := range []string{"owner-failure", "wrong-version", "wrong-port", "missing-proxy", "unknown-action", "invalid-domain", "changed-before-save", "invalid-save", "external-edit"} {
		t.Run(scenario, func(t *testing.T) {
			engine.evidence = valid
			engine.actionError = nil
			engine.failCall = 0
			engine.reloadError = nil
			expected := 409
			switch scenario {
			case "owner-failure":
				engine.actionError = errors.New("expired evidence")
			case "wrong-version":
				engine.evidence.ConfigVersion++
			case "wrong-port":
				engine.evidence.Port = 80
			case "missing-proxy":
				engine.evidence.Action = "proxy"
				engine.evidence.OutboundID = "deleted-id"
			case "unknown-action":
				engine.evidence.Action = "unknown"
			case "invalid-domain":
				engine.evidence.Domain = "bad domain"
				expected = 400
			case "changed-before-save":
				engine.actionError = errors.New("network changed")
				engine.failCall = engine.calls + 2
			case "invalid-save":
				engine.evidence.Domain = "bad domain"
				expected = 400
			case "external-edit":
				changed := cloneDocument(c.doc)
				changed.Version++
				require.NoError(t, writeDocument(c.settingsPath(), changed))
				defer func() { require.NoError(t, writeDocument(c.settingsPath(), c.doc)) }()
			}
			action := "accept"
			if scenario == "invalid-domain" {
				action = "preview"
			}
			response := request(t, c, token, "POST", "/api/v1/smart", kone.SmartAction{Action: action, ID: valid.ID, Version: version})
			require.Equal(t, expected, response.Code, response.Body.String())
			require.Equal(t, version, c.doc.Version)
			for _, rule := range c.doc.Config.Rule {
				require.NotEqual(t, "smart", rule.Source)
			}
		})
	}
}
