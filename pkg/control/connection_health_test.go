package control

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
	"os"
	"testing"
	"time"
)

type healthMemoryEngine struct {
	*memoryEngine
	ledger      *kone.HealthLedger
	suggestions map[uint16]string
}

func (e *healthMemoryEngine) HealthData(q kone.HealthQuery) (kone.HealthState, error) {
	rows, total := e.ledger.Filtered(q.Offset, q.Limit, q.Status, q.Search)
	for i := range rows {
		rows[i].Suggestions = e.suggestions
	}
	return kone.HealthState{Status: "running", Entries: rows, Total: total}, nil
}
func (e *healthMemoryEngine) HealthAction(a kone.HealthAction) (kone.HealthIncident, error) {
	rows, _ := e.ledger.Filtered(0, 100, "", a.Domain)
	for _, row := range rows {
		if row.Domain == a.Domain && row.Generation == a.Generation {
			if a.Action == "handled" {
				return row, e.ledger.Resolve(a.Domain, a.Scope, a.Generation, "user", time.Now())
			}
			row.Suggestions = e.suggestions
			return row, nil
		}
	}
	return kone.HealthIncident{}, ErrConflict
}
func TestHealthPinUsesVersionedTransactionAndKeepsManualRules(t *testing.T) {
	ledger, _ := kone.OpenHealthLedger("")
	entry, err := ledger.Observe("service.example", "", "web_unreachable", kone.HealthResult{Protocol: "tcp", Port: 443, Status: "failed", Source: "probe", Time: time.Now()})
	require.NoError(t, err)
	engine := &healthMemoryEngine{memoryEngine: newMemoryEngine(), ledger: ledger, suggestions: map[uint16]string{443: "office"}}
	c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) { return engine, nil }})
	cfg := currentRequest(c)
	cfg.Config["outbounds"] = []map[string]any{{"id": "office-id", "name": "office", "url": "http://127.0.0.1:1080"}}
	cfg.Config["rules"] = []map[string]any{{"id": "manual", "type": "DOMAIN", "pattern": "manual.example", "outbound": "direct"}, {"id": "final", "type": "FINAL", "outbound": "direct"}}
	_, err = c.Save(cfg)
	require.NoError(t, err)
	enable(t, c)
	require.NoError(t, c.Start(context.Background()))
	token := owner(t, c)
	version := c.doc.Version
	response := request(t, c, token, "GET", "/api/v1/connection-health?status=attention", nil)
	require.Equal(t, 200, response.Code, response.Body.String())
	response = request(t, c, token, "POST", "/api/v1/connection-health", kone.HealthAction{Action: "pin", Domain: entry.Domain, Generation: entry.Generation, Version: version})
	require.Equal(t, 200, response.Code, response.Body.String())
	require.Equal(t, version+1, c.doc.Version)
	require.Equal(t, "manual", c.doc.Config.Rule[0].ID)
	require.Equal(t, "office", c.doc.Config.Rule[1].Outbound)
	require.Equal(t, []uint16{443}, c.doc.Config.Rule[1].Ports)
	require.Equal(t, "user", c.doc.Config.Rule[1].Source)
	repeat := request(t, c, token, "POST", "/api/v1/connection-health", kone.HealthAction{Action: "pin", Domain: entry.Domain, Generation: entry.Generation, Version: version})
	require.Equal(t, 409, repeat.Code)
}
func TestPausedHealthHistoryPersistsAcknowledgementAndReportsCorruption(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	entry := kone.HealthIncident{ID: 1, Generation: 3, Domain: "x.com", Status: "attention", Reason: "dns_failed", First: time.Now(), Last: time.Now()}
	data, _ := json.Marshal(kone.HealthState{Entries: []kone.HealthIncident{entry}, Total: 1})
	require.NoError(t, atomicWrite(c.healthArchivePath(), data))
	response := request(t, c, token, "GET", "/api/v1/connection-health?status=attention", nil)
	require.Equal(t, 200, response.Code)
	require.Contains(t, response.Body.String(), "x.com")
	response = request(t, c, token, "POST", "/api/v1/connection-health", kone.HealthAction{Action: "handled", Domain: "x.com", Generation: 3})
	require.Equal(t, 200, response.Code, response.Body.String())
	state, err := c.archivedHealth()
	require.NoError(t, err)
	require.Equal(t, "history", state.Entries[0].Status)
	require.Equal(t, "user", state.Entries[0].Resolution)
	response = request(t, c, token, "GET", "/api/v1/connection-health?status=attention", nil)
	require.Equal(t, 200, response.Code)
	require.NotContains(t, response.Body.String(), "x.com")
	require.NoError(t, os.WriteFile(c.healthArchivePath(), []byte("bad"), 0600))
	response = request(t, c, token, "GET", "/api/v1/connection-health", nil)
	require.Equal(t, 503, response.Code)
}
func TestHealthRulePinDoesNotDuplicateOrOverwriteExactConflict(t *testing.T) {
	cfg := kone.DefaultConfig()
	cfg.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: "x.com", Protocol: "tcp", Ports: []uint16{443}, Outbound: "direct"}, {Schema: "FINAL", Outbound: "direct"}}
	doc := Document{Version: 7, Config: cfg}
	_, err := healthRuleSave(doc, kone.HealthIncident{Domain: "x.com", Suggestions: map[uint16]string{443: "office"}})
	require.Error(t, err)
	save, err := healthRuleSave(doc, kone.HealthIncident{Domain: "x.com", Suggestions: map[uint16]string{443: "direct"}})
	require.NoError(t, err)
	require.Len(t, save.Config["rules"], 2)
}

func TestHealthMirrorPagesAndPreservesPausedAcknowledgements(t *testing.T) {
	ledger, _ := kone.OpenHealthLedger("")
	var first kone.HealthIncident
	for i := 0; i < 105; i++ {
		entry, err := ledger.Observe(fmt.Sprintf("site-%d.example", i), "", "dns_failed", kone.HealthResult{Protocol: "dns", Source: "business", Status: "failed", Time: time.Now()})
		require.NoError(t, err)
		if i == 0 {
			first = entry
		}
	}
	c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) {
		return &healthMemoryEngine{memoryEngine: newMemoryEngine(), ledger: ledger}, nil
	}})
	enable(t, c)
	require.NoError(t, c.Start(context.Background()))
	token := owner(t, c)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { c.mirrorConnectionHealth(ctx); close(done) }()
	require.Eventually(t, func() bool { state, err := c.archivedHealth(); return err == nil && len(state.Entries) == 105 }, 4*time.Second, 10*time.Millisecond)
	require.NoError(t, c.Pause(t.Context()))
	response := request(t, c, token, "POST", "/api/v1/connection-health", kone.HealthAction{Action: "handled", Domain: first.Domain, Generation: first.Generation})
	require.Equal(t, 200, response.Code, response.Body.String())
	require.NoError(t, c.Start(t.Context()))
	require.Eventually(t, func() bool { rows, _ := ledger.Filtered(0, 100, "attention", first.Domain); return len(rows) == 0 }, 4*time.Second, 10*time.Millisecond)
	cancel()
	<-done
}
