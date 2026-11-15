package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestFreshReadinessOnlyBlocksOnInvalidEnvironment(t *testing.T) {
	c := testController(t, Options{Preflight: func(context.Context, *kone.KoneConfig) kone.PreflightReport {
		return kone.PreflightReport{Ready: false, Issues: []kone.PreflightIssue{{Code: "outbound_interface", Severity: "error", Message: "physical interface unavailable"}, {Code: "network_overlap", Severity: "error", Message: "TUN network overlaps"}}}
	}})
	require.Equal(t, "paused", c.State().State)
	require.True(t, c.doc.Inbound.Enabled)
	require.Empty(t, c.doc.Config.Core.Tun, "platform backend allocates an available native name (utunN on macOS)")
	require.NoError(t, c.doc.Config.Validate())
	require.Empty(t, c.doc.Config.DNS.Servers)
	require.Equal(t, kone.BuiltinDirect, c.doc.Config.Rule[0].Outbound)
	report := c.Readiness(t.Context())
	require.False(t, report.Ready)
	require.Len(t, report.Blockers, 2)
	require.True(t, report.DirectOnly)
	require.False(t, report.DirectOnlyConfirmed)
	for _, issue := range report.Blockers {
		require.NotEmpty(t, issue.Page)
		require.NotEmpty(t, issue.Action)
		require.NotEmpty(t, issue.ID)
	}
	err := c.Start(t.Context())
	require.Error(t, err)
	require.NotContains(t, err.Error(), "direct-only")
	require.ErrorContains(t, err, "physical interface unavailable")
	require.ErrorContains(t, err, "TUN network overlaps")
	require.Nil(t, c.engine)
	require.NoFileExists(t, c.journalPath())
}

func TestDirectOnlyStartsWithoutConfirmationAndPreservesLegacyProfiles(t *testing.T) {
	c := testController(t, Options{})
	require.Empty(t, c.doc.Config.Outbounds)
	require.False(t, c.doc.Config.Core.AutoRoute)
	require.False(t, c.doc.Config.Core.AutoRoute6)
	require.Equal(t, kone.SupportsSystemDNS(), c.doc.Config.DNS.System)
	require.Len(t, c.doc.Config.Rule, 1, "no user rules; only the default direct fallback")
	rules := kone.NewRule(c.doc.Config.Rule, c.doc.Config.Outbounds)
	for _, protocol := range []string{"", "tcp", "udp"} {
		decision := rules.Decide("example.net", protocol, 443)
		require.Equal(t, kone.BuiltinDirect, decision.Outbound)
		require.False(t, decision.CaptureOnly)
	}
	require.True(t, c.Readiness(t.Context()).Ready)
	require.NoError(t, c.Start(t.Context()), "native tray and HTTP both accept default direct routing")
	require.NoError(t, c.Pause(t.Context()))
	request := currentRequest(c)
	yes := true
	request.DirectOnlyConfirmed = &yes
	_, err := c.Save(request)
	require.NoError(t, err)
	require.True(t, c.Readiness(t.Context()).Ready)
	require.NoError(t, c.Start(t.Context()))
	require.NoError(t, c.Pause(t.Context()))
	saved, err := readDocument(c.settingsPath())
	require.NoError(t, err)
	require.True(t, saved.DirectOnlyConfirmed)

	directory := t.TempDir()
	cfg := kone.DefaultConfig()
	cfg.Core.Network = "10.206.0.1/24"
	text, err := toml.Marshal(cfg)
	require.NoError(t, err)
	legacy, err := json.Marshal(map[string]any{"version": uint64(9), "toml": string(text), "inbound": Inbound{ID: "tun-main", Name: "Existing gateway", Enabled: true}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, "settings.json"), legacy, 0600))
	again := testController(t, Options{Directory: directory})
	require.True(t, again.doc.DirectOnlyConfirmed)
	require.Equal(t, "10.206.0.1/24", again.doc.Config.Core.Network)
	require.Equal(t, "Existing gateway", again.doc.Inbound.Name)
	require.NoError(t, again.Start(t.Context()))
}

func TestRunningCaptureRejectsNetworkChangesAndHotApplyCanRetryTheSavedVersion(t *testing.T) {
	engine := newMemoryEngine()
	c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) { return engine, nil }})
	enable(t, c)
	require.NoError(t, c.Start(t.Context()))
	require.True(t, c.State().CaptureLocked)
	before, err := os.ReadFile(c.settingsPath())
	require.NoError(t, err)
	request := currentRequest(c)
	request.Config["core"].(map[string]any)["network"] = "10.207.0.1/24"
	_, err = c.Save(request)
	require.ErrorIs(t, err, ErrCaptureLocked)
	after, err := os.ReadFile(c.settingsPath())
	require.NoError(t, err)
	require.Equal(t, before, after)
	request = currentRequest(c)
	request.Inbound.Name = "Changed TUN"
	_, err = c.Save(request)
	require.ErrorIs(t, err, ErrCaptureLocked)
	request = currentRequest(c)
	request.Config["dns"].(map[string]any)["read-timeout"] = uint(9)
	_, err = c.Save(request)
	require.ErrorIs(t, err, ErrCaptureLocked)

	old := c.State().RunningVersion
	engine.reloadError = errors.New("injected reload failure")
	request = currentRequest(c)
	request.Config["rules"] = []any{map[string]any{"type": "DOMAIN", "pattern": "blocked.example", "outbound": "reject"}, map[string]any{"type": "FINAL", "outbound": "direct"}}
	result, err := c.Save(request)
	require.NoError(t, err)
	require.Equal(t, false, result["applied"])
	require.Contains(t, result["apply_error"], "injected reload failure")
	require.Equal(t, old, c.State().RunningVersion)
	require.Greater(t, c.State().SavedVersion, old)
	engine.reloadError = nil
	require.NoError(t, c.Apply(t.Context()))
	require.Equal(t, c.State().SavedVersion, c.State().RunningVersion)
	require.Equal(t, c.State().SavedVersion, c.State().ConfirmedVersion)
	require.Empty(t, c.State().LastError)

	request = currentRequest(c)
	request.Config["rules"] = []any{map[string]any{"type": "FINAL", "outbound": "direct"}}
	result, err = c.Save(request)
	require.NoError(t, err)
	require.Equal(t, true, result["applied"])
	require.Equal(t, c.State().SavedVersion, c.State().RunningVersion)
}

func TestProxyToDirectEditAppliesWithoutConfirmation(t *testing.T) {
	c := testController(t, Options{})
	request := currentRequest(c)
	request.Config["policy"].(map[string]any)["mode"] = "custom"
	request.Config["outbounds"] = []any{map[string]any{"name": "Primary", "url": "http://127.0.0.1:18080"}}
	request.Config["rules"] = []any{map[string]any{"type": "FINAL", "outbound": "Primary"}}
	_, err := c.Save(request)
	require.NoError(t, err)
	require.NoError(t, c.Start(t.Context()), "unverified proxy is guidance, not an automatic direct fallback")
	request = currentRequest(c)
	request.Config["rules"] = []any{map[string]any{"type": "FINAL", "outbound": "direct"}}
	saved, err := c.Save(request)
	require.NoError(t, err)
	require.Equal(t, true, saved["applied"])
	require.False(t, c.doc.DirectOnlyConfirmed)
	require.NoError(t, c.Apply(t.Context()))
	require.True(t, c.Readiness(t.Context()).Ready)
	require.Equal(t, c.State().SavedVersion, c.State().RunningVersion)
}

func TestReadinessHTTPAndRuntimeLockedErrorsProvideActions(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	response := request(t, c, token, "GET", "/api/v1/readiness", nil)
	require.Equal(t, 200, response.Code)
	var report ReadinessReport
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &report))
	require.True(t, report.Ready)
	require.Empty(t, report.Blockers)
	enable(t, c)
	require.NoError(t, c.Start(t.Context()))
	next := currentRequest(c)
	next.Config["core"].(map[string]any)["tun"] = "different-tun"
	response = request(t, c, token, "PUT", "/api/v1/config", next)
	require.Equal(t, 409, response.Code)
	require.Contains(t, response.Body.String(), "capture_locked")
}

func TestReadinessLeavesPreviousCaptureMaintenanceToStart(t *testing.T) {
	c := testController(t, Options{})
	enable(t, c)
	require.NoError(t, c.writeRecoveryJournal(c.doc.Config, "interrupted-run-1234"))
	for _, state := range []string{"paused", "recovery_required", "recovery_failed"} {
		c.state = state
		report := c.Readiness(t.Context())
		require.True(t, report.Ready)
		require.Nil(t, report.Recovery, "normal readiness does not expose maintenance metadata")
		require.Empty(t, report.Blockers)
		require.True(t, c.Preflight(t.Context()).Ready)
		require.Equal(t, "paused", c.State().State)
		require.FileExists(t, c.journalPath(), "readiness must not perform cleanup")
	}
	require.NoError(t, os.WriteFile(c.journalPath(), []byte("invalid"), 0600))
	report := c.Readiness(t.Context())
	require.True(t, report.Ready, "unsafe residues produce an actionable failure only when capture is actually requested")
	require.Nil(t, report.Recovery)
	c.state = "paused"
}

func TestRunningCIDRChangesSaveAndApplyWithoutRestart(t *testing.T) {
	engine := newMemoryEngine()
	c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) { return engine, nil }})
	enable(t, c)
	require.NoError(t, c.Start(t.Context()))
	for _, pattern := range []string{"192.0.2.0/24", "203.0.113.0/24", ""} {
		request := currentRequest(c)
		request.Config["rules"] = []any{map[string]any{"type": "FINAL", "outbound": "direct"}}
		if pattern != "" {
			request.Config["rules"] = []any{map[string]any{"type": "IP-CIDR", "pattern": pattern, "outbound": "reject"}, map[string]any{"type": "FINAL", "outbound": "direct"}}
		}
		validation, err := c.Validate(request)
		require.NoError(t, err)
		require.Equal(t, false, validation["restart_required"])
		result, err := c.Save(request)
		require.NoError(t, err)
		require.Equal(t, true, result["applied"])
		require.Equal(t, "running", c.State().DataState)
		require.Equal(t, c.State().SavedVersion, c.State().RunningVersion)
	}
}
