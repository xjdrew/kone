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

func TestFreshReadinessCollectsBlockersAndRequiresDirectConfirmation(t *testing.T) {
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
	require.Len(t, report.Blockers, 3)
	require.True(t, report.DirectOnly)
	require.False(t, report.DirectOnlyConfirmed)
	for _, issue := range report.Blockers {
		require.NotEmpty(t, issue.Page)
		require.NotEmpty(t, issue.Action)
		require.NotEmpty(t, issue.ID)
	}
	err := c.Start(t.Context())
	require.ErrorContains(t, err, "direct-only")
	require.ErrorContains(t, err, "physical interface unavailable")
	require.ErrorContains(t, err, "TUN network overlaps")
	require.Nil(t, c.engine)
	require.NoFileExists(t, c.journalPath())
}

func TestDirectOnlyConfirmationIsPersistedAndLegacyIntentIsPreserved(t *testing.T) {
	c := testController(t, Options{})
	require.Error(t, c.Start(t.Context()), "native tray and HTTP both use the same controller gate")
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
	request.Config["rules"] = []any{map[string]any{"type": "FINAL", "outbound": "reject"}}
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

func TestProxyToDirectEditNeedsConfirmationBeforeHotApply(t *testing.T) {
	c := testController(t, Options{})
	request := currentRequest(c)
	request.Config["outbounds"] = []any{map[string]any{"name": "Primary", "url": "http://127.0.0.1:18080"}}
	request.Config["rules"] = []any{map[string]any{"type": "FINAL", "outbound": "Primary"}}
	_, err := c.Save(request)
	require.NoError(t, err)
	require.NoError(t, c.Start(t.Context()), "unverified proxy is guidance, not an automatic direct fallback")
	running := c.State().RunningVersion
	request = currentRequest(c)
	request.Config["rules"] = []any{map[string]any{"type": "FINAL", "outbound": "direct"}}
	saved, err := c.Save(request)
	require.NoError(t, err)
	require.Equal(t, false, saved["applied"])
	require.False(t, c.doc.DirectOnlyConfirmed)
	require.Equal(t, running, c.State().RunningVersion)
	require.ErrorContains(t, c.Apply(t.Context()), "direct-only")
	require.False(t, c.Readiness(t.Context()).Ready)
	yes := true
	request = currentRequest(c)
	request.DirectOnlyConfirmed = &yes
	saved, err = c.Save(request)
	require.NoError(t, err)
	require.Equal(t, true, saved["applied"])
	require.Equal(t, c.State().SavedVersion, c.State().RunningVersion)
}

func TestReadinessHTTPAndRuntimeLockedErrorsProvideActions(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	response := request(t, c, token, "GET", "/api/v1/readiness", nil)
	require.Equal(t, 200, response.Code)
	var report ReadinessReport
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &report))
	require.False(t, report.Ready)
	require.Equal(t, "confirm_direct", report.Blockers[0].Action)
	enable(t, c)
	require.NoError(t, c.Start(t.Context()))
	next := currentRequest(c)
	next.Config["core"].(map[string]any)["tun"] = "different-tun"
	response = request(t, c, token, "PUT", "/api/v1/config", next)
	require.Equal(t, 409, response.Code)
	require.Contains(t, response.Body.String(), "capture_locked")
}
