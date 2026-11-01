package control

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
	"github.com/xjdrew/kone/pkg/logstore"
)

func managementLogMessages(t *testing.T, c *Controller, message string) []logstore.Record {
	t.Helper()
	page, err := c.logs.Query(logstore.Query{Limit: 200, Source: "management"})
	require.NoError(t, err)
	var matches []logstore.Record
	for _, record := range page.Records {
		if record.Message == message {
			matches = append(matches, record)
		}
	}
	return matches
}

func TestManagementSaveAndResetLogsContainVersionsWithoutConfiguration(t *testing.T) {
	c := testController(t, Options{})
	r := currentRequest(c)
	r.Config["outbounds"] = []map[string]any{{"name": "private-upstream", "url": "socks5://owner:save-private-password@127.0.0.1:1080"}}
	_, err := c.Save(r)
	require.NoError(t, err)
	saved := managementLogMessages(t, c, "Settings saved")
	require.Len(t, saved, 1)
	require.Equal(t, "save", saved[0].Attrs["stage"])
	require.EqualValues(t, 2, saved[0].Attrs["saved_version"])
	_, err = c.Save(r)
	require.ErrorIs(t, err, ErrConflict)
	failed := managementLogMessages(t, c, "Saving settings failed")
	require.Len(t, failed, 1)
	require.Equal(t, "ERROR", failed[0].Level)
	require.EqualValues(t, 1, failed[0].Attrs["base_version"])
	_, err = c.ResetConfiguration(t.Context(), c.State().SavedVersion)
	require.NoError(t, err)
	reset := managementLogMessages(t, c, "All managed settings reset to defaults")
	require.Len(t, reset, 1)
	require.Equal(t, "reset", reset[0].Attrs["stage"])
	require.EqualValues(t, 3, reset[0].Attrs["saved_version"])
	page, err := c.logs.Query(logstore.Query{})
	require.NoError(t, err)
	encoded, err := json.Marshal(page)
	require.NoError(t, err)
	for _, secret := range []string{"save-private-password", "private-upstream", "socks5://", "127.0.0.1:1080"} {
		require.NotContains(t, string(encoded), secret, "management actions log versions and outcomes, never configuration values")
	}
}

func TestExplicitPreflightLogsRequestResultAndRedactedIssue(t *testing.T) {
	for _, ready := range []bool{true, false} {
		c := testController(t, Options{Preflight: func(context.Context, *kone.KoneConfig) kone.PreflightReport {
			return kone.PreflightReport{Ready: ready, Issues: []kone.PreflightIssue{{Code: "test", Severity: "warning", Message: "proxy socks5://owner:preflight-private-password@127.0.0.1:1080?token=preflight-private-token"}}}
		}})
		report := c.Preflight(t.Context())
		require.Equal(t, ready, report.Ready)
		requested := managementLogMessages(t, c, "Capture preflight requested")
		completed := managementLogMessages(t, c, "Capture preflight completed")
		require.Len(t, requested, 1)
		require.Len(t, completed, 1)
		require.Less(t, requested[0].ID, completed[0].ID)
		require.Equal(t, ready, completed[0].Attrs["ready"])
		require.EqualValues(t, 1, completed[0].Attrs["saved_version"])
		require.EqualValues(t, 1, completed[0].Attrs["issues"])
		issues := managementLogMessages(t, c, "Capture preflight reported an issue")
		require.Len(t, issues, 1)
		require.Equal(t, "WARN", issues[0].Level)
		data, err := json.Marshal(issues)
		require.NoError(t, err)
		require.NotContains(t, string(data), "preflight-private-password")
		require.NotContains(t, string(data), "preflight-private-token")
	}
}

func TestManagementPollingDoesNotEmitActionEvents(t *testing.T) {
	c := testController(t, Options{})
	before, err := c.logs.Query(logstore.Query{})
	require.NoError(t, err)
	for range 3 {
		c.State()
		c.Document()
		c.Readiness(t.Context())
	}
	after, err := c.logs.Query(logstore.Query{})
	require.NoError(t, err)
	require.Equal(t, before.NextCursor, after.NextCursor)
}

func TestApplyLogsEveryOutcomeAndRedactsKnownProxyPassword(t *testing.T) {
	engine := newMemoryEngine()
	c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) { return engine, nil }})
	err := c.Apply(t.Context())
	require.ErrorContains(t, err, "capture is paused")
	r := currentRequest(c)
	r.Config["outbounds"] = []map[string]any{{"name": "proxy", "url": "socks5://owner:apply-private-password@127.0.0.1:1080"}}
	confirmed := true
	r.DirectOnlyConfirmed = &confirmed
	_, err = c.Save(r)
	require.NoError(t, err)
	require.NoError(t, c.Start(t.Context()))
	require.NoError(t, c.Apply(t.Context()))
	engine.reloadError = errors.New("upstream rejected apply-private-password")
	require.Error(t, c.Apply(t.Context()))
	started := managementLogMessages(t, c, "Applying saved settings")
	completed := managementLogMessages(t, c, "Saved settings application completed")
	failed := managementLogMessages(t, c, "Applying saved settings failed")
	require.Len(t, started, 3)
	require.Len(t, completed, 1)
	require.Len(t, failed, 2)
	require.EqualValues(t, 2, completed[0].Attrs["saved_version"])
	require.EqualValues(t, 2, completed[0].Attrs["running_version"])
	require.Equal(t, "running", completed[0].Attrs["state"])
	data, err := json.Marshal(failed)
	require.NoError(t, err)
	require.NotContains(t, string(data), "apply-private-password")
	require.Equal(t, "upstream rejected REDACTED", failed[1].Attrs["error"])
	require.NoError(t, c.Pause(t.Context()))
}
