package control

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func journalController(t *testing.T) *Controller {
	t.Helper()
	return &Controller{directory: t.TempDir(), now: time.Now}
}

func TestRecoveryJournalNeverStoresProxyCredentials(t *testing.T) {
	c := journalController(t)
	cfg := kone.DefaultConfig()
	cfg.Outbounds = []kone.OutboundConfig{{Name: "private", URL: "http://secret-user:secret-password@127.0.0.1:9999"}}
	require.NoError(t, c.writeRecoveryJournal(cfg, "first-run-1234"))
	data, err := os.ReadFile(c.journalPath())
	require.NoError(t, err)
	require.NotContains(t, string(data), "secret-")
	require.NotContains(t, string(data), "9999")
	require.NotContains(t, string(data), "outbounds")
	var record recoveryJournal
	require.NoError(t, json.Unmarshal(data, &record))
	require.Equal(t, "first-run-1234", record.RunID)
	report, err := c.inspectRecovery(context.Background(), func() ([]net.Interface, error) {
		t.Fatal("unknown device must not be inferred by name")
		return nil, nil
	})
	require.NoError(t, err)
	require.False(t, report.CanClear)
	require.Equal(t, "identity_unknown", report.Items[0].Status)
	require.Error(t, c.Recover(context.Background()))
	require.Equal(t, "recovery_required", c.state)
}

func TestRecoveryEpochCannotRemoveNewRun(t *testing.T) {
	c := journalController(t)
	cfg := kone.DefaultConfig()
	require.Error(t, c.writeRecoveryJournal(cfg, "short"))
	require.Error(t, c.writeRecoveryJournal(nil, "valid-run-1234"))
	require.NoError(t, c.writeRecoveryJournal(cfg, "first-run-1234"))
	require.Error(t, c.writeRecoveryJournal(cfg, "second-run-1234"))
	require.Error(t, c.recordRecoveryDevice("different-run-1234", "kone", 321))
	require.NoError(t, c.recordRecoveryDevice("first-run-1234", "kone", 321))
	require.Error(t, c.recordRecoveryDevice("first-run-1234", "different", 321))
	require.NoError(t, c.removeRecoveryJournal("first-run-1234"))
	require.NoError(t, c.writeRecoveryJournal(cfg, "second-run-1234"))
	var workers sync.WaitGroup
	for range 10 {
		workers.Add(1)
		go func() { defer workers.Done(); require.NoError(t, c.removeRecoveryJournal("first-run-1234")) }()
	}
	workers.Wait()
	require.FileExists(t, c.journalPath())
	require.NoError(t, c.removeRecoveryJournal("second-run-1234"))
	require.NoError(t, c.removeRecoveryJournal("second-run-1234"))
	require.NoError(t, c.Recover(context.Background()))
	require.Equal(t, "paused", c.state)
}

func TestRecoveryPreservesReusedAndExistingInterfaces(t *testing.T) {
	for _, tc := range []struct {
		name   string
		device net.Interface
		status string
	}{
		{"owned-still-present", net.Interface{Name: "kone-test", Index: 54321}, "still_present"},
		{"name-reused", net.Interface{Name: "kone-test", Index: 123}, "identity_changed"},
		{"index-reused-or-renamed", net.Interface{Name: "unrelated-vpn", Index: 54321}, "identity_changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := journalController(t)
			require.NoError(t, c.writeRecoveryJournal(kone.DefaultConfig(), "owned-run-1234"))
			require.NoError(t, c.recordRecoveryDevice("owned-run-1234", "kone-test", 54321))
			report, err := c.inspectRecovery(context.Background(), func() ([]net.Interface, error) { return []net.Interface{tc.device}, nil })
			require.NoError(t, err)
			require.False(t, report.CanClear)
			require.Equal(t, tc.status, report.Items[0].Status)
			require.FileExists(t, c.journalPath())
		})
	}
	c := journalController(t)
	require.NoError(t, c.writeRecoveryJournal(kone.DefaultConfig(), "owned-run-1234"))
	require.NoError(t, c.recordRecoveryDevice("owned-run-1234", "kone-test", 54321))
	report, err := c.inspectRecovery(context.Background(), func() ([]net.Interface, error) { return nil, nil })
	require.NoError(t, err)
	require.Equal(t, runtime.GOOS != "windows", report.CanClear)
	if runtime.GOOS == "windows" {
		require.Equal(t, "unverified", report.Items[1].Status)
	}
	_, err = c.inspectRecovery(context.Background(), func() ([]net.Interface, error) { return nil, errors.New("denied") })
	require.ErrorContains(t, err, "denied")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.InspectRecovery(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestRecoveryMigratesCredentialBearingLegacyRecord(t *testing.T) {
	c := journalController(t)
	cfg := kone.DefaultConfig()
	cfg.Outbounds = []kone.OutboundConfig{{Name: "legacy", URL: "http://legacy-user:legacy-password@127.0.0.1:9999"}}
	data, err := toml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(c.journalPath(), data, 0600))
	report, err := c.InspectRecovery(context.Background())
	require.NoError(t, err)
	require.Equal(t, "unverified", report.Ownership)
	require.False(t, report.CanClear)
	data, err = os.ReadFile(c.journalPath())
	require.NoError(t, err)
	require.NotContains(t, string(data), "legacy-password")
	require.True(t, json.Valid(data))
	for _, invalid := range []string{"invalid", strings.Repeat("x", 65537), `{"version":99}`, string(data) + " {}"} {
		require.NoError(t, os.WriteFile(c.journalPath(), []byte(invalid), 0600))
		report, err = c.InspectRecovery(context.Background())
		require.Error(t, err)
		require.True(t, report.Required)
		require.False(t, report.CanClear)
		require.FileExists(t, c.journalPath())
	}
}
