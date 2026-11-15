package kone

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHealthLedgerSurvivesRestartAndRejectsLateRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "health.json")
	ledger, err := OpenHealthLedger(path)
	require.NoError(t, err)
	now := time.Now().UTC()
	result := HealthResult{Protocol: "dns", Source: "business", Status: "failed", Stage: "dns", Time: now}
	first, err := ledger.Observe("X.COM.", "system", "dns_failed", result)
	require.NoError(t, err)
	reopened, err := OpenHealthLedger(path)
	require.NoError(t, err)
	rows, total := reopened.Snapshot(0, 20)
	require.Equal(t, 1, total)
	require.Equal(t, "attention", rows[0].Status)
	require.Equal(t, "x.com", rows[0].Domain)
	require.NoError(t, reopened.Resolve("x.com", "system", first.Generation, "retest", now.Add(time.Minute)))
	result.Time = now.Add(24 * time.Hour)
	next, err := reopened.Observe("x.com", "system", "dns_failed", result)
	require.NoError(t, err)
	require.Greater(t, next.Generation, first.Generation)
	require.Error(t, reopened.Resolve("x.com", "system", first.Generation, "retest", result.Time))
	rows, _ = reopened.Snapshot(0, 20)
	require.Equal(t, "attention", rows[0].Status)
	rows[0].Results[0].Status = "modified"
	rows, _ = reopened.Snapshot(0, 20)
	require.Equal(t, "failed", rows[0].Results[0].Status)
	require.NoError(t, reopened.Resolve("x.com", "system", next.Generation, "automatic", result.Time))
	rows, _ = reopened.Snapshot(0, 20)
	require.Equal(t, "adjusted", rows[0].Status)
}
func TestHealthLedgerDoesNotHideStorageFailureOrCorruption(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "health.json")
	require.NoError(t, os.WriteFile(path, []byte("broken"), 0600))
	_, err := OpenHealthLedger(path)
	require.Error(t, err)
	require.NoError(t, os.Remove(path))
	ledger, err := OpenHealthLedger(path)
	require.NoError(t, err)
	require.NoError(t, os.Mkdir(path, 0700))
	_, err = ledger.Observe("example.com", "system", "dns_failed", HealthResult{Time: time.Now()})
	require.Error(t, err)
	_, total := ledger.Snapshot(0, 20)
	require.Zero(t, total)
}
