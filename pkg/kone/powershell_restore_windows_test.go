package kone

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWindowsRestorationBatchContinuesAfterFailureAndRunsOnce(t *testing.T) {
	// Exercise the real PowerShell batching syntax without touching adapters,
	// routes, DNS or the firewall. Each action appends only to this test's file.
	path := filepath.Join(t.TempDir(), "restoration-order.txt")
	calls := 0
	batch := windowsRestoreBatch{network: systemNetwork{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls++
		return runCommand(ctx, name, args...)
	}}}
	batch.add("first", `[IO.File]::AppendAllText($p.Path,$p.Marker)`, map[string]string{"Path": path, "Marker": "A"})
	batch.add("second", `[IO.File]::AppendAllText($p.Path,$p.Marker); throw 'injected restoration failure'`, map[string]string{"Path": path, "Marker": "B"})
	batch.add("third", `[IO.File]::AppendAllText($p.Path,$p.Marker)`, map[string]string{"Path": path, "Marker": "C"})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := batch.restore(ctx)
	require.ErrorContains(t, err, "second: injected restoration failure")
	payload, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "CBA", string(payload), "failure must not skip the remaining reverse-order actions")
	require.Equal(t, 1, calls, "same-stage properties share one process and one timeout budget")
	require.NoError(t, batch.restore(context.Background()))
	require.Equal(t, 1, calls, "restoring twice never repeats network writes")
}
