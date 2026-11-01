package control

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
	"github.com/xjdrew/kone/pkg/logstore"
)

func TestCaptureStartAutomaticallyMaintainsSafePreviousRecords(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		t.Run(map[bool]string{false: "interrupted-before-network", true: "device-already-absent"}[recorded], func(t *testing.T) {
			var c *Controller
			var factoryCalls atomic.Int32
			c = testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) {
				factoryCalls.Add(1)
				_, err := os.Stat(c.journalPath())
				require.ErrorIs(t, err, os.ErrNotExist, "maintenance precedes engine construction or host networking")
				return newMemoryEngine(), nil
			}})
			enable(t, c)
			require.NoError(t, c.writeRecoveryJournal(c.doc.Config, "previous-safe-start"))
			if recorded {
				require.NoError(t, c.recordRecoveryDevice("previous-safe-start", "kone-nonexistent-automatic-recovery", 2147483647))
			}
			require.Equal(t, "paused", c.State().State)
			require.True(t, c.Readiness(t.Context()).Ready)
			var callers sync.WaitGroup
			for range 2 {
				callers.Go(func() { require.NoError(t, c.Start(t.Context())) })
			}
			callers.Wait()
			require.Equal(t, int32(1), factoryCalls.Load(), "concurrent start requests share one capture epoch")
			require.Equal(t, "running", c.State().State)
			current, err := c.readRecoveryJournal(false)
			require.NoError(t, err)
			require.NotEqual(t, "previous-safe-start", current.RunID)
			require.NoError(t, c.Pause(t.Context()))
			require.NoFileExists(t, c.journalPath())
			logs, err := c.logs.Query(logstore.Query{Limit: 200})
			require.NoError(t, err)
			cleared := 0
			for _, record := range logs.Records {
				if record.Message == "Previous capture recovery record cleared automatically" {
					cleared++
					require.Equal(t, true, record.Attrs["automatic"])
					require.Equal(t, "previous-safe-start", record.Attrs["run_id"])
				}
			}
			require.Equal(t, 1, cleared)
		})
	}
}

func TestCaptureStartPreservesUnverifiableRecordsAndLogsEvidence(t *testing.T) {
	for _, scenario := range []string{"invalid", "foreign-platform", "remaining-interface"} {
		t.Run(scenario, func(t *testing.T) {
			var factoryCalls atomic.Int32
			c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) {
				factoryCalls.Add(1)
				return newMemoryEngine(), nil
			}})
			enable(t, c)
			switch scenario {
			case "invalid":
				require.NoError(t, os.WriteFile(c.journalPath(), []byte("malformed private-credential-must-not-be-logged"), 0600))
			case "foreign-platform":
				require.NoError(t, c.saveRecoveryJournal(recoveryJournal{Version: recoveryJournalVersion, RunID: "foreign-start-1234", StartedAt: time.Now(), Platform: "foreign"}))
			case "remaining-interface":
				devices, err := net.Interfaces()
				require.NoError(t, err)
				require.NotEmpty(t, devices)
				require.NoError(t, c.writeRecoveryJournal(c.doc.Config, "existing-device-start"))
				require.NoError(t, c.recordRecoveryDevice("existing-device-start", devices[0].Name, devices[0].Index))
			}
			before, err := os.ReadFile(c.journalPath())
			require.NoError(t, err)
			require.ErrorIs(t, c.Start(t.Context()), errAutomaticRecovery)
			require.Equal(t, "paused", c.State().State)
			require.Equal(t, int32(0), factoryCalls.Load())
			after, err := os.ReadFile(c.journalPath())
			require.NoError(t, err)
			require.Equal(t, before, after, "uncertain ownership never authorizes deleting records or interfaces")
			logs, err := c.logs.Query(logstore.Query{Limit: 200})
			require.NoError(t, err)
			encoded, err := json.Marshal(logs)
			require.NoError(t, err)
			require.Contains(t, string(encoded), "Previous capture cleanup could not be completed")
			require.Contains(t, string(encoded), `"stage":"recovery"`)
			require.NotContains(t, string(encoded), "private-credential-must-not-be-logged")
		})
	}
}

func TestCaptureChecksSavedIntentBeforePreviousRecordMaintenance(t *testing.T) {
	c := testController(t, Options{})
	require.NoError(t, c.writeRecoveryJournal(c.doc.Config, "unconfirmed-start-1234"))
	before, err := os.ReadFile(c.journalPath())
	require.NoError(t, err)
	require.ErrorContains(t, c.Start(t.Context()), "direct-only")
	after, err := os.ReadFile(c.journalPath())
	require.NoError(t, err)
	require.Equal(t, before, after)
	enable(t, c)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, c.Start(ctx), context.Canceled)
	after, err = os.ReadFile(c.journalPath())
	require.NoError(t, err)
	require.Equal(t, before, after, "cancellation must not discard prior ownership information")
}
