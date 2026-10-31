package control

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestControlStartupPersistenceFailuresStopTheEngine(t *testing.T) {
	for _, stage := range []string{"observer", "journal", "confirmation"} {
		t.Run(stage, func(t *testing.T) {
			e := newMemoryEngine()
			if stage == "observer" {
				e.observerError = errors.New("observer installation failed")
			}
			c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) { return e, nil }})
			enable(t, c)
			if stage == "journal" {
				require.NoError(t, os.Mkdir(c.journalPath(), 0700))
			}
			if stage == "confirmation" {
				require.NoError(t, os.Mkdir(c.confirmedPath(), 0700))
			}
			require.Error(t, c.Start(context.Background()))
			require.Equal(t, "paused", c.State().State)
			require.NotEmpty(t, c.State().LastError)
			select {
			case <-e.stop:
			default:
				t.Fatal("failed startup left the engine open")
			}
			if stage == "confirmation" {
				require.NoFileExists(t, c.journalPath())
			}
		})
	}
}

func TestCleanupFailureBlocksRestartAndReportsUnrestoredState(t *testing.T) {
	e := newMemoryEngine()
	e.failure = errors.New("startup failed")
	e.closeError = errors.New("owned route could not be restored")
	c, err := New(Options{Directory: t.TempDir(), Factory: func(*kone.KoneConfig) (Engine, error) { return e, nil }, Preflight: func(context.Context, *kone.KoneConfig) kone.PreflightReport { return kone.PreflightReport{Ready: true} }})
	require.NoError(t, err)
	enable(t, c)
	require.Error(t, c.Start(context.Background()))
	require.Equal(t, "recovery_failed", c.State().State)
	require.FileExists(t, c.journalPath())
	require.False(t, c.Preflight(context.Background()).Ready)
	require.ErrorContains(t, c.Start(context.Background()), "recovery")
	require.ErrorContains(t, c.Close(), "route could not be restored")
	require.ErrorContains(t, c.Close(), "route could not be restored")
}
