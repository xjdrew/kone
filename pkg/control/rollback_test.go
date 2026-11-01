package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

func TestCorruptSettingsOfferLastValidBackupWithoutOverwritingOrStarting(t *testing.T) {
	directory := t.TempDir()
	cfg := kone.DefaultConfig()
	backup := Document{Version: 8, Config: cfg, Inbound: Inbound{ID: "tun-main", Name: "Last confirmed gateway", Enabled: true}}
	require.NoError(t, writeDocument(filepath.Join(directory, "confirmed.json"), backup))
	bad := []byte("{damaged-settings}")
	require.NoError(t, os.WriteFile(filepath.Join(directory, "settings.json"), bad, 0600))
	c := testController(t, Options{Directory: directory})
	require.Equal(t, uint64(8), c.State().SavedVersion)
	require.Equal(t, "Last confirmed gateway", c.doc.Inbound.Name)
	require.Error(t, c.Start(t.Context()))
	original, err := os.ReadFile(c.settingsPath())
	require.NoError(t, err)
	require.Equal(t, bad, original)
	_, err = c.Save(currentRequest(c))
	require.NoError(t, err)
	require.Equal(t, uint64(9), c.State().SavedVersion)
}

func TestManagedLoggingIsConfiguredBeforeCaptureAndUsesSavedSettings(t *testing.T) {
	var levels []string
	c := testController(t, Options{ConfigureLogging: func(cfg kone.GeneralConfig) error { levels = append(levels, cfg.LogLevel); return nil }})
	require.Equal(t, []string{"info"}, levels)
	r := currentRequest(c)
	r.Config["general"].(map[string]any)["log-level"] = "debug"
	r.Inbound.Enabled = true
	_, err := c.Save(r)
	require.NoError(t, err)
	require.NoError(t, c.Start(t.Context()))
	require.Equal(t, []string{"info", "debug"}, levels)
	require.NoError(t, c.Pause(t.Context()))
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
