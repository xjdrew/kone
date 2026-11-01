package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

type memoryEngine struct {
	ready, stop                      chan struct{}
	once                             sync.Once
	failure, closeError, reloadError error
	observerError                    error
	wait                             bool
}

func newMemoryEngine() *memoryEngine {
	return &memoryEngine{ready: make(chan struct{}), stop: make(chan struct{})}
}
func (e *memoryEngine) Run(ctx context.Context) error {
	if e.failure != nil {
		return e.failure
	}
	if !e.wait {
		close(e.ready)
	}
	select {
	case <-ctx.Done():
	case <-e.stop:
	}
	return nil
}
func (e *memoryEngine) Ready() <-chan struct{}                         { return e.ready }
func (e *memoryEngine) Close() error                                   { e.once.Do(func() { close(e.stop) }); return e.closeError }
func (e *memoryEngine) Reload(*kone.KoneConfig) error                  { return e.reloadError }
func (e *memoryEngine) SetTrafficObserver(*kone.TrafficObserver) error { return e.observerError }

func testController(t *testing.T, options Options) *Controller {
	t.Helper()
	if options.Directory == "" {
		options.Directory = t.TempDir()
	}
	if options.Preflight == nil {
		options.Preflight = func(context.Context, *kone.KoneConfig) kone.PreflightReport { return kone.PreflightReport{Ready: true} }
	}
	if options.Factory == nil {
		options.Factory = func(*kone.KoneConfig) (Engine, error) { return newMemoryEngine(), nil }
	}
	if options.InspectSystemDNSRecovery == nil {
		options.InspectSystemDNSRecovery = func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) { return nil, nil }
	}
	c, err := New(options)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	return c
}
func currentRequest(c *Controller) SaveRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return SaveRequest{BaseVersion: c.doc.Version, Config: jsonConfig(c.doc.Config), Inbound: c.doc.Inbound}
}
func enable(t *testing.T, c *Controller) {
	t.Helper()
	r := currentRequest(c)
	r.Inbound.Enabled = true
	confirmed := true
	r.DirectOnlyConfirmed = &confirmed
	_, err := c.Save(r)
	require.NoError(t, err)
}

func TestPersistentManagementNeverInheritsHostProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://deliberately-unreachable.invalid:1")
	dir := t.TempDir()
	c := testController(t, Options{Directory: dir})
	require.Equal(t, "paused", c.State().State)
	require.Empty(t, c.doc.Config.Outbounds)
	require.True(t, c.doc.Inbound.Enabled)
	r := currentRequest(c)
	r.Inbound.Name = "Family gateway"
	_, err := c.Save(r)
	require.NoError(t, err)
	require.Equal(t, uint64(2), c.State().SavedVersion)
	_, err = c.Save(r)
	require.ErrorIs(t, err, ErrConflict)
	require.NoError(t, c.Close())
	again := testController(t, Options{Directory: dir})
	require.Equal(t, "Family gateway", again.doc.Inbound.Name)
	require.FileExists(t, filepath.Join(dir, "settings.json.previous"))
	_, err = again.Undo(again.doc.Version)
	require.ErrorContains(t, err, "no previously applied")
}

func TestCorruptProfileIsPreservedUntilExplicitRepair(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	original := []byte("{broken original}")
	require.NoError(t, os.WriteFile(path, original, 0600))
	c := testController(t, Options{Directory: dir})
	require.NotEmpty(t, c.State().ConfigError)
	require.False(t, c.Preflight(context.Background()).Ready)
	require.Error(t, c.Start(context.Background()))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, data)
	r := currentRequest(c)
	_, err = c.Save(r)
	require.NoError(t, err)
	files, err := filepath.Glob(path + ".broken-*")
	require.NoError(t, err)
	require.Len(t, files, 1)
	data, err = os.ReadFile(files[0])
	require.NoError(t, err)
	require.Equal(t, original, data)
	require.Empty(t, c.State().ConfigError)
}

func TestCaptureLifecycleVersionsAndUndo(t *testing.T) {
	c := testController(t, Options{})
	require.ErrorContains(t, c.Start(context.Background()), "direct-only")
	enable(t, c)
	require.NoError(t, c.Start(context.Background()))
	require.NoError(t, c.Start(context.Background()))
	require.Equal(t, "running", c.State().DataState)
	r := currentRequest(c)
	r.Config["rules"] = []any{map[string]any{"type": "FINAL", "outbound": "reject"}}
	validation, err := c.Validate(r)
	require.NoError(t, err)
	require.False(t, validation["restart_required"].(bool))
	_, err = c.Save(r)
	require.NoError(t, err)
	require.Equal(t, c.State().SavedVersion, c.State().RunningVersion)
	_, err = c.Undo(c.State().SavedVersion)
	require.NoError(t, err)
	require.Equal(t, "TUN", c.doc.Inbound.Name)
	require.NoError(t, c.Apply(context.Background()))
	require.Equal(t, c.State().SavedVersion, c.State().ConfirmedVersion)
	var group sync.WaitGroup
	for range 6 {
		group.Go(func() { require.NoError(t, c.Pause(context.Background())); _ = c.Document(); _ = c.State() })
	}
	group.Wait()
	require.Equal(t, "paused", c.State().State)
	require.NoFileExists(t, c.journalPath())
	require.ErrorContains(t, c.Apply(context.Background()), "paused")
	require.NoError(t, c.Start(context.Background()))
	r = currentRequest(c)
	r.Inbound.Enabled = false
	_, err = c.Save(r)
	require.ErrorIs(t, err, ErrCaptureLocked)
	require.NoError(t, c.Pause(context.Background()))
	_, err = c.Save(r)
	require.NoError(t, err)
	require.Equal(t, "paused", c.State().State)
	require.NoError(t, c.Close())
	require.ErrorContains(t, c.Start(context.Background()), "stopping")
}

func TestStartupFailuresKeepManagementAndRollback(t *testing.T) {
	for _, stage := range []string{"preflight", "factory", "run", "cancel", "reload"} {
		t.Run(stage, func(t *testing.T) {
			e := newMemoryEngine()
			options := Options{Factory: func(*kone.KoneConfig) (Engine, error) {
				if stage == "factory" {
					return nil, errors.New("factory failed")
				}
				return e, nil
			}}
			if stage == "preflight" {
				options.Preflight = func(context.Context, *kone.KoneConfig) kone.PreflightReport {
					return kone.PreflightReport{Ready: false}
				}
			}
			if stage == "run" {
				e.failure = errors.New("occupied DNS TCP port")
			}
			if stage == "cancel" {
				e.wait = true
			}
			c := testController(t, options)
			enable(t, c)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "cancel" {
				cancel()
			}
			err := c.Start(ctx)
			if stage == "reload" {
				require.NoError(t, err)
				e.reloadError = errors.New("restart required")
				require.Error(t, c.Apply(ctx))
				require.Equal(t, uint64(2), c.State().RunningVersion)
			} else {
				require.Error(t, err)
				require.Equal(t, "paused", c.State().State)
			}
			require.Equal(t, "ready", c.State().ControlState)
		})
	}
}

func TestConfigValidationAndExternalConflict(t *testing.T) {
	c := testController(t, Options{})
	r := currentRequest(c)
	r.Config["core"].(map[string]any)["network"] = "10.193.0.1/16"
	result, err := c.Validate(r)
	require.NoError(t, err)
	require.True(t, result["restart_required"].(bool))
	r.Config["unknown"] = true
	_, err = c.Validate(r)
	require.Error(t, err)
	r = currentRequest(c)
	disk := cloneDocument(c.doc)
	disk.Version++
	require.NoError(t, writeDocument(c.settingsPath(), disk))
	_, err = c.Save(r)
	require.ErrorIs(t, err, ErrConflict)
	require.Equal(t, uint64(1), c.State().SavedVersion)
	require.NoError(t, os.Remove(c.settingsPath()))
	_, err = c.Save(r)
	require.ErrorContains(t, err, "unreadable")
}

func TestManagedCredentialsArePreservedRenamedAndRedacted(t *testing.T) {
	c := testController(t, Options{})
	r := currentRequest(c)
	r.Config["outbounds"] = []any{map[string]any{"name": "office", "url": "http://alice:secret-value@127.0.0.1:8080"}}
	_, err := c.Save(r)
	require.NoError(t, err)
	require.True(t, hasCredentials(c.doc.Config.Outbounds[0].URL))
	require.NotContains(t, c.Document(), "secret-value")
	redacted := jsonConfig(c.doc.Config)["outbounds"].([]any)[0].(map[string]any)["url"].(string)
	require.Contains(t, redacted, "REDACTED")
	r = currentRequest(c)
	rows := r.Config["outbounds"].([]any)
	rows[0].(map[string]any)["name"] = "renamed"
	r.CredentialActions = map[string]CredentialAction{"renamed": {Action: "preserve", OriginalName: "office"}}
	_, err = c.Save(r)
	require.NoError(t, err)
	require.Contains(t, c.doc.Config.Outbounds[0].URL, "secret-value")
	r = currentRequest(c)
	r.Config["outbounds"].([]any)[0].(map[string]any)["url"] = "http://REDACTED:REDACTED@127.0.0.2:8080"
	_, err = c.Save(r)
	require.ErrorContains(t, err, "endpoint")
	r.CredentialActions = map[string]CredentialAction{"renamed": {Action: "replace", Username: "new", Password: "new-secret"}}
	_, err = c.Save(r)
	require.NoError(t, err)
	require.Contains(t, c.doc.Config.Outbounds[0].URL, "new-secret")
	r = currentRequest(c)
	r.CredentialActions = map[string]CredentialAction{"renamed": {Action: "clear"}}
	_, err = c.Save(r)
	require.NoError(t, err)
	require.False(t, hasCredentials(c.doc.Config.Outbounds[0].URL))
	message := safeMessage(errors.New("connect "+c.doc.Config.Outbounds[0].URL+strings.Repeat("a", 2000)), c.doc.Config)
	require.LessOrEqual(t, len(message), 1024)
}

func TestControllerJournalRequiresRecovery(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "capture.json"), []byte("invalid"), 0600))
	c := testController(t, Options{Directory: dir})
	require.Equal(t, "recovery_required", c.State().State)
	require.Error(t, c.Start(context.Background()))
	require.Error(t, c.Recover(context.Background()))
	require.FileExists(t, c.journalPath())
	require.NoError(t, os.Remove(c.journalPath()))
	require.NoError(t, c.Recover(context.Background()))
	require.Equal(t, "paused", c.State().State)
}

func waitOperation(t *testing.T, c *Controller, id string) Operation {
	t.Helper()
	var result Operation
	require.Eventually(t, func() bool {
		for _, op := range c.Operations() {
			if op.ID == id {
				result = op
				return op.Status != "running"
			}
		}
		return false
	}, 3*time.Second, time.Millisecond)
	return result
}
