package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/geoip"
	"github.com/xjdrew/kone/pkg/kone"
)

func installResetGeoIP(t *testing.T, c *Controller) []byte {
	t.Helper()
	repository, err := geoip.OpenRepository(filepath.Join(c.directory, "geoip"))
	require.NoError(t, err)
	data, digest := controlGeoIPFixture(t)
	_, err = repository.Install(data, digest)
	require.NoError(t, err)
	manifest, err := os.ReadFile(filepath.Join(c.directory, "geoip", "manifest.json"))
	require.NoError(t, err)
	return manifest
}

func TestResetConfigurationRestoresAllManagedDefaults(t *testing.T) {
	var levels []string
	c := testController(t, Options{ConfigureLogging: func(cfg kone.GeneralConfig) error { levels = append(levels, cfg.LogLevel); return nil }})
	token := owner(t, c)
	requestValue := currentRequest(c)
	requestValue.Inbound.Name, requestValue.Inbound.Enabled = "Custom inbound", false
	requestValue.Config["general"].(map[string]any)["log-level"] = "debug"
	requestValue.Config["dns"].(map[string]any)["servers"] = []string{"1.1.1.1:53"}
	requestValue.Config["core"].(map[string]any)["auto-route"] = true
	requestValue.Config["core"].(map[string]any)["outbound-interface"] = "fixture-uplink"
	requestValue.Config["outbounds"] = []map[string]any{{"name": "proxy", "url": "socks5://user:secret@127.0.0.1:1080"}}
	confirmed := true
	requestValue.DirectOnlyConfirmed = &confirmed
	_, err := c.Save(requestValue)
	require.NoError(t, err)
	installResetGeoIP(t, c)
	_, remote, err := c.passwordSession("control-test-password", true)
	require.NoError(t, err)
	pair, err := c.pair("read")
	require.NoError(t, err)
	server := httptest.NewServer(c.Handler())
	c.mu.Lock()
	c.lan = &lanServer{server: server.Config, listener: server.Listener}
	c.mu.Unlock()

	value, err := c.ResetConfiguration(t.Context(), c.doc.Version)
	require.NoError(t, err)
	require.Equal(t, uint64(3), value["version"])
	require.Equal(t, false, value["applied"])
	require.Equal(t, "paused", c.State().State)
	require.False(t, c.State().CaptureLocked)
	require.Equal(t, Inbound{ID: "tun-main", Name: "TUN", Enabled: true}, c.doc.Inbound)
	require.Equal(t, jsonConfig(managementDefaults()), jsonConfig(c.doc.Config))
	require.False(t, c.doc.DirectOnlyConfirmed)
	require.Empty(t, c.doc.Config.Outbounds)
	require.Equal(t, []string{"info", "info"}, levels)
	require.Equal(t, false, c.LANStatus()["enabled"])
	require.False(t, c.revoke(remote.ID), "remote sessions are revoked")
	_, _, err = c.claim("", pair.Code, true)
	require.Error(t, err, "unused pairing codes are revoked")
	require.Equal(t, 200, request(t, c, token, "GET", "/api/v1/state", nil).Code, "local login survives")
	require.True(t, c.passwordConfigured())
	repository, err := geoip.OpenRepository(filepath.Join(c.directory, "geoip"))
	require.NoError(t, err)
	require.True(t, repository.Current().Metadata().Builtin)
	require.Nil(t, repository.Previous())
	require.NoError(t, c.Close())
	reopened := testController(t, Options{Directory: c.directory})
	require.Equal(t, c.doc.Version, reopened.doc.Version)
	require.Equal(t, jsonConfig(managementDefaults()), jsonConfig(reopened.doc.Config))
	require.True(t, reopened.passwordConfigured())
}

func TestResetConfigurationRejectsActiveAndUnrecoveredCapture(t *testing.T) {
	for _, state := range []string{"starting", "running", "degraded", "pausing", "stopping", "recovery_required", "recovery_failed"} {
		t.Run(state, func(t *testing.T) {
			c := testController(t, Options{})
			c.state = state
			_, err := c.ResetConfiguration(t.Context(), c.doc.Version)
			require.Error(t, err)
			require.Equal(t, uint64(1), c.doc.Version)
			c.state = "paused"
		})
	}
	t.Run("engine", func(t *testing.T) {
		c := testController(t, Options{})
		c.engine = newMemoryEngine()
		_, err := c.ResetConfiguration(t.Context(), c.doc.Version)
		require.ErrorIs(t, err, ErrCaptureLocked)
		c.engine = nil
	})
	t.Run("journal", func(t *testing.T) {
		c := testController(t, Options{})
		require.NoError(t, c.writeRecoveryJournal(c.doc.Config, "reset-test-run"))
		_, err := c.ResetConfiguration(t.Context(), c.doc.Version)
		require.ErrorContains(t, err, "recovery")
		require.FileExists(t, c.journalPath())
	})
}

func TestResetConfigurationRetainsPreviousStateOnFailure(t *testing.T) {
	for _, failure := range []string{"version", "disk-conflict", "logging", "revision-limit", "cancelled", "closed", "backup-unreadable"} {
		t.Run(failure, func(t *testing.T) {
			failLogging := false
			c := testController(t, Options{ConfigureLogging: func(kone.GeneralConfig) error {
				if failLogging {
					return errors.New("logging unavailable")
				}
				return nil
			}})
			r := currentRequest(c)
			r.Inbound.Name = "Saved inbound"
			_, err := c.Save(r)
			require.NoError(t, err)
			manifest := installResetGeoIP(t, c)
			base := c.doc.Version
			ctx := t.Context()
			switch failure {
			case "version":
				base--
			case "disk-conflict":
				disk := cloneDocument(c.doc)
				disk.Inbound.Name = "External edit"
				require.NoError(t, writeDocument(c.settingsPath(), disk))
			case "logging":
				failLogging = true
			case "revision-limit":
				c.doc.Version = ^uint64(0)
				base = c.doc.Version
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "closed":
				c.closed = true
			case "backup-unreadable":
				require.NoError(t, os.Remove(c.settingsPath()+".previous"))
				require.NoError(t, os.Mkdir(c.settingsPath()+".previous", 0700))
			}
			before, err := os.ReadFile(c.settingsPath())
			require.NoError(t, err)
			_, err = c.ResetConfiguration(ctx, base)
			require.Error(t, err)
			require.Equal(t, "Saved inbound", c.doc.Inbound.Name)
			after, err := os.ReadFile(c.settingsPath())
			require.NoError(t, err)
			require.Equal(t, before, after)
			afterManifest, err := os.ReadFile(filepath.Join(c.directory, "geoip", "manifest.json"))
			require.NoError(t, err)
			require.Equal(t, manifest, afterManifest)
		})
	}
}

func TestResetConfigurationAPIAuthorizationAndInput(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	for _, body := range []string{`{}`, `{"base_version":1,"unknown":true}`, `{"base_version":1} {}`, `{"base_version":-1}`, strings.Repeat("x", (1<<20)+1)} {
		response := request(t, c, token, "POST", "/api/v1/config/defaults", body)
		require.Contains(t, []int{400, 409}, response.Code)
	}
	require.Equal(t, 401, request(t, c, "", "POST", "/api/v1/config/defaults", map[string]any{"base_version": 1}).Code)
	pair, err := c.pair("read")
	require.NoError(t, err)
	readToken, _, err := c.claim("", pair.Code, true)
	require.NoError(t, err)
	require.Equal(t, 403, request(t, c, readToken, "POST", "/api/v1/config/defaults", map[string]any{"base_version": 1}).Code)
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/config/defaults", map[string]any{"base_version": 1}).Code)
}

func TestResetConfigurationPreservesExternalEditDuringReset(t *testing.T) {
	var c *Controller
	editDuringReset := false
	c = testController(t, Options{ConfigureLogging: func(kone.GeneralConfig) error {
		if editDuringReset {
			editDuringReset = false
			disk := cloneDocument(c.doc)
			disk.Inbound.Name = "External edit during reset"
			return writeDocument(c.settingsPath(), disk)
		}
		return nil
	}})
	manifest := installResetGeoIP(t, c)
	editDuringReset = true
	_, err := c.ResetConfiguration(t.Context(), c.doc.Version)
	require.ErrorIs(t, err, ErrConflict)
	disk, err := readDocument(c.settingsPath())
	require.NoError(t, err)
	require.Equal(t, "External edit during reset", disk.Inbound.Name)
	require.Equal(t, "TUN", c.doc.Inbound.Name)
	afterManifest, err := os.ReadFile(filepath.Join(c.directory, "geoip", "manifest.json"))
	require.NoError(t, err)
	require.Equal(t, manifest, afterManifest)
}

func TestResetConfigurationCannotRaceCaptureStartup(t *testing.T) {
	entered, proceed := make(chan struct{}), make(chan struct{})
	c := testController(t, Options{Factory: func(*kone.KoneConfig) (Engine, error) {
		close(entered)
		<-proceed
		return newMemoryEngine(), nil
	}})
	enable(t, c)
	base := c.doc.Version
	started, reset := make(chan error, 1), make(chan error, 1)
	go func() { started <- c.Start(t.Context()) }()
	<-entered
	go func() {
		_, err := c.ResetConfiguration(t.Context(), base)
		reset <- err
	}()
	close(proceed)
	require.NoError(t, <-started)
	require.ErrorIs(t, <-reset, ErrCaptureLocked)
	require.Equal(t, base, c.State().SavedVersion)
	require.Equal(t, "running", c.State().State)
	require.NoError(t, c.Pause(t.Context()))
}

func TestResetConfigurationRepairsDamagedSettingsAndPreservesOriginal(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "settings.json")
	original := []byte("{damaged-settings}")
	require.NoError(t, os.WriteFile(path, original, 0600))
	c := testController(t, Options{Directory: directory})
	require.NotEmpty(t, c.State().ConfigError)
	_, err := c.ResetConfiguration(t.Context(), c.State().SavedVersion)
	require.NoError(t, err)
	require.Empty(t, c.State().ConfigError)
	require.Equal(t, "paused", c.State().State)
	require.Equal(t, jsonConfig(managementDefaults()), jsonConfig(c.doc.Config))
	files, err := filepath.Glob(path + ".broken-*")
	require.NoError(t, err)
	require.Len(t, files, 1)
	backup, err := os.ReadFile(files[0])
	require.NoError(t, err)
	require.Equal(t, original, backup)
}

func TestResetConfigurationRequiresLocalSessionAndRequest(t *testing.T) {
	for _, scenario := range []string{"remote-session", "remote-request"} {
		t.Run(scenario, func(t *testing.T) {
			c := testController(t, Options{})
			token := owner(t, c)
			if scenario == "remote-session" {
				c.sessions[tokenHash(token)].Remote = true
			}
			r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9200/api/v1/config/defaults", strings.NewReader(`{"base_version":1}`))
			r.RemoteAddr = "127.0.0.1:12345"
			if scenario == "remote-request" {
				r.RemoteAddr = "192.168.1.100:12345"
			}
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			if scenario == "remote-request" {
				// Exercise the route boundary after authorization; an actual
				// non-LAN remote request is also rejected by the outer origin guard.
				c.route(w, r, "config/defaults", c.sessions[tokenHash(token)])
			} else {
				c.Handler().ServeHTTP(w, r)
			}
			require.Equal(t, 403, w.Code)
			require.Contains(t, w.Body.String(), "local_only")
			require.Equal(t, uint64(1), c.State().SavedVersion)
		})
	}
}
