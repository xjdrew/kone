package kone

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagerEmptyStatisticsPage(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	response := httptest.NewRecorder()
	one.manager.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), "<title>kone</title>")
	require.Contains(t, response.Body.String(), "<th>Total Traffic</th><td>0</td>")
	require.Empty(t, one.manager.hosts)
	require.Empty(t, one.manager.websites)
	require.Empty(t, one.manager.proxies)
}

func TestManagerReloadAndRedaction(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	filename := filepath.Join(t.TempDir(), "config.toml")
	cfg := one.Snapshot().Config
	cfg.source = filename
	require.NoError(t, one.Reload(cfg))
	m := NewManager(one, one.Snapshot().Config)
	handler := m.Handler()
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/reload/", nil))
	require.Equal(t, http.StatusMethodNotAllowed, get.Code)
	// A failed reload leaves both the engine and management configuration intact.
	require.NoError(t, os.WriteFile(filename, []byte("[core]\nnetwork='invalid'\n"), 0600))
	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/reload/", nil))
	require.Equal(t, http.StatusInternalServerError, post.Code)
	require.Equal(t, "A", one.policy.Load().rule.Proxy("example.com"))
	require.Equal(t, "A", one.Snapshot().Config.Rule[0].Outbound)
	cfg = one.Snapshot().Config
	setTestOutbound(cfg, "Secret", "https://user:password@example.com:443")
	require.NoError(t, one.Reload(cfg))
	view := httptest.NewRecorder()
	handler.ServeHTTP(view, httptest.NewRequest(http.MethodGet, "/config/", nil))
	require.Equal(t, http.StatusOK, view.Code)
	require.False(t, strings.Contains(view.Body.String(), "password"))
	// Each engine owns an independent mux; no global handler registrations.
	require.NotPanics(t, func() { NewManager(one, one.Snapshot().Config).Handler() })
}
