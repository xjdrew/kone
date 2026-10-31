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

func TestManagerReloadAndRedaction(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	filename := filepath.Join(t.TempDir(), "config.toml")
	one.cfg.source = filename
	m := NewManager(one, one.cfg)
	handler := m.Handler()
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/reload/", nil))
	require.Equal(t, http.StatusMethodNotAllowed, get.Code)
	// A failed reload leaves both the engine and management configuration intact.
	require.NoError(t, os.WriteFile(filename, []byte("[core]\nnetwork='invalid'\n"), 0600))
	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/reload/", nil))
	require.Equal(t, http.StatusInternalServerError, post.Code)
	require.Equal(t, "A", one.rule.Proxy("example.com"))
	require.Equal(t, "A", m.cfg.Rule[0].Proxy)
	m.cfg.Proxy["Secret"] = "https://user:password@example.com:443"
	view := httptest.NewRecorder()
	handler.ServeHTTP(view, httptest.NewRequest(http.MethodGet, "/config/", nil))
	require.Equal(t, http.StatusOK, view.Code)
	require.False(t, strings.Contains(view.Body.String(), "password"))
	// Each engine owns an independent mux; no global handler registrations.
	require.NotPanics(t, func() { NewManager(one, one.cfg).Handler() })
}
