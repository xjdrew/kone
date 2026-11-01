package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestOnlyPasswordConsoleProvidesManagement(t *testing.T) {
	directory := t.TempDir()
	// A previously saved managed profile may contain the retired listener.
	// It must still open safely, without losing capture intent or credentials.
	configuration := "[general]\nmanager-addr='0.0.0.0:9200'\n[[outbounds]]\nname='office'\nurl='http://user:private-credential@127.0.0.1:8080'\n[[rules]]\ntype='FINAL'\noutbound='office'\n"
	_, err := kone.ParseConfig([]byte(configuration))
	require.ErrorContains(t, err, "general.manager-addr was removed")
	stored, err := json.Marshal(map[string]any{"version": 7, "toml": configuration, "inbound": map[string]any{"id": "tun-existing", "name": "Office", "enabled": false}, "direct_only_confirmed": false})
	require.NoError(t, err)
	path := filepath.Join(directory, "settings.json")
	require.NoError(t, os.WriteFile(path, stored, 0600))
	c, err := control.New(control.Options{Directory: directory})
	require.NoError(t, err)
	defer c.Close()
	require.Empty(t, c.State().ConfigError)
	require.Equal(t, "paused", c.State().DataState)
	backup, err := os.ReadFile(path + ".legacy-manager")
	require.NoError(t, err)
	require.Equal(t, stored, backup)
	current, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, stored, current, "merely opening management does not rewrite the existing profile")
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	for _, request := range []struct {
		method, path string
		status       int
	}{
		{"POST", "/reload/", http.StatusMethodNotAllowed},
		{"GET", "/config/", http.StatusNotFound},
		{"GET", "/host/", http.StatusNotFound},
		{"GET", "/dns/", http.StatusNotFound},
		{"GET", "/api/v1/config", http.StatusUnauthorized},
		{"POST", "/api/v1/capture/start", http.StatusUnauthorized},
	} {
		r, err := http.NewRequest(request.method, server.URL+request.path, bytes.NewReader(nil))
		require.NoError(t, err)
		response, err := client.Do(r)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		require.NoError(t, err)
		require.Equal(t, request.status, response.StatusCode, "%s %s: %s", request.method, request.path, body)
		require.NotContains(t, string(body), "private-credential")
	}
	require.Equal(t, uint64(7), c.State().SavedVersion)
}
