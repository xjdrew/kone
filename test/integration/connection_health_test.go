package integration

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/kone"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConnectionHealthHTTPHandlesPausedDNSFailureAndPersistsAcrossManagerRestart(t *testing.T) {
	directory := t.TempDir()
	now := time.Now()
	state := kone.HealthState{Status: "paused", Entries: []kone.HealthIncident{{ID: 1, Generation: 2, Domain: "x.com", Status: "attention", Reason: "dns_failed", First: now, Last: now, Results: []kone.HealthResult{{Protocol: "dns", Source: "business", Status: "failed", DNSCode: "SERVFAIL", Time: now}}}}, Total: 1}
	data, err := json.Marshal(state)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, "connection-health.json"), data, 0600))
	manager, err := control.New(control.Options{Directory: directory})
	require.NoError(t, err)
	defer manager.Close()
	call := recoveryConsole(t, manager)
	status, response := call("GET", "connection-health?status=attention", nil)
	require.Equal(t, 200, status)
	require.Equal(t, float64(1), response["total"])
	status, _ = call("POST", "connection-health", map[string]any{"action": "recheck", "domain": "x.com", "generation": 2})
	require.Equal(t, 409, status)
	status, _ = call("POST", "connection-health", map[string]any{"action": "handled", "domain": "x.com", "generation": 2})
	require.Equal(t, 200, status)
	status, response = call("GET", "connection-health?status=attention", nil)
	require.Equal(t, 200, status)
	require.Equal(t, float64(0), response["total"])
	require.NoError(t, manager.Close())
	restarted, err := control.New(control.Options{Directory: directory})
	require.NoError(t, err)
	defer restarted.Close()
	server := httptest.NewServer(restarted.Handler())
	defer server.Close()
	client := server.Client()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client.Jar = jar
	session, err := client.Post(server.URL+"/api/v1/session", "application/json", strings.NewReader(`{}`))
	require.NoError(t, err)
	session.Body.Close()
	require.Equal(t, 200, session.StatusCode)
	again := func(method, path string, body any) (int, map[string]any) {
		response, err := client.Get(server.URL + "/api/v1/" + path)
		require.NoError(t, err)
		defer response.Body.Close()
		var value map[string]any
		require.NoError(t, json.NewDecoder(response.Body).Decode(&value))
		return response.StatusCode, value
	}
	status, response = again("GET", "connection-health?status=history", nil)
	require.Equal(t, 200, status)
	require.Equal(t, float64(1), response["total"])
	status, response = again("GET", "state", nil)
	require.Equal(t, 200, status)
	require.Equal(t, "paused", response["data_state"])
}
