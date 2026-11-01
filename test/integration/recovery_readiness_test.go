package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestInterruptedStartupRecoveryAllowsCaptureEndToEnd(t *testing.T) {
	// Replay a startup interrupted before durable device recording. The real
	// management API must explain and clear the journal without touching host
	// networking, and allow the user's next explicit capture request.
	directory := t.TempDir()
	journal := filepath.Join(directory, "capture.json")
	data, err := json.Marshal(map[string]any{"version": 1, "run_id": "interrupted-startup-1234", "pid": os.Getpid(), "started_at": time.Now(), "platform": runtime.GOOS, "device_recorded": false, "network": "10.192.0.1/16", "auto_route": false})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(journal, data, 0600))
	c, err := control.New(control.Options{Directory: directory, Factory: func(*kone.KoneConfig) (control.Engine, error) {
		return &isolatedEngine{ready: make(chan struct{}), stop: make(chan struct{})}, nil
	}, Preflight: func(context.Context, *kone.KoneConfig) kone.PreflightReport { return kone.PreflightReport{Ready: true} }})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	var cookie *http.Cookie
	csrf := ""
	call := func(method, path string, body any) (int, map[string]any) {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		r, err := http.NewRequest(method, server.URL+"/api/v1/"+path, bytes.NewReader(data))
		require.NoError(t, err)
		if cookie != nil {
			r.AddCookie(cookie)
			r.Header.Set("X-CSRF-Token", csrf)
		}
		response, err := client.Do(r)
		require.NoError(t, err)
		defer response.Body.Close()
		if cookies := response.Cookies(); len(cookies) > 0 {
			cookie = cookies[0]
		}
		var value map[string]any
		require.NoError(t, json.NewDecoder(response.Body).Decode(&value))
		return response.StatusCode, value
	}
	status, auth := call("POST", "session", map[string]any{"token": c.BootstrapToken()})
	require.Equal(t, 200, status)
	csrf = auth["csrf_token"].(string)
	status, auth = call("POST", "auth/password", map[string]any{"password": "recovery-owner-password", "confirm_password": "recovery-owner-password"})
	require.Equal(t, 200, status)
	csrf = auth["csrf_token"].(string)
	status, doc := call("GET", "config", nil)
	require.Equal(t, 200, status)
	status, _ = call("PUT", "config", map[string]any{"base_version": doc["version"], "config": doc["config"], "inbound": doc["inbound"], "direct_only_confirmed": true})
	require.Equal(t, 200, status)
	status, readiness := call("GET", "readiness", nil)
	require.Equal(t, 200, status)
	require.False(t, readiness["ready"].(bool))
	recovery := readiness["recovery"].(map[string]any)
	require.True(t, recovery["can_clear"].(bool))
	require.Equal(t, "not_configured", recovery["items"].([]any)[0].(map[string]any)["status"])
	require.FileExists(t, journal)
	status, report := call("GET", "recovery", nil)
	require.Equal(t, 200, status)
	require.Equal(t, recovery["next_action"], report["next_action"])
	for _, action := range []string{"recover", "start", "pause"} {
		status, operation := call("POST", "lifecycle/"+action, map[string]any{})
		require.Equal(t, 202, status)
		require.Eventually(t, func() bool {
			status, value := call("GET", "operations/"+operation["id"].(string), nil)
			return status == 200 && value["status"] == "succeeded"
		}, 2*time.Second, time.Millisecond)
		if action == "recover" {
			require.NoFileExists(t, journal)
			status, readiness = call("GET", "readiness", nil)
			require.Equal(t, 200, status)
			require.True(t, readiness["ready"].(bool))
		}
	}
	require.NoFileExists(t, journal)
}
