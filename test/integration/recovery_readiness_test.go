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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestInterruptedStartupRecoveryAllowsCaptureEndToEnd(t *testing.T) {
	// Replay a startup interrupted before durable device recording. The real
	// management API must show paused capture and automatically maintain the
	// old record on the user's next start, without a separate recovery action.
	directory := t.TempDir()
	journal := filepath.Join(directory, "capture.json")
	data, err := json.Marshal(map[string]any{"version": 1, "run_id": "interrupted-startup-1234", "pid": os.Getpid(), "started_at": time.Now(), "platform": runtime.GOOS, "device_recorded": false, "network": "10.192.0.1/16", "auto_route": false})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(journal, data, 0600))
	c, err := control.New(control.Options{Directory: directory, Factory: func(*kone.KoneConfig) (control.Engine, error) {
		return &isolatedEngine{ready: make(chan struct{}), stop: make(chan struct{})}, nil
	}, Preflight: func(context.Context, *kone.KoneConfig) kone.PreflightReport { return kone.PreflightReport{Ready: true} },
		InspectSystemDNSRecovery: func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) { return nil, nil },
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	call := recoveryConsole(t, c)
	status, doc := call("GET", "config", nil)
	require.Equal(t, 200, status)
	status, _ = call("PUT", "config", map[string]any{"base_version": doc["version"], "config": doc["config"], "inbound": doc["inbound"], "direct_only_confirmed": true})
	require.Equal(t, 200, status)
	status, readiness := call("GET", "readiness", nil)
	require.Equal(t, 200, status)
	require.True(t, readiness["ready"].(bool))
	require.NotContains(t, readiness, "recovery")
	require.FileExists(t, journal)
	status, state := call("GET", "state", nil)
	require.Equal(t, 200, status)
	require.Equal(t, "paused", state["data_state"])
	require.Empty(t, state["last_error"])
	for _, action := range []string{"start", "pause"} {
		status, operation := call("POST", "lifecycle/"+action, map[string]any{})
		require.Equal(t, 202, status)
		require.Eventually(t, func() bool {
			status, value := call("GET", "operations/"+operation["id"].(string), nil)
			return status == 200 && value["status"] == "succeeded"
		}, 2*time.Second, time.Millisecond)
		if action == "start" {
			current, readErr := os.ReadFile(journal)
			require.NoError(t, readErr)
			require.NotContains(t, string(current), "interrupted-startup-1234")
		}
	}
	require.NoFileExists(t, journal)
	status, logs := call("GET", "logs", nil)
	require.Equal(t, 200, status)
	found := false
	for _, item := range logs["records"].([]any) {
		record := item.(map[string]any)
		if record["message"] == "Previous capture recovery record cleared automatically" {
			found = true
			require.Equal(t, true, record["attrs"].(map[string]any)["automatic"])
		}
	}
	require.True(t, found, "successful automatic maintenance remains available in runtime logs")
}

func TestMachineDNSRecoveryRequiresConfirmationBeforeCaptureEndToEnd(t *testing.T) {
	// The controller, HTTP authorization and lifecycle are real; only the
	// machine lease inspector/restorer and TUN engine are isolated fakes.
	var mu sync.Mutex
	remaining := true
	var factoryCalls, recoveryCalls atomic.Int32
	c, err := control.New(control.Options{Directory: t.TempDir(), Factory: func(*kone.KoneConfig) (control.Engine, error) {
		factoryCalls.Add(1)
		return &isolatedEngine{ready: make(chan struct{}), stop: make(chan struct{})}, nil
	}, Preflight: func(context.Context, *kone.KoneConfig) kone.PreflightReport { return kone.PreflightReport{Ready: true} },
		InspectSystemDNSRecovery: func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) {
			mu.Lock()
			defer mu.Unlock()
			if remaining {
				return []kone.SystemDNSRecoveryEntry{{ID: strings.Repeat("a", 32), Status: "orphaned", CanRecover: true}}, nil
			}
			return nil, nil
		}, RecoverSystemDNS: func(context.Context, string) error {
			recoveryCalls.Add(1)
			mu.Lock()
			remaining = false
			mu.Unlock()
			return nil
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	call := recoveryConsole(t, c)
	status, doc := call("GET", "config", nil)
	require.Equal(t, 200, status)
	inbound := doc["inbound"].(map[string]any)
	inbound["enabled"] = true
	status, _ = call("PUT", "config", map[string]any{"base_version": doc["version"], "config": doc["config"], "inbound": inbound, "direct_only_confirmed": true})
	require.Equal(t, 200, status)
	wait := func(operation map[string]any, wanted string) {
		t.Helper()
		require.Eventually(t, func() bool {
			status, result := call("GET", "operations/"+operation["id"].(string), nil)
			return status == 200 && result["status"] == wanted
		}, 2*time.Second, time.Millisecond)
	}
	status, operation := call("POST", "lifecycle/start", map[string]any{})
	require.Equal(t, 202, status)
	wait(operation, "failed")
	require.Zero(t, factoryCalls.Load())
	require.Zero(t, recoveryCalls.Load(), "start must never launch an implicit elevated recovery")
	status, state := call("GET", "state", nil)
	require.Equal(t, 200, status)
	require.Equal(t, "paused", state["data_state"])
	require.Contains(t, state["last_error"], "explicit recovery")
	status, report := call("GET", "recovery", nil)
	require.Equal(t, 200, status)
	require.True(t, report["required"].(bool))
	require.False(t, report["can_clear"].(bool))
	require.Len(t, report["system_dns"], 1)
	status, _ = call("POST", "lifecycle/recover", map[string]any{})
	require.Equal(t, 400, status)
	require.Zero(t, recoveryCalls.Load())
	status, operation = call("POST", "lifecycle/recover", map[string]any{"confirm": true})
	require.Equal(t, 202, status)
	wait(operation, "succeeded")
	require.EqualValues(t, 1, recoveryCalls.Load())
	for _, action := range []string{"start", "pause"} {
		status, operation = call("POST", "lifecycle/"+action, map[string]any{})
		require.Equal(t, 202, status)
		wait(operation, "succeeded")
	}
	require.EqualValues(t, 1, factoryCalls.Load())
}

func recoveryConsole(t *testing.T, c *control.Controller) func(string, string, any) (int, map[string]any) {
	t.Helper()
	server := httptest.NewServer(c.Handler())
	t.Cleanup(server.Close)
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
	return call
}
