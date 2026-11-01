package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestSystemDNSRecoveryHTTPRequiresConfirmationAndPreservesExternalChanges(t *testing.T) {
	// Exercise real HTTP, password/cookie/CSRF and recovery operations. Only
	// machine DNS inspection/mutation is replaced; no host networking is touched.
	var mu sync.Mutex
	entries := []kone.SystemDNSRecoveryEntry{{ID: strings.Repeat("a", 32), DeviceName: "owned-test", Status: "orphaned", CanRecover: true}, {ID: strings.Repeat("b", 32), DeviceName: "external-test", Status: "external_change"}}
	var recovered []string
	c, err := control.New(control.Options{Directory: t.TempDir(),
		Factory: func(*kone.KoneConfig) (control.Engine, error) {
			t.Error("recovery started a capture engine")
			return nil, errors.New("unexpected engine")
		},
		InspectSystemDNSRecovery: func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) {
			mu.Lock()
			defer mu.Unlock()
			return append([]kone.SystemDNSRecoveryEntry(nil), entries...), nil
		},
		RecoverSystemDNS: func(_ context.Context, id string) error {
			mu.Lock()
			defer mu.Unlock()
			recovered = append(recovered, id)
			entries = entries[1:]
			return nil
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	var cookie *http.Cookie
	csrf := ""
	call := func(method, path string, input any) (int, map[string]any) {
		body, err := json.Marshal(input)
		require.NoError(t, err)
		r, err := http.NewRequest(method, server.URL+"/api/v1/"+path, bytes.NewReader(body))
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
		var result map[string]any
		require.NoError(t, json.NewDecoder(response.Body).Decode(&result))
		if next, ok := result["csrf_token"].(string); ok {
			csrf = next
		}
		return response.StatusCode, result
	}
	status, _ := call("POST", "session", map[string]any{"token": c.BootstrapToken()})
	require.Equal(t, 200, status)
	status, _ = call("POST", "auth/password", map[string]any{"password": "dns-recovery-owner-password", "confirm_password": "dns-recovery-owner-password"})
	require.Equal(t, 200, status)
	status, report := call("GET", "recovery", nil)
	require.Equal(t, 200, status)
	require.Len(t, report["system_dns"], 2)
	status, _ = call("POST", "lifecycle/recover", map[string]any{})
	require.Equal(t, 400, status)
	proof := csrf
	csrf = ""
	status, _ = call("POST", "lifecycle/recover", map[string]any{"confirm": true})
	require.Equal(t, 401, status)
	csrf = proof
	run := func(expected string) {
		status, operation := call("POST", "lifecycle/recover", map[string]any{"confirm": true})
		require.Equal(t, 202, status)
		require.Eventually(t, func() bool {
			status, result := call("GET", "operations/"+operation["id"].(string), nil)
			return status == 200 && result["status"] == expected
		}, 2*time.Second, 5*time.Millisecond)
	}
	run("failed")
	mu.Lock()
	require.Equal(t, []string{strings.Repeat("a", 32)}, recovered)
	require.Len(t, entries, 1)
	require.Equal(t, "external_change", entries[0].Status)
	mu.Unlock()
	status, report = call("GET", "recovery", nil)
	require.Equal(t, 200, status)
	require.Equal(t, true, report["required"])
	require.Len(t, report["system_dns"], 1)
	mu.Lock()
	entries = nil
	mu.Unlock() // Simulate separate, explicit owner repair.
	run("succeeded")
	status, state := call("GET", "state", nil)
	require.Equal(t, 200, status)
	require.Equal(t, "paused", state["data_state"])
	require.Equal(t, float64(1), state["saved_version"])
}
