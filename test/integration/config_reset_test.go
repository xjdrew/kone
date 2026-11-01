package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestConfigurationResetRequiresPausedCaptureAndPersistsDefaults(t *testing.T) {
	// Real HTTP/authentication/persistence, with only the privileged engine
	// replaced. This journey never changes system networking.
	directory := t.TempDir()
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
	call := func(method, path string, input any) (int, map[string]any) {
		var body io.Reader
		if input != nil {
			data, marshalErr := json.Marshal(input)
			require.NoError(t, marshalErr)
			body = bytes.NewReader(data)
		}
		r, requestErr := http.NewRequest(method, server.URL+"/api/v1/"+path, body)
		require.NoError(t, requestErr)
		if cookie != nil {
			r.AddCookie(cookie)
			r.Header.Set("X-CSRF-Token", csrf)
		}
		response, callErr := client.Do(r)
		require.NoError(t, callErr)
		defer response.Body.Close()
		if cookies := response.Cookies(); len(cookies) != 0 {
			cookie = cookies[0]
		}
		var value map[string]any
		require.NoError(t, json.NewDecoder(response.Body).Decode(&value))
		if next, ok := value["csrf_token"].(string); ok {
			csrf = next
		}
		return response.StatusCode, value
	}
	status, _ := call("POST", "session", map[string]any{"token": c.BootstrapToken()})
	require.Equal(t, 200, status)
	status, _ = call("POST", "auth/password", map[string]any{"password": "reset-owner-password", "confirm_password": "reset-owner-password"})
	require.Equal(t, 200, status)
	status, doc := call("GET", "config", nil)
	require.Equal(t, 200, status)
	inbound := doc["inbound"].(map[string]any)
	inbound["name"] = "Custom capture"
	status, saved := call("PUT", "config", map[string]any{"base_version": doc["version"], "config": doc["config"], "inbound": inbound, "direct_only_confirmed": true})
	require.Equal(t, 200, status)
	run := func(action string) {
		status, operation := call("POST", "lifecycle/"+action, nil)
		require.Equal(t, 202, status)
		require.Eventually(t, func() bool {
			status, result := call("GET", "operations/"+operation["id"].(string), nil)
			return status == 200 && result["status"] == "succeeded"
		}, 2*time.Second, time.Millisecond)
	}
	run("start")
	status, blocked := call("POST", "config/defaults", map[string]any{"base_version": saved["version"]})
	require.Equal(t, 409, status)
	require.Equal(t, "capture_locked", blocked["error"].(map[string]any)["code"])
	run("pause")
	status, _ = call("POST", "config/defaults", map[string]any{"base_version": doc["version"]})
	require.Equal(t, 409, status, "stale browser must reload")
	status, reset := call("POST", "config/defaults", map[string]any{"base_version": saved["version"]})
	require.Equal(t, 200, status)
	require.Equal(t, false, reset["direct_only_confirmed"])
	require.Equal(t, "TUN", reset["inbound"].(map[string]any)["name"])
	require.Equal(t, false, reset["applied"])
	status, state := call("GET", "state", nil)
	require.Equal(t, 200, status, "local login survives the reset")
	require.Equal(t, "paused", state["data_state"])
	status, _ = call("POST", "session/logout", nil)
	require.Equal(t, 200, status)
	status, _ = call("POST", "session", map[string]any{"password": "reset-owner-password"})
	require.Equal(t, 200, status, "reset preserves the management password")
	require.NoError(t, c.Close())
	reopened, err := control.New(control.Options{Directory: directory})
	require.NoError(t, err)
	defer reopened.Close()
	require.Equal(t, reset["version"], float64(reopened.State().SavedVersion))
	require.Equal(t, "TUN", reopened.Document()["inbound"].(control.Inbound).Name)
	require.Equal(t, "paused", reopened.State().State)
}
