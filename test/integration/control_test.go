package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/kone"
)

type isolatedEngine struct {
	ready, stop chan struct{}
	once        sync.Once
}

func (e *isolatedEngine) Run(ctx context.Context) error {
	close(e.ready)
	select {
	case <-ctx.Done():
	case <-e.stop:
	}
	return nil
}
func (e *isolatedEngine) Close() error                                   { e.once.Do(func() { close(e.stop) }); return nil }
func (e *isolatedEngine) Ready() <-chan struct{}                         { return e.ready }
func (e *isolatedEngine) Reload(*kone.KoneConfig) error                  { return nil }
func (e *isolatedEngine) SetTrafficObserver(*kone.TrafficObserver) error { return nil }

func TestManagementConfigurationCaptureAndPauseEndToEnd(t *testing.T) {
	// Exercise the real HTTP, authorization, persistence and lifecycle together;
	// replace only privileged device ownership. No host networking is modified.
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
			data, e := json.Marshal(input)
			require.NoError(t, e)
			body = bytes.NewReader(data)
		}
		r, e := http.NewRequest(method, server.URL+"/api/v1/"+path, body)
		require.NoError(t, e)
		if cookie != nil {
			r.AddCookie(cookie)
			r.Header.Set("X-CSRF-Token", csrf)
		}
		response, e := client.Do(r)
		require.NoError(t, e)
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
	status, auth = call("POST", "auth/password", map[string]any{"password": "integration-owner-password", "confirm_password": "integration-owner-password"})
	require.Equal(t, 200, status)
	csrf = auth["csrf_token"].(string)
	status, doc := call("GET", "config", nil)
	require.Equal(t, 200, status)
	inbound := doc["inbound"].(map[string]any)
	inbound["enabled"] = true
	status, _ = call("PUT", "config", map[string]any{"base_version": doc["version"], "config": doc["config"], "inbound": inbound, "direct_only_confirmed": true})
	require.Equal(t, 200, status)
	for _, action := range []string{"start", "pause", "start", "stop"} {
		status, operation := call("POST", "lifecycle/"+action, nil)
		require.Equal(t, 202, status)
		require.Eventually(t, func() bool {
			status, result := call("GET", "operations/"+operation["id"].(string), nil)
			return status == 200 && result["status"] == "succeeded"
		}, 2*time.Second, time.Millisecond)
		status, state := call("GET", "state", nil)
		require.Equal(t, 200, status)
		require.Equal(t, "ready", state["control_state"])
	}
	status, state := call("GET", "state", nil)
	require.Equal(t, 200, status)
	require.Equal(t, "paused", state["data_state"])
	require.NoError(t, c.Close())
	reopened, err := control.New(control.Options{Directory: directory})
	require.NoError(t, err)
	defer reopened.Close()
	require.Equal(t, "paused", reopened.State().State)
	require.Equal(t, uint64(2), reopened.State().SavedVersion)
}
