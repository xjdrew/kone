package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
)

func TestManagementPasswordChangeRevokesOldSessionsAndPersists(t *testing.T) {
	directory := t.TempDir()
	c, err := control.New(control.Options{Directory: directory})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	server := httptest.NewServer(c.Handler())
	t.Cleanup(server.Close)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	call := func(method, path string, body any, cookie *http.Cookie, csrf string) (int, map[string]any, *http.Cookie) {
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
		var result map[string]any
		require.NoError(t, json.NewDecoder(response.Body).Decode(&result))
		var next *http.Cookie
		if cookies := response.Cookies(); len(cookies) != 0 {
			next = cookies[0]
		}
		return response.StatusCode, result, next
	}
	status, auth, cookie := call("POST", "session", map[string]any{"token": c.BootstrapToken()}, nil, "")
	require.Equal(t, 200, status)
	status, auth, cookie = call("POST", "auth/password", map[string]any{"password": "original-owner-password", "confirm_password": "original-owner-password"}, cookie, auth["csrf_token"].(string))
	require.Equal(t, 200, status)
	csrf := auth["csrf_token"].(string)
	status, _, second := call("POST", "session", map[string]any{"password": "original-owner-password"}, nil, "")
	require.Equal(t, 200, status)
	status, _, _ = call("PUT", "auth/password", map[string]any{"current_password": "incorrect-password", "password": "replacement-owner-password", "confirm_password": "replacement-owner-password"}, cookie, csrf)
	require.Equal(t, 403, status)
	status, replacement, next := call("PUT", "auth/password", map[string]any{"current_password": "original-owner-password", "password": "replacement-owner-password", "confirm_password": "replacement-owner-password"}, cookie, csrf)
	require.Equal(t, 200, status)
	require.NotNil(t, next)
	require.NotEqual(t, cookie.Value, next.Value)
	require.NotEqual(t, csrf, replacement["csrf_token"])
	for _, stale := range []*http.Cookie{cookie, second} {
		status, _, _ = call("GET", "state", nil, stale, "")
		require.Equal(t, 401, status)
	}
	status, state, _ := call("GET", "state", nil, next, "")
	require.Equal(t, 200, status)
	require.Equal(t, "paused", state["data_state"])
	require.Equal(t, float64(1), state["saved_version"], "changing passwords does not rewrite capture configuration")
	status, _, _ = call("POST", "session", map[string]any{"password": "original-owner-password"}, nil, "")
	require.Equal(t, 401, status)
	status, _, _ = call("POST", "session", map[string]any{"password": "replacement-owner-password"}, nil, "")
	require.Equal(t, 200, status)
	require.NoError(t, c.Close())
	reopened, err := control.New(control.Options{Directory: directory})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	server.Close()
	server = httptest.NewServer(reopened.Handler())
	t.Cleanup(server.Close)
	status, _, _ = call("POST", "session", map[string]any{"password": "replacement-owner-password"}, nil, "")
	require.Equal(t, 200, status, "replacement password survives restart")
}
