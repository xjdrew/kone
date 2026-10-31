package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func request(t *testing.T, c *Controller, token, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			reader = strings.NewReader(s)
		} else {
			data, err := json.Marshal(body)
			require.NoError(t, err)
			reader = bytes.NewReader(data)
		}
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:9200"+path, reader)
	r.RemoteAddr = "127.0.0.1:12345"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	c.Handler().ServeHTTP(w, r)
	return w
}
func owner(t *testing.T, c *Controller) string {
	t.Helper()
	token, _, err := c.claim(c.BootstrapToken(), "", false)
	require.NoError(t, err)
	return token
}
func TestManagementAuthorizationAndReadOnlyRoles(t *testing.T) {
	c := testController(t, Options{})
	require.Equal(t, 401, request(t, c, "", "GET", "/api/v1/config", nil).Code)
	r := request(t, c, "", "POST", "/api/v1/session", map[string]any{"token": c.BootstrapToken()})
	require.Equal(t, 200, r.Code)
	require.Len(t, r.Result().Cookies(), 1)
	cookie := r.Result().Cookies()[0]
	require.True(t, cookie.HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	var auth map[string]any
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &auth))
	makeCookieRequest := func(csrf string) int {
		r := httptest.NewRequest("POST", "http://127.0.0.1:9200/api/v1/privacy/clear", nil)
		r.RemoteAddr = "127.0.0.1:12"
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		c.Handler().ServeHTTP(w, r)
		return w.Code
	}
	require.Equal(t, 401, makeCookieRequest(""))
	require.Equal(t, 200, makeCookieRequest(auth["csrf_token"].(string)))
	_, _, err := c.claim(cookie.Value, "", false)
	require.Error(t, err)
	for _, role := range []string{"read", "admin"} {
		pair, err := c.pair(role)
		require.NoError(t, err)
		token, session, err := c.claim("", pair.Code, true)
		require.NoError(t, err)
		_, _, err = c.claim("", pair.Code, true)
		require.Error(t, err)
		require.Equal(t, 200, request(t, c, token, "GET", "/api/v1/state", nil).Code)
		status := request(t, c, token, "POST", "/api/v1/privacy/clear", nil).Code
		if role == "read" {
			require.Equal(t, 403, status)
			require.Equal(t, 403, request(t, c, token, "GET", "/api/v1/sessions", nil).Code)
		} else {
			require.Equal(t, 200, status)
		}
		require.True(t, c.revoke(session.ID))
		require.False(t, c.revoke(session.ID))
		require.Equal(t, 401, request(t, c, token, "GET", "/api/v1/state", nil).Code)
	}
	_, err = c.pair("owner")
	require.Error(t, err)
}

func TestAPIHostOriginAndInputBoundaries(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	for _, host := range []string{"evil.example:9200", "127.0.0.1", "example.com", "192.0.2.1:9200"} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:9200/api/v1/state", nil)
		r.Host = host
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		c.Handler().ServeHTTP(w, r)
		require.Equal(t, 403, w.Code, host)
	}
	for _, header := range []string{"Origin", "Sec-Fetch-Site"} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:9200/api/v1/state", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		if header == "Origin" {
			r.Header.Set(header, "https://evil.example")
		} else {
			r.Header.Set(header, "cross-site")
		}
		w := httptest.NewRecorder()
		c.Handler().ServeHTTP(w, r)
		require.Equal(t, 403, w.Code)
	}
	for _, body := range []string{`{"unknown":true}`, `{} {}`, `not-json`, strings.Repeat("x", (1<<20)+1)} {
		require.Equal(t, 400, request(t, c, token, "PUT", "/api/v1/config", body).Code)
	}
	require.Equal(t, 404, request(t, c, token, "GET", "/api/v1/unknown", nil).Code)
	require.Equal(t, 405, request(t, c, "", "POST", "/", nil).Code)
	require.Equal(t, 200, request(t, c, "", "GET", "/healthz", nil).Code)
	static := request(t, c, "", "GET", "/", nil)
	require.Equal(t, 200, static.Code)
	require.Contains(t, static.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
}

func TestConfigAPIAndRuleSimulation(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	r := currentRequest(c)
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/config/validate", r).Code)
	require.Equal(t, 200, request(t, c, token, "PUT", "/api/v1/config", r).Code)
	require.Equal(t, 409, request(t, c, token, "PUT", "/api/v1/config", r).Code)
	exact := map[string]any{"base_version": c.doc.Version, "target": "example.com", "outbound": "direct", "protocol": "tcp", "port": 443}
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/rules/exact", exact).Code)
	require.Equal(t, 409, request(t, c, token, "POST", "/api/v1/rules/exact", exact).Code)
	for _, target := range []string{"example.com", "192.0.2.1"} {
		r := request(t, c, token, "POST", "/api/v1/rules/simulate", map[string]any{"target": target, "protocol": "tcp", "port": 443})
		require.Equal(t, 200, r.Code, r.Body.String())
		require.Contains(t, r.Body.String(), "config_version")
	}
	require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/rules/simulate", map[string]any{"target": "bad/url"}).Code)
	for _, target := range []string{"bad name", "2001:db8::1"} {
		exact["target"] = target
		require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/rules/exact", exact).Code)
	}
	require.Equal(t, 200, request(t, c, token, "GET", "/api/v1/export", nil).Code)
	require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/config/undo", map[string]any{"base_version": c.doc.Version}).Code)
	for _, endpoint := range []string{"config", "traffic?flow_ids=one,two&path_ids=x&limit=90000&metric=cumulative", "flows", "dns", "diagnostics", "operations", "sessions", "access/lan"} {
		require.Equal(t, 200, request(t, c, token, "GET", "/api/v1/"+endpoint, nil).Code, endpoint)
	}
	require.Equal(t, 410, request(t, c, token, "GET", "/api/v1/flows/expired", nil).Code)
	require.Equal(t, 404, request(t, c, token, "GET", "/api/v1/operations/expired", nil).Code)
	require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/diagnostics/expired/cancel", nil).Code)
	require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/access/lan", map[string]any{"enabled": true, "address": "0.0.0.0:9201"}).Code)
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/access/lan", map[string]any{"enabled": false}).Code)
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/pairing", map[string]any{"role": "read"}).Code)
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/sessions/expired/revoke", nil).Code)
	require.Equal(t, 404, request(t, c, token, "POST", "/api/v1/lifecycle/unknown", nil).Code)
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/lifecycle/preflight", nil).Code)
}

func TestServeSingleInstanceAndCancellation(t *testing.T) {
	c := testController(t, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	result := make(chan error, 1)
	go func() { result <- c.Serve(ctx, "127.0.0.1:0", func(url string) { ready <- url }) }()
	var raw string
	select {
	case raw = <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("control server did not start")
	}
	u, err := url.Parse(raw)
	require.NoError(t, err)
	require.NotEmpty(t, u.Fragment)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	u.Fragment = ""
	u.Path = "/healthz"
	response, err := client.Get(u.String())
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, 200, response.StatusCode)
	lock, err := lockInstance(filepath.Join(c.directory, "instance.lock"))
	require.Error(t, err)
	if lock != nil {
		lock.Close()
	}
	cancel()
	select {
	case err = <-result:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("control did not stop")
	}
	lock, err = lockInstance(filepath.Join(c.directory, "instance.lock"))
	require.NoError(t, err)
	require.NoError(t, lock.Close())
	other := testController(t, Options{})
	require.ErrorContains(t, other.Serve(context.Background(), "0.0.0.0:0", nil), "loopback")
}

func TestSessionExpiryAndRateLimits(t *testing.T) {
	now := time.Now()
	var mu sync.Mutex
	c := testController(t, Options{Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }})
	token := owner(t, c)
	mu.Lock()
	now = now.Add(9 * time.Hour)
	mu.Unlock()
	require.Equal(t, 401, request(t, c, token, "GET", "/api/v1/state", nil).Code)
	var status int
	for range 9 {
		status = request(t, c, "", "POST", "/api/v1/session", `{"token":"invalid"}`).Code
	}
	require.Equal(t, 429, status)
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	require.Equal(t, 401, request(t, c, "", "POST", "/api/v1/session", `{"token":"invalid"}`).Code)
	for range 32 {
		c.mu.Lock()
		c.newSession("read", true)
		c.mu.Unlock()
	}
	_, _, err := c.claim("", "", true)
	require.ErrorContains(t, err, "session limit")
	for range 4 {
		_, err := c.pair("read")
		require.NoError(t, err)
	}
	_, err = c.pair("read")
	require.ErrorContains(t, err, "too many")
	query := trafficQuery(httptest.NewRequest("GET", "http://127.0.0.1:1/?flow_ids=a,b&path_ids=x&since=2026-11-01T00:00:00Z&limit=5", nil))
	require.Equal(t, []string{"a", "b"}, query.FlowIDs)
	require.Equal(t, 5, query.Limit)
	require.False(t, query.Since.IsZero())
}

var _ = kone.BuiltinDirect
