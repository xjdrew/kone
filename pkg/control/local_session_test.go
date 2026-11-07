package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoopbackAutomaticSession(t *testing.T) {
	c := testController(t, Options{})
	login := request(t, c, "", "POST", "/api/v1/session", map[string]any{})
	require.Equal(t, 200, login.Code, login.Body.String())
	cookie := login.Result().Cookies()[0]
	var session map[string]any
	require.NoError(t, json.Unmarshal(login.Body.Bytes(), &session))
	makeRequest := func(method, path, body string) *http.Request {
		r := httptest.NewRequest(method, "http://127.0.0.1:9200/api/v1/"+path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:12345"
		r.AddCookie(cookie)
		return r
	}
	state := httptestResponse(c, makeRequest("GET", "state", ""))
	require.Equal(t, 200, state.Code)
	require.Contains(t, state.Body.String(), `"role":"admin"`)
	require.Contains(t, state.Body.String(), `"password_configured":false`)
	r := makeRequest("POST", "auth/password", `{"password":"owner-password","confirm_password":"owner-password"}`)
	require.Equal(t, 401, httptestResponse(c, r).Code, "local writes still require CSRF")
	r = makeRequest("POST", "auth/password", `{"password":"owner-password","confirm_password":"owner-password"}`)
	r.Header.Set("X-CSRF-Token", session["csrf_token"].(string))
	require.Equal(t, 200, httptestResponse(c, r).Code)
	require.Equal(t, "paused", c.State().DataState)
}

func TestAutomaticSessionRejectsUntrustedOriginAndForwardedHeaders(t *testing.T) {
	c := testController(t, Options{})
	for _, tc := range []struct{ host, remote, origin string }{
		{"127.0.0.1:9200", "192.0.2.1:9000", ""},
		{"evil.example:9200", "127.0.0.1:9000", ""},
		{"127.0.0.1:9200", "127.0.0.1:9000", "https://evil.example"},
		{"localhost:9200", "127.0.0.1:9000", ""},
	} {
		r := httptest.NewRequest("POST", "http://"+tc.host+"/api/v1/session", strings.NewReader(`{}`))
		r.RemoteAddr = tc.remote
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("X-Forwarded-For", "127.0.0.1")
		require.NotEqual(t, 200, httptestResponse(c, r).Code)
	}
	c.mu.Lock()
	token, session := c.newSession("admin", false)
	session.Local = true
	c.mu.Unlock()
	r := httptest.NewRequest("GET", "http://127.0.0.1:9200/api/v1/state", nil)
	r.RemoteAddr = "192.0.2.1:9000"
	r.Header.Set("Authorization", "Bearer "+token)
	_, ok := c.authorize(r)
	require.False(t, ok, "a local token cannot be used remotely")
}

func TestLocalSessionRemainsAvailableWithPasswordAndRespectsLimit(t *testing.T) {
	c := testController(t, Options{})
	owner(t, c)
	require.Equal(t, 200, request(t, c, "", "POST", "/api/v1/session", map[string]any{}).Code)
	c.mu.Lock()
	for len(c.sessions) < 32 {
		c.newSession("read", true)
	}
	c.mu.Unlock()
	require.Equal(t, 429, request(t, c, "", "POST", "/api/v1/session", map[string]any{}).Code)
	c.mu.Lock()
	for _, session := range c.sessions {
		session.Expires = c.now().Add(-time.Second)
	}
	c.mu.Unlock()
	require.Equal(t, 200, request(t, c, "", "POST", "/api/v1/session", map[string]any{}).Code)
	c.Close()
	require.Equal(t, 429, request(t, c, "", "POST", "/api/v1/session", map[string]any{}).Code)
}

func TestSavedIPv6ChoiceSurvivesManagementRestart(t *testing.T) {
	c := testController(t, Options{})
	request := currentRequest(c)
	request.Config["core"].(map[string]any)["ipv6-network"] = ""
	_, err := c.Save(request)
	require.NoError(t, err)
	require.NoError(t, c.Close())
	reopened := testController(t, Options{Directory: c.directory})
	require.Empty(t, reopened.doc.Config.Core.IPv6Network)
}
