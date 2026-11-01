package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func httptestPasswordRequest(t *testing.T, token, csrf string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "http://127.0.0.1:9200/api/v1/auth/password", strings.NewReader(`{"password":"owner-password","confirm_password":"owner-password"}`))
	r.RemoteAddr = "127.0.0.2:12345"
	r.AddCookie(&http.Cookie{Name: "kone_session", Value: token})
	r.Header.Set("X-CSRF-Token", csrf)
	return r
}
func httptestResponse(c *Controller, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c.Handler().ServeHTTP(w, r)
	return w
}

func TestFirstPasswordRequiresLocalSetupProofAndNeverGrantsCaptureAccess(t *testing.T) {
	c := testController(t, Options{})
	info := request(t, c, "", "GET", "/api/v1/auth", nil)
	require.Equal(t, 200, info.Code)
	require.Contains(t, info.Body.String(), `"setup_authorized":false`)
	require.Equal(t, 401, request(t, c, "", "POST", "/api/v1/auth/password", map[string]any{"password": "owner-password", "confirm_password": "owner-password"}).Code)
	setup, session, err := c.claim(c.BootstrapToken(), "", false)
	require.NoError(t, err)
	require.Equal(t, "setup", session.Role)
	for _, path := range []string{"state", "config", "logs", "readiness", "outbounds/health"} {
		require.Equal(t, 403, request(t, c, setup, "GET", "/api/v1/"+path, nil).Code, path)
	}
	require.Equal(t, 403, request(t, c, setup, "POST", "/api/v1/lifecycle/start", nil).Code)
	require.Equal(t, "paused", c.State().DataState)
	require.Contains(t, request(t, c, setup, "GET", "/api/v1/auth", nil).Body.String(), `"setup_authorized":true`)
	_, err = c.pair("read")
	require.Error(t, err)
	for _, input := range []map[string]any{
		{"password": "short", "confirm_password": "short"},
		{"password": "owner-password", "confirm_password": "different"},
		{"password": strings.Repeat(" ", 8), "confirm_password": strings.Repeat(" ", 8)},
		{"password": strings.Repeat("x", 129), "confirm_password": strings.Repeat("x", 129)},
		{"password": "owner-password", "confirm_password": "owner-password", "unexpected": true},
	} {
		require.Equal(t, 400, request(t, c, setup, "POST", "/api/v1/auth/password", input).Code)
	}
	result := request(t, c, setup, "POST", "/api/v1/auth/password", map[string]any{"password": "中文口令测试八字符", "confirm_password": "中文口令测试八字符"})
	require.Equal(t, 200, result.Code, result.Body.String())
	require.Equal(t, 401, request(t, c, setup, "GET", "/api/v1/state", nil).Code, "setup proof must be revoked after password creation")
	admin := result.Result().Cookies()[0].Value
	require.Equal(t, 200, request(t, c, admin, "GET", "/api/v1/state", nil).Code)
	require.Equal(t, "paused", c.State().DataState)
}

func TestPasswordPersistsAsSaltedHashAndBootstrapCannotBypassLogin(t *testing.T) {
	c := testController(t, Options{})
	admin := owner(t, c)
	data, err := os.ReadFile(filepath.Join(c.directory, "auth.json"))
	require.NoError(t, err)
	require.False(t, bytes.Contains(data, []byte("control-test-password")))
	var persisted passwordCredentials
	require.NoError(t, json.Unmarshal(data, &persisted))
	require.Len(t, persisted.Salt, 16)
	require.Len(t, persisted.Hash, 32)
	if runtime.GOOS != "windows" {
		stat, err := os.Stat(filepath.Join(c.directory, "auth.json"))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), stat.Mode().Perm())
	}
	require.NotContains(t, request(t, c, admin, "GET", "/api/v1/export", nil).Body.String(), "control-test-password")
	require.NoError(t, c.Close())
	reopened := testController(t, Options{Directory: c.directory})
	require.Equal(t, 401, request(t, reopened, admin, "GET", "/api/v1/state", nil).Code)
	require.Equal(t, 401, request(t, reopened, "", "POST", "/api/v1/session", map[string]any{"token": reopened.BootstrapToken()}).Code)
	wrong := request(t, reopened, "", "POST", "/api/v1/session", map[string]any{"password": "incorrect-password"})
	require.Equal(t, 401, wrong.Code)
	require.NotContains(t, wrong.Body.String(), "incorrect-password")
	login := request(t, reopened, "", "POST", "/api/v1/session", map[string]any{"password": "control-test-password"})
	require.Equal(t, 200, login.Code, login.Body.String())
	cookie := login.Result().Cookies()[0]
	require.True(t, cookie.HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	require.Equal(t, 200, request(t, reopened, cookie.Value, "GET", "/api/v1/state", nil).Code)
	require.Equal(t, 200, request(t, reopened, cookie.Value, "POST", "/api/v1/session/logout", nil).Code)
	require.Equal(t, 401, request(t, reopened, cookie.Value, "GET", "/api/v1/state", nil).Code)
}

func TestPasswordSetupValidatesCSRFOriginAndVerificationBudgets(t *testing.T) {
	c := testController(t, Options{})
	setup, s, err := c.claim(c.BootstrapToken(), "", false)
	require.NoError(t, err)
	r := request(t, c, setup, "POST", "/api/v1/auth/password", map[string]any{"password": "invalid"})
	require.Equal(t, 400, r.Code)
	for range 8 {
		request(t, c, "", "POST", "/api/v1/session", map[string]any{"password": "incorrect-password"})
	}
	require.Equal(t, 429, request(t, c, "", "POST", "/api/v1/session", map[string]any{"password": "incorrect-password"}).Code)
	req := httptestPasswordRequest(t, setup, s.csrf)
	req.Header.Del("X-CSRF-Token")
	w := httptestResponse(c, req)
	require.Equal(t, 401, w.Code)
	req = httptestPasswordRequest(t, setup, s.csrf)
	req.Header.Set("Origin", "https://untrusted.invalid")
	require.Equal(t, 403, httptestResponse(c, req).Code)
}

func TestPasswordFileCorruptionFailsClosedAndSetupRaceHasOneWinner(t *testing.T) {
	for _, data := range []string{`{}`, `{"version":999,"salt":"eA==","hash":"eA=="}`, strings.Repeat("x", 4097), `{`} {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "auth.json"), []byte(data), 0600))
		_, err := New(Options{Directory: dir})
		require.Error(t, err)
	}
	c := testController(t, Options{})
	first, _, err := c.claim(c.BootstrapToken(), "", false)
	require.NoError(t, err)
	c.mu.Lock()
	c.bootstrap = randomToken()
	c.mu.Unlock()
	second, _, err := c.claim(c.BootstrapToken(), "", false)
	require.NoError(t, err)
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for _, token := range []string{first, second} {
		wg.Go(func() {
			codes <- request(t, c, token, "POST", "/api/v1/auth/password", map[string]any{"password": "race-owner-password", "confirm_password": "race-owner-password"}).Code
		})
	}
	wg.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 200 {
			success++
		} else {
			require.Contains(t, []int{401, 409}, code)
		}
	}
	require.Equal(t, 1, success)
}

func TestRequestRateCapacityPreservesExistingClientsAndLocalOwnerAccess(t *testing.T) {
	now := time.Now()
	c := testController(t, Options{Now: func() time.Time { return now }})
	probe := func(address string, login bool) bool {
		r := httptest.NewRequest("GET", "http://127.0.0.1:9200/api/v1/auth", nil)
		r.RemoteAddr = address
		return c.allowRequest(r, login)
	}
	for i := range 252 {
		require.True(t, probe(fmt.Sprintf("198.51.%d.%d:1000", i/256, i%256), false))
	}
	require.False(t, probe("203.0.113.1:1000", false))
	for _, host := range []string{"127.0.0.1:1000", "[::1]:1000"} {
		require.True(t, probe(host, false))
		require.True(t, probe(host, true))
	}
	require.Len(t, c.requestRates, 256)
	now = now.Add(time.Second)
	require.True(t, probe("198.51.0.0:1000", false), "an existing remote bucket must survive its own window reset")
	require.True(t, probe("127.0.0.1:1000", false), "owner status must remain reachable")
	require.False(t, probe("203.0.113.1:1000", false))
	now = now.Add(2 * time.Minute)
	require.True(t, probe("203.0.113.1:1000", false), "expired buckets must free their capacity")
}
