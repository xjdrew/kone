package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func passwordChangeInput(password string) map[string]any {
	return map[string]any{"current_password": "control-test-password", "password": password, "confirm_password": password}
}

func TestPasswordChangeValidatesCurrentPasswordAndStrictInput(t *testing.T) {
	for name, body := range map[string]any{
		"wrong current":   map[string]any{"current_password": "incorrect-password", "password": "new-owner-password", "confirm_password": "new-owner-password"},
		"short":           passwordChangeInput("short"),
		"spaces":          passwordChangeInput(strings.Repeat(" ", 8)),
		"oversize":        passwordChangeInput(strings.Repeat("x", 129)),
		"utf8 bytes":      passwordChangeInput(strings.Repeat("中", 43)),
		"too few runes":   passwordChangeInput(strings.Repeat("中", 7)),
		"mismatch":        map[string]any{"current_password": "control-test-password", "password": "new-owner-password", "confirm_password": "other-password"},
		"unknown field":   map[string]any{"current_password": "control-test-password", "password": "new-owner-password", "confirm_password": "new-owner-password", "extra": true},
		"missing current": map[string]any{"password": "new-owner-password", "confirm_password": "new-owner-password"},
		"framing":         `{"current_password":"control-test-password","password":"new-owner-password","confirm_password":"new-owner-password"} {}`,
		"malformed":       `{`,
	} {
		t.Run(name, func(t *testing.T) {
			c := testController(t, Options{})
			token := owner(t, c)
			before := append([]byte(nil), c.credentials.Hash...)
			response := request(t, c, token, "PUT", "/api/v1/auth/password", body)
			want := 400
			if name == "wrong current" {
				want = 403
			}
			require.Equal(t, want, response.Code, response.Body.String())
			require.Equal(t, before, c.credentials.Hash)
			require.NotContains(t, response.Body.String(), "control-test-password")
		})
	}
}

func TestPasswordChangeRotatesSessionsPairingAndPersists(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	oldSalt := append([]byte(nil), c.credentials.Salt...)
	_, oldSession, err := c.passwordSession("control-test-password", false)
	require.NoError(t, err)
	pair, err := c.pair("read")
	require.NoError(t, err)
	password := strings.Repeat("中", 8)
	response := request(t, c, token, "PUT", "/api/v1/auth/password", passwordChangeInput(password))
	require.Equal(t, 200, response.Code, response.Body.String())
	require.NotEqual(t, oldSalt, c.credentials.Salt)
	cookie := response.Result().Cookies()[0]
	require.NotEqual(t, token, cookie.Value)
	require.True(t, cookie.HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	var result map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.NotEmpty(t, result["csrf_token"])
	require.NotEmpty(t, result["session_id"])
	require.Equal(t, 401, request(t, c, token, "GET", "/api/v1/state", nil).Code)
	require.False(t, c.revoke(oldSession.ID))
	_, _, err = c.claim("", pair.Code, true)
	require.Error(t, err)
	require.Equal(t, 200, request(t, c, cookie.Value, "GET", "/api/v1/state", nil).Code)
	_, _, err = c.passwordSession("control-test-password", false)
	require.Error(t, err)
	_, _, err = c.passwordSession(password, false)
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(c.directory, "auth.json"))
	require.NoError(t, err)
	require.NotContains(t, string(data), password)
	require.NoError(t, c.Close())
	reopened := testController(t, Options{Directory: c.directory})
	_, _, err = reopened.passwordSession("control-test-password", false)
	require.Error(t, err)
	_, _, err = reopened.passwordSession(password, false)
	require.NoError(t, err)
}

func TestPasswordChangeRequiresAdminCSRFAndTrustedOrigin(t *testing.T) {
	c := testController(t, Options{})
	setup, _, err := c.claim(c.BootstrapToken(), "", false)
	require.NoError(t, err)
	require.Equal(t, 403, request(t, c, setup, "PUT", "/api/v1/auth/password", passwordChangeInput("new-password")).Code)
	setupResult := request(t, c, setup, "POST", "/api/v1/auth/password", map[string]any{"password": "control-test-password", "confirm_password": "control-test-password"})
	require.Equal(t, 200, setupResult.Code)
	token := setupResult.Result().Cookies()[0].Value
	pair, err := c.pair("read")
	require.NoError(t, err)
	reader, _, err := c.claim("", pair.Code, true)
	require.NoError(t, err)
	require.Equal(t, 403, request(t, c, reader, "PUT", "/api/v1/auth/password", passwordChangeInput("new-password")).Code)
	require.Equal(t, 401, request(t, c, "", "PUT", "/api/v1/auth/password", passwordChangeInput("new-password")).Code)
	for _, scenario := range []string{"missing-csrf", "wrong-csrf", "origin"} {
		data, err := json.Marshal(passwordChangeInput("new-password"))
		require.NoError(t, err)
		r := httptest.NewRequest("PUT", "http://127.0.0.1:9200/api/v1/auth/password", bytes.NewReader(data))
		r.RemoteAddr = "127.0.0.1:12345"
		r.AddCookie(&http.Cookie{Name: "kone_session", Value: token})
		r.Header.Set("X-CSRF-Token", c.sessions[tokenHash(token)].csrf)
		want := 401
		switch scenario {
		case "missing-csrf":
			r.Header.Del("X-CSRF-Token")
		case "wrong-csrf":
			r.Header.Set("X-CSRF-Token", "invalid")
		case "origin":
			r.Header.Set("Origin", "https://untrusted.invalid")
			want = 403
		}
		require.Equal(t, want, httptestResponse(c, r).Code, scenario)
	}
}

func TestPasswordChangeFailureKeepsPreviousCredentials(t *testing.T) {
	for _, scenario := range []string{"busy", "persistence"} {
		t.Run(scenario, func(t *testing.T) {
			c := testController(t, Options{})
			token := owner(t, c)
			before := append([]byte(nil), c.credentials.Hash...)
			want := 429
			if scenario == "busy" {
				c.credentials.slots <- struct{}{}
				c.credentials.slots <- struct{}{}
			} else {
				path := filepath.Join(c.directory, "auth.json")
				require.NoError(t, os.Rename(path, path+".saved"))
				require.NoError(t, os.Mkdir(path, 0700))
				want = 500
			}
			response := request(t, c, token, "PUT", "/api/v1/auth/password", passwordChangeInput("new-owner-password"))
			require.Equal(t, want, response.Code)
			require.Equal(t, before, c.credentials.Hash)
			require.Empty(t, response.Result().Cookies())
			if scenario == "busy" {
				<-c.credentials.slots
				<-c.credentials.slots
			} else {
				path := filepath.Join(c.directory, "auth.json")
				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Rename(path+".saved", path))
			}
			_, _, err := c.passwordSession("control-test-password", false)
			require.NoError(t, err)
		})
	}
}

type passwordChangeBody struct {
	io.Reader
	once       sync.Once
	beforeRead func()
}

func (r *passwordChangeBody) Read(buffer []byte) (int, error) {
	r.once.Do(r.beforeRead)
	return r.Reader.Read(buffer)
}

func TestPasswordChangeRejectsSessionRevocationAndStopBeforeCommit(t *testing.T) {
	for _, scenario := range []string{"revoked", "expired", "closed"} {
		t.Run(scenario, func(t *testing.T) {
			c := testController(t, Options{})
			token := owner(t, c)
			before := append([]byte(nil), c.credentials.Hash...)
			data, err := json.Marshal(passwordChangeInput("new-owner-password"))
			require.NoError(t, err)
			body := &passwordChangeBody{Reader: bytes.NewReader(data), beforeRead: func() {
				c.mu.Lock()
				defer c.mu.Unlock()
				switch scenario {
				case "revoked":
					delete(c.sessions, tokenHash(token))
				case "expired":
					c.sessions[tokenHash(token)].Expires = c.now().Add(-1)
				case "closed":
					c.closed = true
				}
			}}
			r := httptest.NewRequest("PUT", "http://127.0.0.1:9200/api/v1/auth/password", body)
			r.RemoteAddr = "127.0.0.1:12345"
			r.Header.Set("Authorization", "Bearer "+token)
			require.Equal(t, 409, httptestResponse(c, r).Code)
			require.Equal(t, before, c.credentials.Hash)
		})
	}
}

func TestConcurrentPasswordChangesHaveOneWinner(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	second, _, err := c.passwordSession("control-test-password", false)
	require.NoError(t, err)
	codes := make(chan int, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i, token := range []string{token, second} {
		workers.Go(func() {
			<-start
			password := []string{"first-new-password", "second-new-password"}[i]
			codes <- request(t, c, token, "PUT", "/api/v1/auth/password", passwordChangeInput(password)).Code
		})
	}
	close(start)
	workers.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 200 {
			success++
		} else {
			require.Contains(t, []int{401, 403, 409}, code)
		}
	}
	require.Equal(t, 1, success)
	require.Len(t, c.sessions, 1)
}

func TestPasswordChangeAcceptsMaximumBytesAndPreservesRemoteScope(t *testing.T) {
	c := testController(t, Options{})
	owner(t, c)
	token, _, err := c.passwordSession("control-test-password", true)
	require.NoError(t, err)
	password := strings.Repeat("x", 128)
	response := request(t, c, token, "PUT", "/api/v1/auth/password", passwordChangeInput(password))
	require.Equal(t, 200, response.Code)
	newToken := response.Result().Cookies()[0].Value
	require.True(t, c.sessions[tokenHash(newToken)].Remote)
	_, _, err = c.passwordSession(password, false)
	require.NoError(t, err)
}
