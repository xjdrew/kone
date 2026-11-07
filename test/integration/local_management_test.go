package integration

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
)

func TestLocalBrowserSessionWithoutPassword(t *testing.T) {
	c, err := control.New(control.Options{Directory: t.TempDir()})
	require.NoError(t, err)
	defer c.Close()
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := server.Client()
	client.Jar = jar
	response, err := client.Post(server.URL+"/api/v1/session", "application/json", strings.NewReader(`{}`))
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode)
	var session map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&session))
	response.Body.Close()
	response, err = client.Get(server.URL + "/api/v1/state")
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode)
	var state map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&state))
	response.Body.Close()
	require.Equal(t, "admin", state["role"])
	require.Equal(t, true, state["local_access"])
	require.Equal(t, false, state["password_configured"])
	require.Equal(t, "paused", state["data_state"])
	// Mutations still require proof obtained through the same-origin session.
	response, err = client.Post(server.URL+"/api/v1/auth/password", "application/json", strings.NewReader(`{"password":"remote-password","confirm_password":"remote-password"}`))
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	response.Body.Close()
	request, err := http.NewRequest("POST", server.URL+"/api/v1/auth/password", strings.NewReader(`{"password":"remote-password","confirm_password":"remote-password"}`))
	require.NoError(t, err)
	request.Header.Set("X-CSRF-Token", session["csrf_token"].(string))
	response, err = client.Do(request)
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode)
	response.Body.Close()
	require.Equal(t, "paused", c.State().DataState)
}
