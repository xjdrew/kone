package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/kone"
	"github.com/xjdrew/kone/pkg/logstore"
)

func TestRuntimeStructuredLogsReachAuthenticatedManagementWithoutCapture(t *testing.T) {
	store := logstore.NewWithOptions(logstore.Options{Capacity: 3})
	var logger *slog.Logger
	c, err := control.New(control.Options{Directory: t.TempDir(), LogStore: store, ConfigureLogging: func(cfg kone.GeneralConfig) error {
		next, err := kone.NewLoggingHandler(io.Discard, cfg, false)
		if err == nil {
			logger = slog.New(store.Handler(next, "management"))
		}
		return err
	}})
	require.NoError(t, err)
	defer c.Close()
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	body, err := json.Marshal(map[string]string{"token": c.BootstrapToken()})
	require.NoError(t, err)
	auth, err := client.Post(server.URL+"/api/v1/session", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, 200, auth.StatusCode)
	cookie := auth.Cookies()[0]
	var setup struct {
		CSRF string `json:"csrf_token"`
	}
	require.NoError(t, json.NewDecoder(auth.Body).Decode(&setup))
	auth.Body.Close()
	passwordBody := `{"password":"integration-logs-password","confirm_password":"integration-logs-password"}`
	passwordRequest, err := http.NewRequest("POST", server.URL+"/api/v1/auth/password", strings.NewReader(passwordBody))
	require.NoError(t, err)
	passwordRequest.AddCookie(cookie)
	passwordRequest.Header.Set("Content-Type", "application/json")
	passwordRequest.Header.Set("X-CSRF-Token", setup.CSRF)
	configured, err := client.Do(passwordRequest)
	require.NoError(t, err)
	require.Equal(t, 200, configured.StatusCode)
	cookie = configured.Cookies()[0]
	configured.Body.Close()
	for range 4 {
		logger.Info("capture stays paused")
	}
	logger.Error("proxy http://user:private-password@127.0.0.1:1/?token=private-token", "password", "private-field")
	request, err := http.NewRequest("GET", server.URL+"/api/v1/logs?limit=2", nil)
	require.NoError(t, err)
	request.AddCookie(cookie)
	response, err := client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, 200, response.StatusCode)
	data, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	for _, secret := range []string{"private-password", "private-token", "private-field"} {
		require.NotContains(t, string(data), secret)
	}
	var logs logstore.Page
	require.NoError(t, json.Unmarshal(data, &logs))
	require.Len(t, logs.Records, 2)
	require.Equal(t, "ERROR", logs.Records[1].Level)
	require.Equal(t, uint64(2), logs.Dropped)
	require.True(t, logs.Gap)
	request, err = http.NewRequest("GET", server.URL+"/api/v1/logs?after="+strconv.FormatUint(logs.NextCursor, 10), nil)
	require.NoError(t, err)
	request.AddCookie(cookie)
	next, err := client.Do(request)
	require.NoError(t, err)
	defer next.Body.Close()
	require.NoError(t, json.NewDecoder(next.Body).Decode(&logs))
	require.Empty(t, logs.Records)
	require.Equal(t, "paused", c.State().DataState)
}
