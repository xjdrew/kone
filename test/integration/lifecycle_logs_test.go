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
	"github.com/xjdrew/kone/pkg/logstore"
)

func TestRuntimeLogsExplainStartupCaptureAndPauseWithoutSyntheticRecords(t *testing.T) {
	// Exercise the production HTTP/authentication/logging path. Replace only
	// the privileged engine so no host networking or upstream proxy is touched.
	c, err := control.New(control.Options{Directory: t.TempDir(), Factory: func(*kone.KoneConfig) (control.Engine, error) {
		return &isolatedEngine{ready: make(chan struct{}), stop: make(chan struct{})}, nil
	}, Preflight: func(context.Context, *kone.KoneConfig) kone.PreflightReport { return kone.PreflightReport{Ready: true} }})
	require.NoError(t, err)
	defer c.Close()
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	var cookie *http.Cookie
	csrf := ""
	call := func(method, path string, input any, result any) {
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
		require.Contains(t, []int{200, 202}, response.StatusCode, path)
		if cookies := response.Cookies(); len(cookies) != 0 {
			cookie = cookies[0]
		}
		require.NoError(t, json.NewDecoder(response.Body).Decode(result))
	}
	var auth struct {
		CSRF string `json:"csrf_token"`
	}
	call("POST", "session", map[string]any{"token": c.BootstrapToken()}, &auth)
	csrf = auth.CSRF
	call("POST", "auth/password", map[string]any{"password": "lifecycle-log-password", "confirm_password": "lifecycle-log-password"}, &auth)
	csrf = auth.CSRF
	var startup logstore.Page
	call("GET", "logs?min_level=info", nil, &startup)
	require.NotEmpty(t, startup.Records, "opening management must produce useful logs before capture starts")
	for _, record := range startup.Records {
		require.Equal(t, "management", record.Source)
	}
	doc := c.Document()
	config := doc["config"].(map[string]any)
	config["outbounds"] = []map[string]any{{"name": "unused-proxy", "url": "socks5://owner:must-not-appear@127.0.0.1:1080"}}
	confirmed := true
	_, err = c.Save(control.SaveRequest{BaseVersion: c.State().SavedVersion, Config: config, Inbound: doc["inbound"].(control.Inbound), DirectOnlyConfirmed: &confirmed})
	require.NoError(t, err)
	for _, action := range []string{"start", "pause"} {
		var operation control.Operation
		call("POST", "lifecycle/"+action, nil, &operation)
		require.Eventually(t, func() bool {
			var current control.Operation
			call("GET", "operations/"+operation.ID, nil, &current)
			return current.Status == "succeeded"
		}, 2*time.Second, time.Millisecond)
	}
	var completed logstore.Page
	call("GET", "logs?min_level=info", nil, &completed)
	stages := map[string]bool{}
	for _, record := range completed.Records {
		stage, _ := record.Attrs["stage"].(string)
		stages[stage] = true
	}
	require.True(t, stages["preflight"], "the timeline must explain the preflight result")
	require.True(t, stages["startup"], "starting and pausing capture must retain management startup history")
	require.True(t, stages["ready"], "the timeline must confirm when capture became usable")
	require.True(t, stages["pause"], "the timeline must confirm cleanup after pausing")
	encoded, err := json.Marshal(completed)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "must-not-appear")
	require.NotContains(t, string(encoded), "lifecycle-log-password")
	require.NotContains(t, string(encoded), "csrf_token")
	require.Equal(t, "paused", c.State().DataState)
}
