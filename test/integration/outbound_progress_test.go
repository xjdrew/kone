package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestExplicitOutboundProbeReportsLiveProgressAndMeasuredEvidenceOverHTTP(t *testing.T) {
	// Only an explicit test opens these loopback sockets. No capture engine,
	// system adapter, ICMP privilege or external endpoint is involved.
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		fmt.Fprint(connection, "HTTP/1.1 200 Connection established\r\n\r\n")
		io.Copy(io.Discard, connection)
	}))
	defer proxy.Close()
	defer unblock()
	c, err := control.New(control.Options{Directory: t.TempDir(), InspectSystemDNSRecovery: func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) { return nil, nil }})
	require.NoError(t, err)
	defer c.Close()
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	var cookie *http.Cookie
	csrf := ""
	call := func(method, path string, input any) map[string]any {
		var body io.Reader
		if input != nil {
			data, err := json.Marshal(input)
			require.NoError(t, err)
			body = bytes.NewReader(data)
		}
		request, err := http.NewRequest(method, server.URL+"/api/v1/"+path, body)
		require.NoError(t, err)
		if cookie != nil {
			request.AddCookie(cookie)
			request.Header.Set("X-CSRF-Token", csrf)
		}
		response, err := client.Do(request)
		require.NoError(t, err)
		defer response.Body.Close()
		require.Contains(t, []int{200, 202}, response.StatusCode)
		if cookies := response.Cookies(); len(cookies) > 0 {
			cookie = cookies[0]
		}
		var value map[string]any
		require.NoError(t, json.NewDecoder(response.Body).Decode(&value))
		if next, ok := value["csrf_token"].(string); ok {
			csrf = next
		}
		return value
	}
	call("POST", "session", map[string]any{"token": c.BootstrapToken()})
	call("POST", "auth/password", map[string]any{"password": "outbound-evidence-password", "confirm_password": "outbound-evidence-password"})
	doc := call("GET", "config", nil)
	config := doc["config"].(map[string]any)
	config["dns"] = map[string]any{"system": false, "servers": []string{"127.0.0.1:9"}}
	config["outbounds"] = []map[string]any{{"name": "measured", "url": strings.Replace(proxy.URL, "://", "://probe-user:private-probe-key@", 1)}}
	config["rules"] = []map[string]any{{"type": "FINAL", "outbound": "measured"}}
	saved := call("PUT", "config", map[string]any{"base_version": doc["version"], "config": config, "inbound": doc["inbound"]})
	outbound := saved["config"].(map[string]any)["outbounds"].([]any)[0].(map[string]any)
	initial := call("GET", "outbounds/health", nil)["statuses"].([]any)[0].(map[string]any)
	require.Equal(t, "unknown", initial["host"].(map[string]any)["status"])
	for _, check := range initial["protocols"].(map[string]any) {
		protocol := check.(map[string]any)
		require.Equal(t, "unknown", protocol["status"])
		require.Equal(t, false, protocol["tested"])
		require.NotContains(t, protocol, "evidence")
	}
	require.NotContains(t, initial, "connect_latency_ms")
	require.Empty(t, c.Operations(), "reading health must not start a background connection test")
	operation := call("POST", "outbounds/test", map[string]any{"base_version": saved["version"], "outbound_id": outbound["id"], "target": "example.com:443", "tls": false})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("explicit test did not reach the proxy")
	}
	running := call("GET", "operations/"+operation["id"].(string), nil)
	require.Equal(t, "running", running["status"])
	require.Equal(t, "proxy_handshake", running["stage"])
	progress := running["result"].(map[string]any)
	require.Equal(t, "healthy", progress["host"].(map[string]any)["status"])
	require.Contains(t, progress, "connect_latency_ms")
	require.Equal(t, "testing", progress["protocols"].(map[string]any)["tcp"].(map[string]any)["status"])
	unblock()
	var final map[string]any
	require.Eventually(t, func() bool {
		final = call("GET", "operations/"+operation["id"].(string), nil)
		return final["status"] == "succeeded"
	}, 3*time.Second, 10*time.Millisecond)
	result := final["result"].(map[string]any)
	require.Equal(t, "healthy", result["status"])
	udp := result["protocols"].(map[string]any)["udp"].(map[string]any)
	require.Equal(t, "unsupported", udp["status"])
	require.Equal(t, "protocol", udp["evidence"])
	require.Equal(t, false, udp["tested"], "a TCP probe must not claim any UDP round trip")
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "private-probe-key")
	require.NotContains(t, string(encoded), "probe-user")
	require.Equal(t, "paused", c.State().State)

	call("POST", "config/defaults", map[string]any{"base_version": saved["version"]})
	stale, err := json.Marshal(map[string]any{"base_version": saved["version"], "outbound_id": outbound["id"], "tls": false})
	require.NoError(t, err)
	request, err := http.NewRequest("POST", server.URL+"/api/v1/outbounds/test", bytes.NewReader(stale))
	require.NoError(t, err)
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusConflict, response.StatusCode, "reset revokes the browser's old outbound snapshot before any new connection")
	health := call("GET", "outbounds/health", nil)
	require.Empty(t, health["statuses"], "stale requests cannot restore the discarded outbound health cache")
}
