package integration

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestBareTargetsPersistAndUsePort80ThroughActualProxyProtocol(t *testing.T) {
	targets := make(chan string, 4)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Error("expected CONNECT")
			w.WriteHeader(400)
			return
		}
		targets <- r.Host
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		io.Copy(io.Discard, conn)
	}))
	defer proxy.Close()
	manager, err := control.New(control.Options{Directory: t.TempDir()})
	require.NoError(t, err)
	defer manager.Close()
	call := recoveryConsole(t, manager)
	status, doc := call("GET", "config", nil)
	require.Equal(t, 200, status)
	config := doc["config"].(map[string]any)
	config["dns"].(map[string]any)["servers"] = []string{"127.0.0.1:9"}
	config["outbounds"] = []map[string]any{{"id": "local-proxy", "name": "office", "url": proxy.URL, "check-target": "saved.example", "check-tls": false, "check-enabled": false}}
	status, doc = call("PUT", "config", map[string]any{"base_version": doc["version"], "config": config, "inbound": doc["inbound"]})
	require.Equal(t, 200, status, doc)
	require.Equal(t, "saved.example:80", doc["config"].(map[string]any)["outbounds"].([]any)[0].(map[string]any)["check-target"])
	for _, scenario := range []struct {
		path, target string
		request      map[string]any
	}{
		{"outbounds/test", "saved.example:80", map[string]any{"base_version": doc["version"], "outbound_id": "local-proxy"}},
		{"outbounds/test", "draft.example:80", map[string]any{"base_version": doc["version"], "draft": map[string]any{"name": "draft", "url": proxy.URL, "check-target": "draft.example", "check-tls": false}}},
		{"diagnostics", "manual.example:80", map[string]any{"target": "manual.example", "outbounds": []string{"office"}, "tls": false}},
	} {
		status, operation := call("POST", scenario.path, scenario.request)
		require.Equal(t, 202, status, operation)
		var result map[string]any
		require.Eventually(t, func() bool {
			status, result = call("GET", "operations/"+operation["id"].(string), nil)
			return status == 200 && result["status"] != "running"
		}, 3*time.Second, 5*time.Millisecond)
		require.Equal(t, "succeeded", result["status"], result)
		select {
		case actual := <-targets:
			require.Equal(t, scenario.target, actual)
		case <-time.After(time.Second):
			t.Fatal("proxy did not receive a target")
		}
	}
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	cfg.Outbounds = []kone.OutboundConfig{{Name: "office", URL: proxy.URL}}
	one, err := kone.FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	conn, err := one.DialDiagnostic(t.Context(), "office", "library.example")
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Equal(t, "library.example:80", <-targets)
	require.Equal(t, "paused", manager.State().State)
}
