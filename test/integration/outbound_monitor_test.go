package integration

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
)

func TestManagerAutomaticallyChecksSavedOutboundUsingProxyProtocol(t *testing.T) {
	requests := make(chan *http.Request, 4)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(context.Background())
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		io.WriteString(connection, "HTTP/1.1 200 Connection established\r\n\r\n")
		io.Copy(io.Discard, connection)
	}))
	defer proxy.Close()
	c, err := control.New(control.Options{Directory: t.TempDir()})
	require.NoError(t, err)
	defer c.Close()
	doc := c.Document()
	config := doc["config"].(map[string]any)
	config["dns"] = map[string]any{"system": false, "servers": []string{"127.0.0.1:9"}}
	config["outbounds"] = []map[string]any{{"id": "monitor", "name": "office", "url": strings.Replace(proxy.URL, "://", "://probe:fixture-key@", 1), "check-target": "192.0.2.7:443", "check-tls": false}}
	_, err = c.Save(control.SaveRequest{BaseVersion: doc["version"].(uint64), Config: config, Inbound: doc["inbound"].(control.Inbound)})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Serve(ctx, "127.0.0.1:0", nil) }()
	// No browser, API health read, manual diagnostic or capture start triggers it.
	select {
	case request := <-requests:
		require.Equal(t, "CONNECT", request.Method)
		require.Equal(t, "192.0.2.7:443", request.Host)
		require.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("probe:fixture-key")), request.Header.Get("Proxy-Authorization"))
	case <-time.After(3 * time.Second):
		t.Fatal("automatic proxy check did not run")
	}
	require.Eventually(t, func() bool {
		for _, operation := range c.Operations() {
			if operation.Kind == "outbound_check" && operation.Status == "succeeded" {
				result, ok := operation.Result.(control.OutboundHealth)
				return ok && result.Automatic && result.Status == "healthy" && result.ConnectLatencyMS != nil
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, "paused", c.State().DataState)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("manager did not stop")
	}
}
