package integration

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestDiagnosticTotalTimeIncludesProxyTargetAcknowledgement(t *testing.T) {
	// The endpoint is local and quick; the proxy deliberately delays CONNECT
	// acknowledgement. The summary must include that wait, not just local TCP.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Error("diagnostics must not fetch an HTTP page")
		}
		time.Sleep(30 * time.Millisecond)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		io.Copy(io.Discard, conn)
	}))
	defer proxy.Close()
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	cfg.Outbounds = []kone.OutboundConfig{{Name: "loopback", URL: proxy.URL}}
	one, err := kone.FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	result, err := one.ProbeDiagnostic(t.Context(), "loopback", "192.0.2.10:443", false)
	require.NoError(t, err)
	require.Equal(t, "reachable", result.Status)
	require.NotNil(t, result.ConnectLatencyMS)
	require.GreaterOrEqual(t, result.DurationMS, int64(30))
	require.Greater(t, result.DurationMS, *result.ConnectLatencyMS)
}
