package control

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
	"testing"
)

func TestDNSComparisonAPIHasFixedResolversAndDefaultPortIsAccepted(t *testing.T) {
	c := testController(t, Options{ProbeUDP: func(_ context.Context, _ *kone.KoneConfig, source, target string, o kone.DiagnosticOptions) ProbeResult {
		require.Equal(t, "dns", o.Protocol)
		require.Equal(t, "example.com", target)
		require.Contains(t, []string{"system", "kone"}, source)
		return ProbeResult{Target: target, Outbound: source, Protocol: "dns", DNSType: o.DNSType, Status: "answered"}
	}, Probe: func(_ context.Context, _ *kone.KoneConfig, _ string, target string, _ bool) ProbeResult {
		require.Equal(t, "example.com:80", target)
		return ProbeResult{Status: "reachable"}
	}})
	session := owner(t, c)
	response := request(t, c, session, "POST", "/api/v1/diagnostics/dns", map[string]any{"name": "Example.COM.", "type": "AAAA"})
	require.Equal(t, 202, response.Code, response.Body.String())
	var operation Operation
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &operation))
	result := waitOperation(t, c, operation.ID)
	require.Equal(t, "succeeded", result.Status)
	require.Equal(t, []string{"system", "kone"}, result.Outbounds)
	rows := result.Result.(map[string]any)["results"].([]ProbeResult)
	require.Len(t, rows, 2)
	require.Equal(t, "AAAA", rows[0].DNSType)
	for _, input := range []map[string]any{{"name": "127.0.0.1"}, {"name": "bad:53"}, {"name": "example.com", "type": "ANY"}, {"name": "example.com", "outbound": "proxy"}} {
		require.Equal(t, 400, request(t, c, session, "POST", "/api/v1/diagnostics/dns", input).Code)
	}
	op, err := c.Diagnose("example.com", nil, false, "")
	require.NoError(t, err)
	require.Equal(t, "succeeded", waitOperation(t, c, op.ID).Status)
}
