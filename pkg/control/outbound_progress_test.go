package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestUntestedOutboundHealthReportsUnknownWithoutProbing(t *testing.T) {
	var probes atomic.Int32
	c := testController(t, Options{Probe: func(context.Context, *kone.KoneConfig, string, string, bool) ProbeResult {
		probes.Add(1)
		return ProbeResult{Status: "reachable"}
	}})
	savedHealthOutbound(t, c, "http://127.0.0.1:8080")
	version := c.State().SavedVersion
	response := request(t, c, owner(t, c), "GET", "/api/v1/outbounds/health", nil)
	require.Equal(t, http.StatusOK, response.Code)
	var body struct {
		Statuses []OutboundHealth `json:"statuses"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.Len(t, body.Statuses, 1)
	status := body.Statuses[0]
	require.Equal(t, "unknown", status.Status)
	require.Equal(t, "unknown", status.Host.Status)
	require.Nil(t, status.ConnectLatencyMS)
	require.Nil(t, status.CheckedAt)
	for _, protocol := range []kone.DiagnosticCheck{status.Protocols.TCP, status.Protocols.TLS, status.Protocols.UDP} {
		require.Equal(t, "unknown", protocol.Status)
		require.False(t, protocol.Tested)
		require.Empty(t, protocol.Evidence, "a configured URL alone does not publish protocol test evidence")
	}
	require.Equal(t, version, c.State().SavedVersion)
	require.Empty(t, c.Operations())
	require.Zero(t, probes.Load())
}

func TestOutboundTestPublishesMeasuredTransportBeforeProxyAcknowledgement(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer server.Close()
	defer unblock()
	c := testController(t, Options{})
	outbound := savedHealthOutbound(t, c, strings.Replace(server.URL, "://", "://progress-user:private-progress-password@", 1))
	withoutTLS := false
	op, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: outbound.ID, TLS: &withoutTLS}, "")
	require.NoError(t, err)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy handshake was not reached")
	}
	var progress OutboundHealth
	for _, running := range c.Operations() {
		if running.ID == op.ID {
			require.Equal(t, "running", running.Status)
			require.Equal(t, "proxy_handshake", running.Stage)
			progress = running.Result.(OutboundHealth)
		}
	}
	require.Equal(t, "healthy", progress.Host.Status)
	require.Equal(t, server.Listener.Addr().String(), progress.Host.Address)
	require.NotNil(t, progress.ConnectLatencyMS)
	require.GreaterOrEqual(t, *progress.ConnectLatencyMS, int64(0))
	require.Equal(t, "testing", progress.Protocols.TCP.Status)
	require.Equal(t, "unsupported", progress.Protocols.UDP.Status)
	require.False(t, progress.Protocols.UDP.Tested)
	require.Equal(t, "protocol", progress.Protocols.UDP.Evidence)
	unblock()
	finished := healthResult(t, c, op)
	require.Equal(t, "healthy", finished.Status)
	require.Equal(t, "healthy", finished.Protocols.TCP.Status)
	require.True(t, finished.Protocols.TCP.Tested)
	require.Equal(t, "unknown", finished.Protocols.TLS.Status)
	require.False(t, finished.Protocols.TLS.Tested)
	require.Equal(t, "complete", finished.Progress.Stage)
	require.Equal(t, "testing", progress.Protocols.TCP.Status, "published snapshots must not mutate after HTTP readers receive them")
	encoded, err := json.Marshal(finished)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "private-progress-password")
	require.NotContains(t, string(encoded), "progress-user")
}

func TestOutboundTestDistinguishesEndpointFailureFromProtocolFailure(t *testing.T) {
	for _, scenario := range []string{"endpoint-refused", "proxy-rejected"} {
		t.Run(scenario, func(t *testing.T) {
			endpoint := ""
			if scenario == "endpoint-refused" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				endpoint = "http://" + listener.Addr().String()
				require.NoError(t, listener.Close())
			} else {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "denied", http.StatusForbidden) }))
				defer server.Close()
				endpoint = server.URL
			}
			c := testController(t, Options{})
			outbound := savedHealthOutbound(t, c, endpoint)
			withoutTLS := false
			op, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: outbound.ID, TLS: &withoutTLS}, "")
			require.NoError(t, err)
			result := healthResult(t, c, op)
			require.Equal(t, "unhealthy", result.Status)
			require.Equal(t, "failed", result.Protocols.TCP.Status)
			if scenario == "endpoint-refused" {
				require.Equal(t, "failed", result.Host.Status)
				require.Nil(t, result.ConnectLatencyMS)
			} else {
				require.Equal(t, "healthy", result.Host.Status)
				require.NotNil(t, result.ConnectLatencyMS)
			}
		})
	}
}

func TestResetDuringOutboundProbeDoesNotRestoreItsDiscardedHealth(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		http.Error(w, "stopped", http.StatusForbidden)
	}))
	defer server.Close()
	defer unblock()
	c := testController(t, Options{})
	outbound := savedHealthOutbound(t, c, server.URL)
	withoutTLS := false
	op, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: outbound.ID, TLS: &withoutTLS}, "")
	require.NoError(t, err)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy handshake was not reached")
	}
	_, err = c.ResetConfiguration(t.Context(), c.doc.Version)
	require.NoError(t, err)
	unblock()
	healthResult(t, c, op)
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Nil(t, c.health, "finishing a pre-reset test must not repopulate discarded health state")
}

func TestChangingUDPFallbackPreservesUnchangedTCPProbeEvidence(t *testing.T) {
	c := testController(t, Options{Probe: func(context.Context, *kone.KoneConfig, string, string, bool) ProbeResult {
		return ProbeResult{Status: "reachable", Stage: "connect"}
	}})
	outbound := savedHealthOutbound(t, c, "http://127.0.0.1:8080")
	op, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: outbound.ID}, "")
	require.NoError(t, err)
	before := healthResult(t, c, op)
	request := currentRequest(c)
	request.Config["outbounds"].([]any)[0].(map[string]any)["udp-fallback"] = "direct"
	_, err = c.Save(request)
	require.NoError(t, err)
	after := healthStatuses(t, c)[0]
	require.Equal(t, before.ConfigurationID, after.ConfigurationID, "UDP fallback does not affect the already measured TCP/TLS endpoint path")
	require.Equal(t, "healthy", after.Status)
}

func TestResetInvalidatesOutboundSnapshotBeforeDiagnosticAdmission(t *testing.T) {
	var probes atomic.Int32
	c := testController(t, Options{Probe: func(context.Context, *kone.KoneConfig, string, string, bool) ProbeResult {
		probes.Add(1)
		return ProbeResult{Status: "reachable"}
	}})
	outbound := savedHealthOutbound(t, c, "http://127.0.0.1:8080")
	c.mu.Lock()
	snapshot := cloneDocument(c.doc)
	c.mu.Unlock()
	request := OutboundTestRequest{BaseVersion: snapshot.Version, OutboundID: outbound.ID}
	_, prepared, err := prepareOutboundTest(request, snapshot)
	require.NoError(t, err)

	// The saved snapshot was valid when preparation began, but reset can finish
	// before the next controller lock admits the test. Do not let that snapshot
	// reconstruct the discarded cache or authorize the old connection.
	_, err = c.ResetConfiguration(t.Context(), snapshot.Version)
	require.NoError(t, err)
	c.mu.Lock()
	store, generation, admissionErr := c.reserveOutboundTestLocked(snapshot.Version, outboundIdentity(snapshot.Config, prepared))
	cache := c.health
	c.mu.Unlock()
	require.ErrorIs(t, admissionErr, ErrConflict)
	require.Nil(t, store)
	require.Zero(t, generation)
	require.Nil(t, cache)
	op, err := c.TestOutbound(request, "")
	require.ErrorIs(t, err, ErrConflict)
	require.Empty(t, op.ID)
	require.Empty(t, c.Operations())
	require.Zero(t, probes.Load(), "a stale pre-reset request must not open any diagnostic connection")
}
