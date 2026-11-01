package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func savedHealthOutbound(t *testing.T, c *Controller, endpoint string) kone.OutboundConfig {
	t.Helper()
	r := currentRequest(c)
	r.Config["outbounds"] = []any{map[string]any{"id": "outbound-health-test", "name": "office", "url": endpoint}}
	r.Config["rules"] = []any{map[string]any{"type": "FINAL", "outbound": "office"}}
	dns := r.Config["dns"].(map[string]any)
	dns["servers"] = []any{"127.0.0.1:9"}
	dns["system"] = false
	_, err := c.Save(r)
	require.NoError(t, err)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.doc.Config.Outbounds[0]
}
func healthResult(t *testing.T, c *Controller, op Operation) OutboundHealth {
	t.Helper()
	finished := waitOperation(t, c, op.ID)
	result, ok := finished.Result.(OutboundHealth)
	require.True(t, ok, "unexpected health result %T", finished.Result)
	return result
}
func healthStatuses(t *testing.T, c *Controller) []OutboundHealth {
	t.Helper()
	c.mu.Lock()
	cfg := cloneDocument(c.doc).Config
	c.mu.Unlock()
	return c.outboundStatuses(cfg)
}

func TestOutboundHealthExpiresAndChangesInvalidateWithoutCredentialHashes(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	var calls atomic.Int32
	c := testController(t, Options{Now: func() time.Time { return time.Unix(clock.Load(), 0) }, Probe: func(_ context.Context, cfg *kone.KoneConfig, name, target string, tls bool) ProbeResult {
		calls.Add(1)
		require.Equal(t, "office", name)
		require.Equal(t, "example.com:443", target)
		require.True(t, tls)
		return ProbeResult{Status: "reachable", Stage: "target_tls", Message: "Verified target TLS", DurationMS: 12}
	}})
	outbound := savedHealthOutbound(t, c, "http://health-user:health-password@127.0.0.1:8080")
	initial := healthStatuses(t, c)[0]
	require.Equal(t, "unknown", initial.Status)
	require.Zero(t, calls.Load())
	op, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: outbound.ID}, "repeat")
	require.NoError(t, err)
	result := healthResult(t, c, op)
	require.Equal(t, "healthy", result.Status)
	duplicate, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: outbound.ID}, "repeat")
	require.NoError(t, err)
	require.Equal(t, op.ID, duplicate.ID)
	require.Equal(t, int32(1), calls.Load())
	current := healthStatuses(t, c)[0]
	require.Equal(t, initial.ConfigurationID, current.ConfigurationID)
	require.Equal(t, int64(12), current.DurationMS)
	data, err := json.Marshal(current)
	require.NoError(t, err)
	for _, secret := range []string{"health-user", "health-password", outboundIdentity(c.doc.Config, outbound)} {
		require.NotContains(t, string(data), secret)
	}
	checks := c.outboundReadiness(c.doc.Config)
	require.Len(t, checks, 1)
	require.Equal(t, "ready", checks[0].Status)
	clock.Add(61)
	expired := healthStatuses(t, c)[0]
	require.Equal(t, "unknown", expired.Status)
	require.True(t, expired.Stale)
	require.NotNil(t, expired.CheckedAt)
	r := currentRequest(c)
	r.CredentialActions = map[string]CredentialAction{"office": {Action: "replace", Username: "health-user", Password: "changed-password"}}
	_, err = c.Save(r)
	require.NoError(t, err)
	changed := healthStatuses(t, c)[0]
	require.Equal(t, "unknown", changed.Status)
	require.NotEqual(t, current.ConfigurationID, changed.ConfigurationID)
	require.Equal(t, int32(1), calls.Load(), "GET and configuration saves do not probe automatically")
}

func TestOutboundDraftCredentialMergeAndSavedIdentityReuse(t *testing.T) {
	var observed atomic.Value
	c := testController(t, Options{Probe: func(_ context.Context, cfg *kone.KoneConfig, _, _ string, _ bool) ProbeResult {
		observed.Store(cfg.Outbounds[0].URL)
		return ProbeResult{Status: "reachable", Stage: "connect", Message: "Connected"}
	}})
	old := savedHealthOutbound(t, c, "http://old-user:old-password@127.0.0.1:8080")
	version := c.doc.Version
	draft := &OutboundTestDraft{ID: old.ID, Name: "renamed", URL: "http://REDACTED:REDACTED@127.0.0.1:8080"}
	op, err := c.TestOutbound(OutboundTestRequest{BaseVersion: version, Draft: draft, CredentialAction: CredentialAction{Action: "replace", Username: "new-user", Password: "new-password"}}, "")
	require.NoError(t, err)
	tested := healthResult(t, c, op)
	require.Contains(t, observed.Load().(string), "new-user:new-password")
	require.Equal(t, version, c.doc.Version)
	require.Equal(t, "office", c.doc.Config.Outbounds[0].Name, "testing a draft does not save it")
	r := currentRequest(c)
	row := r.Config["outbounds"].([]any)[0].(map[string]any)
	row["name"] = "renamed"
	r.Config["rules"] = []any{map[string]any{"type": "FINAL", "outbound": "renamed"}}
	r.CredentialActions = map[string]CredentialAction{"renamed": {Action: "replace", OriginalName: "office", Username: "new-user", Password: "new-password"}}
	_, err = c.Save(r)
	require.NoError(t, err)
	saved := healthStatuses(t, c)[0]
	require.Equal(t, "healthy", saved.Status)
	require.Equal(t, tested.ConfigurationID, saved.ConfigurationID)
	for _, action := range []CredentialAction{{Action: "preserve"}, {Action: "clear"}} {
		request := OutboundTestRequest{BaseVersion: c.doc.Version, Draft: &OutboundTestDraft{ID: old.ID, Name: "renamed", URL: "http://REDACTED:REDACTED@127.0.0.1:8080"}, CredentialAction: action}
		op, err = c.TestOutbound(request, "")
		require.NoError(t, err)
		healthResult(t, c, op)
		if action.Action == "preserve" {
			require.Contains(t, observed.Load().(string), "new-user:new-password")
		} else {
			u, err := url.Parse(observed.Load().(string))
			require.NoError(t, err)
			require.Nil(t, u.User)
		}
	}
	// A new draft needs no saved ID and never writes a new configuration.
	newDraft := OutboundTestRequest{BaseVersion: c.doc.Version, Draft: &OutboundTestDraft{Name: "new", URL: "http://127.0.0.1:8090"}}
	op, err = c.TestOutbound(newDraft, "")
	require.NoError(t, err)
	require.Equal(t, "healthy", healthResult(t, c, op).Status)
}

func TestOutboundDraftValidationRejectsStaleOrMaskedCredentialConfusion(t *testing.T) {
	c := testController(t, Options{})
	old := savedHealthOutbound(t, c, "http://user:password@127.0.0.1:8080")
	for _, request := range []OutboundTestRequest{
		{BaseVersion: 0, OutboundID: old.ID},
		{BaseVersion: c.doc.Version},
		{BaseVersion: c.doc.Version, OutboundID: "missing"},
		{BaseVersion: c.doc.Version, OutboundID: old.ID, CredentialAction: CredentialAction{Action: "replace"}},
		{BaseVersion: c.doc.Version, OutboundID: old.ID, Draft: &OutboundTestDraft{ID: "other", Name: "office", URL: old.URL}},
		{BaseVersion: c.doc.Version, OutboundID: "missing", Draft: &OutboundTestDraft{Name: "office", URL: old.URL}},
		{BaseVersion: c.doc.Version, Draft: &OutboundTestDraft{Name: "new", URL: "http://REDACTED:REDACTED@127.0.0.1:9"}},
		{BaseVersion: c.doc.Version, Draft: &OutboundTestDraft{ID: old.ID, Name: "office", URL: "http://REDACTED:REDACTED@127.0.0.2:8080"}},
		{BaseVersion: c.doc.Version, Draft: &OutboundTestDraft{ID: old.ID, Name: "office", URL: old.URL}, CredentialAction: CredentialAction{Action: "preserve", OriginalName: "other"}},
		{BaseVersion: c.doc.Version, Draft: &OutboundTestDraft{Name: "new", URL: "bad"}},
	} {
		_, err := c.TestOutbound(request, "")
		require.Error(t, err)
	}
	for _, target := range []string{"", "http://example.com", "0.0.0.0:443", "127.0.0.1:0", "x:99999"} {
		_, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: old.ID, Target: &target}, "")
		require.Error(t, err)
	}
	disabled := false
	_, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, Draft: &OutboundTestDraft{Name: "disabled", URL: old.URL, Enabled: &disabled}}, "")
	require.ErrorContains(t, err, "enable")
	r := currentRequest(c)
	r.Config["outbounds"].([]any)[0].(map[string]any)["enabled"] = false
	_, err = c.Save(r)
	require.NoError(t, err)
	_, err = c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: old.ID}, "")
	require.ErrorContains(t, err, "enable")
	require.Equal(t, "disabled", healthStatuses(t, c)[0].Stage)
}

func TestOutboundHealthLatestGenerationCancellationAndCapacityAreBounded(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once atomic.Bool
	c := testController(t, Options{Probe: func(ctx context.Context, _ *kone.KoneConfig, _, target string, _ bool) ProbeResult {
		if strings.HasPrefix(target, "old.") {
			if once.CompareAndSwap(false, true) {
				close(started)
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return ProbeResult{Status: "failed", Message: "older failure"}
		}
		if strings.HasPrefix(target, "cancel.") {
			<-ctx.Done()
			return ProbeResult{Status: "canceled"}
		}
		return ProbeResult{Status: "reachable", Stage: "target_tls"}
	}})
	old := savedHealthOutbound(t, c, "http://127.0.0.1:8080")
	a, b := "old.example:443", "new.example:443"
	first, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: old.ID, Target: &a}, "")
	require.NoError(t, err)
	<-started
	second, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: old.ID, Target: &b}, "")
	require.NoError(t, err)
	require.Equal(t, "healthy", healthResult(t, c, second).Status)
	close(release)
	healthResult(t, c, first)
	require.Equal(t, "healthy", healthStatuses(t, c)[0].Status)
	require.Equal(t, b, healthStatuses(t, c)[0].Target)
	for range 4 {
		c.probeSlots <- struct{}{}
	}
	busy, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: old.ID}, "")
	require.NoError(t, err)
	require.Equal(t, "capacity", healthResult(t, c, busy).Stage)
	for range 4 {
		<-c.probeSlots
	}
	cancelTarget := "cancel.example:443"
	canceled, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: old.ID, Target: &cancelTarget}, "")
	require.NoError(t, err)
	require.NoError(t, c.cancelOperation(canceled.ID))
	require.Equal(t, "canceled", waitOperation(t, c, canceled.ID).Status)
	for i := range maxOutboundHealthEntries + 10 {
		c.mu.Lock()
		c.healthEntryLocked(fmt.Sprint(i), c.now())
		c.mu.Unlock()
	}
	require.LessOrEqual(t, len(c.health.entries), maxOutboundHealthEntries)
}

func TestOutboundHealthHTTPUsesActualProxyAuthenticationAndConnect(t *testing.T) {
	var connects atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "CONNECT", r.Method)
		require.Equal(t, "explicit-test.example:443", r.Host)
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("tester:correct-password")) {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		connects.Add(1)
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		_ = buffer.Flush()
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		_, err = buffer.ReadByte()
		require.ErrorIs(t, err, io.EOF, "health probes send no application request after CONNECT")
	}))
	defer proxy.Close()
	endpoint, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	endpoint.User = url.UserPassword("tester", "correct-password")
	c := testController(t, Options{})
	old := savedHealthOutbound(t, c, endpoint.String())
	ownerToken := owner(t, c)
	response := request(t, c, ownerToken, "POST", "/api/v1/outbounds/test", map[string]any{"base_version": c.doc.Version, "outbound_id": old.ID, "target": "explicit-test.example:443", "tls": false})
	require.Equal(t, 202, response.Code, response.Body.String())
	var op Operation
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &op))
	good := healthResult(t, c, op)
	require.Equal(t, "healthy", good.Status)
	require.Equal(t, int32(1), connects.Load())
	bad, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, Draft: &OutboundTestDraft{ID: old.ID, Name: old.Name, URL: proxy.URL}, CredentialAction: CredentialAction{Action: "replace", Username: "tester", Password: "incorrect-password"}, Target: &good.Target, TLS: &good.TLS}, "")
	require.NoError(t, err)
	failed := healthResult(t, c, bad)
	require.Equal(t, "unhealthy", failed.Status)
	require.Equal(t, "proxy_auth", failed.Stage)
	require.NotContains(t, failed.Message, "incorrect-password")
	readPair, err := c.pair("read")
	require.NoError(t, err)
	readToken, _, err := c.claim("", readPair.Code, true)
	require.NoError(t, err)
	require.Equal(t, 200, request(t, c, readToken, "GET", "/api/v1/outbounds/health", nil).Code)
	require.Equal(t, 403, request(t, c, readToken, "POST", "/api/v1/outbounds/test", map[string]any{}).Code)
	require.Equal(t, 400, request(t, c, ownerToken, "GET", "/api/v1/outbounds/health?target=hidden", nil).Code)
	require.Equal(t, 400, request(t, c, ownerToken, "POST", "/api/v1/outbounds/test", `{"unknown":true}`).Code)
	require.Equal(t, 409, request(t, c, ownerToken, "POST", "/api/v1/outbounds/test", map[string]any{"base_version": 0, "outbound_id": old.ID}).Code)
}

type healthDNSCapture struct {
	CaptureData
	status kone.DNSRuntimeStatus
	err    error
}

func (s healthDNSCapture) DNSData() (kone.DNSRuntimeStatus, []kone.DNSQueryEvent, error) {
	return s.status, nil, s.err
}

type healthActiveEngine struct {
	*memoryEngine
	probe func(context.Context, string, string, bool, uint64) (kone.DiagnosticResult, error)
}

func (e healthActiveEngine) ProbeDiagnosticVersion(ctx context.Context, name, target string, tls bool, version uint64) (kone.DiagnosticResult, error) {
	return e.probe(ctx, name, target, tls, version)
}

func TestOutboundDraftKeepsActivePrivateResolverSnapshotAndFailureDoesNotFallback(t *testing.T) {
	var calls atomic.Int32
	c := testController(t, Options{Probe: func(_ context.Context, cfg *kone.KoneConfig, _, _ string, _ bool) ProbeResult {
		calls.Add(1)
		require.Equal(t, []string{"192.0.2.53:53"}, cfg.DNS.Servers)
		require.True(t, cfg.DNS.SystemContext.UseTCP)
		require.False(t, cfg.DNS.System)
		require.Equal(t, "private.example", cfg.DNS.Rules[0].Suffix)
		require.True(t, cfg.DNS.Rules[0].Unavailable)
		return ProbeResult{Status: "reachable", Stage: "target_tls"}
	}})
	old := savedHealthOutbound(t, c, "http://127.0.0.1:8080")
	c.mu.Lock()
	c.engine = newMemoryEngine()
	c.dataSource = healthDNSCapture{status: kone.DNSRuntimeStatus{Servers: []string{"192.0.2.53:53"}, UpstreamTCP: true, Rules: []kone.DNSRouteConfig{{Suffix: "private.example", Automatic: true, Unavailable: true, Reason: "secure scope unavailable"}}}}
	c.mu.Unlock()
	t.Cleanup(func() { c.mu.Lock(); c.engine = nil; c.dataSource = nil; c.mu.Unlock() })
	request := OutboundTestRequest{BaseVersion: c.doc.Version, Draft: &OutboundTestDraft{ID: old.ID, Name: old.Name, URL: old.URL}}
	op, err := c.TestOutbound(request, "")
	require.NoError(t, err)
	require.Equal(t, "healthy", healthResult(t, c, op).Status)
	for _, source := range []CaptureData{nil, healthDNSCapture{err: errors.New("private resolver disconnected")}, healthDNSCapture{}} {
		c.mu.Lock()
		c.dataSource = source
		c.mu.Unlock()
		op, err = c.TestOutbound(request, "")
		require.NoError(t, err)
		result := healthResult(t, c, op)
		require.Equal(t, "unknown", result.Status)
		require.Equal(t, "context", result.Stage)
	}
	require.Equal(t, int32(1), calls.Load(), "missing active resolver context cannot silently use system/public defaults")
	c.mu.Lock()
	c.engine = healthActiveEngine{memoryEngine: newMemoryEngine(), probe: func(_ context.Context, name, target string, tls bool, version uint64) (kone.DiagnosticResult, error) {
		require.Equal(t, c.doc.Version, version)
		return ProbeResult{Status: "reachable", Stage: "target_tls"}, nil
	}}
	c.mu.Unlock()
	op, err = c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: old.ID}, "")
	require.NoError(t, err)
	require.Equal(t, "healthy", healthResult(t, c, op).Status)
	require.Equal(t, int32(1), calls.Load(), "saved outbounds use the active engine diagnostics directly")
}

func TestShadowsocksOpenPortAloneIsNotHealthy(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			close(accepted)
			defer connection.Close()
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			_, _ = io.Copy(io.Discard, connection)
		}
	}()
	c := testController(t, Options{})
	endpoint := "ss://aes-128-gcm:test-password@" + listener.Addr().String()
	old := savedHealthOutbound(t, c, endpoint)
	target := "explicit-test.example:443"
	withoutTLS := false
	op, err := c.TestOutbound(OutboundTestRequest{BaseVersion: c.doc.Version, OutboundID: old.ID, Target: &target, TLS: &withoutTLS}, "")
	require.NoError(t, err)
	result := healthResult(t, c, op)
	require.Equal(t, "unknown", result.Status)
	require.Contains(t, result.Message, "acknowledgement")
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("proxy transport was not actually opened")
	}
}
