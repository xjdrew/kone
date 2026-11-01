package control

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestDiagnosticsBoundedIdempotentCancelableAndNoAutomaticRules(t *testing.T) {
	c := testController(t, Options{Probe: func(ctx context.Context, cfg *kone.KoneConfig, name, target string, tls bool) ProbeResult {
		status := "failed"
		if name == "office" {
			status = "reachable"
		}
		if target == "cancel.example:443" {
			<-ctx.Done()
		}
		return ProbeResult{Target: target, Outbound: name, Status: status}
	}})
	r := currentRequest(c)
	r.Config["outbounds"] = []any{map[string]any{"name": "office", "url": "http://127.0.0.1:8080"}}
	_, err := c.Save(r)
	require.NoError(t, err)
	version := c.doc.Version
	op, err := c.Diagnose("example.com:443", []string{"direct", "office"}, true, "same")
	require.NoError(t, err)
	duplicate, err := c.Diagnose("example.com:443", []string{"direct", "office"}, true, "same")
	require.NoError(t, err)
	require.Equal(t, op.ID, duplicate.ID)
	result := waitOperation(t, c, op.ID)
	require.Equal(t, "succeeded", result.Status)
	require.True(t, result.Result.(map[string]any)["suggest_proxy"].(bool))
	require.Equal(t, version, c.doc.Version)
	for _, target := range []string{"http://example.com", "127.0.0.1:0", "0.0.0.0:80", "[ff02::1]:53", "bad name:443", "x:99999", "x:-1"} {
		_, err := c.Diagnose(target, nil, false, "")
		require.Error(t, err, target)
	}
	_, err = c.Diagnose("example.com:443", []string{"reject"}, false, "")
	require.Error(t, err)
	_, err = c.Diagnose("example.com:443", make([]string, 9), false, "")
	require.Error(t, err)
	op, err = c.Diagnose("cancel.example:443", nil, false, "")
	require.NoError(t, err)
	require.NoError(t, c.cancelOperation(op.ID))
	require.Equal(t, "canceled", waitOperation(t, c, op.ID).Status)
	token := owner(t, c)
	w := request(t, c, token, "POST", "/api/v1/diagnostics", map[string]any{"target": "example.com:443"})
	require.Equal(t, 202, w.Code)
	for range 70 {
		op := c.beginOperation("test", "", time.Second, func(context.Context) (any, error) { return nil, nil })
		require.Equal(t, "succeeded", waitOperation(t, c, op.ID).Status)
	}
	require.LessOrEqual(t, len(c.Operations()), 64)
}

func TestOperationLimitAndFailedTasks(t *testing.T) {
	c := testController(t, Options{})
	var ids []string
	for range 8 {
		op := c.beginOperation("wait", "", time.Minute, func(ctx context.Context) (any, error) { <-ctx.Done(); return nil, ctx.Err() })
		ids = append(ids, op.ID)
	}
	blocked := c.beginOperation("extra", "", time.Second, func(context.Context) (any, error) { t.Error("must not run"); return nil, nil })
	require.Equal(t, "failed", blocked.Status)
	require.Empty(t, blocked.ID)
	for _, id := range ids {
		require.NoError(t, c.cancelOperation(id))
		waitOperation(t, c, id)
	}
	op := c.beginOperation("failure", "", time.Second, func(context.Context) (any, error) { return nil, errors.New("expected failure") })
	require.Equal(t, "expected failure", waitOperation(t, c, op.ID).Error)
}

func TestDiagnosticTCPAndTLSDoNotReplayApplicationRequests(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("diagnostics sent an application request") }))
	defer server.Close()
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	target := strings.TrimPrefix(server.URL, "https://")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := probeTarget(ctx, cfg, "direct", target, false)
	require.Equal(t, "reachable", result.Status)
	require.Equal(t, "connect", result.Stage)
	result = probeTarget(ctx, cfg, "direct", target, true)
	require.Equal(t, "failed", result.Status)
	require.Equal(t, "target_tls", result.Stage)
	result = probeTarget(ctx, cfg, "direct", "bad/url", false)
	require.Equal(t, "failed", result.Status)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	listener.Close()
	result = probeTarget(ctx, cfg, "direct", address, false)
	require.Equal(t, "failed", result.Status)
	cfg.Core.Network = "invalid"
	result = probeTarget(ctx, cfg, "direct", target, false)
	require.Equal(t, "configuration_or_dns", result.Stage)
}

func TestStoreStrictSchemaAtomicWritesAndCredentialActions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	for _, content := range []string{`{}`, `{"version":1,"toml":"unknown=1"}`, `{"version":1,"toml":"","unknown":true}`, `{"version":1,"toml":""} {}`, strings.Repeat(" ", 1<<20+1)} {
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))
		_, err := readDocument(path)
		require.Error(t, err)
	}
	_, err := normalizeJSON(map[string]any{"n": []any{json.Number("1.5")}})
	require.Error(t, err)
	_, err = normalizeJSON([]any{1.5})
	require.Error(t, err)
	_, err = decodeManaged(map[string]any{"bad": make(chan int)})
	require.Error(t, err)
	require.Error(t, atomicWrite(filepath.Join(path, "child"), nil))
	c := testController(t, Options{})
	r := currentRequest(c)
	r.Inbound.ID = "different"
	_, err = c.Save(r)
	require.ErrorContains(t, err, "ID")
	r = currentRequest(c)
	r.Inbound.Name = "line\nbreak"
	_, err = c.Save(r)
	require.ErrorContains(t, err, "name")
	r = currentRequest(c)
	r.Config["outbounds"] = []any{map[string]any{"name": "secret", "url": "http://REDACTED:REDACTED@127.0.0.1:8080"}}
	_, err = c.Save(r)
	require.ErrorContains(t, err, "masked credentials")
	r.CredentialActions = map[string]CredentialAction{"secret": {Action: "unknown"}}
	_, err = c.Save(r)
	require.ErrorContains(t, err, "credential action")
	require.NoError(t, brokenBackup(filepath.Join(dir, "missing")))
}

func TestImportExportRoundTripAndSafeDefaults(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	document := "[[outbounds]]\nname='office'\nurl='http://alice:private-password@127.0.0.1:8080'\n"
	body := map[string]any{"base_version": c.doc.Version, "toml": document}
	preview := request(t, c, token, "POST", "/api/v1/config/import/validate", body)
	require.Equal(t, 200, preview.Code, preview.Body.String())
	require.NotContains(t, preview.Body.String(), "private-password")
	require.Equal(t, uint64(1), c.doc.Version)
	saved := request(t, c, token, "POST", "/api/v1/config/import", body)
	require.Equal(t, 200, saved.Code)
	require.NotContains(t, saved.Body.String(), "private-password")
	export := request(t, c, token, "GET", "/api/v1/export", nil)
	require.NotContains(t, export.Body.String(), "private-password")
	body["base_version"] = c.doc.Version
	body["toml"] = export.Body.String()
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/config/import", body).Code)
	require.Contains(t, c.doc.Config.Outbounds[0].URL, "private-password")
	body["toml"] = "bad-field=1"
	body["base_version"] = c.doc.Version
	require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/config/import", body).Code)
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/config/defaults", map[string]any{"base_version": c.doc.Version}).Code)
	require.Empty(t, c.doc.Config.Outbounds)
	require.True(t, c.doc.Inbound.Enabled)
	require.False(t, c.doc.DirectOnlyConfirmed)
	require.Equal(t, "paused", c.State().State)
}
