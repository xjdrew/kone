package control

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestAppliedRuleCanBeUndoneWithoutLosingConcurrentEdits(t *testing.T) {
	c := testController(t, Options{})
	enable(t, c)
	require.NoError(t, c.Start(t.Context()))
	r := currentRequest(c)
	r.Config["rules"] = []any{map[string]any{"type": "DOMAIN", "pattern": "example.com", "outbound": "reject"}}
	_, err := c.Save(r)
	require.NoError(t, err)
	require.NoError(t, c.Apply(t.Context()))
	require.Len(t, c.doc.Config.Rule, 1)
	_, err = c.Undo(c.doc.Version - 1)
	require.ErrorIs(t, err, ErrConflict)
	_, err = c.Undo(c.doc.Version)
	require.NoError(t, err)
	require.Empty(t, c.doc.Config.Rule)
	require.NoError(t, c.Apply(t.Context()))
	require.NoError(t, c.Pause(t.Context()))
	require.FileExists(t, c.confirmedPath()+".previous")
}

func TestExternalSameRevisionEditIsNotOverwritten(t *testing.T) {
	c := testController(t, Options{})
	r := currentRequest(c)
	disk := cloneDocument(c.doc)
	disk.Inbound.Name = "Edited outside the browser"
	require.NoError(t, writeDocument(c.settingsPath(), disk))
	_, err := c.Save(r)
	require.ErrorIs(t, err, ErrConflict)
	persisted, err := readDocument(c.settingsPath())
	require.NoError(t, err)
	require.Equal(t, disk.Inbound.Name, persisted.Inbound.Name)
}

func TestLegacyProfilesWithoutIDsCanSaveAndKeepStableIdentities(t *testing.T) {
	directory := t.TempDir()
	cfg := kone.DefaultConfig()
	cfg.Outbounds = []kone.OutboundConfig{{Name: "office", URL: "http://127.0.0.1:8080"}}
	cfg.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: "example.com", Outbound: "office"}}
	path := filepath.Join(directory, "settings.json")
	require.NoError(t, writeDocument(path, Document{Version: 3, Config: cfg, Inbound: Inbound{ID: "tun-main", Name: "TUN"}}))
	first, err := readDocument(path)
	require.NoError(t, err)
	second, err := readDocument(path)
	require.NoError(t, err)
	require.True(t, sameDocument(first, second))
	c := testController(t, Options{Directory: directory})
	_, err = c.Save(currentRequest(c))
	require.NoError(t, err)
	require.Equal(t, first.Config.Outbounds[0].ID, c.doc.Config.Outbounds[0].ID)
	require.Equal(t, first.Config.Rule[0].ID, c.doc.Config.Rule[0].ID)
}

func TestExactTemporaryRuleValidationAndPortScopes(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	input := map[string]any{"base_version": c.doc.Version, "target": "example.com", "outbound": "reject", "protocol": "tcp", "port": 443, "temporary_seconds": 300}
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/rules/exact", input).Code)
	expires, err := time.Parse(time.RFC3339, c.doc.Config.Rule[0].ExpiresAt)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now().Add(5*time.Minute), expires, 2*time.Second)
	input["base_version"] = c.doc.Version
	input["port"] = 80
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/rules/exact", input).Code)
	for _, target := range []string{"bad:443", "", "."} {
		input["target"] = target
		require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/rules/exact", input).Code)
	}
	input["target"] = "192.0.2.1"
	require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/rules/exact", input).Code)
	input["target"] = "another.example"
	input["temporary_seconds"] = 1
	require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/rules/exact", input).Code)
}

type unavailableCaptureData struct{}

func (unavailableCaptureData) TrafficData(kone.TrafficQuery, kone.SankeyOptions) (kone.TrafficSnapshot, kone.SankeySnapshot, error) {
	return kone.TrafficSnapshot{}, kone.SankeySnapshot{}, errors.New("transport disconnected")
}
func (unavailableCaptureData) FlowRecord(string) (kone.FlowRecord, bool, error) {
	return kone.FlowRecord{}, false, errors.New("transport disconnected")
}
func (unavailableCaptureData) DNSData() (kone.DNSRuntimeStatus, []kone.DNSQueryEvent, error) {
	return kone.DNSRuntimeStatus{}, nil, errors.New("transport disconnected")
}
func (unavailableCaptureData) ClearObservation() error { return errors.New("transport disconnected") }

func TestDisconnectedCaptureNeverMasqueradesAsAnEmptyHealthySnapshot(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	c.dataSource = unavailableCaptureData{}
	for _, endpoint := range []string{"traffic", "flows", "flows/a", "dns"} {
		require.Equal(t, 503, request(t, c, token, "GET", "/api/v1/"+endpoint, nil).Code)
	}
	require.Equal(t, 503, request(t, c, token, "POST", "/api/v1/privacy/clear", nil).Code)
	require.Equal(t, 200, request(t, c, token, "GET", "/api/v1/state", nil).Code)
}

func TestLocalDesktopBootstrapRenewalAndOperationBoundaries(t *testing.T) {
	c := testController(t, Options{})
	_, err := c.LocalAccessURL()
	require.Error(t, err)
	c.address = "127.0.0.1:9200"
	old := c.BootstrapToken()
	url, err := c.LocalAccessURL()
	require.NoError(t, err)
	require.NotContains(t, url, old)
	require.Contains(t, url, "#token=")
	_, _, err = c.claim(old, "", false)
	require.Error(t, err)
	w := httptest.NewRecorder()
	writeOperation(w, Operation{Error: "limit"})
	require.Equal(t, 429, w.Code)
	c.observer.Begin(kone.FlowRecord{Protocol: "tcp", Target: "test"})
	require.NoError(t, c.Close())
	_, err = c.LocalAccessURL()
	require.Error(t, err)
	op := c.beginOperation("closed", "", time.Second, func(context.Context) (any, error) { t.Error("closed controller must not run actions"); return nil, nil })
	require.Empty(t, op.ID)
	_, err = c.Save(currentRequest(c))
	require.ErrorContains(t, err, "stopping")
}
