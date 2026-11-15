package control

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRecoveryStatusEligibilityPreservesUnverifiedResources(t *testing.T) {
	cases := []struct {
		name    string
		report  RecoveryReport
		active  bool
		detail  string
		want    string
		allowed bool
	}{
		{name: "clean", want: "clear"},
		{name: "active", active: true, want: "active"},
		{name: "invalid", report: RecoveryReport{Required: true}, detail: "unreadable record", want: "inspection_failed"},
		{name: "owned", report: RecoveryReport{Required: true, CanClear: true}, want: "ready", allowed: true},
		{name: "unknown", report: RecoveryReport{Required: true}, want: "unverified"},
		{name: "dns-owned", report: RecoveryReport{Required: true, SystemDNS: []kone.SystemDNSRecoveryEntry{{CanRecover: true}}}, want: "ready", allowed: true},
		{name: "dns-external", report: RecoveryReport{Required: true, SystemDNS: []kone.SystemDNSRecoveryEntry{{CanRecover: false}}}, want: "unverified"},
		{name: "dns-and-live-device", report: RecoveryReport{Required: true, SystemDNS: []kone.SystemDNSRecoveryEntry{{CanRecover: true}}, Items: []RecoveryItem{{Kind: "tun", Status: "still_present"}}}, want: "unverified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := recoveryStatus(tc.report, tc.active, tc.detail)
			require.Equal(t, tc.want, v.Blocker)
			require.Equal(t, tc.allowed, v.CanRecover)
		})
	}
}
func TestRecoveryStatusKeepsCorruptJournalEvidence(t *testing.T) {
	c := testController(t, Options{InspectSystemDNSRecovery: func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) { return nil, nil }})
	require.NoError(t, os.WriteFile(c.journalPath(), []byte("broken"), 0600))
	view := c.RecoveryStatus(t.Context())
	require.Equal(t, "inspection_failed", view.Blocker)
	require.NotEmpty(t, view.InspectionError)
	require.NotEmpty(t, view.Items)
	require.FileExists(t, c.journalPath())
	c.mu.Lock()
	token, session := c.newSession("admin", false)
	session.Local = true
	c.mu.Unlock()
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:3456/api/v1/recovery", nil)
	r.RemoteAddr = "127.0.0.1:4444"
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	c.Handler().ServeHTTP(w, r)
	require.Equal(t, 200, w.Code)
	var response RecoveryStatus
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	require.Equal(t, "inspection_failed", response.Blocker)
	require.NotEmpty(t, response.Items)

	c.inspectSystemDNSRecovery = func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) {
		return nil, errors.New("controlled lease failure")
	}
	view = c.RecoveryStatus(t.Context())
	require.Contains(t, view.InspectionError, "controlled lease failure")
}
