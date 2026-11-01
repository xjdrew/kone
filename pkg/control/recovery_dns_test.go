package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestDNSRecoveryOnlyMutatesVerifiedEntriesAndRechecksBeforeClearing(t *testing.T) {
	var mu sync.Mutex
	entries := []kone.SystemDNSRecoveryEntry{{ID: strings.Repeat("a", 32), Status: "orphaned", CanRecover: true}, {ID: strings.Repeat("b", 32), Status: "external_change", CanRecover: false}}
	var recovered []string
	c := testController(t, Options{
		InspectSystemDNSRecovery: func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) {
			mu.Lock()
			defer mu.Unlock()
			return append([]kone.SystemDNSRecoveryEntry(nil), entries...), nil
		},
		RecoverSystemDNS: func(_ context.Context, id string) error {
			mu.Lock()
			defer mu.Unlock()
			recovered = append(recovered, id)
			entries = entries[1:]
			return nil
		},
	})
	require.NoError(t, c.writeRecoveryJournal(kone.DefaultConfig(), "interrupted-run-1234"))
	require.Error(t, c.Recover(t.Context()), "externally changed leases remain visible and block clearing")
	require.Equal(t, []string{strings.Repeat("a", 32)}, recovered)
	require.FileExists(t, c.journalPath())
	mu.Lock()
	entries = nil
	mu.Unlock()
	require.NoError(t, c.Recover(t.Context()))
	require.NoFileExists(t, c.journalPath())
	require.Equal(t, "paused", c.State().State)
}

func TestDNSRecoveryRetainsJournalOnFailureCancellationOrNoEffect(t *testing.T) {
	for _, mode := range []string{"failed", "canceled", "no_effect"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			c := testController(t, Options{InspectSystemDNSRecovery: func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) {
				return []kone.SystemDNSRecoveryEntry{{ID: strings.Repeat("a", 32), CanRecover: true, Status: "orphaned"}}, nil
			}, RecoverSystemDNS: func(context.Context, string) error {
				calls++
				if mode == "canceled" {
					cancel()
					return context.Canceled
				}
				if mode == "failed" {
					return errors.New("authorization declined")
				}
				return nil
			}})
			require.NoError(t, c.writeRecoveryJournal(kone.DefaultConfig(), "interrupted-run-1234"))
			require.Error(t, c.Recover(ctx))
			require.Equal(t, 1, calls)
			require.FileExists(t, c.journalPath())
			require.Equal(t, "recovery_required", c.State().State)
		})
	}
}

func TestDNSRecoveryRouteRequiresLocalAdminConfirmationAndIsIdempotent(t *testing.T) {
	var mu sync.Mutex
	remaining, calls := true, 0
	c := testController(t, Options{InspectSystemDNSRecovery: func(context.Context) ([]kone.SystemDNSRecoveryEntry, error) {
		mu.Lock()
		defer mu.Unlock()
		if remaining {
			return []kone.SystemDNSRecoveryEntry{{ID: strings.Repeat("a", 32), CanRecover: true, Status: "orphaned"}}, nil
		}
		return nil, nil
	}, RecoverSystemDNS: func(context.Context, string) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		remaining = false
		return nil
	}})
	admin := owner(t, c)
	require.Equal(t, 400, request(t, c, admin, "POST", "/api/v1/lifecycle/recover", map[string]any{}).Code)
	c.mu.Lock()
	remote, _ := c.newSession("admin", true)
	read, _ := c.newSession("read", false)
	c.mu.Unlock()
	require.Equal(t, 403, request(t, c, remote, "POST", "/api/v1/lifecycle/recover", map[string]any{"confirm": true}).Code)
	require.Equal(t, 403, request(t, c, read, "POST", "/api/v1/lifecycle/recover", map[string]any{"confirm": true}).Code)
	for _, remote := range []string{"127.0.0.1:5678", "192.0.2.1:5678"} {
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:3456/api/v1/lifecycle/recover", strings.NewReader(`{"confirm":true}`))
		r.RemoteAddr = remote
		if strings.HasPrefix(remote, "127.") {
			r.AddCookie(&http.Cookie{Name: "kone_session", Value: admin}) // No CSRF proof.
		} else {
			r.Header.Set("Authorization", "Bearer "+admin)
		}
		w := httptest.NewRecorder()
		c.Handler().ServeHTTP(w, r)
		if strings.HasPrefix(remote, "127.") {
			require.Equal(t, 401, w.Code)
		} else {
			require.Equal(t, 403, w.Code)
		}
	}
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:3456/api/v1/lifecycle/recover", strings.NewReader(`{"confirm":true}`))
		r.RemoteAddr = "127.0.0.1:5678"
		r.Header.Set("Authorization", "Bearer "+admin)
		r.Header.Set("Idempotency-Key", "recovery-once")
		w := httptest.NewRecorder()
		c.Handler().ServeHTTP(w, r)
		return w
	}
	w := call()
	require.Equal(t, 202, w.Code, w.Body.String())
	var op Operation
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &op))
	require.Equal(t, "succeeded", waitOperation(t, c, op.ID).Status)
	duplicate := call()
	require.Equal(t, 202, duplicate.Code)
	var repeated Operation
	require.NoError(t, json.Unmarshal(duplicate.Body.Bytes(), &repeated))
	require.Equal(t, op.ID, repeated.ID)
	mu.Lock()
	require.Equal(t, 1, calls)
	mu.Unlock()
}
