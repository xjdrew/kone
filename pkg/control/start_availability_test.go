package control

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/desktop"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestManagementReadsRemainAvailableDuringAndAfterHelperStartupFailure(t *testing.T) {
	authorizing := make(chan struct{})
	reject := make(chan struct{})
	c := testController(t, Options{Factory: func(cfg *kone.KoneConfig) (Engine, error) {
		return desktop.NewRemote(cfg, func(ctx context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
			close(authorizing)
			// Model an outstanding UAC/transport handshake without starting a
			// helper process, creating TUN or changing the host network.
			select {
			case <-reject:
				return nil, nil, errors.New("injected helper handshake failure")
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		})
	}})
	t.Cleanup(func() {
		select {
		case <-reject:
		default:
			close(reject)
		}
	})
	enable(t, c)
	token := owner(t, c)
	response := request(t, c, token, "POST", "/api/v1/lifecycle/start", nil)
	require.Equal(t, 202, response.Code, response.Body.String())
	select {
	case <-authorizing:
	case <-time.After(3 * time.Second):
		t.Fatal("the injected authorization wait did not start")
	}
	read := func(path string, status int) *httptest.ResponseRecorder {
		t.Helper()
		complete := make(chan *httptest.ResponseRecorder, 1)
		go func() { complete <- request(t, c, token, "GET", path, nil) }()
		select {
		case value := <-complete:
			require.Equal(t, status, value.Code, value.Body.String())
			return value
		case <-time.After(2 * time.Second):
			t.Fatalf("management read %s was blocked by the capture operation", path)
			return nil
		}
	}
	require.Contains(t, read("/api/v1/state", 200).Body.String(), `"data_state":"starting"`)
	read("/api/v1/config", 200)
	require.Contains(t, read("/api/v1/diagnostics", 200).Body.String(), `"status":"running"`)
	read("/api/v1/traffic", 503)
	read("/api/v1/dns", 503)
	// An unavailable data plane must not turn the independent control plane
	// into an unavailable service or revoke its owner's session.
	read("/api/v1/state", 200)
	close(reject)
	require.Eventually(t, func() bool {
		operations := c.Operations()
		return len(operations) == 1 && operations[0].Status == "failed"
	}, 3*time.Second, time.Millisecond)
	require.Contains(t, read("/api/v1/state", 200).Body.String(), `"data_state":"paused"`)
	read("/api/v1/config", 200)
	require.Contains(t, read("/api/v1/diagnostics", 200).Body.String(), "injected helper handshake failure")
	read("/api/v1/traffic", 503)
	read("/api/v1/dns", 503)
}
