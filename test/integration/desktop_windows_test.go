package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/desktop"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestDesktopUnresponsiveAuthorizationKeepsManagementAvailable(t *testing.T) {
	// Replace only the native UAC launcher with an unresponsive dialog. No
	// helper is created, and no TUN, route, DNS or host proxy can be changed.
	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var launches atomic.Int32
	c, err := control.New(control.Options{Directory: t.TempDir(), Preflight: func(context.Context, *kone.KoneConfig) kone.PreflightReport { return kone.PreflightReport{Ready: true} }, Factory: func(cfg *kone.KoneConfig) (control.Engine, error) {
		return desktop.NewEngine(cfg, func(context.Context, string, []string) error { launches.Add(1); close(entered); <-release; return nil })
	}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	document := c.Document()
	inbound := document["inbound"].(control.Inbound)
	inbound.Enabled = true
	_, err = c.Save(control.SaveRequest{BaseVersion: c.State().SavedVersion, Config: document["config"].(map[string]any), Inbound: inbound})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("test authorization was not reached")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("canceled startup retained the controller action lock")
	}
	require.Equal(t, "paused", c.State().DataState)
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	response, err := client.Get(server.URL + "/")
	require.NoError(t, err)
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode, "local management remains usable during an abandoned native UAC dialog")
	require.ErrorContains(t, c.Start(context.Background()), "still pending")
	require.Equal(t, int32(1), launches.Load(), "retrying cannot stack another native authorization dialog")
}
