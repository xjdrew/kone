package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/desktop"
	"github.com/xjdrew/kone/pkg/kone"
)

type probeOnlyHelperEngine struct {
	*kone.One
	ready chan struct{}
	stop  chan struct{}
	once  sync.Once
}

func (engine *probeOnlyHelperEngine) Run(ctx context.Context) error {
	close(engine.ready)
	select {
	case <-ctx.Done():
	case <-engine.stop:
	}
	return nil
}
func (engine *probeOnlyHelperEngine) Close() error {
	engine.once.Do(func() { close(engine.stop) })
	return engine.One.Close()
}
func (engine *probeOnlyHelperEngine) Ready() <-chan struct{}                           { return engine.ready }
func (engine *probeOnlyHelperEngine) SetCaptureRecorder(func(string, int) error) error { return nil }
func (engine *probeOnlyHelperEngine) CaptureDeviceIdentity() (string, int, bool)       { return "", 0, false }

func TestActiveHelperOutboundProbeStreamsRealStagesThroughPrivateRPC(t *testing.T) {
	// The private command/events RPC and actual proxy protocol run unchanged.
	// Replace only the helper's capture loop: no privileged process, TUN or
	// system network mutation is created by this integration journey.
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer proxy.Close()
	defer unblock()
	helperDone := make(chan error, 1)
	c, err := control.New(control.Options{Directory: t.TempDir(), Preflight: func(context.Context, *kone.KoneConfig) kone.PreflightReport { return kone.PreflightReport{Ready: true} }, Factory: func(cfg *kone.KoneConfig) (control.Engine, error) {
		commandsParent, commandsHelper := net.Pipe()
		eventsParent, eventsHelper := net.Pipe()
		go func() {
			helperDone <- desktop.ServeHelper(t.Context(), commandsHelper, eventsHelper, func(cfg *kone.KoneConfig) (desktop.NetworkEngine, error) {
				one, err := kone.FromConfig(cfg)
				if err != nil {
					return nil, err
				}
				return &probeOnlyHelperEngine{One: one, ready: make(chan struct{}), stop: make(chan struct{})}, nil
			})
		}()
		return desktop.NewRemote(cfg, func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
			return commandsParent, eventsParent, nil
		})
	}})
	require.NoError(t, err)
	defer c.Close()
	document := c.Document()
	config := document["config"].(map[string]any)
	config["outbounds"] = []map[string]any{{"name": "measured", "url": proxy.URL}}
	config["rules"] = []map[string]any{{"type": "FINAL", "outbound": "measured"}}
	_, err = c.Save(control.SaveRequest{BaseVersion: c.State().SavedVersion, Config: config, Inbound: document["inbound"].(control.Inbound)})
	require.NoError(t, err)
	require.NoError(t, c.Start(t.Context()))
	saved := c.Document()["config"].(map[string]any)["outbounds"].([]any)[0].(map[string]any)
	withoutTLS := false
	operation, err := c.TestOutbound(control.OutboundTestRequest{BaseVersion: c.State().SavedVersion, OutboundID: saved["id"].(string), TLS: &withoutTLS}, "")
	require.NoError(t, err)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("helper did not reach the loopback proxy")
	}
	var progress control.OutboundHealth
	require.Eventually(t, func() bool {
		for _, current := range c.Operations() {
			if current.ID == operation.ID && current.Stage == "proxy_handshake" {
				progress = current.Result.(control.OutboundHealth)
				return current.Status == "running"
			}
		}
		return false
	}, time.Second, time.Millisecond)
	require.Equal(t, "healthy", progress.Host.Status)
	require.NotNil(t, progress.ConnectLatencyMS)
	require.Equal(t, "testing", progress.Protocols.TCP.Status)
	unblock()
	var final control.OutboundHealth
	require.Eventually(t, func() bool {
		for _, current := range c.Operations() {
			if current.ID == operation.ID && current.Status == "succeeded" {
				final = current.Result.(control.OutboundHealth)
				return true
			}
		}
		return false
	}, 3*time.Second, time.Millisecond)
	require.Equal(t, "healthy", final.Protocols.TCP.Status)
	require.Equal(t, "unsupported", final.Protocols.UDP.Status)
	require.False(t, final.Protocols.UDP.Tested)
	require.Equal(t, "testing", progress.Protocols.TCP.Status)
	require.NoError(t, c.Close())
	select {
	case err := <-helperDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("private helper did not release its IPC after stop")
	}
}
