package integration

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/desktop"
	"github.com/xjdrew/kone/pkg/kone"
	"github.com/xjdrew/kone/pkg/logstore"
)

type finalLogHelperEngine struct {
	*probeOnlyHelperEngine
	returning chan struct{}
	release   <-chan struct{}
	logs      *logstore.Store
}

func (e *finalLogHelperEngine) Run(ctx context.Context) error {
	err := e.probeOnlyHelperEngine.Run(ctx)
	close(e.returning)
	<-e.release
	e.logs.Append(logstore.Record{Level: "INFO", Message: "Final owned-resource cleanup record"})
	return err
}

func TestHelperShutdownRetainsFinalLogsBeforePrivateIPCCloses(t *testing.T) {
	// Real private RPC and log forwarding, with an in-memory capture engine.
	// No privileged helper, TUN, system DNS or external network is involved.
	synctest.Test(t, func(t *testing.T) {
		cfg := kone.DefaultConfig()
		cfg.DNS.Servers = []string{"127.0.0.1:9"}
		one, err := kone.FromConfig(cfg)
		require.NoError(t, err)
		release := make(chan struct{})
		finish := sync.OnceFunc(func() { close(release) })
		store, sink := logstore.New(), logstore.New()
		engine := &finalLogHelperEngine{probeOnlyHelperEngine: &probeOnlyHelperEngine{One: one, ready: make(chan struct{}), stop: make(chan struct{})}, returning: make(chan struct{}), release: release, logs: store}
		commandsParent, commandsHelper := net.Pipe()
		eventsParent, eventsHelper := net.Pipe()
		helperDone := make(chan error, 1)
		go func() {
			helperDone <- desktop.ServeHelper(t.Context(), commandsHelper, eventsHelper, func(*kone.KoneConfig) (desktop.NetworkEngine, error) { return engine, nil }, desktop.HelperLogging{Store: store})
		}()
		remote, err := desktop.NewRemote(cfg, func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
			return commandsParent, eventsParent, nil
		})
		require.NoError(t, err)
		defer func() { finish(); remote.Close(); commandsParent.Close(); eventsParent.Close() }()
		require.NoError(t, remote.SetLogStore(sink))
		run := make(chan error, 1)
		go func() { run <- remote.Run(t.Context()) }()
		select {
		case <-remote.Ready():
		case err := <-run:
			t.Fatalf("helper exited before readiness: %v", err)
		}
		stopped := make(chan error, 1)
		go func() { stopped <- remote.Close() }()
		<-engine.returning
		synctest.Wait()
		select {
		case err := <-stopped:
			t.Fatalf("private IPC closed before the final cleanup record: %v", err)
		default:
		}
		finish()
		require.NoError(t, <-stopped)
		require.NoError(t, <-run)
		require.NoError(t, <-helperDone)
		page, err := sink.Query(logstore.Query{})
		require.NoError(t, err)
		messages := make([]string, 0, len(page.Records))
		for _, record := range page.Records {
			messages = append(messages, record.Message)
		}
		require.Contains(t, messages, "Final owned-resource cleanup record")
		require.Contains(t, messages, "Network helper engine cleanup completed")
	})
}
