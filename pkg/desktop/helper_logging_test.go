package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/rpc"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
	"github.com/xjdrew/kone/pkg/logstore"
)

type logNetworkEngine struct {
	*fakeNetworkEngine
	logger *atomic.Pointer[slog.Logger]
}

func (e *logNetworkEngine) Run(ctx context.Context) error {
	e.logger.Load().Info("helper engine started", "proxy", "http://user:helper-password@127.0.0.1:1")
	defer e.logger.Load().Warn("helper engine cleanup completed")
	return e.fakeNetworkEngine.Run(ctx)
}

func TestHelperRuntimeLogsTravelPrivateIPCAndRemainAfterShutdown(t *testing.T) {
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:53"}
	store := logstore.NewWithOptions(logstore.Options{Capacity: 3})
	for range 5 {
		store.Append(logstore.Record{Level: "INFO", Message: "early helper startup"})
	}
	var logger atomic.Pointer[slog.Logger]
	var configured atomic.Int32
	fake := &logNetworkEngine{fakeNetworkEngine: newFakeNetworkEngine(t, cfg), logger: &logger}
	commandsParent, commandsHelper := net.Pipe()
	eventsParent, eventsHelper := net.Pipe()
	finished := make(chan error, 1)
	go func() {
		finished <- ServeHelper(context.Background(), commandsHelper, eventsHelper, func(*kone.KoneConfig) (NetworkEngine, error) { return fake, nil }, HelperLogging{Store: store, Configure: func(general kone.GeneralConfig) error {
			next, err := kone.NewLoggingHandler(io.Discard, general, false)
			if err == nil {
				logger.Store(slog.New(store.Handler(next, "helper")))
				configured.Add(1)
			}
			return err
		}})
	}()
	remote, err := NewRemote(cfg, func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
		return commandsParent, eventsParent, nil
	})
	require.NoError(t, err)
	sink := logstore.New()
	require.NoError(t, remote.SetLogStore(sink))
	require.Error(t, remote.SetLogStore(nil))
	require.NoError(t, remote.SetCaptureRecorder(func(string, int) error { return nil }))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	run := make(chan error, 1)
	go func() { run <- remote.Run(ctx) }()
	t.Cleanup(func() { remote.Close(); commandsParent.Close(); eventsParent.Close() })
	select {
	case <-remote.Ready():
	case err := <-run:
		t.Fatalf("helper failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("helper readiness timed out")
	}
	require.Error(t, remote.SetLogStore(sink))
	require.Eventually(t, func() bool {
		v, _ := sink.Query(logstore.Query{})
		for _, record := range v.Records {
			if record.Message == "helper engine started" {
				return true
			}
		}
		return false
	}, 5*time.Second, time.Millisecond)
	require.True(t, remote.LogStatus().Connected)
	require.GreaterOrEqual(t, remote.LogStatus().Dropped, uint64(2))
	require.NoError(t, remote.ReloadVersion(cfg, 2))
	require.Equal(t, int32(2), configured.Load())
	require.NoError(t, remote.Close())
	select {
	case <-run:
	case <-time.After(5 * time.Second):
		t.Fatal("remote did not stop")
	}
	select {
	case err := <-finished:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not stop")
	}
	require.False(t, remote.LogStatus().Connected)
	retained, err := remote.Logs(logstore.Query{})
	require.NoError(t, err)
	encoded, err := json.Marshal(retained)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "helper-password")
	require.Contains(t, string(encoded), "helper engine cleanup completed")
	for _, record := range retained.Records {
		require.Equal(t, "helper", record.Source)
	}
	shared, err := sink.Query(logstore.Query{})
	require.NoError(t, err)
	encoded, err = json.Marshal(shared)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "helper engine cleanup completed")
	for _, message := range []string{"Waiting for network helper authorization and connection", "Network helper connected", "Network helper capture is ready", "Network helper stopping capture"} {
		require.Contains(t, string(encoded), message, "the shared runtime log must retain successful helper stages")
	}
}

func TestHelperStartupFailureLogsFlushBeforeIPCCloses(t *testing.T) {
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:53"}
	commandsParent, commandsHelper := net.Pipe()
	eventsParent, eventsHelper := net.Pipe()
	store := logstore.New()
	go ServeHelper(context.Background(), commandsHelper, eventsHelper, func(*kone.KoneConfig) (NetworkEngine, error) {
		return nil, errors.New("proxy https://name:failed-secret@127.0.0.1 password=private token=private-token")
	}, HelperLogging{Store: store})
	remote, err := NewRemote(cfg, func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
		return commandsParent, eventsParent, nil
	})
	require.NoError(t, err)
	defer remote.Close()
	require.Error(t, remote.Run(t.Context()))
	require.NoError(t, remote.Close())
	logs, err := remote.Logs(logstore.Query{})
	require.NoError(t, err)
	data, err := json.Marshal(logs)
	require.NoError(t, err)
	require.Contains(t, string(data), "Capture startup failed")
	for _, secret := range []string{"failed-secret", "password=private", "private-token"} {
		require.NotContains(t, string(data), secret)
	}
	require.NotEmpty(t, remote.LogStatus().Error)
}

func TestHelperLogBatchInputBoundsCursorReplayAndTimeout(t *testing.T) {
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:53"}
	remote, err := NewRemote(cfg, func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) { return nil, nil, nil })
	require.NoError(t, err)
	callback := &callbacks{engine: remote}
	encode := func(records []logstore.Record) []byte {
		data, err := json.Marshal(records)
		require.NoError(t, err)
		return data
	}
	valid := LogBatch{Data: encode([]logstore.Record{{ID: 1, Message: "received", Attrs: map[string]any{"password": "secret"}}}), Cursor: 1}
	require.NoError(t, callback.Logs(valid, &Empty{}))
	require.NoError(t, callback.Logs(valid, &Empty{}))
	logs, err := remote.Logs(logstore.Query{})
	require.NoError(t, err)
	require.Len(t, logs.Records, 1)
	for _, batch := range []LogBatch{
		{Data: []byte(strings.Repeat("x", maxLogBatchBytes+1)), Cursor: 2},
		{Data: []byte("not json"), Cursor: 2},
		{Data: []byte("[] []"), Cursor: 2},
		{Data: []byte(`[{"unknown":true}]`), Cursor: 2},
		{Data: encode(make([]logstore.Record, 9)), Cursor: 2},
		{Data: encode([]logstore.Record{{ID: 1}}), Cursor: 2},
		{Data: encode([]logstore.Record{{ID: 3}}), Cursor: 2},
	} {
		require.Error(t, callback.Logs(batch, &Empty{}))
	}
	left, right := net.Pipe()
	defer right.Close()
	client := rpc.NewClient(left)
	defer client.Close()
	store := logstore.New()
	store.Append(logstore.Record{Message: "cannot forward"})
	forwarder := helperLogForwarder{store: store, client: client}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- forwarder.flush(ctx) }()
	select {
	case err := <-finished:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("blocked log forwarding did not cancel")
	}
}

func TestProductionHelperLoggingNeverReplacesAnotherInstanceAfterReturn(t *testing.T) {
	old := slog.Default()
	require.Error(t, serveProductionHelper(t.Context(), nil, nil, nil))
	require.Same(t, old, slog.Default())
	require.Error(t, serveProductionHelper(t.Context(), nil, nil, func(*kone.KoneConfig) (NetworkEngine, error) { return nil, errors.New("unused") }))
	require.Same(t, old, slog.Default())
}

type slowLogCallbacks struct {
	block   <-chan struct{}
	started chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (s *slowLogCallbacks) Logs(LogBatch, *Empty) error {
	s.calls.Add(1)
	s.once.Do(func() { close(s.started) })
	<-s.block
	return nil
}
func (s *slowLogCallbacks) Device(DeviceIdentity, *Empty) error  { return nil }
func (s *slowLogCallbacks) Finished(FinishedEvent, *Empty) error { return nil }

func TestSlowLogDeliveryKeepsCriticalEventsAndOnlyOnePendingCall(t *testing.T) {
	left, right := net.Pipe()
	block := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(block) })
	callbacks := &slowLogCallbacks{block: block, started: make(chan struct{})}
	server := rpc.NewServer()
	require.NoError(t, server.RegisterName("Callbacks", callbacks))
	serverDone := make(chan struct{})
	go func() { server.ServeConn(right); close(serverDone) }()
	client := rpc.NewClient(left)
	defer client.Close()
	store := logstore.New()
	store.Append(logstore.Record{Message: "best effort"})
	forwarder := helperLogForwarder{store: store, client: client}
	for range 2 {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
		err := forwarder.flush(ctx)
		cancel()
		require.ErrorIs(t, err, context.DeadlineExceeded)
	}
	require.Equal(t, int32(1), callbacks.calls.Load(), "repeated timeouts reuse one pending RPC, without creating new send goroutines")
	for _, method := range []string{"Device", "Finished"} {
		var reply Empty
		var input any = DeviceIdentity{Name: "owned", Index: 1, Known: true}
		if method == "Finished" {
			input = FinishedEvent{}
		}
		call := client.Go("Callbacks."+method, input, &reply, make(chan *rpc.Call, 1))
		select {
		case result := <-call.Done:
			require.NoError(t, result.Error)
		case <-time.After(time.Second):
			t.Fatalf("slow logs blocked critical %s event", method)
		}
	}
	pending := forwarder.pending
	require.NotNil(t, pending)
	require.True(t, (&helperService{logForwarder: &forwarder}).logsDegraded())
	require.NoError(t, client.Close())
	select {
	case err := <-pending.result:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("lifecycle close did not release pending log goroutine")
	}
	release.Do(func() { close(block) })
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("event server did not exit after lifecycle cancellation")
	}
}
