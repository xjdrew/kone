package desktop

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"net"
	"net/rpc"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestRemoteProbeProgressUsesRequestIdentityOrderAndCancellation(t *testing.T) {
	var received []int
	ctx, cancel := context.WithCancel(kone.WithDiagnosticProgress(t.Context(), func(result kone.DiagnosticResult) { received = append(received, result.Progress.Completed) }))
	observer := &remoteProbeProgress{ctx: ctx}
	observer.active.Store(true)
	engine := &RemoteEngine{probeObservers: map[string]*remoteProbeProgress{"owned": observer}}
	receiver := &callbacks{engine: engine}
	event := func(id string, seq uint64) ProbeProgressEvent {
		return ProbeProgressEvent{ID: id, Sequence: seq, Result: kone.DiagnosticResult{Progress: kone.DiagnosticProgress{Stage: "proxy_handshake", Completed: int(seq), Total: 8}}}
	}
	for _, input := range []ProbeProgressEvent{event("unknown", 1), event("owned", 2), event("owned", 1), event("owned", 2), event("owned", 9)} {
		require.NoError(t, receiver.ProbeProgress(input, &Empty{}))
	}
	require.Equal(t, []int{2}, received)
	cancel()
	require.NoError(t, receiver.ProbeProgress(event("owned", 3), &Empty{}))
	require.Equal(t, []int{2}, received, "canceled requests must not receive later helper milestones")
	delete(engine.probeObservers, "owned")
	require.NoError(t, receiver.ProbeProgress(event("owned", 4), &Empty{}))
}

type blockedProbeCallbacks struct {
	release <-chan struct{}
	entered chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (receiver *blockedProbeCallbacks) ProbeProgress(ProbeProgressEvent, *Empty) error {
	receiver.calls.Add(1)
	receiver.once.Do(func() { close(receiver.entered) })
	<-receiver.release
	return nil
}
func (receiver *blockedProbeCallbacks) Device(DeviceIdentity, *Empty) error { return nil }

func TestSlowProbeProgressHasGlobalBoundsAndCannotBlockCriticalIPC(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	release := make(chan struct{})
	defer close(release)
	receiver := &blockedProbeCallbacks{release: release, entered: make(chan struct{})}
	server := rpc.NewServer()
	require.NoError(t, server.RegisterName("Callbacks", receiver))
	go server.ServeConn(right)
	client := rpc.NewClient(left)
	defer client.Close()
	slots := make(chan struct{}, 2)
	for index := range 6 {
		progress := helperProbeProgress{client: client, id: string(rune('a' + index)), slots: slots}
		for range 3 {
			progress.publish(t.Context(), kone.DiagnosticResult{})
		}
	}
	<-receiver.entered
	require.LessOrEqual(t, receiver.calls.Load(), int32(2), "finished probes cannot accumulate unbounded blocked progress senders")
	require.Equal(t, 2, len(slots))
	var reply Empty
	call := client.Go("Callbacks.Device", DeviceIdentity{Name: "owned", Index: 1, Known: true}, &reply, make(chan *rpc.Call, 1))
	select {
	case result := <-call.Done:
		require.NoError(t, result.Error)
	case <-time.After(time.Second):
		t.Fatal("optional progress blocked durable device recording")
	}
}

type LegacyProbeRequest struct {
	ID, Outbound, Target string
	TLS                  bool
	ExpectedVersion      uint64
	TimeoutMS            int64
	Deadline             time.Time
}
type legacyProbeService struct{}

func (legacyProbeService) Probe(request LegacyProbeRequest, reply *kone.DiagnosticResult) error {
	*reply = kone.DiagnosticResult{Target: request.Target, Status: "reachable"}
	return nil
}

func TestNewRemoteProbeCanUseAnOlderHelperWithoutProgress(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	server := rpc.NewServer()
	require.NoError(t, server.RegisterName("Network", legacyProbeService{}))
	go server.ServeConn(right)
	client := rpc.NewClient(left)
	defer client.Close()
	engine := &RemoteEngine{client: client, requests: make(chan struct{}, 8)}
	result, err := engine.ProbeDiagnosticVersion(t.Context(), "office", "example.com:443", false, 7)
	require.NoError(t, err)
	require.Equal(t, "reachable", result.Status)
	require.Empty(t, engine.probeObservers, "completion must release per-request observers")
}

func TestProbeProgressWireSnapshotDropsSensitiveAndMutableFields(t *testing.T) {
	latency := int64(12)
	input := kone.DiagnosticResult{Target: "private-target", Outbound: "private-name", Message: "private-detail", ConnectLatencyMS: &latency, Host: kone.DiagnosticHost{Address: "http://user:private-key@host:80"}, Protocols: kone.DiagnosticProtocols{TCP: kone.DiagnosticCheck{Message: "http://user:private-key@host:80"}}}
	result := safeProbeProgress(input)
	latency = 99
	require.Equal(t, int64(12), *result.ConnectLatencyMS)
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	for _, secret := range []string{"private-target", "private-name", "private-detail", "private-key"} {
		require.NotContains(t, string(encoded), secret)
	}
	require.True(t, strings.Contains(string(encoded), "redacted"))
}

type oldProbeCallbacks struct{}

func (oldProbeCallbacks) Device(DeviceIdentity, *Empty) error { return nil }

func TestHelperDisablesOptionalProgressWhenOlderCallbacksHaveNoMethod(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	server := rpc.NewServer()
	require.NoError(t, server.RegisterName("Callbacks", oldProbeCallbacks{}))
	go server.ServeConn(right)
	client := rpc.NewClient(left)
	defer client.Close()
	progress := helperProbeProgress{client: client, id: "optional", slots: make(chan struct{}, 1)}
	progress.publish(t.Context(), kone.DiagnosticResult{})
	require.Eventually(t, func() bool {
		progress.publish(t.Context(), kone.DiagnosticResult{})
		return progress.disabled
	}, time.Second, time.Millisecond)
	require.Equal(t, uint64(1), progress.sequence, "do not repeatedly send an unsupported optional callback")
	var reply Empty
	require.NoError(t, client.Call("Callbacks.Device", DeviceIdentity{Name: "owned", Index: 1, Known: true}, &reply))
}

func TestZeroMillisecondMeasurementSurvivesTheHelperGobBoundary(t *testing.T) {
	latency := int64(0)
	var wire bytes.Buffer
	input := safeProbeProgress(kone.DiagnosticResult{ConnectLatencyMS: &latency})
	require.NoError(t, gob.NewEncoder(&wire).Encode(input))
	var received kone.DiagnosticResult
	require.NoError(t, gob.NewDecoder(&wire).Decode(&received))
	received = safeProbeProgress(received)
	require.NotNil(t, received.ConnectLatencyMS, "zero elapsed milliseconds is measured, not missing evidence")
	require.Zero(t, *received.ConnectLatencyMS)
	negative := int64(-1)
	invalid := safeProbeProgress(kone.DiagnosticResult{ConnectLatencyMS: &negative, ConnectLatencyMeasured: true})
	require.Nil(t, invalid.ConnectLatencyMS, "malformed helper measurements cannot become negative latency")
	require.False(t, invalid.ConnectLatencyMeasured)
}

func TestRemoteProbeFinalResultWaitsForItsInFlightProgressDelivery(t *testing.T) {
	remote, fake, _ := helperHarness(t, false)
	ready := make(chan struct{})
	fake.probe = func(ctx context.Context, _, _ string, _ bool, _ uint64) (kone.DiagnosticResult, error) {
		kone.ReportDiagnosticProgress(ctx, kone.DiagnosticResult{Progress: kone.DiagnosticProgress{Stage: "connect", Total: 2}})
		close(ready)
		return kone.DiagnosticResult{Status: "reachable"}, nil
	}
	running := startRemote(t, remote)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	ctx := kone.WithDiagnosticProgress(t.Context(), func(kone.DiagnosticResult) { close(entered); <-release })
	finished := make(chan error, 1)
	go func() {
		_, err := remote.ProbeDiagnosticVersion(ctx, kone.BuiltinDirect, "127.0.0.1:443", false, 7)
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("progress callback did not begin")
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("helper did not finish its bounded progress publication")
	}
	select {
	case <-finished:
		t.Fatal("final result overtook its in-flight progress callback")
	case <-time.After(60 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-finished:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("finishing progress did not release the final result")
	}
	require.Empty(t, remote.probeObservers)
	require.NoError(t, remote.Close())
	require.NoError(t, <-running)
}
