package desktop

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/geoip"
	"github.com/xjdrew/kone/pkg/kone"
)

type fakeNetworkEngine struct {
	*kone.One
	mu                sync.Mutex
	recorder          func(string, int) error
	ready, done, stop chan struct{}
	once              sync.Once
	started           bool
	wait              bool
	closeError        error
	probe             func(context.Context, string, string, bool, uint64) (kone.DiagnosticResult, error)
}

func newFakeNetworkEngine(t *testing.T, cfg *kone.KoneConfig) *fakeNetworkEngine {
	t.Helper()
	one, err := kone.FromConfig(cfg)
	require.NoError(t, err)
	return &fakeNetworkEngine{One: one, ready: make(chan struct{}), done: make(chan struct{}), stop: make(chan struct{})}
}
func (e *fakeNetworkEngine) SetCaptureRecorder(record func(string, int) error) error {
	e.mu.Lock()
	e.recorder = record
	e.mu.Unlock()
	return nil
}
func (e *fakeNetworkEngine) CaptureDeviceIdentity() (string, int, bool) {
	return "owned-test-device", 12345, true
}
func (e *fakeNetworkEngine) Ready() <-chan struct{} { return e.ready }

func (e *fakeNetworkEngine) ProbeDiagnosticVersion(ctx context.Context, outbound, target string, tls bool, version uint64) (kone.DiagnosticResult, error) {
	e.mu.Lock()
	probe := e.probe
	e.mu.Unlock()
	if probe != nil {
		return probe(ctx, outbound, target, tls, version)
	}
	return e.One.ProbeDiagnosticVersion(ctx, outbound, target, tls, version)
}
func (e *fakeNetworkEngine) Run(ctx context.Context) error {
	e.mu.Lock()
	e.started = true
	record := e.recorder
	e.mu.Unlock()
	defer close(e.done)
	if record != nil {
		if err := record("owned-test-device", 12345); err != nil {
			return err
		}
	}
	flow := e.TrafficObserver().Begin(kone.FlowRecord{Protocol: "tcp", Target: "example.com:443", ConfigVersion: 7})
	flow.Decision(kone.RoutingDecision{RuleID: "rule-test", Outbound: kone.BuiltinDirect}, kone.BuiltinDirect, "", true)
	flow.AddUpload(17, 0)
	flow.AddDownload(23, 0)
	defer flow.Finish(nil, false)
	if !e.wait {
		close(e.ready)
	}
	select {
	case <-ctx.Done():
	case <-e.stop:
	}
	return nil
}
func (e *fakeNetworkEngine) Close() error {
	e.once.Do(func() { close(e.stop) })
	e.mu.Lock()
	started := e.started
	e.mu.Unlock()
	if started {
		<-e.done
	}
	return errors.Join(e.closeError, e.One.Close())
}

func helperHarness(t *testing.T, wait bool) (*RemoteEngine, *fakeNetworkEngine, <-chan error) {
	t.Helper()
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:53"}
	fake := newFakeNetworkEngine(t, cfg)
	fake.wait = wait
	commandParent, commandHelper := net.Pipe()
	eventParent, eventHelper := net.Pipe()
	finished := make(chan error, 1)
	go func() {
		finished <- ServeHelper(context.Background(), commandHelper, eventHelper, func(*kone.KoneConfig) (NetworkEngine, error) { return fake, nil })
	}()
	remote, err := NewRemote(cfg, func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
		return commandParent, eventParent, nil
	})
	require.NoError(t, err)
	t.Cleanup(func() { remote.Close(); commandParent.Close(); eventParent.Close() })
	return remote, fake, finished
}

func startRemote(t *testing.T, remote *RemoteEngine) <-chan error {
	t.Helper()
	require.NoError(t, remote.SetTrafficObserver(kone.NewTrafficObserver(kone.ObservationOptions{})))
	require.NoError(t, remote.SetConfigVersion(7))
	require.NoError(t, remote.SetGeoIPDatabase(geoip.Builtin()))
	require.NoError(t, remote.SetCaptureRecorder(func(name string, index int) error {
		if name != "owned-test-device" || index != 12345 {
			return errors.New("unexpected actual identity")
		}
		return nil
	}))
	done := make(chan error, 1)
	go func() { done <- remote.Run(context.Background()) }()
	select {
	case <-remote.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("helper never became ready")
	}
	return done
}

func TestRemoteHelperReportsRealSnapshotsAndPreservesFinalEvidence(t *testing.T) {
	remote, _, helperDone := helperHarness(t, false)
	done := startRemote(t, remote)
	traffic, graph, err := remote.TrafficData(kone.TrafficQuery{}, kone.SankeyOptions{Metric: "cumulative"})
	require.NoError(t, err)
	require.Equal(t, uint64(40), traffic.Totals.Bytes)
	require.Equal(t, float64(40), graph.Total)
	require.False(t, traffic.Frozen)
	require.Len(t, traffic.Records, 1)
	record, ok, err := remote.FlowRecord(traffic.Records[0].ID)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "example.com:443", record.Target)
	name, index, known := remote.CaptureDeviceIdentity()
	require.True(t, known)
	require.Equal(t, "owned-test-device", name)
	require.Equal(t, 12345, index)
	_, queries, err := remote.DNSData()
	require.NoError(t, err)
	require.Empty(t, queries)
	status, err := remote.GeoIPData()
	require.NoError(t, err)
	require.True(t, status.Current.Builtin)
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:53"}
	require.NoError(t, remote.ReloadVersion(cfg, 8))
	require.NoError(t, remote.Close())
	require.NoError(t, <-done)
	select {
	case err := <-helperDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("helper did not exit after normal parent shutdown")
	}
	traffic, graph, err = remote.TrafficData(kone.TrafficQuery{}, kone.SankeyOptions{Metric: "cumulative"})
	require.NoError(t, err)
	require.True(t, traffic.Frozen)
	require.True(t, graph.Frozen)
	require.Equal(t, uint64(40), traffic.Totals.Bytes)
	require.Zero(t, traffic.Totals.Active)
	*traffic.Records[0].EndedAt = time.Unix(0, 0)
	record, ok, err = remote.FlowRecord(record.ID)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotEqual(t, time.Unix(0, 0), *record.EndedAt)
	_, _, err = remote.TrafficData(kone.TrafficQuery{Protocol: "udp"}, kone.SankeyOptions{})
	require.ErrorContains(t, err, "stopped")
	require.NoError(t, remote.ClearObservation())
	traffic, graph, err = remote.TrafficData(kone.TrafficQuery{}, kone.SankeyOptions{Metric: "cumulative"})
	require.NoError(t, err)
	require.Empty(t, traffic.Records)
	require.Equal(t, uint64(40), traffic.Totals.Bytes)
	require.Equal(t, float64(40), graph.Total)
	require.True(t, graph.Paths[0].Other)
}

func TestParentDisconnectionCancelsStartupAndRestoresHelper(t *testing.T) {
	remote, fake, helperDone := helperHarness(t, true)
	recorded := make(chan struct{})
	require.NoError(t, remote.SetCaptureRecorder(func(string, int) error { close(recorded); return nil }))
	done := make(chan error, 1)
	go func() { done <- remote.Run(context.Background()) }()
	<-recorded
	remote.mu.Lock()
	commands := remote.commands
	events := remote.events
	remote.mu.Unlock()
	commands.Close()
	events.Close()
	select {
	case <-fake.done:
	case <-time.After(time.Second):
		t.Fatal("helper kept capture alive after parent EOF during startup")
	}
	select {
	case <-helperDone:
	case <-time.After(time.Second):
		t.Fatal("helper did not finish rollback")
	}
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("remote engine did not report helper failure")
	}
	require.Error(t, remote.Close(), "unknown cleanup acknowledgement must retain the recovery journal")
}

func TestDeviceRecorderFailurePreventsHelperReadiness(t *testing.T) {
	remote, _, _ := helperHarness(t, false)
	require.NoError(t, remote.SetCaptureRecorder(func(string, int) error { return errors.New("disk full: private detail") }))
	done := make(chan error, 1)
	go func() { done <- remote.Run(context.Background()) }()
	select {
	case err := <-done:
		require.ErrorContains(t, err, "durable capture")
		require.NotContains(t, err.Error(), "private detail")
	case <-time.After(3 * time.Second):
		t.Fatal("failed durable identity recording did not stop startup")
	}
	select {
	case <-remote.Ready():
		t.Fatal("helper became ready without durable ownership")
	default:
	}
}

func TestRemoteGuardsAndCredentialRedaction(t *testing.T) {
	_, err := NewRemote(nil, nil)
	require.Error(t, err)
	_, err = NewRemote(kone.DefaultConfig(), nil)
	require.Error(t, err)
	remote, _, _ := helperHarness(t, false)
	require.Error(t, remote.SetTrafficObserver(nil))
	require.Error(t, remote.SetConfigVersion(0))
	require.Error(t, remote.SetGeoIPDatabase(nil))
	require.Error(t, remote.SetCaptureRecorder(nil))
	require.Error(t, remote.ReloadVersion(nil, 1))
	_, _, err = remote.TrafficData(kone.TrafficQuery{}, kone.SankeyOptions{})
	require.Error(t, err)
	require.NotContains(t, helperError(errors.New("dial https://user:password@proxy:443 failed")), "password")
	selected := make(chan int, 3)
	actions := TrayActions{Open: func() { selected <- 1 }, Pause: func() { selected <- 2 }, Exit: func() { selected <- 3 }}
	for index := 1; index <= 3; index++ {
		invokeTrayAction(actions, uintptr(index))
		require.Equal(t, index, <-selected)
	}
	invokeTrayAction(TrayActions{}, 1)
	invokeTrayAction(actions, 99)
}

func TestRemoteDiagnosticUsesRunningRevisionAndCancelKeepsCaptureAlive(t *testing.T) {
	remote, fake, _ := helperHarness(t, false)
	done := startRemote(t, remote)
	result, err := remote.ProbeDiagnosticVersion(context.Background(), kone.BuiltinDirect, "example.invalid:443", false, 8)
	require.NoError(t, err)
	require.Equal(t, "not_applied", result.Status)
	require.Equal(t, uint64(7), result.ConfigVersion)
	entered := make(chan struct{})
	canceled := make(chan struct{})
	fake.mu.Lock()
	fake.probe = func(ctx context.Context, _, _ string, _ bool, _ uint64) (kone.DiagnosticResult, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		return kone.DiagnosticResult{Status: "canceled"}, nil
	}
	fake.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	probeDone := make(chan error, 1)
	go func() {
		_, err := remote.ProbeDiagnostic(ctx, kone.BuiltinDirect, "127.0.0.1:443", false)
		probeDone <- err
	}()
	<-entered
	cancel()
	require.ErrorIs(t, <-probeDone, context.Canceled)
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("helper did not cancel its diagnostic")
	}
	traffic, _, err := remote.TrafficData(kone.TrafficQuery{}, kone.SankeyOptions{})
	require.NoError(t, err)
	require.Equal(t, uint64(1), traffic.Totals.Active, "canceling one diagnostic cannot stop business capture")
	require.NoError(t, remote.Close())
	require.NoError(t, <-done)
}

func TestHelperRemembersCancellationBeforeProbeRegistration(t *testing.T) {
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:53"}
	fake := newFakeNetworkEngine(t, cfg)
	defer fake.Close()
	fake.probe = func(context.Context, string, string, bool, uint64) (kone.DiagnosticResult, error) {
		t.Fatal("a canceled request must not resolve or connect later")
		return kone.DiagnosticResult{}, nil
	}
	service := &helperService{ctx: context.Background(), engine: fake}
	require.NoError(t, service.CancelProbe("early", &Empty{}))
	var reply kone.DiagnosticResult
	err := service.Probe(ProbeRequest{ID: "early", Target: "127.0.0.1:443", TimeoutMS: 1000, Deadline: time.Now().Add(time.Second)}, &reply)
	require.ErrorIs(t, err, context.Canceled)
	err = service.Probe(ProbeRequest{ID: "expired", Target: "127.0.0.1:443", TimeoutMS: 1000, Deadline: time.Now().Add(-time.Second)}, &reply)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestRemoteCleanupFailureCannotProduceAConfirmedFinalArchive(t *testing.T) {
	remote, fake, helperDone := helperHarness(t, false)
	fake.closeError = errors.New("owned route changed externally; restoration was not confirmed")
	done := startRemote(t, remote)
	require.ErrorContains(t, remote.Close(), "restoration was not confirmed")
	require.Error(t, <-done)
	_, _, err := remote.TrafficData(kone.TrafficQuery{}, kone.SankeyOptions{})
	require.Error(t, err, "failed cleanup cannot be represented as a clean frozen snapshot")
	select {
	case err := <-helperDone:
		require.ErrorContains(t, err, "restoration was not confirmed")
	case <-time.After(time.Second):
		t.Fatal("helper failed to exit after reporting an unconfirmed cleanup")
	}
}
