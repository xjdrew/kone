package kone

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type memoryDevice struct {
	closed chan struct{}
	fault  chan error
	once   sync.Once
	closes atomic.Int32
}

func newMemoryDevice() *memoryDevice {
	return &memoryDevice{closed: make(chan struct{}), fault: make(chan error, 1)}
}
func (d *memoryDevice) Name() string { return "kone-test" }
func (d *memoryDevice) Read([]byte) (int, error) {
	select {
	case <-d.closed:
		return 0, net.ErrClosed
	case err := <-d.fault:
		return 0, err
	}
}
func (d *memoryDevice) Write(p []byte) (int, error) { return len(p), nil }
func (d *memoryDevice) Close() error {
	d.once.Do(func() { d.closes.Add(1); close(d.closed) })
	return nil
}

type memoryNetwork struct {
	device                                          *memoryDevice
	mu                                              sync.Mutex
	events                                          []string
	configured                                      bool
	routes                                          map[string]bool
	failOpen, failConfigure, failRoute, failRestore bool
	configureWait                                   chan struct{}
}

func newMemoryNetwork() *memoryNetwork {
	return &memoryNetwork{device: newMemoryDevice(), routes: make(map[string]bool)}
}
func (n *memoryNetwork) Open(ctx context.Context, _ CoreConfig) (Device, error) {
	if n.failOpen {
		return nil, errors.New("injected open failure")
	}
	return n.device, ctx.Err()
}
func (n *memoryNetwork) Configure(ctx context.Context, _ Device, _ CoreConfig) (Cleanup, error) {
	n.mu.Lock()
	n.configured = true
	n.events = append(n.events, "configure")
	n.mu.Unlock()
	undo := func(ctx context.Context) error {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.configured = false
		n.events = append(n.events, "restore")
		if n.failRestore {
			return errors.New("injected restore failure")
		}
		return ctx.Err()
	}
	if n.configureWait != nil {
		close(n.configureWait)
		<-ctx.Done()
		return undo, ctx.Err()
	}
	if n.failConfigure {
		return undo, errors.New("injected configuration failure")
	}
	return undo, nil
}
func (n *memoryNetwork) AddRoute(_ context.Context, _ Device, p *net.IPNet) (Cleanup, error) {
	key := p.String()
	n.mu.Lock()
	n.routes[key] = true
	n.events = append(n.events, "add "+key)
	n.mu.Unlock()
	undo := func(context.Context) error {
		n.mu.Lock()
		defer n.mu.Unlock()
		delete(n.routes, key)
		n.events = append(n.events, "delete "+key)
		return nil
	}
	if n.failRoute && strings.HasPrefix(key, "203.") {
		return undo, errors.New("injected route failure")
	}
	return undo, nil
}

type loopSockets struct {
	mu       sync.Mutex
	lc       net.ListenConfig
	tcp      []net.Listener
	udp      []net.PacketConn
	failAt   string
	occupied string
}

func (s *loopSockets) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, port, _ := net.SplitHostPort(address)
	bind := "127.0.0.1:0"
	if s.failAt == "manager" && port == "9200" {
		bind = s.occupied
	}
	ln, err := s.lc.Listen(ctx, network, bind)
	if err == nil {
		s.tcp = append(s.tcp, ln)
	}
	return ln, err
}
func (s *loopSockets) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bind := "127.0.0.1:0"
	if s.failAt == "dns" {
		bind = s.occupied
	}
	conn, err := s.lc.ListenPacket(ctx, network, bind)
	if err == nil {
		s.udp = append(s.udp, conn)
	}
	return conn, err
}

func lifecycleEngine(t *testing.T, n *memoryNetwork, s *loopSockets) *One {
	t.Helper()
	cleanProxyEnv(t)
	cfg := parseTestConfig(t, `[[rules]]
type='IP-CIDR'
pattern='198.51.100.0/24'
outbound='reject'
[[rules]]
type='IP-CIDR'
pattern='203.0.113.0/24'
outbound='reject'
`)
	one, err := FromConfig(cfg, WithNetwork(n), WithSockets(s), WithShutdownTimeout(time.Second))
	require.NoError(t, err)
	one.stackFactory = fixtureStackFactory(one)
	return one
}

// Model only the stack lifecycle boundary. Packet processing belongs to
// sing-tun and is exercised by native system/mixed acceptance tests.
type fixtureStack struct {
	start func() error
	close func() error
	wg    sync.WaitGroup
}

func (s *fixtureStack) Start() error { return s.start() }
func (s *fixtureStack) Close() error { return s.close() }
func (s *fixtureStack) Wait()        { s.wg.Wait() }
func fixtureStackFactory(one *One) stackFactory {
	return func(ctx context.Context, device Device, _ CoreConfig, _ *flowHandler, failures chan<- error) (packetStack, error) {
		s := &fixtureStack{close: func() error { return nil }}
		s.start = func() error {
			if sockets, ok := one.sockets.(*loopSockets); ok && sockets.failAt == "stack" {
				return errors.New("injected stack start failure")
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				_, err := device.Read(make([]byte, MTU))
				if ctx.Err() == nil {
					select {
					case failures <- err:
					default:
					}
				}
			}()
			return nil
		}
		return s, nil
	}
}
func assertReleased(t *testing.T, n *memoryNetwork, s *loopSockets) {
	t.Helper()
	require.Equal(t, int32(1), n.device.closes.Load())
	n.mu.Lock()
	require.False(t, n.configured)
	require.Empty(t, n.routes)
	n.mu.Unlock()
	for _, ln := range s.tcp {
		replacement, err := net.Listen("tcp", ln.Addr().String())
		require.NoError(t, err)
		replacement.Close()
	}
	for _, conn := range s.udp {
		replacement, err := net.ListenPacket("udp", conn.LocalAddr().String())
		require.NoError(t, err)
		replacement.Close()
	}
}

func runReady(t *testing.T, one *One) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- one.Run(ctx) }()
	select {
	case <-one.Ready():
	case err := <-done:
		cancel()
		t.Fatalf("startup failed: %v", err)
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("startup timed out")
	}
	t.Cleanup(func() { cancel(); one.Close() })
	return cancel, done
}

func waitRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("engine did not stop")
		return nil
	}
}

func TestLifecycleStartupRollback(t *testing.T) {
	for _, kind := range []string{"configure", "route", "stack", "dns", "manager"} {
		t.Run(kind, func(t *testing.T) {
			n, s := newMemoryNetwork(), &loopSockets{}
			var occupied io.Closer
			switch kind {
			case "configure":
				n.failConfigure = true
			case "route":
				n.failRoute = true
			case "stack":
				s.failAt = kind
			case "manager":
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				occupied = ln
				s.occupied = ln.Addr().String()
				s.failAt = kind
			case "dns":
				conn, err := net.ListenPacket("udp", "127.0.0.1:0")
				require.NoError(t, err)
				occupied = conn
				s.occupied = conn.LocalAddr().String()
				s.failAt = kind
			}
			if occupied != nil {
				defer occupied.Close()
			}
			one := lifecycleEngine(t, n, s)
			require.Error(t, one.Run(context.Background()))
			require.NoError(t, one.Close())
			assertReleased(t, n, s)
			if kind == "route" {
				require.Equal(t, []string{"configure", "add 198.51.100.0/24", "add 203.0.113.0/24", "delete 203.0.113.0/24", "delete 198.51.100.0/24", "restore"}, n.events)
			}
		})
	}
}

func TestLifecycleNormalAndConcurrentClose(t *testing.T) {
	n, s := newMemoryNetwork(), &loopSockets{}
	one := lifecycleEngine(t, n, s)
	_, done := runReady(t, one)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := one.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	require.NoError(t, waitRun(t, done))
	assertReleased(t, n, s)
	require.Error(t, one.Run(context.Background()))
	require.Error(t, one.Reload(one.Snapshot().Config))
}

func TestLifecycleUnexpectedFailureStopsPeers(t *testing.T) {
	n, s := newMemoryNetwork(), &loopSockets{}
	one := lifecycleEngine(t, n, s)
	_, done := runReady(t, one)
	n.device.fault <- errors.New("injected read failure")
	require.ErrorContains(t, waitRun(t, done), "injected read failure")
	assertReleased(t, n, s)
}

func TestLifecycleCloseDuringStartup(t *testing.T) {
	n, s := newMemoryNetwork(), &loopSockets{}
	n.configureWait = make(chan struct{})
	one := lifecycleEngine(t, n, s)
	done := make(chan error, 1)
	go func() { done <- one.Run(context.Background()) }()
	select {
	case <-n.configureWait:
	case <-time.After(time.Second):
		t.Fatal("configure not called")
	}
	require.NoError(t, one.Close())
	require.NoError(t, waitRun(t, done))
	assertReleased(t, n, s)
}

func TestLifecycleReportsCleanupFailure(t *testing.T) {
	n, s := newMemoryNetwork(), &loopSockets{}
	n.failRestore = true
	one := lifecycleEngine(t, n, s)
	cancel, done := runReady(t, one)
	cancel()
	require.ErrorContains(t, waitRun(t, done), "injected restore failure")
	require.ErrorContains(t, one.Close(), "injected restore failure")
	assertReleased(t, n, s)
}

func TestLifecyclePreCanceledAndCloseBeforeRun(t *testing.T) {
	n, s := newMemoryNetwork(), &loopSockets{}
	one := lifecycleEngine(t, n, s)
	require.NoError(t, one.Close())
	require.Error(t, one.Run(context.Background()))
	require.Zero(t, n.device.closes.Load())
	one = lifecycleEngine(t, newMemoryNetwork(), &loopSockets{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, one.Run(ctx))
	require.NoError(t, one.Close())
	n = newMemoryNetwork()
	n.failOpen = true
	one = lifecycleEngine(t, n, &loopSockets{})
	require.ErrorContains(t, one.Run(context.Background()), "injected open failure")
}
