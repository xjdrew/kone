package kone

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemovedManagerOptionHasMigrationError(t *testing.T) {
	cleanProxyEnv(t)
	for _, address := range []string{"", "127.0.0.1:9200", "0.0.0.0:9200"} {
		for _, parse := range []func(any) (*KoneConfig, error){ParseConfig, ParseManagedConfig} {
			_, err := parse([]byte("[general]\nmanager-addr='" + address + "'\n"))
			require.ErrorContains(t, err, "general.manager-addr was removed")
			require.ErrorContains(t, err, "-manage")
		}
	}
	data, err := DefaultConfig().RedactedTOML()
	require.NoError(t, err)
	require.NotContains(t, string(data), "manager-addr")
}

type fileModeSockets struct {
	*loopSockets
	addresses []string
}

func (s *fileModeSockets) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	s.addresses = append(s.addresses, address)
	return s.loopSockets.Listen(ctx, network, address)
}

func TestFileModeOnlyOpensDNSListeners(t *testing.T) {
	network, sockets := newMemoryNetwork(), &loopSockets{}
	one := lifecycleEngine(t, network, sockets)
	requested := &fileModeSockets{loopSockets: sockets}
	one.sockets = requested
	_, done := runReady(t, one)
	// Reaching Ready establishes that every listener was requested. No legacy
	// HTML/config/reload listener may be started, including its former default.
	require.Equal(t, []string{one.dns.server.Addr}, requested.addresses)
	require.Len(t, sockets.tcp, 1)
	require.Len(t, sockets.udp, 1)
	require.NoError(t, one.Close())
	require.NoError(t, waitRun(t, done))
	assertReleased(t, network, sockets)
}

type countedCloseListener struct {
	net.Listener
	closes atomic.Int32
	err    error
}

func (l *countedCloseListener) Close() error { l.closes.Add(1); return l.err }

func TestDNSListenerRetainsSingleCloseAndError(t *testing.T) {
	for _, failure := range []error{nil, errors.New("DNS socket close failure")} {
		underlying := &countedCloseListener{err: failure}
		listener := &ownedListener{Listener: underlying}
		var workers sync.WaitGroup
		for range 8 {
			workers.Go(func() {
				err := listener.Close()
				if !errors.Is(err, failure) {
					t.Errorf("close error: got %v, want %v", err, failure)
				}
			})
		}
		workers.Wait()
		require.Equal(t, int32(1), underlying.closes.Load())
	}
}
