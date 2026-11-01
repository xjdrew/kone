package kone

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDNSFixtureRetriesCrossProtocolCollisionWithoutReleasingReservation(t *testing.T) {
	var allocations []net.Listener
	t.Cleanup(func() {
		for _, conn := range allocations {
			conn.Close()
		}
	})
	var occupied net.PacketConn
	udp, tcp, err := bindDNSFixturePair(func(network, address string) (net.PacketConn, error) {
		// The TCP port must remain reserved throughout the matching UDP bind.
		otherTCP, bindErr := net.Listen("tcp4", address)
		if otherTCP != nil {
			otherTCP.Close()
		}
		require.True(t, dnsFixtureAddressInUse(bindErr), "held TCP reservation must reject a second TCP bind: %v", bindErr)
		if occupied == nil {
			var err error
			occupied, err = net.ListenPacket(network, address)
			if err != nil {
				return nil, err
			}
			t.Cleanup(func() { occupied.Close() })
		}
		return net.ListenPacket(network, address)
	}, func(network, address string) (net.Listener, error) {
		require.Equal(t, "127.0.0.1:0", address, "TCP must choose the shared port")
		conn, err := net.Listen(network, address)
		if err == nil {
			allocations = append(allocations, conn)
		}
		return conn, err
	})
	require.NoError(t, err)
	defer udp.Close()
	defer tcp.Close()
	require.GreaterOrEqual(t, len(allocations), 2)
	require.Equal(t, udp.LocalAddr().String(), tcp.Addr().String())
	for _, previous := range allocations[:len(allocations)-1] {
		previous.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
		_, err := previous.Accept()
		require.ErrorIs(t, err, net.ErrClosed, "an abandoned candidate must not leak a TCP reservation")
	}
}

func TestDNSFixtureDoesNotRetryOtherErrorsAndBoundsPersistentCollisions(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		attempts int
	}{
		{name: "other_error", err: errors.New("injected listener failure"), attempts: 1},
		{name: "permission_denied", err: syscall.EACCES, attempts: 1},
		{name: "windows_permission_denied", err: syscall.Errno(10013), attempts: 1},
		{name: "persistent_collision", err: syscall.EADDRINUSE, attempts: 32},
	} {
		t.Run(test.name, func(t *testing.T) {
			var allocations []net.Listener
			_, _, err := bindDNSFixturePair(func(string, string) (net.PacketConn, error) { return nil, test.err }, func(network, address string) (net.Listener, error) {
				conn, err := net.Listen(network, address)
				if err == nil {
					allocations = append(allocations, conn)
				}
				return conn, err
			})
			require.ErrorIs(t, err, test.err)
			require.Len(t, allocations, test.attempts)
			for _, conn := range allocations {
				conn.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
				_, err := conn.Accept()
				require.ErrorIs(t, err, net.ErrClosed)
			}
		})
	}
}
