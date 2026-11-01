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
	var allocations []net.PacketConn
	t.Cleanup(func() {
		for _, conn := range allocations {
			conn.Close()
		}
	})
	var occupied net.Listener
	udp, tcp, err := bindDNSFixturePair(func(network, address string) (net.PacketConn, error) {
		conn, err := net.ListenPacket(network, address)
		if err == nil {
			allocations = append(allocations, conn)
		}
		return conn, err
	}, func(network, address string) (net.Listener, error) {
		// The UDP port must remain reserved throughout the matching TCP bind.
		otherUDP, bindErr := net.ListenPacket("udp4", address)
		if otherUDP != nil {
			otherUDP.Close()
		}
		require.True(t, dnsFixtureAddressInUse(bindErr), "held UDP reservation must reject a second UDP bind: %v", bindErr)
		if occupied == nil {
			var err error
			occupied, err = net.Listen(network, address)
			if err != nil {
				return nil, err
			}
			t.Cleanup(func() { occupied.Close() })
		}
		return net.Listen(network, address)
	})
	require.NoError(t, err)
	defer udp.Close()
	defer tcp.Close()
	require.GreaterOrEqual(t, len(allocations), 2)
	require.Equal(t, udp.LocalAddr().String(), tcp.Addr().String())
	for _, previous := range allocations[:len(allocations)-1] {
		previous.SetReadDeadline(time.Now().Add(time.Second))
		_, _, err := previous.ReadFrom(make([]byte, 1))
		require.ErrorIs(t, err, net.ErrClosed, "an abandoned candidate must not leak a UDP reservation")
	}
}

func TestDNSFixtureDoesNotRetryOtherErrorsAndBoundsPersistentCollisions(t *testing.T) {
	for _, collision := range []bool{false, true} {
		t.Run(map[bool]string{false: "other_error", true: "persistent_collision"}[collision], func(t *testing.T) {
			var allocations []net.PacketConn
			var want error = errors.New("injected listener failure")
			if collision {
				want = syscall.EADDRINUSE
			}
			_, _, err := bindDNSFixturePair(func(network, address string) (net.PacketConn, error) {
				conn, err := net.ListenPacket(network, address)
				if err == nil {
					allocations = append(allocations, conn)
				}
				return conn, err
			}, func(string, string) (net.Listener, error) { return nil, want })
			require.ErrorIs(t, err, want)
			if collision {
				require.Len(t, allocations, 32)
			} else {
				require.Len(t, allocations, 1)
			}
			for _, conn := range allocations {
				conn.SetReadDeadline(time.Now().Add(time.Second))
				_, _, err := conn.ReadFrom(make([]byte, 1))
				require.ErrorIs(t, err, net.ErrClosed)
			}
		})
	}
}
