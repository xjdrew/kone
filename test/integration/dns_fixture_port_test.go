package integration

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

var windowsDNSFixtureSequence atomic.Uint32

func nextWindowsDNSFixturePort() int {
	// Keep DNS listeners away from Windows' dynamic TCP range. A UDP port-zero
	// allocation says nothing about TCP exclusions or the stack's TCP forwarder.
	return 20000 + int((windowsDNSFixtureSequence.Add(1)-1)%10000)
}

func availableWindowsDNSFixturePort(t *testing.T, ipv6 bool) int {
	t.Helper()
	port, err := selectDNSFixturePort(ipv6, nextWindowsDNSFixturePort)
	require.NoError(t, err)
	return port
}

func selectDNSFixturePort(ipv6 bool, next func() int) (int, error) {
	var last error
	for range 128 {
		port := next()
		if err := probeDNSFixturePort(port, ipv6); err == nil {
			return port, nil
		} else {
			last = err
		}
	}
	return 0, fmt.Errorf("no common DNS fixture port available after 128 candidates: %w", last)
}

func probeDNSFixturePort(port int, ipv6 bool) error {
	var sockets []io.Closer
	defer func() {
		for _, socket := range sockets {
			socket.Close()
		}
	}()
	for _, family := range []string{"4", "6"} {
		if family == "6" && !ipv6 {
			break
		}
		host := "0.0.0.0"
		if family == "6" {
			host = "::"
		}
		address := net.JoinHostPort(host, strconv.Itoa(port))
		listener, err := net.Listen("tcp"+family, address)
		if err != nil {
			return err
		}
		sockets = append(sockets, listener)
		packet, err := net.ListenPacket("udp"+family, address)
		if err != nil {
			return err
		}
		sockets = append(sockets, packet)
	}
	return nil
}

func TestDNSFixturePortRejectsAnyListenerCollisionAndReleasesPartialProbes(t *testing.T) {
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			ipv6 := network[len(network)-1] == '6'
			if ipv6 {
				probe, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Skip("IPv6 loopback is unavailable")
				}
				probe.Close()
			}
			port := availableWindowsDNSFixturePort(t, ipv6)
			host := "0.0.0.0"
			if ipv6 {
				host = "::"
			}
			address := net.JoinHostPort(host, strconv.Itoa(port))
			var occupied io.Closer
			var err error
			if network[:3] == "tcp" {
				occupied, err = net.Listen(network, address)
			} else {
				occupied, err = net.ListenPacket(network, address)
			}
			require.NoError(t, err)
			defer occupied.Close()
			require.Error(t, probeDNSFixturePort(port, ipv6), "a UDP-free port must still reject a TCP collision, and vice versa")
			safe := availableWindowsDNSFixturePort(t, ipv6)
			calls := 0
			selected, err := selectDNSFixturePort(ipv6, func() int {
				calls++
				if calls == 1 {
					return port
				}
				return safe
			})
			require.NoError(t, err)
			require.Equal(t, safe, selected)
			require.Equal(t, 2, calls)
			require.GreaterOrEqual(t, selected, 20000)
			require.Less(t, selected, 30000)
			require.NoError(t, probeDNSFixturePort(selected, ipv6), "a successful selection releases every temporary probe")
			require.NoError(t, occupied.Close())
			require.NoError(t, probeDNSFixturePort(port, ipv6), "a failed final-family probe must also release the earlier sockets")
		})
	}
}

func TestDNSFixturePortExhaustionIsBounded(t *testing.T) {
	port := availableWindowsDNSFixturePort(t, false)
	occupied, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	require.NoError(t, err)
	defer occupied.Close()
	calls := 0
	selected, err := selectDNSFixturePort(false, func() int { calls++; return port })
	require.Zero(t, selected)
	require.ErrorContains(t, err, "128 candidates")
	require.True(t, errors.As(err, new(*net.OpError)), "retain the binding failure for actionable fixture diagnostics")
	require.Equal(t, 128, calls)
}
