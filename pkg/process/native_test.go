package process

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNativeAttributionOfOwnLocalTCPConnection(t *testing.T) {
	if !Supported() {
		t.Skip("native process attribution is not available")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	defer conn.Close()
	peer := <-accepted
	defer peer.Close()
	source, err := netip.ParseAddrPort(conn.LocalAddr().String())
	require.NoError(t, err)
	destination, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	require.NoError(t, err)
	var result Result
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		result, err = lookupNative(ctx, Query{Protocol: "tcp", Source: source, Destination: destination, ObservedAt: time.Now()})
		return err == nil
	}, 5*time.Second, 100*time.Millisecond, "native socket/PID attribution must work for this process: %v", err)
	require.Equal(t, uint32(os.Getpid()), result.PID)
	require.Equal(t, "matched", result.Status)
	require.NotEmpty(t, result.Name)
	require.NotEmpty(t, result.Path)
	require.False(t, result.StartedAt.IsZero())
}
