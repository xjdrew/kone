package kone

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer ln.Close()
	client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	server, err := ln.AcceptTCP()
	require.NoError(t, err)
	client.SetDeadline(time.Now().Add(3 * time.Second))
	server.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func TestRelayPreservesTCPHalfClose(t *testing.T) {
	left, a := tcpPair(t)
	right, b := tcpPair(t)
	done := make(chan [2]int64, 1)
	go func() { up, down := relayConnections(a, b); done <- [2]int64{up, down} }()
	_, err := left.Write([]byte("ping"))
	require.NoError(t, err)
	require.NoError(t, left.CloseWrite())
	request, err := io.ReadAll(right)
	require.NoError(t, err)
	require.Equal(t, "ping", string(request))
	_, err = right.Write([]byte("pong"))
	require.NoError(t, err)
	require.NoError(t, right.CloseWrite())
	response, err := io.ReadAll(left)
	require.NoError(t, err)
	require.Equal(t, "pong", string(response))
	select {
	case count := <-done:
		require.Equal(t, [2]int64{4, 4}, count)
	case <-time.After(time.Second):
		t.Fatal("copy workers leaked")
	}
}
