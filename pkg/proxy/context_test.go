package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type deadlineFailureConn struct {
	net.Conn
	err error
}

func (c deadlineFailureConn) SetDeadline(time.Time) error { return c.err }

func TestHTTPHandshakeDeadlineFailureClosesTransport(t *testing.T) {
	// Cancellation could previously hit this path only if it won the race
	// between the transport dial and handshake deadline setup. Inject the
	// deadline failure directly, and verify the transport cannot leak.
	transport, peer := net.Pipe()
	defer transport.Close()
	defer peer.Close()
	want := errors.New("injected handshake deadline failure")
	p, err := FromUrl("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := p.DialContextVia(context.Background(), "tcp", "example.com:443", func(context.Context, string, string) (net.Conn, error) {
		return deadlineFailureConn{Conn: transport, err: want}, nil
	})
	if conn != nil || !errors.Is(err, want) {
		t.Fatalf("conn=%v error=%v; want deadline failure", conn, err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("transport not closed after failed deadline setup: %v", err)
	}
}

func TestCancelPendingProxyHandshake(t *testing.T) {
	for _, scheme := range []string{"http", "https", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, err := ln.Accept()
				if err == nil {
					accepted <- conn
				}
			}()
			p, err := FromUrl(scheme + "://" + ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := p.DialContext(ctx, "tcp", "example.com:443")
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			select {
			case conn := <-accepted:
				defer conn.Close()
			case <-time.After(time.Second):
				t.Fatal("proxy not connected")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("handshake ignored cancellation")
			}
		})
	}
}

func TestPreCanceledDirectDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := Direct.DialContext(ctx, "tcp", "127.0.0.1:1")
	if conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("conn=%v error=%v", conn, err)
	}
}
