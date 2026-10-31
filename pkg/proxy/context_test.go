package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type handshakeFailureConn struct {
	net.Conn
	err      error
	stage    string
	response *strings.Reader
}

func (c handshakeFailureConn) SetDeadline(deadline time.Time) error {
	if c.stage == "set deadline" || c.stage == "clear deadline" && deadline.IsZero() {
		return c.err
	}
	return c.Conn.SetDeadline(deadline)
}

func (c handshakeFailureConn) Write(p []byte) (int, error) {
	if c.stage == "write request" {
		return 0, c.err
	}
	return len(p), nil
}

func (c handshakeFailureConn) Read(p []byte) (int, error) {
	if c.stage == "read response" {
		return 0, c.err
	}
	return c.response.Read(p)
}

func TestHTTPHandshakeFailuresCloseTransport(t *testing.T) {
	// Cancellation can interrupt any handshake stage. Inject each failure
	// directly so cleanup assertions and coverage never depend on scheduling.
	for _, stage := range []string{"set deadline", "write request", "read response", "proxy rejection", "clear deadline"} {
		t.Run(stage, func(t *testing.T) {
			transport, peer := net.Pipe()
			defer transport.Close()
			defer peer.Close()
			want := errors.New("injected handshake failure")
			response := "HTTP/1.1 200 Connection established\r\n\r\n"
			if stage == "proxy rejection" {
				response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
			}
			p, err := FromUrl("http://127.0.0.1:8080")
			if err != nil {
				t.Fatal(err)
			}
			conn, err := p.DialContextVia(context.Background(), "tcp", "example.com:443", func(context.Context, string, string) (net.Conn, error) {
				return handshakeFailureConn{Conn: transport, err: want, stage: stage, response: strings.NewReader(response)}, nil
			})
			if conn != nil || err == nil {
				t.Fatalf("conn=%v error=%v; want handshake failure", conn, err)
			}
			if stage == "proxy rejection" {
				if !strings.Contains(err.Error(), "403 Forbidden") {
					t.Fatalf("lost proxy rejection: %v", err)
				}
			} else if !errors.Is(err, want) {
				t.Fatalf("lost handshake failure: %v", err)
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("transport not closed after failed handshake: %v", err)
			}
		})
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
