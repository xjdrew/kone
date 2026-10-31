package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

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
