package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestShadowsocksURLValidationAndSupportedMethods(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, encoded := range []bool{false, true} {
			userinfo := url.UserPassword(method, "private:password").String()
			if encoded {
				userinfo = base64.RawURLEncoding.EncodeToString([]byte(method + ":private:password"))
			}
			p, err := FromUrl("ss://" + userinfo + "@127.0.0.1:8388/#profile")
			require.NoError(t, err)
			require.True(t, p.SupportsUDP())
			require.Equal(t, method, p.Url.User.Username())
			password, ok := p.Url.User.Password()
			require.True(t, ok)
			require.Equal(t, "private:password", password)
		}
	}
	for _, raw := range []string{
		"ss://127.0.0.1:8388", "ss://aes-128-gcm:@127.0.0.1:8388", "ss://rc4:private@127.0.0.1:8388",
		"ss://invalid@127.0.0.1:8388", "ss://bm8tY29sb24@127.0.0.1:8388",
		"ss://aes-128-gcm:private@127.0.0.1:8388/?plugin=external", "ss://aes-128-gcm:private@127.0.0.1:8388/path",
	} {
		_, err := FromUrl(raw)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "private")
	}
}

func TestShadowsocksHandshakeFailureClosesTransport(t *testing.T) {
	for _, stage := range []string{"set deadline", "write request", "clear deadline"} {
		t.Run(stage, func(t *testing.T) {
			transport, peer := net.Pipe()
			defer peer.Close()
			defer transport.Close()
			marker := errors.New("injected SS handshake failure")
			p, err := FromUrl("ss://aes-128-gcm:private@127.0.0.1:8388")
			require.NoError(t, err)
			_, err = p.DialContextVia(context.Background(), "tcp", "remote.invalid:443", func(context.Context, string, string) (net.Conn, error) {
				return handshakeFailureConn{Conn: transport, err: marker, stage: stage}, nil
			})
			require.ErrorIs(t, err, marker)
			peer.SetReadDeadline(time.Now().Add(time.Second))
			_, err = peer.Read(make([]byte, 1))
			require.ErrorIs(t, err, io.EOF)
		})
	}
}

func TestShadowsocksCancelsPendingHandshakeAndAssociation(t *testing.T) {
	p, err := FromUrl("ss://aes-128-gcm:private@127.0.0.1:8388")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	transport, peer := net.Pipe()
	defer peer.Close()
	defer transport.Close()
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := p.DialContextVia(ctx, "tcp", "remote.invalid:443", func(context.Context, string, string) (net.Conn, error) {
			close(entered)
			return transport, nil
		})
		done <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("SS handshake ignored cancellation")
	}
	_, err = p.DialUDPContext(ctx, "remote.invalid:443")
	require.ErrorIs(t, err, context.Canceled)
	ctx, cancel = context.WithCancel(context.Background())
	transport, peer = net.Pipe()
	defer peer.Close()
	conn, err := p.DialUDPContextVia(ctx, "remote.invalid:443", func(_ context.Context, network, address string) (net.Conn, error) {
		require.Equal(t, "udp", network)
		require.Equal(t, "127.0.0.1:8388", address)
		return transport, nil
	})
	require.NoError(t, err)
	require.Equal(t, "remote.invalid:443", conn.RemoteAddr().String())
	cancel()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	_, err = peer.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	require.NoError(t, conn.Close())
}
