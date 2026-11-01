package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProxyFailureStagesUseProtocolEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusProxyAuthRequired) }))
	defer server.Close()
	p, err := FromUrl(server.URL)
	require.NoError(t, err)
	_, err = p.DialContext(context.Background(), "tcp", "example.com:443")
	require.Error(t, err)
	require.Equal(t, StageAuth, ErrorStage(err))
	require.Contains(t, err.Error(), "407")
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsServer.Close()
	p, err = FromUrl(tlsServer.URL)
	require.NoError(t, err)
	_, err = p.DialContext(context.Background(), "tcp", "example.com:443")
	require.Error(t, err)
	require.Equal(t, StageTLS, ErrorStage(err))
	var verification *tls.CertificateVerificationError
	require.ErrorAs(t, err, &verification, "certificate errors retain their original identity")
	want := errors.New("transport failure")
	p, err = FromUrl("http://127.0.0.1:8080")
	require.NoError(t, err)
	_, err = p.DialContextVia(context.Background(), "tcp", "example.com:443", func(context.Context, string, string) (net.Conn, error) { return nil, want })
	require.Equal(t, StageConnect, ErrorStage(err))
	require.Equal(t, want.Error(), err.Error())
	require.ErrorIs(t, err, want)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = p.DialContext(ctx, "tcp", "example.com:443")
	require.ErrorIs(t, err, context.Canceled)
}

type scriptedAuthConn struct {
	net.Conn
	response io.Reader
}

func (c scriptedAuthConn) Write(data []byte) (int, error) { return len(data), nil }
func (c scriptedAuthConn) Read(data []byte) (int, error)  { return c.response.Read(data[:1]) }

func TestSOCKSAuthenticationStageFromWireReplies(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply []byte
		stage string
	}{
		{"method-rejected", []byte{5, 255}, StageAuth},
		{"username-password-rejected", []byte{5, 2, 1, 1}, StageAuth},
		{"invalid-greeting-version", []byte{4, 0}, StageHandshake},
		{"target-connect-refused", []byte{5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0}, StageHandshake},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer right.Close()
			p, err := FromUrl("socks5://alice:private-password@127.0.0.1:8080")
			require.NoError(t, err)
			_, err = p.DialContextVia(context.Background(), "tcp", "example.com:443", func(context.Context, string, string) (net.Conn, error) {
				return scriptedAuthConn{Conn: left, response: strings.NewReader(string(tc.reply))}, nil
			})
			require.Error(t, err)
			require.Equal(t, tc.stage, ErrorStage(err))
			require.NotContains(t, err.Error(), "private-password")
			right.SetReadDeadline(time.Now().Add(time.Second))
			_, readErr := right.Read(make([]byte, 1))
			require.ErrorIs(t, readErr, io.EOF)
		})
	}
}

func TestStageErrorPreservesTimeoutAndShadowsocksEvidenceBoundary(t *testing.T) {
	want := &net.DNSError{Err: "timed out", IsTimeout: true, IsTemporary: true}
	err := atStage(StageConnect, want)
	require.True(t, err.(net.Error).Timeout())
	require.True(t, err.(*StageError).Temporary())
	require.Equal(t, want.Error(), err.Error())
	require.ErrorIs(t, err, want)
	require.Same(t, err, atStage(StageHandshake, err))
	require.Nil(t, atStage(StageConnect, nil))
	ss, err := FromUrl("ss://aes-128-gcm:secret@127.0.0.1:8388")
	require.NoError(t, err)
	require.False(t, ss.TargetAcknowledged())
	for _, url := range []string{"http://127.0.0.1:8080", "https://127.0.0.1:8080", "socks5://127.0.0.1:1080"} {
		p, err := FromUrl(url)
		require.NoError(t, err)
		require.True(t, p.TargetAcknowledged())
	}
}
