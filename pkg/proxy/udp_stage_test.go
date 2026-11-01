package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUDPProxyAuthenticationAndAssociationStagesFromWireEvidence(t *testing.T) {
	for _, tc := range []struct {
		reply []byte
		stage string
	}{{[]byte{5, 255}, StageAuth}, {[]byte{5, 2, 1, 1}, StageAuth}, {[]byte{4, 0}, StageHandshake}, {[]byte{5, 0, 5, 5, 0, 1}, "proxy_association"}} {
		t.Run(tc.stage, func(t *testing.T) {
			left, right := net.Pipe()
			defer right.Close()
			p, err := FromUrl("socks5://alice:private-password@127.0.0.1:1")
			require.NoError(t, err)
			_, err = p.DialUDPContextVia(t.Context(), "example.com:53", func(context.Context, string, string) (net.Conn, error) {
				return scriptedAuthConn{Conn: left, response: strings.NewReader(string(tc.reply))}, nil
			})
			require.Error(t, err)
			require.Equal(t, tc.stage, ErrorStage(err))
			require.NotContains(t, err.Error(), "private-password")
			right.SetReadDeadline(time.Now().Add(time.Second))
			_, err = right.Read(make([]byte, 1))
			require.ErrorIs(t, err, io.EOF)
		})
	}
	for _, raw := range []string{"socks5://127.0.0.1:1", "ss://aes-128-gcm:private-password@127.0.0.1:1"} {
		p, err := FromUrl(raw)
		require.NoError(t, err)
		want := &net.DNSError{Err: "resolver failed"}
		_, err = p.DialUDPContextVia(t.Context(), "remote.invalid:53", func(context.Context, string, string) (net.Conn, error) { return nil, want })
		require.ErrorIs(t, err, want)
		require.Equal(t, StageDNS, ErrorStage(err))
		failure := errors.New("socket failed")
		_, err = p.DialUDPContextVia(t.Context(), "remote.invalid:53", func(context.Context, string, string) (net.Conn, error) { return nil, failure })
		require.ErrorIs(t, err, failure)
	}
}
