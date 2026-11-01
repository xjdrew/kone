package kone

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/logstore"
)

type flowLogTransport struct {
	diagnosticTransport
	reader *strings.Reader
	fail   error
}

type udpWriteFailureThenEOF struct {
	diagnosticTransport
	written chan struct{}
	failure error
	closed  sync.Once
}

func (c *udpWriteFailureThenEOF) Read([]byte) (int, error) {
	<-c.written
	return 0, io.EOF
}
func (c *udpWriteFailureThenEOF) Write([]byte) (int, error) {
	c.closed.Do(func() { close(c.written) })
	return 0, c.failure
}
func (c *udpWriteFailureThenEOF) Close() error {
	c.closed.Do(func() { close(c.written) })
	return nil
}

func TestUDPWriteFailureIsNotReplacedByAReadSideEOF(t *testing.T) {
	cleanProxyEnv(t)
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	store := logstore.New()
	next, err := NewLoggingHandler(io.Discard, cfg.General, false)
	require.NoError(t, err)
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(store.Handler(next, "helper")))
	failure := errors.New("real UDP write failure")
	one.policy.Load().outbounds.dial = func(context.Context, string, string) (net.Conn, error) {
		return &udpWriteFailureThenEOF{written: make(chan struct{}), failure: failure}, nil
	}
	incoming, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer incoming.Close()
	client, err := net.DialUDP("udp4", nil, incoming.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer client.Close()
	_, err = client.Write([]byte("one datagram"))
	require.NoError(t, err)
	var closedWith error
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	one.flows.NewPacketConnectionEx(ctx, bufio.NewPacketConn(incoming), M.SocksaddrFromNet(client.LocalAddr()), M.ParseSocksaddr("192.0.2.9:443"), func(err error) { closedWith = err })
	require.ErrorIs(t, closedWith, failure)
	logs, err := store.Query(logstore.Query{MinLevel: "error"})
	require.NoError(t, err)
	require.Len(t, logs.Records, 1)
	require.Equal(t, "real UDP write failure", logs.Records[0].Attrs["error"])
}

func (c *flowLogTransport) Read(data []byte) (int, error) {
	if c.reader.Len() > 0 {
		return c.reader.Read(data)
	}
	if c.fail != nil {
		return 0, c.fail
	}
	return 0, io.EOF
}

func TestActualTCPFlowFailuresAreVisibleAtInfoAndNeverExposeCredentials(t *testing.T) {
	cleanProxyEnv(t)
	previous := slog.Default()
	defer slog.SetDefault(previous)
	for _, scenario := range []struct {
		name, stage, response string
		dialError             error
		transferError         error
	}{
		{"connect", "proxy_connect", "", errors.New("refused log-user log-password"), nil},
		{"authentication", "proxy_auth", "HTTP/1.1 407 log-user log-password\r\nContent-Length: 0\r\n\r\n", nil, nil},
		{"handshake EOF", "proxy_handshake", "", nil, nil},
		{"transfer", "transfer", "HTTP/1.1 200 OK\r\n\r\n", nil, errors.New("remote read failed log-user log-password")},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DNS.Servers = []string{"127.0.0.1:9"}
			cfg.Outbounds = []OutboundConfig{{Name: "mono", URL: "http://log-user:log-password@127.0.0.1:8080"}}
			cfg.Rule = []RuleConfig{{Schema: "FINAL", Outbound: "mono"}}
			one, err := FromConfig(cfg)
			require.NoError(t, err)
			defer one.Close()
			require.NoError(t, one.SetConfigVersion(73))
			store := logstore.New()
			next, err := NewLoggingHandler(io.Discard, cfg.General, false)
			require.NoError(t, err)
			slog.SetDefault(slog.New(store.Handler(next, "helper")))
			one.policy.Load().outbounds.dial = func(context.Context, string, string) (net.Conn, error) {
				if scenario.dialError != nil {
					return nil, scenario.dialError
				}
				return &flowLogTransport{reader: strings.NewReader(scenario.response), fail: scenario.transferError}, nil
			}
			record := one.dnsTable.Set("example.com", "mono")
			client, accepted := net.Pipe()
			defer client.Close()
			one.flows.NewConnectionEx(t.Context(), accepted, M.ParseSocksaddr("192.0.2.2:40000"), M.SocksaddrFromNet(&net.TCPAddr{IP: record.IP, Port: 443}), nil)
			logs, err := store.Query(logstore.Query{MinLevel: "error"})
			require.NoError(t, err)
			require.Len(t, logs.Records, 1)
			failure := logs.Records[0]
			require.Equal(t, "Outbound flow failed", failure.Message)
			require.Equal(t, "ERROR", failure.Level)
			require.Equal(t, "mono", failure.Attrs["outbound"])
			require.Equal(t, "tcp", failure.Attrs["protocol"])
			require.Equal(t, "example.com:443", failure.Attrs["target"])
			require.Equal(t, scenario.stage, failure.Attrs["stage"])
			require.Equal(t, float64(73), failure.Attrs["config_version"])
			data, err := json.Marshal(logs)
			require.NoError(t, err)
			require.NotContains(t, string(data), "log-password")
			require.NotContains(t, string(data), "log-user")
		})
	}
}

func TestActualUDPAssociationAndTransferFailuresAreVisibleAtInfo(t *testing.T) {
	cleanProxyEnv(t)
	previous := slog.Default()
	defer slog.SetDefault(previous)
	for _, transfer := range []bool{false, true} {
		cfg := DefaultConfig()
		cfg.DNS.Servers = []string{"127.0.0.1:9"}
		outbound := "mono"
		cfg.Outbounds = []OutboundConfig{{Name: "mono", URL: "socks5://udp-user:udp-password@127.0.0.1:1080"}}
		if transfer {
			outbound = BuiltinDirect
		}
		cfg.Rule = []RuleConfig{{Schema: "FINAL", Outbound: outbound}}
		one, err := FromConfig(cfg)
		require.NoError(t, err)
		store := logstore.New()
		next, err := NewLoggingHandler(io.Discard, cfg.General, false)
		require.NoError(t, err)
		slog.SetDefault(slog.New(store.Handler(next, "helper")))
		one.policy.Load().outbounds.dial = func(context.Context, string, string) (net.Conn, error) {
			failure := errors.New("UDP failed udp-user udp-password")
			if transfer {
				return &flowLogTransport{reader: strings.NewReader(""), fail: failure}, nil
			}
			return nil, failure
		}
		incoming, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		one.flows.NewPacketConnectionEx(t.Context(), bufio.NewPacketConn(incoming), M.ParseSocksaddr("192.0.2.2:40000"), M.ParseSocksaddr("192.0.2.9:443"), nil)
		logs, err := store.Query(logstore.Query{MinLevel: "error"})
		require.NoError(t, err)
		require.Len(t, logs.Records, 1)
		require.Equal(t, "udp", logs.Records[0].Attrs["protocol"])
		require.Equal(t, outbound, logs.Records[0].Attrs["outbound"])
		if transfer {
			require.Equal(t, "transfer", logs.Records[0].Attrs["stage"])
		}
		data, err := json.Marshal(logs)
		require.NoError(t, err)
		require.NotContains(t, string(data), "udp-password")
		require.NotContains(t, string(data), "udp-user")
		require.NoError(t, one.Close())
	}
}

func TestIntentionalFlowTerminationNeverProducesAnErrorLog(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	defer one.Close()
	store := logstore.New()
	next, err := NewLoggingHandler(io.Discard, DefaultConfig().General, false)
	require.NoError(t, err)
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(store.Handler(next, "helper")))
	for _, result := range []error{nil, ErrRejected, ErrOutboundDisabled, ErrUDPUnsupported, net.ErrClosed, io.EOF, context.Canceled} {
		one.flows.logFlowFailure(t.Context(), one.policy.Load(), "udp", "A", "example.com:443", "transfer", result)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	one.flows.logFlowFailure(ctx, one.policy.Load(), "tcp", "A", "example.com:443", "dial", errors.New("stopping"))
	one.flows.close()
	one.flows.logFlowFailure(t.Context(), one.policy.Load(), "tcp", "A", "example.com:443", "transfer", errors.New("cleanup"))
	logs, err := store.Query(logstore.Query{MinLevel: "error"})
	require.NoError(t, err)
	require.Empty(t, logs.Records)
}
