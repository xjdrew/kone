package kone

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type failedDNSTCPSockets struct{ *loopSockets }

func (s failedDNSTCPSockets) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	_, port, _ := net.SplitHostPort(address)
	if port == "53" {
		return nil, errors.New("injected DNS TCP port occupied")
	}
	return s.loopSockets.Listen(ctx, network, address)
}

func TestDNSTCPStartupFailureRollsBackUDPAndDevice(t *testing.T) {
	network, sockets := newMemoryNetwork(), &loopSockets{}
	one := lifecycleEngine(t, network, sockets)
	one.sockets = failedDNSTCPSockets{sockets}
	require.ErrorContains(t, one.Run(context.Background()), "DNS TCP port occupied")
	require.NoError(t, one.Close())
	assertReleased(t, network, sockets)
}

func TestDNSOwnedTCPListenerServesAndCloses(t *testing.T) {
	network, sockets := newMemoryNetwork(), &loopSockets{}
	one := lifecycleEngine(t, network, sockets)
	_, done := runReady(t, one)
	require.True(t, one.DNSStatus().TCP)
	request := new(dns.Msg)
	request.SetQuestion("blocked.example.", dns.TypeA)
	// This suffix rule is rejected without contacting any external resolver.
	cfg := one.Snapshot().Config
	cfg.Rule = append(cfg.Rule, RuleConfig{Schema: "FINAL", Outbound: BuiltinReject})
	require.NoError(t, one.Reload(cfg))
	address := one.dns.tcpServer.Listener.Addr().String()
	answer, _, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(request, address)
	require.NoError(t, err)
	require.Equal(t, dns.RcodeRefused, answer.Rcode)
	require.Equal(t, "tcp", one.DNSQueries()[0].Transport)
	require.NoError(t, one.Close())
	require.NoError(t, waitRun(t, done))
	assertReleased(t, network, sockets)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if conn != nil {
		conn.Close()
	}
	require.Error(t, err, "owned DNS TCP listener must close on shutdown")
}
