package kone

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type ipv6TestSockets struct {
	config net.ListenConfig
	fail   string
}

func (s *ipv6TestSockets) Listen(ctx context.Context, network, _ string) (net.Listener, error) {
	if s.fail == "tcp" {
		return nil, errors.New("IPv6 TCP occupied")
	}
	return s.config.Listen(ctx, network, "[::1]:0")
}
func (s *ipv6TestSockets) ListenPacket(ctx context.Context, network, _ string) (net.PacketConn, error) {
	if s.fail == "udp" {
		return nil, errors.New("IPv6 UDP occupied")
	}
	return s.config.ListenPacket(ctx, network, "[::1]:0")
}

func TestDNSIPv6ListenersServeAAAAAndStop(t *testing.T) {
	one := syntheticIPv6Engine(t)
	sockets := &ipv6TestSockets{}
	require.NoError(t, one.dns.openIPv6Listeners(context.Background(), sockets))
	ctx, cancel := context.WithCancel(context.Background())
	one.dns.ctx = ctx
	var workers sync.WaitGroup
	failures := make(chan error, 4)
	start := func(_ string, serve func() error) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := serve(); err != nil && ctx.Err() == nil {
				failures <- err
			}
		}()
	}
	t.Cleanup(func() { cancel(); one.dns.stopIPv6DNS(context.Background()); workers.Wait() })
	require.NoError(t, one.dns.startIPv6DNS(ctx, start, failures))
	for _, transport := range []string{"udp6", "tcp6"} {
		address := one.dns.ipv6.packet.LocalAddr().String()
		if transport == "tcp6" {
			address = one.dns.ipv6.listener.Addr().String()
		}
		request := new(dns.Msg)
		request.SetQuestion("dual.example.", dns.TypeAAAA)
		response, _, err := (&dns.Client{Net: transport, Timeout: time.Second}).Exchange(request, address)
		require.NoError(t, err)
		require.Len(t, response.Answer, 1)
		require.IsType(t, &dns.AAAA{}, response.Answer[0])
	}
	require.Len(t, one.DNSQueries(), 2)
}

func TestDNSIPv6PartialListenerFailureClosesCreatedSockets(t *testing.T) {
	for _, failure := range []string{"udp", "tcp"} {
		t.Run(failure, func(t *testing.T) {
			one := syntheticIPv6Engine(t)
			require.ErrorContains(t, one.dns.openIPv6Listeners(context.Background(), &ipv6TestSockets{fail: failure}), "occupied")
			require.NoError(t, one.dns.stopIPv6DNS(context.Background()))
			if packet := one.dns.ipv6.packet; packet != nil {
				require.Error(t, packet.SetDeadline(time.Now()))
			}
		})
	}
	one := testEngine(t)
	require.NoError(t, one.dns.openIPv6Listeners(context.Background(), &ipv6TestSockets{fail: "udp"}))
	require.NoError(t, one.dns.startIPv6DNS(context.Background(), nil, nil))
	require.NoError(t, one.dns.stopIPv6DNS(context.Background()))
}
