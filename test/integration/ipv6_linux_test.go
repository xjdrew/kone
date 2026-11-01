package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func ipv6SystemConfig(t *testing.T) *kone.KoneConfig {
	t.Helper()
	cfg := systemConfig(t)
	cfg.Core.IPv6Network = "fd7a:203::1/120"
	cfg.Core.OutboundInterface = "lo"
	return cfg
}

func fakeAAAA(t *testing.T, cfg *kone.KoneConfig, name, transport string) string {
	t.Helper()
	question := new(dns.Msg)
	question.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	address := fmt.Sprintf("[fd7a:203::1]:%d", cfg.DNS.ListenPort)
	response, _, err := (&dns.Client{Net: transport, Timeout: 2 * time.Second}).Exchange(question, address)
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, response.Rcode)
	require.Len(t, response.Answer, 1)
	return response.Answer[0].(*dns.AAAA).AAAA.String()
}

func TestSystemIPv6FakeAAAAProxyTCPAndUDP(t *testing.T) {
	cfg := ipv6SystemConfig(t)
	tcpServer, tcpReceived := ssInteropPeer(t, "aes-128-gcm", "tcp", false)
	udpServer, udpReceived := ssInteropPeer(t, "aes-128-gcm", "udp", false)
	cfg.Outbounds = []kone.OutboundConfig{{Name: "tcp", URL: "ss://aes-128-gcm:interop-password@" + tcpServer}, {Name: "udp", URL: "ss://aes-128-gcm:interop-password@" + udpServer}}
	cfg.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: "virtual6.example", Protocol: "tcp", Outbound: "tcp"}, {Schema: "DOMAIN", Pattern: "virtual6.example", Protocol: "udp", Outbound: "udp"}, {Schema: "FINAL", Outbound: kone.BuiltinDirect}}
	one, stop, done := systemStart(t, cfg)
	fake := fakeAAAA(t, cfg, "virtual6.example", "udp6")
	require.Equal(t, fake, fakeAAAA(t, cfg, "virtual6.example", "tcp6"))
	for _, network := range []string{"tcp6", "udp6"} {
		connection, err := net.DialTimeout(network, net.JoinHostPort(fake, "443"), 2*time.Second)
		require.NoError(t, err)
		connection.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = connection.Write([]byte("IPv6 payload"))
		require.NoError(t, err)
		response := make([]byte, len("IPv6 payload"))
		_, err = io.ReadFull(connection, response)
		connection.Close()
		require.NoError(t, err)
		require.Equal(t, "IPv6 payload", string(response))
	}
	for _, received := range []<-chan []byte{tcpReceived, udpReceived} {
		select {
		case payload := <-received:
			require.Contains(t, string(payload), "virtual6.example")
		case <-time.After(time.Second):
			t.Fatal("proxy did not receive original domain through captured IPv6 flow")
		}
	}
	require.True(t, one.DNSStatus().IPv6)
	stop()
	require.NoError(t, systemWait(t, done))
	noSystemInterface(t, cfg)
}

func TestSystemIPv6FakeAAAADirectUsesRealAAAAAndUDP6(t *testing.T) {
	cfg := ipv6SystemConfig(t)
	listener, err := net.Listen("tcp6", "[::1]:0")
	require.NoError(t, err)
	defer listener.Close()
	packet, err := net.ListenPacket("udp6", listener.Addr().String())
	require.NoError(t, err)
	defer packet.Close()
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(3 * time.Second))
		buffer := make([]byte, 64)
		n, err := connection.Read(buffer)
		if err == nil {
			connection.Write(buffer[:n])
		}
	}()
	go func() {
		defer workers.Done()
		buffer := make([]byte, 64)
		n, source, err := packet.ReadFrom(buffer)
		if err == nil {
			packet.WriteTo(buffer[:n], source)
		}
	}()
	t.Cleanup(func() { listener.Close(); packet.Close(); workers.Wait() })
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	ready := make(chan struct{})
	resolver := &dns.Server{PacketConn: upstream, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.IPv6loopback}}
		w.WriteMsg(response)
	}), NotifyStartedFunc: func() { close(ready) }}
	workers.Add(1)
	go func() { defer workers.Done(); resolver.ActivateAndServe() }()
	t.Cleanup(func() { resolver.Shutdown(); upstream.Close() })
	<-ready
	cfg.DNS.Servers = []string{upstream.LocalAddr().String()}
	cfg.Outbounds = []kone.OutboundConfig{{Name: "staging", URL: "http://127.0.0.1:1"}}
	cfg.Rule = []kone.RuleConfig{{Schema: "FINAL", Outbound: "staging"}}
	one, stop, done := systemStart(t, cfg)
	fake := fakeAAAA(t, cfg, "direct6.example", "udp6")
	cfg.Rule[0].Outbound = kone.BuiltinDirect
	require.NoError(t, one.Reload(cfg))
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	for _, network := range []string{"tcp6", "udp6"} {
		connection, err := net.DialTimeout(network, net.JoinHostPort(fake, port), 2*time.Second)
		require.NoError(t, err)
		connection.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = connection.Write([]byte("direct IPv6"))
		require.NoError(t, err)
		response := make([]byte, len("direct IPv6"))
		_, err = io.ReadFull(connection, response)
		connection.Close()
		require.NoError(t, err)
		require.Equal(t, "direct IPv6", string(response))
	}
	_, records := one.DNSSnapshot()
	found := false
	for _, record := range records {
		if record.Hostname == "direct6.example" && record.IP.To4() == nil {
			require.Equal(t, "::1", record.RealIP.String())
			found = true
		}
	}
	require.True(t, found)
	stop()
	require.NoError(t, systemWait(t, done))
	noSystemInterface(t, cfg)
}

func TestSystemIPv6ListenerAndRouteFailureRestore(t *testing.T) {
	for _, network := range []string{"tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			cfg := ipv6SystemConfig(t)
			var occupied io.Closer
			var address net.Addr
			if network == "tcp6" {
				listener, err := net.Listen(network, "[::]:0")
				require.NoError(t, err)
				occupied, address = listener, listener.Addr()
			} else {
				packet, err := net.ListenPacket(network, "[::]:0")
				require.NoError(t, err)
				occupied, address = packet, packet.LocalAddr()
			}
			defer occupied.Close()
			_, port, _ := net.SplitHostPort(address.String())
			var selected int
			fmt.Sscan(port, &selected)
			cfg.DNS.ListenPort = uint16(selected)
			one, err := kone.FromConfig(cfg)
			require.NoError(t, err)
			require.Error(t, one.Run(context.Background()))
			require.NoError(t, one.Close())
			noSystemInterface(t, cfg)
		})
	}
	cfg := ipv6SystemConfig(t)
	systemCommand(t, "-6", "route", "add", "2001:db8:bad::/64", "dev", "lo")
	defer systemCommand(t, "-6", "route", "del", "2001:db8:bad::/64", "dev", "lo")
	cfg.Rule = []kone.RuleConfig{{Schema: "IP-CIDR6", Pattern: "2001:db8:aaa::/64", Outbound: kone.BuiltinReject}, {Schema: "IP-CIDR6", Pattern: "2001:db8:bad::/64", Outbound: kone.BuiltinReject}}
	one, err := kone.FromConfig(cfg)
	require.NoError(t, err)
	require.ErrorContains(t, one.Run(context.Background()), "IPv6 route")
	require.NoError(t, one.Close())
	noSystemInterface(t, cfg)
	require.Empty(t, systemCommand(t, "-6", "route", "show", "2001:db8:aaa::/64"))
	require.Contains(t, systemCommand(t, "-6", "route", "show", "2001:db8:bad::/64"), "dev lo")
}
