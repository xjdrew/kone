package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func darwinDualDNSPort(t *testing.T) uint16 {
	t.Helper()
	for range 128 {
		port := darwinDNSPort(t)
		address := net.JoinHostPort("::1", fmt.Sprint(port))
		tcp, err := net.Listen("tcp6", address)
		if err != nil {
			continue
		}
		udp, err := net.ListenPacket("udp6", address)
		tcp.Close()
		if err != nil {
			continue
		}
		udp.Close()
		return port
	}
	t.Fatal("no free IPv4/IPv6 UDP/TCP DNS port")
	return 0
}

func darwinIPv6Config(t *testing.T, stack string) *kone.KoneConfig {
	t.Helper()
	cfg := darwinSystemConfig(t, stack)
	cfg.Core.IPv6Network = fmt.Sprintf("fd7a:4d41:%x:%x::1/120", os.Getpid()&65535, darwinSubnetSequence.Add(1)&65535)
	cfg.DNS.ListenPort = darwinDualDNSPort(t)
	require.NoError(t, cfg.Validate())
	return cfg
}

func darwinIPv6Routes(t *testing.T, prefix netip.Prefix) []int {
	t.Helper()
	data, err := route.FetchRIB(unix.AF_INET6, route.RIBTypeRoute, 0)
	require.NoError(t, err)
	messages, err := route.ParseRIB(route.RIBTypeRoute, data)
	require.NoError(t, err)
	var indexes []int
	for _, value := range messages {
		message, ok := value.(*route.RouteMessage)
		if !ok || len(message.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		destination, ok := message.Addrs[unix.RTAX_DST].(*route.Inet6Addr)
		if !ok {
			continue
		}
		bits := 0
		if message.Flags&unix.RTF_HOST != 0 {
			bits = 128
		} else if mask, ok := message.Addrs[unix.RTAX_NETMASK].(*route.Inet6Addr); ok {
			var size int
			bits, size = net.IPMask(mask.IP[:]).Size()
			if size != 128 {
				continue
			}
		}
		if netip.PrefixFrom(netip.AddrFrom16(destination.IP), bits).Masked() == prefix.Masked() {
			indexes = append(indexes, message.Index)
		}
	}
	return indexes
}

func darwinExtraIPv6Prefix(cfg *kone.KoneConfig, number byte) netip.Prefix {
	address := netip.MustParsePrefix(cfg.Core.IPv6Network).Masked().Addr().As16()
	address[14], address[15] = number, 0
	return netip.PrefixFrom(netip.AddrFrom16(address), 120)
}

func darwinIPv6Resolver(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	packet, err := net.ListenPacket("udp6", "[::1]:0")
	require.NoError(t, err)
	count := new(atomic.Int32)
	ready, done := make(chan struct{}), make(chan error, 1)
	server := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		count.Add(1)
		answer := new(dns.Msg)
		answer.SetReply(request)
		for _, question := range request.Question {
			header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}
			if question.Qtype == dns.TypeAAAA {
				answer.Answer = append(answer.Answer, &dns.AAAA{Hdr: header, AAAA: net.IPv6loopback})
			} else if question.Qtype == dns.TypeA {
				answer.Answer = append(answer.Answer, &dns.A{Hdr: header, A: net.IPv4(127, 0, 0, 1)})
			}
		}
		w.WriteMsg(answer)
	})}
	go func() { done <- server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { server.Shutdown(); packet.Close(); require.NoError(t, <-done) })
	return packet.LocalAddr().String(), count
}

func darwinIPv6Query(t *testing.T, cfg *kone.KoneConfig, name string, kind uint16, network string) *dns.Msg {
	t.Helper()
	host := "127.0.0.1"
	if strings.HasSuffix(network, "6") {
		host = "::1"
	}
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(name), kind)
	answer, _, err := (&dns.Client{Net: network, Timeout: 3 * time.Second}).Exchange(request, net.JoinHostPort(host, fmt.Sprint(cfg.DNS.ListenPort)))
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, answer.Rcode)
	require.Len(t, answer.Answer, 1)
	return answer
}

func darwinFakeAAAA(t *testing.T, cfg *kone.KoneConfig, name, network string) string {
	t.Helper()
	answer := darwinIPv6Query(t, cfg, name, dns.TypeAAAA, network)
	address := answer.Answer[0].(*dns.AAAA).AAAA.String()
	require.True(t, netip.MustParsePrefix(cfg.Core.IPv6Network).Contains(netip.MustParseAddr(address)), "AAAA must use the owned Fake-IP pool")
	return address
}

func darwinIPv6Echo(t *testing.T, network, address string) {
	t.Helper()
	connection, err := net.DialTimeout(network, address, 5*time.Second)
	require.NoError(t, err)
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("darwin IPv6 " + network)
	_, err = connection.Write(payload)
	require.NoError(t, err)
	response := make([]byte, len(payload))
	_, err = io.ReadFull(connection, response)
	require.NoError(t, err)
	require.Equal(t, payload, response)
}

func darwinIPv6Start(t *testing.T, cfg *kone.KoneConfig) (*kone.One, func()) {
	t.Helper()
	one := darwinCreate(t, cfg)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- one.Run(ctx) }()
	var once sync.Once
	var result error
	wait := func() error { once.Do(func() { result = darwinWait(t, done) }); return result }
	stop := func() {
		cancel()
		require.NoError(t, one.Close())
		require.NoError(t, wait())
		darwinAssertOwnedGone(t, one)
		require.Empty(t, darwinIPv6Routes(t, netip.MustParsePrefix(cfg.Core.IPv6Network).Masked()))
	}
	t.Cleanup(stop)
	select {
	case <-one.Ready():
	case err := <-done:
		once.Do(func() { result = err })
		t.Fatalf("dual-stack start: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("dual-stack startup timed out")
	}
	return one, stop
}

func TestSystemDarwinIPv6(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("KONE_DARWIN_SYSTEM_TEST") != "1" {
		t.Skip("requires disposable macOS administrator acceptance runner")
	}
	require.Equal(t, 0, os.Geteuid())
	require.True(t, kone.SupportsIPv6Capture())
	baseline := captureDarwinBaseline(t)
	default6 := darwinIPv6Routes(t, netip.MustParsePrefix("::/0"))
	t.Cleanup(func() {
		require.True(t, reflect.DeepEqual(baseline, captureDarwinBaseline(t)))
		require.Equal(t, default6, darwinIPv6Routes(t, netip.MustParsePrefix("::/0")))
	})
	for _, stack := range kone.SupportedStacks() {
		t.Run(stack+"/proxy-tcp-udp", func(t *testing.T) {
			cfg := darwinIPv6Config(t, stack)
			upstream, queries := darwinIPv6Resolver(t)
			cfg.DNS.Servers = []string{upstream}
			socks, seen := ipv6SOCKSPeerOn(t, "::1")
			ssTCP, tcpSeen := ssInteropPeer(t, "aes-128-gcm", "tcp", false)
			ssUDP, udpSeen := ssInteropPeer(t, "chacha20-ietf-poly1305", "udp", false)
			httpProxy := darwinConnectProxy(t)
			cfg.Outbounds = []kone.OutboundConfig{{Name: "socks", URL: socks}, {Name: "ss-tcp", URL: "ss://" + url.UserPassword("aes-128-gcm", "interop-password").String() + "@" + ssTCP}, {Name: "ss-udp", URL: "ss://" + url.UserPassword("chacha20-ietf-poly1305", "interop-password").String() + "@" + ssUDP}, {Name: "http", URL: httpProxy.URL}}
			literal := darwinExtraIPv6Prefix(cfg, 1)
			cfg.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: "socks6.darwin.test", Outbound: "socks"}, {Schema: "DOMAIN", Pattern: "ss6.darwin.test", Protocol: "tcp", Outbound: "ss-tcp"}, {Schema: "DOMAIN", Pattern: "ss6.darwin.test", Protocol: "udp", Outbound: "ss-udp"}, {Schema: "IP-CIDR6", Pattern: literal.String(), Outbound: "socks"}, {Schema: "FINAL", Outbound: "http"}}
			one, stop := darwinIPv6Start(t, cfg)
			for _, domain := range []string{"socks6.darwin.test", "ss6.darwin.test"} {
				fake := darwinFakeAAAA(t, cfg, domain, "udp6")
				for _, network := range []string{"tcp6", "udp4", "tcp4"} {
					require.Equal(t, fake, darwinFakeAAAA(t, cfg, domain, network))
				}
				for _, network := range []string{"tcp6", "udp6"} {
					darwinIPv6Echo(t, network, net.JoinHostPort(fake, "443"))
				}
			}
			literalAddress := literal.Addr().Next().String()
			for _, network := range []string{"tcp6", "udp6"} {
				darwinIPv6Echo(t, network, net.JoinHostPort(literalAddress, "443"))
			}
			for _, expected := range []ipv6SOCKSSeen{{"tcp", "socks6.darwin.test"}, {"udp", "socks6.darwin.test"}, {"tcp", literalAddress}, {"udp", literalAddress}} {
				select {
				case actual := <-seen:
					require.Equal(t, expected, actual)
				case <-time.After(time.Second):
					t.Fatal("IPv6 SOCKS relay did not receive original target")
				}
			}
			for _, observed := range []<-chan []byte{tcpSeen, udpSeen} {
				select {
				case plain := <-observed:
					require.Equal(t, byte(3), plain[0])
					require.Equal(t, "ss6.darwin.test", string(plain[2:2+int(plain[1])]))
				case <-time.After(time.Second):
					t.Fatal("SS peer did not observe original IPv6 business domain")
				}
			}
			client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 5 * time.Second}
			response, err := client.Get("http://" + net.JoinHostPort(darwinFakeAAAA(t, cfg, "http6.darwin.test", "tcp6"), "80") + "/")
			require.NoError(t, err)
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			require.NoError(t, err)
			require.Equal(t, "darwin", string(body))
			require.Zero(t, queries.Load(), "proxy Fake-AAAA targets must use remote DNS")
			require.True(t, one.DNSStatus().IPv6)
			require.GreaterOrEqual(t, len(one.TrafficSnapshot(kone.TrafficQuery{}).Records), 7)
			stop()
			require.Empty(t, darwinIPv6Routes(t, literal))
		})
		t.Run(stack+"/direct-tcp-udp", func(t *testing.T) {
			cfg := darwinIPv6Config(t, stack)
			defaultResolver, defaultQueries := darwinIPv6Resolver(t)
			privateResolver, privateQueries := darwinIPv6Resolver(t)
			cfg.DNS.Servers = []string{defaultResolver}
			cfg.DNS.Rules = []kone.DNSRouteConfig{{Suffix: "internal.test", Servers: []string{privateResolver}, Interface: "lo0"}}
			socks, _ := ipv6SOCKSPeerOn(t, "::1")
			cfg.Outbounds = []kone.OutboundConfig{{Name: "proxy", URL: socks}}
			cfg.Rule = []kone.RuleConfig{{Schema: "FINAL", Outbound: "proxy"}}
			listener, err := net.Listen("tcp6", "[::1]:0")
			require.NoError(t, err)
			packet, err := net.ListenPacket("udp6", listener.Addr().String())
			require.NoError(t, err)
			var workers sync.WaitGroup
			workers.Add(2)
			go func() {
				defer workers.Done()
				connection, err := listener.Accept()
				if err == nil {
					defer connection.Close()
					connection.SetDeadline(time.Now().Add(5 * time.Second))
					io.Copy(connection, connection)
				}
			}()
			go func() {
				defer workers.Done()
				buffer := make([]byte, 2048)
				n, source, err := packet.ReadFrom(buffer)
				if err == nil {
					packet.WriteTo(buffer[:n], source)
				}
			}()
			t.Cleanup(func() { listener.Close(); packet.Close(); workers.Wait() })
			one, stop := darwinIPv6Start(t, cfg)
			fake := darwinFakeAAAA(t, cfg, "direct.internal.test", "udp6")
			updated := one.Snapshot().Config
			updated.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: "direct.internal.test", Outbound: kone.BuiltinDirect}, {Schema: "FINAL", Outbound: "proxy"}}
			require.NoError(t, one.Reload(updated))
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			for _, network := range []string{"tcp6", "udp6"} {
				darwinIPv6Echo(t, network, net.JoinHostPort(fake, port))
			}
			require.Equal(t, int32(1), privateQueries.Load())
			require.Zero(t, defaultQueries.Load(), "private suffix must not fall back to default resolver")
			stop()
		})
		for _, failure := range []string{"udp6", "tcp6"} {
			t.Run(stack+"/"+failure+"-rollback", func(t *testing.T) {
				cfg := darwinIPv6Config(t, stack)
				one := darwinCreate(t, cfg, kone.WithSockets(&darwinIPv6Fault{network: failure}))
				t.Cleanup(func() { one.Close() })
				done := make(chan error, 1)
				go func() { done <- one.Run(t.Context()) }()
				err := darwinWait(t, done)
				require.Error(t, err)
				require.NotContains(t, err.Error(), "fault reservation")
				require.Contains(t, err.Error(), "IPv6 DNS "+map[string]string{"udp6": "UDP", "tcp6": "TCP"}[failure])
				require.NoError(t, one.Close())
				darwinAssertOwnedGone(t, one)
				require.Empty(t, darwinIPv6Routes(t, netip.MustParsePrefix(cfg.Core.IPv6Network).Masked()))
			})
		}
		t.Run(stack+"/route-rollback", func(t *testing.T) {
			cfg := darwinIPv6Config(t, stack)
			owned, foreign := darwinExtraIPv6Prefix(cfg, 1), darwinExtraIPv6Prefix(cfg, 2)
			lo, err := net.InterfaceByName("lo0")
			require.NoError(t, err)
			require.Empty(t, darwinIPv6Routes(t, foreign))
			command := func(action string) {
				// testing cancels its context before Cleanup; releasing the fixture's
				// foreign route must retain a fresh, bounded cleanup budget.
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				data, err := exec.CommandContext(ctx, "/sbin/route", "-n", action, "-inet6", "-net", foreign.String(), "-interface", "lo0").CombinedOutput()
				require.NoError(t, err, string(data))
			}
			command("add")
			require.Equal(t, []int{lo.Index}, darwinIPv6Routes(t, foreign))
			t.Cleanup(func() { command("delete") })
			cfg.Rule = []kone.RuleConfig{{Schema: "IP-CIDR6", Pattern: owned.String(), Outbound: kone.BuiltinReject}, {Schema: "IP-CIDR6", Pattern: foreign.String(), Outbound: kone.BuiltinReject}}
			one := darwinCreate(t, cfg)
			t.Cleanup(func() { one.Close() })
			done := make(chan error, 1)
			go func() { done <- one.Run(t.Context()) }()
			require.ErrorContains(t, darwinWait(t, done), "add IPv6 route "+foreign.String())
			require.NoError(t, one.Close())
			darwinAssertOwnedGone(t, one)
			require.Empty(t, darwinIPv6Routes(t, owned))
			require.Equal(t, []int{lo.Index}, darwinIPv6Routes(t, foreign))
		})
		t.Run(stack+"/owned-routes-restore", func(t *testing.T) {
			cfg := darwinIPv6Config(t, stack)
			extra := darwinExtraIPv6Prefix(cfg, 1)
			cfg.Rule = []kone.RuleConfig{{Schema: "IP-CIDR6", Pattern: extra.String(), Outbound: kone.BuiltinReject}, {Schema: "FINAL", Outbound: kone.BuiltinReject}}
			one, stop := darwinIPv6Start(t, cfg)
			_, index, known := one.CaptureDeviceIdentity()
			require.True(t, known)
			require.Equal(t, []int{index}, darwinIPv6Routes(t, extra))
			stop()
			require.Empty(t, darwinIPv6Routes(t, extra))
			for _, network := range []string{"udp6", "tcp6"} {
				address := net.JoinHostPort("::1", fmt.Sprint(cfg.DNS.ListenPort))
				if network == "udp6" {
					socket, err := net.ListenPacket(network, address)
					require.NoError(t, err)
					socket.Close()
				} else {
					socket, err := net.Listen(network, address)
					require.NoError(t, err)
					socket.Close()
				}
			}
		})
	}
}

type darwinIPv6Fault struct {
	net.ListenConfig
	network string
}

func (s *darwinIPv6Fault) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if network == s.network {
		occupied, err := s.ListenConfig.Listen(ctx, network, address)
		if err != nil {
			return nil, fmt.Errorf("IPv6 fault reservation: %w", err)
		}
		defer occupied.Close()
	}
	return s.ListenConfig.Listen(ctx, network, address)
}
func (s *darwinIPv6Fault) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if network == s.network {
		occupied, err := s.ListenConfig.ListenPacket(ctx, network, address)
		if err != nil {
			return nil, fmt.Errorf("IPv6 fault reservation: %w", err)
		}
		defer occupied.Close()
	}
	return s.ListenConfig.ListenPacket(ctx, network, address)
}
