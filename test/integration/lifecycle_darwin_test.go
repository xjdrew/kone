package integration

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/dnsconfig"
	"github.com/xjdrew/kone/pkg/kone"
)

var darwinSubnetSequence atomic.Uint32
var darwinDNSSequence atomic.Uint32

// Both transports share one DNS port. Keep it outside the kernel's ephemeral
// range: sing-tun creates its TCP forwarder after this fixture is configured.
func darwinDNSPort(t *testing.T) uint16 {
	t.Helper()
	for range 128 {
		port := 20000 + int(darwinDNSSequence.Add(1)%10000)
		address := fmt.Sprintf("0.0.0.0:%d", port)
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			continue
		}
		packet, err := net.ListenPacket("udp4", address)
		listener.Close()
		if err != nil {
			continue
		}
		packet.Close()
		return uint16(port)
	}
	t.Fatal("could not select an unused TCP/UDP DNS fixture port")
	return 0
}

type darwinNetworkBaseline struct {
	route           string
	servers, search []string
}

func captureDarwinBaseline(t *testing.T) darwinNetworkBaseline {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", "default").Output()
	require.NoError(t, err)
	var fields []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") || strings.HasPrefix(line, "interface:") {
			fields = append(fields, line)
		}
	}
	require.NotEmpty(t, fields, "the disposable runner must retain its real default route")
	configuration := dnsconfig.ReadDnsConfig()
	require.NotNil(t, configuration)
	require.NoError(t, configuration.Err)
	servers, search := append([]string(nil), configuration.Servers...), append([]string(nil), configuration.Search...)
	sort.Strings(servers)
	sort.Strings(search)
	return darwinNetworkBaseline{route: strings.Join(fields, "\n"), servers: servers, search: search}
}

func darwinSystemConfig(t *testing.T, stack string) *kone.KoneConfig {
	t.Helper()
	if os.Getenv("KONE_DARWIN_SYSTEM_TEST") != "1" {
		t.Skip("requires opt-in disposable macOS administrator runner")
	}
	require.Equal(t, 0, os.Geteuid(), "native UTUN acceptance requires sudo -n on the disposable runner")
	var network string
	addresses, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for attempts := 0; attempts < 100; attempts++ {
		octet := 120 + (int(darwinSubnetSequence.Add(1))+os.Getpid())%120
		candidate := netip.MustParsePrefix(fmt.Sprintf("198.18.%d.0/24", octet))
		overlap := false
		for _, value := range addresses {
			if prefix, err := netip.ParsePrefix(value.String()); err == nil && prefix.Addr().Is4() && (prefix.Contains(candidate.Addr()) || candidate.Contains(prefix.Addr())) {
				overlap = true
				break
			}
		}
		if !overlap {
			network = fmt.Sprintf("198.18.%d.1/24", octet)
			break
		}
	}
	require.NotEmpty(t, network, "no unoccupied reserved UTUN test prefix was found")
	cfg := kone.DefaultConfig()
	cfg.General.ManagerAddr = ""
	cfg.Core.Network = network
	cfg.Core.Stack = stack
	cfg.Core.AutoRoute = false
	cfg.Core.AutoRoute6 = false
	cfg.Core.IPv6Network = ""
	cfg.DNS.System = false
	cfg.DNS.Servers = []string{"127.0.0.1:5353"}
	cfg.DNS.ListenPort = darwinDNSPort(t)
	require.NoError(t, cfg.Validate())
	return cfg
}

func darwinWait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("UTUN engine did not terminate within its cleanup budget")
		return nil
	}
}
func darwinAssertOwnedGone(t *testing.T, one *kone.One) {
	t.Helper()
	name, index, known := one.CaptureDeviceIdentity()
	require.True(t, known, "actual exclusively created device identity must have been recorded")
	require.Eventually(t, func() bool { device, err := net.InterfaceByName(name); return err != nil || device.Index != index }, 5*time.Second, 25*time.Millisecond, "owned UTUN leaked after close: %s/%d", name, index)
}

func darwinCreate(t *testing.T, cfg *kone.KoneConfig, options ...kone.Option) *kone.One {
	t.Helper()
	require.False(t, cfg.Core.AutoRoute)
	require.False(t, cfg.Core.AutoRoute6)
	require.False(t, cfg.DNS.System)
	one, err := kone.FromConfig(cfg, options...)
	require.NoError(t, err)
	require.NoError(t, one.SetCaptureRecorder(func(name string, index int) error {
		if !strings.HasPrefix(name, "utun") || index <= 0 {
			return fmt.Errorf("invalid created UTUN identity %s/%d", name, index)
		}
		return nil
	}))
	return one
}

func darwinLocalDNS(t *testing.T) string {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	ready := make(chan struct{})
	server := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(r)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)}}
		w.WriteMsg(response)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { server.Shutdown(); require.NoError(t, <-done) })
	return packet.LocalAddr().String()
}

func darwinConnectProxy(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			http.Error(w, "CONNECT required", 400)
			return
		}
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(5 * time.Second))
		buffer.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		if err = buffer.Flush(); err != nil {
			return
		}
		request, err := http.ReadRequest(buffer.Reader)
		if err != nil {
			return
		}
		request.Body.Close()
		io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndarwin")
	}))
	t.Cleanup(server.Close)
	return server
}

func darwinFakeAddress(t *testing.T, cfg *kone.KoneConfig, name string) net.IP {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(name, dns.TypeA)
	// Darwin owns a wildcard DNS listener, reached through the loopback resolver
	// endpoint. Its point-to-point TUN address is not a kernel-local DNS socket.
	response, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(query, fmt.Sprintf("127.0.0.1:%d", cfg.DNS.ListenPort))
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	answer, ok := response.Answer[0].(*dns.A)
	require.True(t, ok)
	require.NotEqual(t, "127.0.0.1", answer.A.String(), "business packets must cross the real Fake-IP route")
	return answer.A
}

type occupiedDarwinDNS struct{ net.ListenConfig }

func (s *occupiedDarwinDNS) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	occupied, err := s.ListenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("fault reservation: %w", err)
	}
	defer occupied.Close()
	return s.ListenConfig.ListenPacket(ctx, network, address)
}

func darwinRoute(t *testing.T, cfg *kone.KoneConfig, action string) {
	t.Helper()
	prefix := netip.MustParsePrefix(cfg.Core.Network).Masked()
	require.True(t, strings.HasPrefix(prefix.String(), "198.18."))
	require.Equal(t, 24, prefix.Bits())
	require.Contains(t, []string{"add", "delete"}, action)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "/sbin/route", "-n", action, "-net", prefix.Addr().String(), "-netmask", "255.255.255.0", "-interface", "lo0").CombinedOutput()
	require.NoError(t, err, string(data))
}

func TestSystemDarwinUTUN(t *testing.T) {
	if os.Getenv("KONE_DARWIN_SYSTEM_TEST") != "1" {
		t.Skip("requires opt-in disposable macOS administrator runner")
	}
	require.Contains(t, kone.SupportedStacks(), "mixed", "acceptance binary must be built with with_gvisor")
	baseline := captureDarwinBaseline(t)
	t.Cleanup(func() {
		require.True(t, reflect.DeepEqual(baseline, captureDarwinBaseline(t)), "native acceptance changed the runner's default route or system DNS")
	})
	for _, stack := range []string{"system", "mixed"} {
		t.Run(stack, func(t *testing.T) {
			t.Run("fake-ip-tcp-udp", func(t *testing.T) {
				cfg := darwinSystemConfig(t, stack)
				cfg.DNS.Servers = []string{darwinLocalDNS(t)}
				upstream := darwinConnectProxy(t)
				cfg.Outbounds = []kone.OutboundConfig{{Name: "local-proxy", URL: upstream.URL, UDPFallback: kone.BuiltinDirect}}
				cfg.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: "tcp.darwin.test", Outbound: "local-proxy"}, {Schema: "DOMAIN", Pattern: "udp.darwin.test", Outbound: "local-proxy"}, {Schema: "FINAL", Outbound: kone.BuiltinDirect}}
				one := darwinCreate(t, cfg)
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() { done <- one.Run(ctx) }()
				t.Cleanup(func() { cancel(); one.Close() })
				select {
				case <-one.Ready():
				case err := <-done:
					t.Fatalf("UTUN startup: %v", err)
				case <-time.After(15 * time.Second):
					t.Fatal("UTUN startup timed out")
				}
				ip := darwinFakeAddress(t, cfg, "tcp.darwin.test.")
				transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				response, err := client.Get("http://" + ip.String() + ":80/")
				require.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				require.NoError(t, err)
				require.Equal(t, "darwin", string(body))
				echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
				require.NoError(t, err)
				defer echo.Close()
				go func() {
					data := make([]byte, 2048)
					n, peer, err := echo.ReadFrom(data)
					if err == nil {
						echo.WriteTo(data[:n], peer)
					}
				}()
				ip = darwinFakeAddress(t, cfg, "udp.darwin.test.")
				connection, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: echo.LocalAddr().(*net.UDPAddr).Port})
				require.NoError(t, err)
				defer connection.Close()
				connection.SetDeadline(time.Now().Add(5 * time.Second))
				_, err = connection.Write([]byte("utun-udp"))
				require.NoError(t, err)
				reply := make([]byte, 64)
				n, err := connection.Read(reply)
				require.NoError(t, err)
				require.Equal(t, "utun-udp", string(reply[:n]))
				require.Eventually(t, func() bool {
					traffic := one.TrafficSnapshot(kone.TrafficQuery{})
					return traffic.Totals.Upload > 0 && traffic.Totals.Download > 0
				}, time.Second, 10*time.Millisecond)
				cancel()
				require.NoError(t, darwinWait(t, done))
				require.NoError(t, one.Close())
				darwinAssertOwnedGone(t, one)
			})
			for _, kind := range []string{"dns", "manager"} {
				t.Run("occupied-"+kind, func(t *testing.T) {
					cfg := darwinSystemConfig(t, stack)
					var options []kone.Option
					var occupied net.Listener
					if kind == "dns" {
						options = []kone.Option{kone.WithSockets(&occupiedDarwinDNS{})}
					} else {
						var err error
						occupied, err = net.Listen("tcp4", "127.0.0.1:0")
						require.NoError(t, err)
						defer occupied.Close()
						cfg.General.ManagerAddr = occupied.Addr().String()
					}
					one := darwinCreate(t, cfg, options...)
					t.Cleanup(func() { one.Close() })
					done := make(chan error, 1)
					go func() { done <- one.Run(context.Background()) }()
					err := darwinWait(t, done)
					require.Error(t, err)
					require.NotContains(t, err.Error(), "fault reservation")
					if kind == "dns" {
						require.Contains(t, err.Error(), "DNS listener:")
					} else {
						require.Contains(t, err.Error(), "manager listener:")
					}
					require.NoError(t, one.Close())
					darwinAssertOwnedGone(t, one)
				})
			}
			t.Run("route-failure-preserves-owner", func(t *testing.T) {
				cfg := darwinSystemConfig(t, stack)
				darwinRoute(t, cfg, "add")
				defer darwinRoute(t, cfg, "delete")
				one := darwinCreate(t, cfg)
				t.Cleanup(func() { one.Close() })
				done := make(chan error, 1)
				go func() { done <- one.Run(context.Background()) }()
				err := darwinWait(t, done)
				require.Error(t, err)
				require.Contains(t, err.Error(), "configure TUN:")
				require.NoError(t, one.Close())
				darwinAssertOwnedGone(t, one)
				prefix := netip.MustParsePrefix(cfg.Core.Network)
				data, err := exec.Command("/sbin/route", "-n", "get", prefix.Addr().Next().String()).Output()
				require.NoError(t, err)
				scanner := bufio.NewScanner(strings.NewReader(string(data)))
				preserved := false
				for scanner.Scan() {
					if strings.TrimSpace(scanner.Text()) == "interface: lo0" {
						preserved = true
					}
				}
				require.True(t, preserved, "startup rollback removed or replaced the test-owned pre-existing prefix route")
			})
		})
	}
}
