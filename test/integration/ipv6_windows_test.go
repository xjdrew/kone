package integration

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

type windowsIPv6Fault struct {
	net.ListenConfig
	network string
}

func (s *windowsIPv6Fault) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if network == s.network {
		occupied, err := s.ListenConfig.Listen(ctx, network, address)
		if err != nil {
			return nil, fmt.Errorf("IPv6 fault reservation: %w", err)
		}
		defer occupied.Close()
	}
	return s.ListenConfig.Listen(ctx, network, address)
}
func (s *windowsIPv6Fault) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if network == s.network {
		occupied, err := s.ListenConfig.ListenPacket(ctx, network, address)
		if err != nil {
			return nil, fmt.Errorf("IPv6 fault reservation: %w", err)
		}
		defer occupied.Close()
	}
	return s.ListenConfig.ListenPacket(ctx, network, address)
}

type windowsSOCKSSeen struct {
	protocol, hostname string
}

func windowsSOCKSPeer(t *testing.T) (string, <-chan windowsSOCKSSeen) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	seen := make(chan windowsSOCKSSeen, 8)
	var workers sync.WaitGroup
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	readTarget := func(reader io.Reader, kind byte) (string, error) {
		size := 0
		switch kind {
		case 1:
			size = 4
		case 4:
			size = 16
		case 3:
			var length [1]byte
			if _, err := io.ReadFull(reader, length[:]); err != nil {
				return "", err
			}
			size = int(length[0])
		default:
			return "", fmt.Errorf("invalid address kind")
		}
		address := make([]byte, size+2)
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		if kind == 3 {
			return string(address[:size]), nil
		}
		return net.IP(address[:size]).String(), nil
	}
	workers.Add(2)
	go func() {
		defer workers.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			active[connection] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				defer func() { mu.Lock(); delete(active, connection); mu.Unlock() }()
				connection.SetDeadline(time.Now().Add(10 * time.Second))
				var hello [2]byte
				if _, err := io.ReadFull(connection, hello[:]); err != nil || hello[0] != 5 || hello[1] > 8 {
					return
				}
				if _, err := io.ReadFull(connection, make([]byte, int(hello[1]))); err != nil {
					return
				}
				connection.Write([]byte{5, 0})
				var request [4]byte
				if _, err := io.ReadFull(connection, request[:]); err != nil {
					return
				}
				hostname, err := readTarget(connection, request[3])
				if err != nil {
					return
				}
				if request[1] == 1 {
					seen <- windowsSOCKSSeen{"tcp", hostname}
					connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
					io.Copy(connection, connection)
				} else if request[1] == 3 {
					_, port, _ := net.SplitHostPort(packet.LocalAddr().String())
					var value int
					fmt.Sscan(port, &value)
					connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(value >> 8), byte(value)})
					connection.SetDeadline(time.Time{})
					io.Copy(io.Discard, connection)
				}
			}()
		}
	}()
	go func() {
		defer workers.Done()
		buffer := make([]byte, 65535)
		for {
			n, source, err := packet.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
				continue
			}
			hostname, err := readTarget(strings.NewReader(string(buffer[4:n])), buffer[3])
			if err != nil {
				continue
			}
			seen <- windowsSOCKSSeen{"udp", hostname}
			packet.WriteTo(buffer[:n], source)
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		packet.Close()
		mu.Lock()
		for connection := range active {
			connection.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return "socks5://" + listener.Addr().String(), seen
}

func windowsIPv6Config(t *testing.T, stack, suffix string) *kone.KoneConfig {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("KONE_WINDOWS_SYSTEM_TEST") != "1" {
		t.Skip("requires disposable administrator Windows IPv6 acceptance runner")
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "SOCKS_PROXY", "http_proxy", "https_proxy", "socks_proxy"} {
		t.Setenv(key, "")
	}
	port, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	dnsPort := port.LocalAddr().(*net.UDPAddr).Port
	port.Close()
	configuration, err := kone.ParseConfig([]byte(fmt.Sprintf(`[general]
manager-addr=""
[core]
tun="kone-v6-%d-%s"
stack="%s"
network="10.204.0.1/24"
ipv6-network="fd7a:204::1/120"
[dns]
listen-port=%d
servers=["[::1]:5353"]
`, os.Getpid(), suffix, stack, dnsPort)))
	require.NoError(t, err)
	return configuration
}

func windowsIPv6Start(t *testing.T, cfg *kone.KoneConfig, options ...kone.Option) (*kone.One, context.CancelFunc, <-chan error) {
	t.Helper()
	one, err := kone.FromConfig(cfg, options...)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	done := make(chan error, 1)
	go func() { done <- one.Run(ctx) }()
	t.Cleanup(func() {
		if t.Failed() {
			name := base64.StdEncoding.EncodeToString([]byte(cfg.Core.Tun))
			script := `$name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + name + `')); Get-NetIPInterface -InterfaceAlias $name -AddressFamily IPv6 | Format-List NlMtu,InterfaceMetric,AutomaticMetric,RouterDiscovery,DadTransmits,Dhcp,ManagedAddressConfiguration,OtherStatefulConfiguration; Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv6 | Format-List IPAddress,PrefixLength,AddressState; Get-NetRoute -InterfaceAlias $name -AddressFamily IPv6 | Format-Table DestinationPrefix,NextHop; Get-NetFirewallRule | Where-Object DisplayName -like 'sing-tun (*)' | Get-NetFirewallAddressFilter | Format-List LocalAddress`
			diagnosticCtx, diagnosticCancel := context.WithTimeout(context.Background(), 20*time.Second)
			out, _ := exec.CommandContext(diagnosticCtx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
			diagnosticCancel()
			t.Logf("owned IPv6 diagnostics:\n%s", out)
		}
		cancel()
		one.Close()
	})
	return one, cancel, done
}

func windowsIPv6Clean(t *testing.T, one *kone.One, cfg *kone.KoneConfig) {
	t.Helper()
	require.NoError(t, one.Close())
	require.Eventually(t, func() bool { _, err := net.InterfaceByName(cfg.Core.Tun); return err != nil }, 10*time.Second, 50*time.Millisecond, "owned IPv6 Wintun adapter leaked")
	program, err := filepath.Abs(os.Args[0])
	require.NoError(t, err)
	rule := base64.StdEncoding.EncodeToString([]byte("sing-tun (" + program + ")"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	script := `$ErrorActionPreference='Stop'; $name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + rule + `')); @(Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $name }).Count`
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	require.NoError(t, err)
	require.Equal(t, "0", strings.TrimSpace(string(out)), "owned IPv6 firewall exception leaked")
}

func TestSystemWindowsIPv6Wintun(t *testing.T) {
	for _, stack := range []string{"system", "mixed"} {
		t.Run(stack+"/traffic", func(t *testing.T) { testWindowsIPv6Traffic(t, stack) })
		for _, failure := range []string{"udp6", "tcp6", "route"} {
			t.Run(stack+"/"+failure+" rollback", func(t *testing.T) {
				cfg := windowsIPv6Config(t, stack, failure)
				var options []kone.Option
				if failure == "route" {
					// The newly owned ULA address creates this exact connected route.
					// Requiring it again injects a real collision without touching any
					// runner default route or pre-existing physical adapter.
					cfg.Rule = []kone.RuleConfig{{Schema: "IP-CIDR6", Pattern: "fd7a:204::/120", Outbound: kone.BuiltinReject}}
				} else {
					options = append(options, kone.WithSockets(&windowsIPv6Fault{network: failure}))
				}
				one, stop, done := windowsIPv6Start(t, cfg, options...)
				defer stop()
				select {
				case err := <-done:
					require.Error(t, err)
					require.NotContains(t, err.Error(), "fault reservation")
					require.Contains(t, err.Error(), "IPv6")
				case <-one.Ready():
					t.Fatal("IPv6 fault unexpectedly reached ready")
				case <-time.After(2 * time.Minute):
					t.Fatal("IPv6 startup failure did not terminate")
				}
				windowsIPv6Clean(t, one, cfg)
			})
		}
	}
}

func testWindowsIPv6Traffic(t *testing.T, stack string) {
	cfg := windowsIPv6Config(t, stack, "traffic")
	socks, socksSeen := windowsSOCKSPeer(t)
	ssTCP, ssTCPSeen := ssInteropPeer(t, "aes-128-gcm", "tcp", false)
	ssUDP, ssUDPSeen := ssInteropPeer(t, "chacha20-ietf-poly1305", "udp", false)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		buffer.Flush()
		if _, err := http.ReadRequest(buffer.Reader); err == nil {
			io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nwintun6")
		}
	}))
	defer proxy.Close()
	upstream, err := net.ListenPacket("udp6", "[::1]:0")
	require.NoError(t, err)
	var actualQueries atomic.Int32
	ready, resolverDone := make(chan struct{}), make(chan struct{})
	resolver := &dns.Server{PacketConn: upstream, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		actualQueries.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.IPv6loopback}}
		w.WriteMsg(response)
	}), NotifyStartedFunc: func() { close(ready) }}
	go func() { defer close(resolverDone); resolver.ActivateAndServe() }()
	t.Cleanup(func() { resolver.Shutdown(); upstream.Close(); <-resolverDone })
	<-ready
	cfg.DNS.Servers = []string{upstream.LocalAddr().String()}
	cfg.Outbounds = []kone.OutboundConfig{{Name: "socks", URL: socks}, {Name: "ss-tcp", URL: "ss://" + url.UserPassword("aes-128-gcm", "interop-password").String() + "@" + ssTCP}, {Name: "ss-udp", URL: "ss://" + url.UserPassword("chacha20-ietf-poly1305", "interop-password").String() + "@" + ssUDP}, {Name: "http", URL: proxy.URL}}
	cfg.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: "socks6.example", Outbound: "socks"}, {Schema: "DOMAIN", Pattern: "ss6.example", Protocol: "tcp", Outbound: "ss-tcp"}, {Schema: "DOMAIN", Pattern: "ss6.example", Protocol: "udp", Outbound: "ss-udp"}, {Schema: "FINAL", Outbound: "http"}}
	one, stop, done := windowsIPv6Start(t, cfg)
	select {
	case <-one.Ready():
	case err := <-done:
		t.Fatalf("native IPv6 stack startup: %v", err)
	case <-time.After(2 * time.Minute):
		t.Fatal("native IPv6 stack did not become ready")
	}
	fakeAAAA := func(name, network string) string {
		t.Helper()
		query := new(dns.Msg)
		query.SetQuestion(name+".", dns.TypeAAAA)
		response, _, err := (&dns.Client{Net: network, Timeout: 5 * time.Second}).Exchange(query, fmt.Sprintf("[fd7a:204::1]:%d", cfg.DNS.ListenPort))
		require.NoError(t, err)
		require.Len(t, response.Answer, 1)
		address := response.Answer[0].(*dns.AAAA).AAAA.String()
		require.True(t, strings.HasPrefix(address, "fd7a:204:"))
		return address
	}
	for _, domain := range []string{"socks6.example", "ss6.example"} {
		fake := fakeAAAA(domain, "udp6")
		require.Equal(t, fake, fakeAAAA(domain, "tcp6"))
		for _, network := range []string{"tcp6", "udp6"} {
			connection, err := net.DialTimeout(network, net.JoinHostPort(fake, "443"), 5*time.Second)
			require.NoError(t, err)
			connection.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("native IPv6 " + domain + " " + network)
			_, err = connection.Write(payload)
			require.NoError(t, err)
			response := make([]byte, len(payload))
			_, err = io.ReadFull(connection, response)
			connection.Close()
			require.NoError(t, err)
			require.Equal(t, payload, response)
		}
	}
	for _, expected := range []string{"tcp", "udp"} {
		select {
		case seen := <-socksSeen:
			require.Equal(t, expected, seen.protocol)
			require.Equal(t, "socks6.example", seen.hostname)
		case <-time.After(time.Second):
			t.Fatal("SOCKS peer did not observe the remote business domain")
		}
	}
	for _, observed := range []<-chan []byte{ssTCPSeen, ssUDPSeen} {
		select {
		case plain := <-observed:
			require.Equal(t, byte(3), plain[0])
			require.Equal(t, "ss6.example", string(plain[2:2+int(plain[1])]))
			require.Equal(t, uint16(443), binary.BigEndian.Uint16(plain[2+int(plain[1]):]))
		case <-time.After(time.Second):
			t.Fatal("SS peer did not decrypt the remote business domain")
		}
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
	response, err := client.Get("http://" + net.JoinHostPort(fakeAAAA("http6.example", "tcp6"), "80") + "/")
	require.NoError(t, err)
	payload, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, "wintun6", string(payload))
	require.Zero(t, actualQueries.Load(), "proxied Fake-AAAA names must not be resolved by the local upstream")
	listener, err := net.Listen("tcp6", "[::1]:0")
	require.NoError(t, err)
	packet, err := net.ListenPacket("udp6", listener.Addr().String())
	require.NoError(t, err)
	var echoWorkers sync.WaitGroup
	echoWorkers.Add(2)
	go func() {
		defer echoWorkers.Done()
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(5 * time.Second))
		io.Copy(connection, connection)
	}()
	go func() {
		defer echoWorkers.Done()
		buffer := make([]byte, 1024)
		n, source, err := packet.ReadFrom(buffer)
		if err == nil {
			packet.WriteTo(buffer[:n], source)
		}
	}()
	t.Cleanup(func() { listener.Close(); packet.Close(); echoWorkers.Wait() })
	fakeDirect := fakeAAAA("direct6.example", "udp6")
	updated := one.Snapshot().Config
	updated.Rule = append([]kone.RuleConfig{{Schema: "DOMAIN", Pattern: "direct6.example", Outbound: kone.BuiltinDirect}}, updated.Rule...)
	require.NoError(t, one.Reload(updated))
	_, directPort, _ := net.SplitHostPort(listener.Addr().String())
	for _, network := range []string{"tcp6", "udp6"} {
		connection, err := net.DialTimeout(network, net.JoinHostPort(fakeDirect, directPort), 5*time.Second)
		require.NoError(t, err)
		connection.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = connection.Write([]byte("direct IPv6 echo"))
		require.NoError(t, err)
		payload := make([]byte, len("direct IPv6 echo"))
		_, err = io.ReadFull(connection, payload)
		connection.Close()
		require.NoError(t, err)
		require.Equal(t, "direct IPv6 echo", string(payload))
	}
	require.Equal(t, int32(1), actualQueries.Load(), "direct Fake-AAAA resolves once through the original IPv6 loopback upstream")
	require.True(t, one.DNSStatus().IPv6)
	records := one.TrafficSnapshot(kone.TrafficQuery{}).Records
	require.GreaterOrEqual(t, len(records), 7)
	for _, record := range records {
		require.NotEmpty(t, record.Domain)
		host, _, err := net.SplitHostPort(record.Source)
		require.NoError(t, err)
		require.NotNil(t, net.ParseIP(host))
		require.Nil(t, net.ParseIP(host).To4())
		require.True(t, strings.HasPrefix(record.FakeIP, "fd7a:204:"))
		if record.Domain == "direct6.example" {
			require.Equal(t, net.JoinHostPort("::1", directPort), record.RealDestination)
		} else {
			require.Empty(t, record.RealDestination, "a remote resolver does not expose the real business IP")
		}
	}
	stop()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("native IPv6 exit did not restore owned resources")
	}
	windowsIPv6Clean(t, one, cfg)
}
