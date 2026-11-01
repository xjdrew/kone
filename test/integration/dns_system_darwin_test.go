package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/dnsconfig"
	"github.com/xjdrew/kone/pkg/kone"
)

func darwinDNSStoreRead(ctx context.Context, script string) (string, error) {
	command := exec.CommandContext(ctx, "/usr/sbin/scutil")
	command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	command.Stdin = strings.NewReader(script)
	command.WaitDelay = time.Second
	data, err := command.Output()
	return string(data), err
}

func darwinOSLookup(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	// dscacheutil uses the real SystemConfiguration/mDNSResponder resolver.
	// A direct dns.Client or PreferGo resolver would not prove system guidance.
	data, err := exec.CommandContext(ctx, "/usr/bin/dscacheutil", "-q", "host", "-a", "name", name).Output()
	if err != nil {
		return nil, err
	}
	var addresses []string
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "ip_address:"); ok {
			addresses = append(addresses, strings.TrimSpace(value))
		}
	}
	return addresses, nil
}

func darwinAssertDNSOrder(t *testing.T, port uint16, wanted string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns").Output()
	require.NoError(t, err)
	found := false
	for _, block := range strings.Split(string(data), "resolver #")[1:] {
		var actualPort, order string
		loopback, scoped := false, false
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
			if !ok {
				continue
			}
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			switch {
			case key == "port":
				actualPort = value
			case key == "order":
				order = value
			case strings.HasPrefix(key, "nameserver["):
				loopback = loopback || value == "127.0.0.1"
			case key == "flags":
				scoped = strings.Contains(value, "Scoped")
			}
		}
		if !scoped && loopback && actualPort == fmt.Sprint(port) {
			found = true
			require.Equal(t, wanted, order, "the OS must honor the explicit numeric supplemental order")
		}
	}
	require.True(t, found, "owned resolver missing from the actual OS resolver configuration")
	t.Logf("system resolver loopback:%d uses explicit supplemental order %s", port, wanted)
}

func darwinOriginalDNSFixture(t *testing.T) string {
	t.Helper()
	configuration := dnsconfig.ReadDnsConfig()
	require.NotNil(t, configuration)
	require.NoError(t, configuration.Err)
	require.NotEmpty(t, configuration.Servers, "keep unknown runner DNS names working through the original DNS")
	upstreams := append([]string(nil), configuration.Servers...)
	port := darwinDNSPort(t)
	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	packet, err := net.ListenPacket("udp4", endpoint)
	require.NoError(t, err)
	listener, err := net.Listen("tcp4", endpoint)
	require.NoError(t, err)
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.RecursionAvailable = true
		if strings.HasSuffix(strings.ToLower(request.Question[0].Name), ".kone-system.test.") {
			if request.Question[0].Qtype == dns.TypeA {
				response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.IPv4(192, 0, 2, 9)}}
			}
		} else {
			response.Rcode = dns.RcodeServerFailure
			for _, server := range upstreams {
				answer, _, err := (&dns.Client{Timeout: time.Second}).Exchange(request, net.JoinHostPort(server, "53"))
				if err == nil {
					response = answer
					break
				}
			}
		}
		_ = writer.WriteMsg(response)
	})
	udpReady, tcpReady := make(chan struct{}), make(chan struct{})
	udp := &dns.Server{PacketConn: packet, Handler: handler, NotifyStartedFunc: func() { close(udpReady) }}
	tcp := &dns.Server{Listener: listener, Handler: handler, NotifyStartedFunc: func() { close(tcpReady) }}
	udpDone, tcpDone := make(chan error, 1), make(chan error, 1)
	go func() { udpDone <- udp.ActivateAndServe() }()
	go func() { tcpDone <- tcp.ActivateAndServe() }()
	<-udpReady
	<-tcpReady
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown(); require.NoError(t, <-udpDone); require.NoError(t, <-tcpDone) })
	var random [16]byte
	_, err = rand.Read(random[:])
	require.NoError(t, err)
	encoded := hex.EncodeToString(random[:])
	id := encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
	key := "State:/Network/Service/" + id + "/DNS"
	command := exec.Command("/usr/sbin/scutil")
	command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	input, err := command.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, command.Start())
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		input.Close()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(3 * time.Second):
			_ = command.Process.Kill()
			<-done
			t.Error("original fixture session did not close")
		}
	})
	_, err = io.WriteString(input, "open\nd.init\nd.add __KONEFixture "+id+"\nd.add ServerAddresses * 127.0.0.1\nd.add ServerPort # "+fmt.Sprint(port)+"\nd.add SupplementalMatchOrders * # 100\nd.add SupplementalMatchDomains * \"\"\nadd "+key+" temporary\n")
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		value, err := darwinDNSStoreRead(ctx, "show "+key+"\nquit\n")
		return err == nil && strings.Contains(value, id)
	}, 5*time.Second, 25*time.Millisecond)
	require.Eventually(t, func() bool {
		result, err := darwinOSLookup("before-" + encoded + ".kone-system.test")
		return err == nil && reflect.DeepEqual(result, []string{"192.0.2.9"})
	}, 8*time.Second, 50*time.Millisecond, "temporary original resolver must be active before starting KONE")
	darwinAssertDNSOrder(t, port, "100")
	return endpoint
}

type darwinFailedManagerListener struct{ net.Listener }

func (l darwinFailedManagerListener) Accept() (net.Conn, error) {
	return nil, errors.New("injected late manager admission failure")
}

type darwinFailedManagerSockets struct {
	net.ListenConfig
	manager string
}

func (s *darwinFailedManagerSockets) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	listener, err := s.ListenConfig.Listen(ctx, network, address)
	if err == nil && address == s.manager {
		return darwinFailedManagerListener{listener}, nil
	}
	return listener, err
}

func TestSystemDarwinDNSGuidance(t *testing.T) {
	if os.Getenv("KONE_DARWIN_DNS_SYSTEM_TEST") != "1" {
		t.Skip("requires disposable macOS system DNS acceptance")
	}
	require.Equal(t, 0, os.Geteuid())
	require.True(t, kone.SupportsSystemDNS(), "macOS system DNS support must be enabled")
	for _, stack := range []string{"system", "mixed"} {
		for _, failure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/late-failure=%t", stack, failure), func(t *testing.T) {
				original := captureDarwinBaseline(t)
				t.Cleanup(func() {
					require.Eventually(t, func() bool {
						configuration := dnsconfig.ReadDnsConfig()
						if configuration == nil || configuration.Err != nil {
							return false
						}
						servers, search := append([]string(nil), configuration.Servers...), append([]string(nil), configuration.Search...)
						sort.Strings(servers)
						sort.Strings(search)
						return reflect.DeepEqual(servers, original.servers) && reflect.DeepEqual(search, original.search)
					}, 8*time.Second, 50*time.Millisecond, "original physical DNS must return after both temporary sessions close")
					require.Equal(t, original.route, captureDarwinBaseline(t).route)
				})
				upstream := darwinOriginalDNSFixture(t)
				cfg := darwinSystemConfig(t, stack)
				cfg.DNS.System = true
				cfg.DNS.Servers = []string{upstream}
				name := fmt.Sprintf("fake-%d-%d.kone-system.test", os.Getpid(), cfg.DNS.ListenPort)
				cfg.Outbounds = []kone.OutboundConfig{{Name: "offline", URL: "http://127.0.0.1:1"}}
				cfg.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: name, Outbound: "offline"}, {Schema: "FINAL", Outbound: kone.BuiltinDirect}}
				var options []kone.Option
				if failure {
					cfg.General.ManagerAddr = fmt.Sprintf("127.0.0.1:%d", darwinDNSPort(t))
					options = append(options, kone.WithSockets(&darwinFailedManagerSockets{manager: cfg.General.ManagerAddr}))
				}
				one, err := kone.FromConfig(cfg, options...)
				require.NoError(t, err)
				require.NoError(t, one.SetCaptureRecorder(func(name string, index int) error {
					if !strings.HasPrefix(name, "utun") || index <= 0 {
						return errors.New("invalid exclusive utun identity")
					}
					return nil
				}))
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				go func() { done <- one.Run(ctx) }()
				var once sync.Once
				var result error
				wait := func() error { once.Do(func() { result = darwinWait(t, done) }); return result }
				t.Cleanup(func() { cancel(); _ = one.Close(); _ = wait() })
				if failure {
					runErr := wait()
					darwinLogDNSDiagnostic(t, runErr)
					require.ErrorContains(t, runErr, "manager")
				} else {
					select {
					case <-one.Ready():
					case err := <-done:
						once.Do(func() { result = err })
						darwinLogDNSDiagnostic(t, err)
						t.Fatalf("start scoped system DNS: %v", err)
					case <-time.After(10 * time.Second):
						t.Fatal("system DNS did not start")
					}
					darwinAssertDNSOrder(t, cfg.DNS.ListenPort, "1")
					freshConfig := *cfg
					freshConfig.DNS = cfg.DNS
					freshConfig.DNS.Servers = nil
					fresh, err := kone.FromConfig(&freshConfig)
					require.NoError(t, err, "a fresh ordinary manager/helper snapshot must exclude KONE's own resolver")
					require.Contains(t, fresh.DNSStatus().Servers, upstream)
					require.NotContains(t, fresh.DNSStatus().Servers, fmt.Sprintf("127.0.0.1:%d", cfg.DNS.ListenPort))
					require.NoError(t, fresh.Close())
					prefix := strings.TrimSuffix(strings.Split(cfg.Core.Network, "/")[0], ".1") + "."
					require.Eventually(t, func() bool {
						ips, err := darwinOSLookup(name)
						return err == nil && len(ips) == 1 && strings.HasPrefix(ips[0], prefix)
					}, 8*time.Second, 50*time.Millisecond, "real OS resolver must reach KONE Fake-IP DNS")
					cancel()
					require.NoError(t, wait())
					require.NoError(t, one.Close())
				}
				darwinAssertOwnedGone(t, one)
				require.Eventually(t, func() bool {
					ips, err := darwinOSLookup("after-" + name)
					return err == nil && reflect.DeepEqual(ips, []string{"192.0.2.9"})
				}, 8*time.Second, 50*time.Millisecond, "stopping/late rollback must restore the original temporary resolver")
			})
		}
	}
}

func darwinLogDNSDiagnostic(t *testing.T, err error) {
	t.Helper()
	var diagnostic interface{ SystemDNSDiagnostic() string }
	if errors.As(err, &diagnostic) {
		t.Log(diagnostic.SystemDNSDiagnostic())
	}
}
