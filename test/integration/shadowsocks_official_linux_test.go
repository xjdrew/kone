package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/proxy"
)

const officialSSImage = "ghcr.io/shadowsocks/ssserver-rust@sha256:22240c07d8ce3a36421ede770bd775dcc5fc56d5d829943196957b05452dc36f"

type officialEcho struct {
	tcp                net.Listener
	udp                net.PacketConn
	workers            sync.WaitGroup
	tcpBytes, udpBytes atomic.Int64
}

func officialEchoServer(t *testing.T) *officialEcho {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	packet, err := net.ListenPacket("udp4", listener.Addr().String())
	require.NoError(t, err)
	echo := &officialEcho{tcp: listener, udp: packet}
	echo.workers.Add(2)
	go func() {
		defer echo.workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			echo.workers.Add(1)
			go func() {
				defer echo.workers.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				buffer := make([]byte, 65535)
				for {
					n, err := conn.Read(buffer)
					if n > 0 {
						echo.tcpBytes.Add(int64(n))
						if _, writeErr := conn.Write(buffer[:n]); writeErr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	go func() {
		defer echo.workers.Done()
		buffer := make([]byte, 65535)
		for {
			n, source, err := packet.ReadFrom(buffer)
			if err != nil {
				return
			}
			echo.udpBytes.Add(int64(n))
			packet.WriteTo(buffer[:n], source)
		}
	}()
	t.Cleanup(func() { listener.Close(); packet.Close(); echo.workers.Wait() })
	return echo
}

func officialSSDNS(t *testing.T) *sync.Map {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:41083")
	require.NoError(t, err)
	queries := &sync.Map{}
	ready, done := make(chan struct{}), make(chan struct{})
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(r)
		if len(r.Question) == 1 {
			name := strings.ToLower(r.Question[0].Name)
			queries.Store(name, true)
			if !strings.HasSuffix(name, ".kone-interop.example.com.") {
				response.SetRcode(r, dns.RcodeNameError)
			} else if r.Question[0].Qtype == dns.TypeA {
				response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.IPv4(127, 0, 0, 1)}}
			}
		}
		w.WriteMsg(response)
	}), NotifyStartedFunc: func() { close(ready) }}
	go func() { defer close(done); server.ActivateAndServe() }()
	t.Cleanup(func() { server.Shutdown(); packet.Close(); <-done })
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("private official-server DNS did not start")
	}
	return queries
}

// This test is executed only inside the digest-pinned official server image,
// with --network none. It never opens a host TUN or changes resolver settings.
func TestOfficialShadowsocksRustInterop(t *testing.T) {
	if os.Getenv("KONE_SS_OFFICIAL_TEST") != "1" {
		t.Skip("requires isolated CI official server container")
	}
	require.Equal(t, "true", os.Getenv("GITHUB_ACTIONS"))
	require.Equal(t, officialSSImage, os.Getenv("KONE_SS_OFFICIAL_IMAGE"))
	version, err := exec.Command("/usr/bin/ssserver", "--version").CombinedOutput()
	require.NoError(t, err)
	require.Contains(t, string(version), "1.25.0")
	t.Logf("Official server: %s; image: %s", strings.TrimSpace(string(version)), officialSSImage)
	queries := officialSSDNS(t)
	for index := 0; index < 3; index++ {
		address := fmt.Sprintf("127.0.0.1:%d", 41080+index)
		deadline := time.Now().Add(5 * time.Second)
		for {
			conn, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
			if err == nil {
				conn.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("official server listener unavailable: %v", err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	previous := net.DefaultResolver
	var localDNS atomic.Int32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		localDNS.Add(1)
		return nil, errors.New("client-side business DNS is forbidden in SS interop")
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	for index, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			server := fmt.Sprintf("127.0.0.1:%d", 41080+index)
			echo := officialEchoServer(t)
			_, port, _ := net.SplitHostPort(echo.tcp.Addr().String())
			p, err := proxy.FromUrl("ss://" + url.UserPassword(method, "kone-ci-only-fixture").String() + "@" + server)
			require.NoError(t, err)
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				require.Equal(t, server, address, "only the literal proxy endpoint may be dialed by the client")
				return proxy.Direct.DialContext(ctx, network, address)
			}
			for _, network := range []string{"tcp", "udp"} {
				name := network + "-" + method + ".kone-interop.example.com"
				target := net.JoinHostPort(name, port)
				var conn net.Conn
				if network == "tcp" {
					conn, err = p.DialContextVia(context.Background(), "tcp", target, dial)
				} else {
					conn, err = p.DialUDPContextVia(context.Background(), target, dial)
				}
				require.NoError(t, err)
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				payload := []byte(method + "/" + network + " verified official echo")
				_, err = conn.Write(payload)
				require.NoError(t, err)
				response := make([]byte, len(payload))
				_, err = io.ReadFull(conn, response)
				conn.Close()
				require.NoError(t, err)
				require.Equal(t, payload, response)
				_, resolved := queries.Load(dns.Fqdn(name))
				require.True(t, resolved, "the official server must resolve the original domain using its private DNS")
			}
			bad, err := proxy.FromUrl("ss://" + url.UserPassword(method, "incorrect-ci-fixture").String() + "@" + server)
			require.NoError(t, err)
			beforeTCP, beforeUDP := echo.tcpBytes.Load(), echo.udpBytes.Load()
			for _, network := range []string{"tcp", "udp"} {
				var conn net.Conn
				if network == "tcp" {
					conn, err = bad.DialContextVia(context.Background(), "tcp", echo.tcp.Addr().String(), dial)
				} else {
					conn, err = bad.DialUDPContextVia(context.Background(), echo.tcp.Addr().String(), dial)
				}
				if err != nil {
					continue
				}
				conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
				_, writeErr := conn.Write([]byte("must not reach echo"))
				if writeErr == nil {
					count, readErr := conn.Read(make([]byte, 64))
					err = readErr
					require.Zero(t, count)
					require.Error(t, err, "wrong password must never return authenticated payload")
				}
				conn.Close()
			}
			require.Equal(t, beforeTCP, echo.tcpBytes.Load())
			require.Equal(t, beforeUDP, echo.udpBytes.Load())
			ctx, cancel := context.WithCancel(context.Background())
			association, err := p.DialUDPContextVia(ctx, echo.tcp.Addr().String(), dial)
			require.NoError(t, err)
			association.SetDeadline(time.Now().Add(2 * time.Second))
			_, err = association.Write([]byte("cancel"))
			require.NoError(t, err)
			confirmed := make([]byte, 6)
			_, err = association.Read(confirmed)
			require.NoError(t, err)
			require.Equal(t, "cancel", string(confirmed))
			reading := make(chan error, 1)
			go func() { _, err := association.Read(make([]byte, 64)); reading <- err }()
			cancel()
			select {
			case err := <-reading:
				require.Error(t, err)
			case <-time.After(time.Second):
				t.Fatal("cancelled official UDP association did not unblock")
			}
			association.Close()
			_, err = p.DialContextVia(ctx, "tcp", echo.tcp.Addr().String(), dial)
			require.ErrorIs(t, err, context.Canceled)
		})
	}
	require.Zero(t, localDNS.Load(), "remote resolution must not leak business queries to the client's resolver")
	report := map[string]any{"server": "shadowsocks-rust", "version": "1.25.0", "source": "ab388c7466d21f979430e33cc9ef10e22fb05955", "image": officialSSImage, "transport": []string{"tcp", "udp"}, "methods": []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}, "remote_domain_dns": true, "incorrect_password_rejected": true, "udp_cancel_unblocked": true, "client_dns_queries": localDNS.Load(), "network": "isolated loopback only (--network none)", "time": time.Now().UTC()}
	data, err := json.MarshalIndent(report, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile("/tmp/shadowsocks-interop.json", append(data, '\n'), 0600))
}
