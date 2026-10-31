package integration

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xjdrew/kone/pkg/kone"
)

type occupiedWindowsDNS struct{ net.ListenConfig }

func (s *occupiedWindowsDNS) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	// Bind the exact newly created TUN address. Windows wildcard UDP sharing
	// does not provide a reliable occupied-port fault on a different adapter.
	occupied, err := s.ListenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("fault reservation: %w", err)
	}
	defer occupied.Close()
	return s.ListenConfig.ListenPacket(ctx, network, address)
}

// Opt in only on a privileged, disposable Windows CI runner. Ordinary tests
// never install drivers or change the developer's adapters/firewall.
func TestSystemWindowsWintun(t *testing.T) {
	if os.Getenv("KONE_WINDOWS_SYSTEM_TEST") != "1" {
		t.Skip("requires disposable administrator Windows runner")
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "SOCKS_PROXY"} {
		t.Setenv(key, "")
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			http.Error(w, "CONNECT required", 400)
			return
		}
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		buffer.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		buffer.Flush()
		request, err := http.ReadRequest(buffer.Reader)
		if err != nil {
			return
		}
		request.Body.Close()
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nwintun")
	}))
	defer proxy.Close()
	for _, stack := range []string{"system", "mixed"} {
		for _, fail := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/occupied=%t", stack, fail), func(t *testing.T) {
				port, err := net.ListenPacket("udp4", "0.0.0.0:0")
				if err != nil {
					t.Fatal(err)
				}
				dnsPort := port.LocalAddr().(*net.UDPAddr).Port
				port.Close()
				name := fmt.Sprintf("kone-ci-%d", os.Getpid())
				cfg, err := kone.ParseConfig([]byte(fmt.Sprintf(`[general]
manager-addr=""
[core]
tun="%s"
stack="%s"
network="10.204.0.1/24"
dns-listen-port=%d
dns-server=["1.1.1.1"]
[proxies]
Win="%s"
[[rules]]
type="FINAL"
proxy="Win"
`, name, stack, dnsPort, proxy.URL)))
				if err != nil {
					t.Fatal(err)
				}
				var options []kone.Option
				if fail {
					options = append(options, kone.WithSockets(&occupiedWindowsDNS{}))
				}
				one, err := kone.FromConfig(cfg, options...)
				if err != nil {
					t.Fatal(err)
				}
				// The first Wintun creation on a clean runner also installs the
				// signed driver. Allow that cold path; fault cases still must return
				// the actual listener error, never a generic configuration failure.
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- one.Run(ctx) }()
				t.Cleanup(func() { cancel(); one.Close() })
				if fail {
					select {
					case err := <-done:
						if err == nil || !strings.Contains(err.Error(), "DNS listener") || strings.Contains(err.Error(), "fault reservation") {
							t.Fatalf("expected occupied DNS listener error, got %v", err)
						}
					case <-one.Ready():
						t.Fatal("occupied DNS listener was accepted")
					case <-ctx.Done():
						t.Fatal("startup did not fail promptly")
					}
				} else {
					select {
					case <-one.Ready():
					case err := <-done:
						t.Fatalf("Wintun startup: %v", err)
					case <-ctx.Done():
						t.Fatal("Wintun startup timed out")
					}
					query := new(dns.Msg)
					query.SetQuestion("wintun.example.", dns.TypeA)
					answer, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(query, fmt.Sprintf("10.204.0.1:%d", dnsPort))
					if err != nil || len(answer.Answer) != 1 {
						t.Fatalf("Wintun DNS: %v %v", err, answer)
					}
					client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
					response, err := client.Get("http://" + answer.Answer[0].(*dns.A).A.String() + "/")
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil || string(body) != "wintun" {
						t.Fatalf("Wintun traffic: %q %v", body, err)
					}
					cancel()
					select {
					case err := <-done:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(30 * time.Second):
						t.Fatal("Wintun shutdown timed out")
					}
				}
				if err := one.Close(); err != nil {
					t.Fatal(err)
				}
				for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
					if _, err := net.InterfaceByName(name); err != nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("owned Wintun adapter leaked")
					}
				}
			})
		}
	}
}
