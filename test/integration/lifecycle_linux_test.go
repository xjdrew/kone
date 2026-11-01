package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pelletier/go-toml/v2"
	singtun "github.com/sagernet/sing-tun"
	"github.com/xjdrew/kone/pkg/kone"
)

var systemDNSSequence atomic.Uint32

// The system stack allocates kernel TCP forwarder ports before DNS listeners.
// Keep the fixture's shared UDP/TCP DNS port below Linux's default ephemeral
// range, and check both transports so previous TCP sessions cannot collide.
func availableSystemDNSPort(t *testing.T) int {
	t.Helper()
	for range 128 {
		port := 20000 + int((systemDNSSequence.Add(1)-1)%10000)
		address := fmt.Sprintf("0.0.0.0:%d", port)
		packet, err := net.ListenPacket("udp4", address)
		if err != nil {
			continue
		}
		listener, err := net.Listen("tcp4", address)
		packet.Close()
		if err != nil {
			continue
		}
		listener.Close()
		return port
	}
	t.Fatal("could not select a shared UDP/TCP DNS fixture port")
	return 0
}

// These tests run only in a root-owned, isolated Linux network namespace in CI.
func systemConfig(t *testing.T) *kone.KoneConfig {
	t.Helper()
	if os.Getenv("KONE_SYSTEM_TEST") != "1" {
		t.Skip("requires isolated network namespace and TUN")
	}
	for _, key := range []string{"http_proxy", "https_proxy", "socks_proxy", "HTTP_PROXY", "HTTPS_PROXY", "SOCKS_PROXY"} {
		t.Setenv(key, "")
	}
	dnsPort := availableSystemDNSPort(t)
	cfg, err := kone.ParseConfig([]byte(fmt.Sprintf(`[core]
tun="kone-e2e"
network="10.203.0.1/24"
[dns]
servers=["127.0.0.1:5353"]
listen-port=%d
`, dnsPort)))
	if err != nil {
		t.Fatal(err)
	}
	if stack := os.Getenv("KONE_TEST_STACK"); stack != "" {
		cfg.Core.Stack = stack
	}
	return cfg
}

func systemCommand(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v: %v %s", args, err, out)
	}
	return string(out)
}
func noSystemInterface(t *testing.T, cfg *kone.KoneConfig) {
	t.Helper()
	if _, err := net.InterfaceByName(cfg.Core.Tun); err == nil {
		t.Fatal("TUN interface leaked")
	}
}
func systemWait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("engine did not terminate")
		return nil
	}
}
func systemStart(t *testing.T, cfg *kone.KoneConfig) (*kone.One, context.CancelFunc, <-chan error) {
	t.Helper()
	one, err := kone.FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- one.Run(ctx) }()
	t.Cleanup(func() { cancel(); one.Close() })
	select {
	case <-one.Ready():
	case err := <-done:
		t.Fatalf("start: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("engine did not become ready")
	}
	return one, cancel, done
}

func TestSystemLifecyclePortFailure(t *testing.T) {
	for _, kind := range []string{"dns", "dns-tcp"} {
		t.Run(kind, func(t *testing.T) {
			cfg := systemConfig(t)
			var occupied io.Closer
			if kind == "dns-tcp" {
				ln, err := net.Listen("tcp4", "0.0.0.0:0")
				if err != nil {
					t.Fatal(err)
				}
				occupied = ln
				port := ln.Addr().(*net.TCPAddr).Port
				cfg.DNS.ListenPort = uint16(port)
			} else {
				conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
				if err != nil {
					t.Fatal(err)
				}
				occupied = conn
				port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
				cfg.DNS.ListenPort = port
			}
			defer occupied.Close()
			one, err := kone.FromConfig(cfg)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- one.Run(context.Background()) }()
			if err := systemWait(t, done); err == nil {
				t.Fatal("occupied port did not fail startup")
			}
			if err := one.Close(); err != nil {
				t.Fatal(err)
			}
			noSystemInterface(t, cfg)
		})
	}
}

func TestSystemLifecycleRouteFailure(t *testing.T) {
	cfg := systemConfig(t)
	systemCommand(t, "route", "add", "203.0.113.0/24", "dev", "lo")
	defer systemCommand(t, "route", "del", "203.0.113.0/24", "dev", "lo")
	cfg.Rule = []kone.RuleConfig{{Schema: "IP-CIDR", Pattern: "198.51.100.0/24", Outbound: kone.BuiltinReject}, {Schema: "IP-CIDR", Pattern: "203.0.113.0/24", Outbound: kone.BuiltinReject}}
	one, err := kone.FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := one.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "add route") {
		t.Fatalf("expected route failure, got %v", err)
	}
	if err := one.Close(); err != nil {
		t.Fatal(err)
	}
	noSystemInterface(t, cfg)
	if routes := systemCommand(t, "route", "show", "198.51.100.0/24"); routes != "" {
		t.Fatalf("owned route leaked: %s", routes)
	}
	if routes := systemCommand(t, "route", "show", "203.0.113.0/24"); !strings.Contains(routes, "dev lo") {
		t.Fatalf("pre-existing route removed: %s", routes)
	}
}

func TestSystemLifecycleExclusiveDevice(t *testing.T) {
	cfg := systemConfig(t)
	cfg.Rule = []kone.RuleConfig{{Schema: "FINAL", Outbound: kone.BuiltinReject}}
	_, cancel, done := systemStart(t, cfg)
	// Bypass KONE's friendly name precheck and exercise kernel-level exclusive
	// creation, protecting against two processes racing that precheck.
	duplicate, err := singtun.New(singtun.Options{Name: cfg.Core.Tun, MTU: 1500, EXP_ExternalConfiguration: true, EXP_Exclusive: true})
	if err == nil {
		duplicate.Close()
		t.Fatal("existing TUN was attached by another owner")
	}
	query := new(dns.Msg)
	query.SetQuestion("ownership.example.", dns.TypeA)
	answer, _, err := (&dns.Client{Timeout: time.Second}).Exchange(query, fmt.Sprintf("10.203.0.1:%d", cfg.DNS.ListenPort))
	if err != nil || answer.Rcode != dns.RcodeRefused {
		t.Fatalf("original engine damaged: %v %v", err, answer)
	}
	cancel()
	if err := systemWait(t, done); err != nil {
		t.Fatal(err)
	}
	noSystemInterface(t, cfg)
}

func TestSystemLifecycleConcurrentClose(t *testing.T) {
	for range 3 {
		cfg := systemConfig(t)
		cfg.Rule = []kone.RuleConfig{{Schema: "FINAL", Outbound: kone.BuiltinReject}}
		one, _, done := systemStart(t, cfg)
		// Exercise a live DNS TCP listener before concurrent cleanup.
		query := new(dns.Msg)
		query.SetQuestion("shutdown.example.", dns.TypeA)
		answer, _, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(query, fmt.Sprintf("10.203.0.1:%d", cfg.DNS.ListenPort))
		if err != nil || answer == nil || answer.Rcode != dns.RcodeRefused {
			t.Fatalf("DNS TCP admission: %v %v", err, answer)
		}
		results := make(chan error, 8)
		var workers sync.WaitGroup
		for range cap(results) {
			workers.Add(1)
			go func() { defer workers.Done(); results <- one.Close() }()
		}
		workers.Wait()
		for range cap(results) {
			if err := <-results; err != nil {
				t.Fatalf("concurrent DNS shutdown: %v", err)
			}
		}
		if err := systemWait(t, done); err != nil {
			t.Fatal(err)
		}
		noSystemInterface(t, cfg)
		listener, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", cfg.DNS.ListenPort))
		if err != nil {
			t.Fatalf("DNS TCP listener leaked: %v", err)
		}
		listener.Close()
	}
}

func localConnectProxy(t *testing.T, body string) *httptest.Server {
	t.Helper()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	t.Cleanup(web.Close)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			http.Error(w, "CONNECT required", 400)
			return
		}
		target, err := net.Dial("tcp", web.Listener.Addr().String())
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer target.Close()
		client, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		buf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		buf.Flush()
		done := make(chan struct{})
		go func() { io.Copy(target, buf); target.Close(); close(done) }()
		io.Copy(client, target)
		client.Close()
		<-done
	}))
	t.Cleanup(proxy.Close)
	return proxy
}

func TestSystemLifecycleTrafficAndReload(t *testing.T) {
	cfg := systemConfig(t)
	oldProxy, newProxy := localConnectProxy(t, "old"), localConnectProxy(t, "new")
	cfg.Outbounds = append(cfg.Outbounds, kone.OutboundConfig{Name: "A", URL: oldProxy.URL})
	cfg.Rule = []kone.RuleConfig{{Schema: "FINAL", Outbound: "A"}}
	one, cancel, done := systemStart(t, cfg)
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	dnsClient := &dns.Client{Timeout: time.Second}
	answer, _, err := dnsClient.Exchange(request, fmt.Sprintf("10.203.0.1:%d", cfg.DNS.ListenPort))
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Answer) != 1 {
		t.Fatalf("invalid DNS answer: %v", answer)
	}
	ip := answer.Answer[0].(*dns.A).A.String()
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	get := func(want string) {
		t.Helper()
		response, err := client.Get("http://" + ip + ":80/")
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(data) != want {
			t.Fatalf("body=%q error=%v want=%q", data, err, want)
		}
	}
	get("old")
	updated := one.Snapshot().Config
	updated.Outbounds[len(updated.Outbounds)-1].URL = newProxy.URL
	if err := one.Reload(updated); err != nil {
		t.Fatal(err)
	}
	get("old") // established TCP flow retains its original proxy generation
	transport.CloseIdleConnections()
	get("new")
	answer, _, err = dnsClient.Exchange(request, fmt.Sprintf("10.203.0.1:%d", cfg.DNS.ListenPort))
	if err != nil {
		t.Fatal(err)
	}
	if got := answer.Answer[0].(*dns.A).A.String(); got != ip {
		t.Fatalf("reload changed virtual IP: %s -> %s", ip, got)
	}
	transport.CloseIdleConnections()
	cancel()
	if err := systemWait(t, done); err != nil {
		t.Fatal(err)
	}
	noSystemInterface(t, cfg)
}

func TestSystemLifecycleCLISignal(t *testing.T) {
	cfg := systemConfig(t)
	cfg.Rule = []kone.RuleConfig{{Schema: "FINAL", Outbound: kone.BuiltinReject}}
	// File mode must not bind its former unauthenticated HTTP default. Owning
	// that port independently must have no effect on real capture or cleanup.
	legacy, err := net.Listen("tcp4", "127.0.0.1:9200")
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	path := os.Getenv("KONE_SYSTEM_CLI")
	if path == "" {
		t.Fatal("KONE_SYSTEM_CLI is missing")
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-config", filename)
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill() }()
	client := &dns.Client{Net: "tcp", Timeout: 100 * time.Millisecond}
	query := new(dns.Msg)
	query.SetQuestion("cli-ready.example.", dns.TypeA)
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response, _, err := client.Exchange(query, fmt.Sprintf("10.203.0.1:%d", cfg.DNS.ListenPort))
		if err == nil && response != nil && response.Rcode == dns.RcodeRefused {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("CLI not ready: %s", &logs)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("signal exit: %v: %s", err, &logs)
	}
	noSystemInterface(t, cfg)
}
