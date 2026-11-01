package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xjdrew/kone/pkg/kone"
)

func privateResolvedCommand(t *testing.T, args ...string) string {
	t.Helper()
	if os.Getenv("KONE_SYSTEM_DNS_TEST") != "1" || os.Getenv("DBUS_SYSTEM_BUS_ADDRESS") != "unix:path=/run/dbus/system_bus_socket" {
		t.Skip("requires private mount/network namespaces and D-Bus daemon")
	}
	for _, kind := range []string{"net", "mnt"} {
		self, selfErr := os.Readlink("/proc/self/ns/" + kind)
		init, initErr := os.Readlink("/proc/1/ns/" + kind)
		if selfErr != nil || initErr != nil || self == init {
			t.Fatal("refusing DNS test in runner host namespace")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// The harness deliberately enables resolver debug logs. Only stdout is the
	// stable configuration evidence; stderr contains per-call D-Bus cookies.
	out, err := exec.CommandContext(ctx, "resolvectl", append([]string{"--no-pager"}, args...)...).Output()
	if err != nil {
		var detail string
		if exit, ok := err.(*exec.ExitError); ok {
			detail = string(exit.Stderr)
		}
		t.Fatalf("private resolvectl %v: %v %s %s", args, err, out, detail)
	}
	return string(out)
}

func privateResolvedFixture(t *testing.T) (string, string) {
	t.Helper()
	privateResolvedCommand(t, "status") // Refuse an ordinary privileged test run.
	if err := kone.CheckSystemDNS(context.Background(), kone.DNSConfig{System: true}); err != nil {
		t.Fatalf("private resolver ownership check before any mutation: %v", err)
	}
	packet, err := net.ListenPacket("udp4", "192.0.2.53:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	server := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		if request.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.IPv4(192, 0, 2, 9)}}
		}
		_ = w.WriteMsg(response)
	})}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown(); <-done })
	<-ready
	upstream := packet.LocalAddr().String()
	privateResolvedCommand(t, "dns", "upstream-test", upstream)
	privateResolvedCommand(t, "default-route", "upstream-test", "yes")
	privateResolvedCommand(t, "dnssec", "upstream-test", "no")
	privateResolvedCommand(t, "dnsovertls", "upstream-test", "no")
	before := privateResolvedCommand(t, "dns", "upstream-test")
	return upstream, before
}

func TestSystemDNSOwnedLinkGuidanceAndRestore(t *testing.T) {
	_, before := privateResolvedFixture(t)
	cfg := systemConfig(t)
	cfg.DNS.System = true
	// Read the real original link resolver before changing the OS stub route.
	cfg.DNS.Servers = nil
	cfg.Outbounds = []kone.OutboundConfig{{Name: "offline-proxy", URL: "http://127.0.0.1:1"}}
	cfg.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: "virtual.example.test", Outbound: "offline-proxy"}, {Schema: "FINAL", Outbound: kone.BuiltinDirect}}
	if err := kone.CheckSystemDNS(context.Background(), cfg.DNS); err != nil {
		t.Fatal(err)
	}
	_, stop, done := systemStart(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := (&net.Resolver{PreferGo: true}).LookupIP(ctx, "ip4", "virtual.example.test")
	if err != nil || len(addresses) != 1 || !strings.HasPrefix(addresses[0].String(), "10.203.0.") {
		t.Fatalf("OS stub did not use KONE Fake-IP: %v %v", addresses, err)
	}
	addresses, err = (&net.Resolver{PreferGo: true}).LookupIP(ctx, "ip4", "active-direct.example.test")
	if err != nil || len(addresses) != 1 || addresses[0].String() != "192.0.2.9" {
		t.Fatalf("KONE did not use the original real upstream (possible stub recursion): %v %v", addresses, err)
	}
	if after := privateResolvedCommand(t, "dns", "upstream-test"); after != before {
		t.Fatalf("physical DNS changed: %s -> %s", before, after)
	}
	stop()
	if err := systemWait(t, done); err != nil {
		t.Fatal(err)
	}
	noSystemInterface(t, cfg)
	addresses, err = (&net.Resolver{PreferGo: true}).LookupIP(ctx, "ip4", "after.example.test")
	if err != nil || len(addresses) != 1 || addresses[0].String() != "192.0.2.9" {
		t.Fatalf("OS resolver did not return to original DNS: %v %v", addresses, err)
	}
	if after := privateResolvedCommand(t, "dns", "upstream-test"); after != before {
		t.Fatal("shutdown modified original link DNS")
	}
}

type failedManagerListener struct{ net.Listener }

func (l failedManagerListener) Accept() (net.Conn, error) {
	return nil, errors.New("injected manager admission failure")
}

type failedManagerSockets struct {
	net.ListenConfig
	manager string
}

func (s failedManagerSockets) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	listener, err := s.ListenConfig.Listen(ctx, network, address)
	if err == nil && address == s.manager {
		return failedManagerListener{listener}, nil
	}
	return listener, err
}

func TestSystemDNSOwnedLinkRollsBackLateStartupFailure(t *testing.T) {
	upstream, before := privateResolvedFixture(t)
	cfg := systemConfig(t)
	cfg.DNS.System = true
	cfg.DNS.Servers = []string{upstream}
	one, err := kone.FromConfig(cfg, kone.WithSockets(&failedManagerSockets{manager: cfg.General.ManagerAddr}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = one.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "manager") {
		t.Fatalf("expected injected late failure: %v", err)
	}
	if err := one.Close(); err != nil {
		t.Fatal(fmt.Errorf("cleanup: %w", err))
	}
	noSystemInterface(t, cfg)
	if after := privateResolvedCommand(t, "dns", "upstream-test"); after != before {
		t.Fatal("failed startup modified original DNS")
	}
}
