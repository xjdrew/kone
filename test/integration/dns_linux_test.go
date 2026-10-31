package integration

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestSystemDNSTCPPortFailureRollsBack(t *testing.T) {
	cfg := systemConfig(t)
	occupied, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	cfg.DNS.ListenPort = uint16(occupied.Addr().(*net.TCPAddr).Port)
	one, err := kone.FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := one.Run(context.Background()); err == nil {
		t.Fatal("occupied DNS TCP port did not fail startup")
	}
	if err := one.Close(); err != nil {
		t.Fatal(err)
	}
	noSystemInterface(t, cfg)
}

func TestSystemDNSTransportsAndExclusiveSplitResolver(t *testing.T) {
	cfg := systemConfig(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	packet, err := net.ListenPacket("udp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	var udpCount, tcpCount atomic.Int32
	readyUDP, readyTCP := make(chan struct{}), make(chan struct{})
	udp := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		udpCount.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		response.Truncated = true
		w.WriteMsg(response)
	}), NotifyStartedFunc: func() { close(readyUDP) }}
	tcp := &dns.Server{Listener: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		tcpCount.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		header := dns.RR_Header{Name: request.Question[0].Name, Rrtype: request.Question[0].Qtype, Class: dns.ClassINET, Ttl: 60}
		if request.Question[0].Qtype == dns.TypeAAAA {
			response.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::53")}}
		} else {
			response.Answer = []dns.RR{&dns.A{Hdr: header, A: net.ParseIP("192.0.2.53")}}
		}
		w.WriteMsg(response)
	}), NotifyStartedFunc: func() { close(readyTCP) }}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); udp.ActivateAndServe() }()
	go func() { defer workers.Done(); tcp.ActivateAndServe() }()
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown(); workers.Wait() })
	for _, ready := range []chan struct{}{readyUDP, readyTCP} {
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("local DNS fixture did not start")
		}
	}
	cfg.DNS.Servers = []string{"127.0.0.1:1"}
	cfg.DNS.Rules = []kone.DNSRouteConfig{{Suffix: "corp", Servers: []string{listener.Addr().String()}}}
	cfg.Outbounds = []kone.OutboundConfig{{Name: "office", URL: "http://127.0.0.1:1"}}
	cfg.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: "virtual.example", Outbound: "office"}, {Schema: "FINAL", Outbound: kone.BuiltinDirect}}
	one, stop, done := systemStart(t, cfg)
	address := fmt.Sprintf("10.203.0.1:%d", cfg.DNS.ListenPort)
	for _, transport := range []string{"udp", "tcp"} {
		for _, question := range []struct {
			name string
			kind uint16
		}{{"db.corp.", dns.TypeA}, {"v6.corp.", dns.TypeAAAA}, {"virtual.example.", dns.TypeA}} {
			request := new(dns.Msg)
			request.SetQuestion(question.name, question.kind)
			response, _, err := (&dns.Client{Net: transport, Timeout: 2 * time.Second}).Exchange(request, address)
			if err != nil || response == nil || response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
				t.Fatalf("%s %s: %v %v", transport, question.name, response, err)
			}
		}
	}
	if udpCount.Load() != 2 || tcpCount.Load() != 2 {
		t.Fatalf("cache/retry counts: UDP=%d TCP=%d", udpCount.Load(), tcpCount.Load())
	}
	events := one.DNSQueries()
	if len(events) != 6 || events[0].Transport != "tcp" {
		t.Fatalf("DNS query history: %+v", events)
	}
	seen := false
	for _, event := range events {
		if event.Upstream == listener.Addr().String() && event.UpstreamTransport == "tcp" && event.Route == "corp" {
			seen = true
		}
	}
	if !seen {
		t.Fatal("history did not record exclusive split upstream and TCP retry")
	}
	stop()
	if err := systemWait(t, done); err != nil {
		t.Fatal(err)
	}
	noSystemInterface(t, cfg)
}
