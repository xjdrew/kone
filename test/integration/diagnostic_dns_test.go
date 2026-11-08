package integration

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestDNSComparisonUsesOSAndKONEThroughAuthenticatedAPIWithoutCapture(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg).SetReply(r)
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.45")}}
		_ = w.WriteMsg(reply)
	})}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	<-ready
	defer func() { require.NoError(t, server.Shutdown()); require.NoError(t, <-done) }()
	var captures atomic.Int32
	manager, err := control.New(control.Options{Directory: t.TempDir(), Factory: func(*kone.KoneConfig) (control.Engine, error) {
		captures.Add(1)
		return &isolatedEngine{ready: make(chan struct{}), stop: make(chan struct{})}, nil
	}})
	require.NoError(t, err)
	defer manager.Close()
	call := recoveryConsole(t, manager)
	status, doc := call("GET", "config", nil)
	require.Equal(t, 200, status)
	config := doc["config"].(map[string]any)
	settings := config["dns"].(map[string]any)
	settings["servers"] = []string{listener.LocalAddr().String()}
	status, _ = call("PUT", "config", map[string]any{"base_version": doc["version"], "config": config, "inbound": doc["inbound"]})
	require.Equal(t, 200, status)
	status, operation := call("POST", "diagnostics/dns", map[string]any{"name": "localhost", "type": "A"})
	require.Equal(t, 202, status)
	var result map[string]any
	require.Eventually(t, func() bool {
		status, result = call("GET", "operations/"+operation["id"].(string), nil)
		return status == 200 && result["status"] != "running"
	}, 3*time.Second, 5*time.Millisecond)
	require.Equal(t, "succeeded", result["status"])
	rows := result["result"].(map[string]any)["results"].([]any)
	require.Len(t, rows, 2)
	system := rows[0].(map[string]any)
	builtIn := rows[1].(map[string]any)
	require.Equal(t, "system", system["outbound"])
	require.Equal(t, "answered", system["status"])
	require.Contains(t, system["dns_answers"], "127.0.0.1")
	require.Equal(t, "kone", builtIn["outbound"])
	require.Equal(t, "answered", builtIn["status"])
	require.Contains(t, builtIn["dns_answers"].([]any)[0], "192.0.2.45")
	require.Equal(t, "saved_configuration", builtIn["scope"])
	require.Zero(t, captures.Load(), "DNS comparison cannot create or start a capture engine")
	status, state := call("GET", "state", nil)
	require.Equal(t, 200, status)
	require.Equal(t, "paused", state["state"])
}
