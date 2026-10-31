package kone

import (
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestConcurrentSnapshotGenerations(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	initial := one.policy.Load()
	a, b := one.Snapshot().Config, one.Snapshot().Config
	setTestOutbound(a, "A", "http://127.0.0.1:8081")
	a.Rule[0].Outbound = "A"
	setTestOutbound(b, "A", "http://127.0.0.1:8082")
	b.Rule[0].Outbound = "B"
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				s := one.policy.Load()
				target := s.rule.Proxy("example.com")
				if s.version > 1 && ((outboundByName(s.cfg, "A").URL == outboundByName(a, "A").URL && target != "A") || (outboundByName(s.cfg, "A").URL == outboundByName(b, "A").URL && target != "B")) {
					t.Error("mixed policy generation")
					return
				}
				copy := one.Snapshot()
				setTestOutbound(copy.Config, "A", "caller mutation")
				copy.Config.Rule[0].Outbound = "caller mutation"
			}
		}()
	}
	for i := 0; i < 100; i++ {
		if i%2 == 0 {
			require.NoError(t, one.Reload(a))
		} else {
			require.NoError(t, one.Reload(b))
		}
	}
	wg.Wait()
	require.Equal(t, uint64(101), one.Snapshot().Version)
	require.Equal(t, "http://Proxy.Example.com:8080", outboundByName(initial.cfg, "A").URL)
	require.Equal(t, "A", initial.rule.Proxy("example.com"))
}

func TestReloadDoesNotWaitForUpstreamDNS(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer upstream.Close()
	one.dns.nameservers = []string{upstream.LocalAddr().String()}
	queryStarted := make(chan struct{})
	go func() { packet := make([]byte, 4096); upstream.ReadFrom(packet); close(queryStarted) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := one.dns.ResolveContext(ctx, "blocked.example"); done <- err }()
	select {
	case <-queryStarted:
	case <-time.After(time.Second):
		t.Fatal("upstream query not received")
	}
	updated := one.Snapshot().Config
	updated.Rule[0].Outbound = "B"
	reloaded := make(chan error, 1)
	go func() { reloaded <- one.Reload(updated) }()
	select {
	case err := <-reloaded:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("reload blocked on upstream")
	}
	cancel()
	require.ErrorIs(t, waitRun(t, done), context.Canceled)
}

func TestStaleDirectDNSCacheCannotOverrideReload(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	old := one.Snapshot().Version
	updated := one.Snapshot().Config
	updated.Rule[0].Outbound = "B"
	require.NoError(t, one.Reload(updated))
	one.dnsTable.SetNonProxyDomain("example.com", 600, old) // old lookup finishes after publication
	r := new(dns.Msg)
	r.SetQuestion("example.com.", dns.TypeA)
	answer, err := one.dns.doIPv4Query(r)
	require.NoError(t, err)
	require.Len(t, answer.Answer, 1)
	require.Equal(t, "B", policyFor(one, "example.com"))
}

func TestManagerConcurrentReadsAndBoundedStatistics(t *testing.T) {
	cleanProxyEnv(t)
	one := testEngine(t)
	m := NewManager(one, one.Snapshot().Config)
	handler := m.Handler()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1200; i++ {
			m.Record(ConnData{Src: "client", Dst: fmt.Sprint(i), Proxy: "A", Upload: 1, Download: 2})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 60; i++ {
			for _, path := range []string{"/", "/host/", "/website/", "/proxy/", "/dns/", "/config/"} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
				if w.Code != 200 {
					t.Errorf("%s: %d", path, w.Code)
				}
			}
		}
	}()
	wg.Wait()
	require.LessOrEqual(t, len(m.websites), 1024)
	require.LessOrEqual(t, len(m.hosts["client"].Details), 64)
	require.Positive(t, m.dropped.Load())
}
