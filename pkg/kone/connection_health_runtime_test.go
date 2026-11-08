package kone

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func healthTestEngine(t *testing.T) (*One, *connectionHealth, healthEvent) {
	one, _ := smartTestEngine(t, "direct-first")
	one.health = newConnectionHealth(one)
	h := one.health
	h.ctx, h.cancel = context.WithCancel(t.Context())
	t.Cleanup(h.cancel)
	h.network = "test-network"
	message := layeredAnswer("service.example", "8.8.8.8")
	for _, rr := range message.Answer {
		rr.Header().Ttl = 300
	}
	e := healthEvent{domain: "service.example", message: message, version: one.policy.Load().version}
	h.resolveLocal = func(context.Context, string) (*dns.Msg, error) { return message.Copy(), nil }
	h.probeDial = func(_ context.Context, outbound, target string, tls bool, version uint64, plan diagnosticProbePlan) (DiagnosticResult, error) {
		host, port, err := net.SplitHostPort(target)
		require.NoError(t, err)
		require.Equal(t, "8.8.8.8", host)
		require.Equal(t, port == "443", tls)
		require.Equal(t, "service.example", plan.serverName)
		require.Equal(t, uint64(7), version)
		status := "failed"
		if outbound == "office" {
			status = "reachable"
		}
		return DiagnosticResult{Status: status, Stage: "connect", DurationMS: 12}, nil
	}
	return one, h, e
}
func TestHealthMonitorsWithoutAutoAndAppliesOnlyVerifiedFinalChoices(t *testing.T) {
	one, h, e := healthTestEngine(t)
	h.check(e)
	state, err := one.HealthData(HealthQuery{})
	require.NoError(t, err)
	require.Len(t, state.Entries, 1)
	require.Equal(t, "attention", state.Entries[0].Status)
	require.Len(t, state.Entries[0].Suggestions, 2)
	decision := one.policy.Load().rule.DecideDNS(e.domain, e.message, "tcp", 80)
	require.Equal(t, BuiltinDirect, h.route(e.domain, 80, "tcp", decision, one.policy.Load()).Outbound)
	a := HealthAction{Action: "apply", Domain: e.domain, Generation: state.Entries[0].Generation, Version: 7}
	_, err = one.HealthAction(a)
	require.NoError(t, err)
	require.Equal(t, "office", h.route(e.domain, 80, "tcp", decision, one.policy.Load()).Outbound)
	protected := decision
	protected.Protected = true
	require.Equal(t, BuiltinDirect, h.route(e.domain, 80, "tcp", protected, one.policy.Load()).Outbound)
	manual := decision
	manual.DecisionSource = "user-rule"
	require.Equal(t, BuiltinDirect, h.route(e.domain, 80, "tcp", manual, one.policy.Load()).Outbound)
	h.invalidate()
	require.Equal(t, BuiltinDirect, h.route(e.domain, 80, "tcp", decision, one.policy.Load()).Outbound)
}
func TestHealthAutoRequiresRepeatAndFreshEvidenceAndCanPin(t *testing.T) {
	one, h, e := healthTestEngine(t)
	one.policy.Load().cfg.Policy.Smart.AutoEnabled = true
	h.check(e)
	require.Empty(t, h.choices)
	h.failures[healthKey(e.domain, "")] = time.Now().Add(-31 * time.Second)
	h.tokens = 6
	h.check(e)
	require.Len(t, h.choices[healthKey(e.domain, "")], 2)
	state, err := one.HealthData(HealthQuery{})
	require.NoError(t, err)
	require.Equal(t, "adjusted", state.Entries[0].Status)
	_, err = one.HealthAction(HealthAction{Action: "pin", Domain: e.domain, Generation: state.Entries[0].Generation, Version: 7})
	require.NoError(t, err)
	h.evidence[healthKey(e.domain, "")] = healthEvidence{expires: time.Now().Add(-time.Minute)}
	_, err = one.HealthAction(HealthAction{Action: "pin", Domain: e.domain, Generation: state.Entries[0].Generation, Version: 7})
	require.Error(t, err)
	h.choices = map[string]map[uint16]healthChoice{}
	state, err = one.HealthData(HealthQuery{Status: "adjusted"})
	require.NoError(t, err)
	require.Equal(t, "adjusted", state.Entries[0].Status, "expired evidence must not remove the row from its filter")
	require.True(t, state.Entries[0].Checking)
}
func TestHealthDNSFailureRetestAndPrivateScope(t *testing.T) {
	one, h, e := healthTestEngine(t)
	_, err := h.ledger.Observe(e.domain, "", "dns_failed", HealthResult{Protocol: "dns", Source: "business", Status: "failed", Time: time.Now()})
	require.NoError(t, err)
	h.probeDial = func(context.Context, string, string, bool, uint64, diagnosticProbePlan) (DiagnosticResult, error) {
		return DiagnosticResult{Status: "reachable"}, nil
	}
	h.check(e)
	state, _ := one.HealthData(HealthQuery{})
	require.Equal(t, "history", state.Entries[0].Status)
	require.Equal(t, "retest", state.Entries[0].Resolution)
	e.scope = "corp"
	h.resolveLocal = func(context.Context, string) (*dns.Msg, error) {
		t.Fatal("private scope must not trigger public probes")
		return nil, errors.New("unexpected")
	}
	h.check(e)
}
func TestHealthBusinessPortIsNotClearedByWebSuccess(t *testing.T) {
	one, h, e := healthTestEngine(t)
	_, err := h.ledger.Observe(e.domain, "", "business_failed", HealthResult{Protocol: "tcp", Port: 8443, Source: "business", Status: "failed", Time: time.Now()})
	require.NoError(t, err)
	h.probeDial = func(_ context.Context, _ string, target string, _ bool, _ uint64, _ diagnosticProbePlan) (DiagnosticResult, error) {
		_, port, _ := net.SplitHostPort(target)
		status := "reachable"
		if port == "8443" {
			status = "failed"
		}
		return DiagnosticResult{Status: status}, nil
	}
	h.check(e)
	state, _ := one.HealthData(HealthQuery{})
	require.Equal(t, "attention", state.Entries[0].Status)
}

func TestHealthWorkersPersistFailuresWithoutWaitingForPublicProbes(t *testing.T) {
	one, h, _ := healthTestEngine(t)
	one.fakeIPDirectory = t.TempDir()
	require.NoError(t, os.Chmod(one.fakeIPDirectory, 0700))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	h.offer(healthEvent{domain: "private.corp", scope: "corp", reason: "dns_failed", version: one.policy.Load().version, result: HealthResult{Protocol: "dns", Source: "business", Status: "failed", Time: time.Now()}})
	require.Eventually(t, func() bool { state, err := one.HealthData(HealthQuery{}); return err == nil && state.Total == 1 }, time.Second, 5*time.Millisecond)
	state, err := one.HealthData(HealthQuery{Status: "attention", Search: "private"})
	require.NoError(t, err)
	require.Len(t, state.Entries, 1)
	require.Empty(t, state.Error)
	cancel()
	require.NoError(t, <-done)
	ledger, err := OpenHealthLedger(filepath.Join(one.fakeIPDirectory, "connection-health-ledger.json"))
	require.NoError(t, err)
	rows, _ := ledger.Snapshot(0, 100)
	require.Len(t, rows, 1)
	require.Equal(t, "dns_failed", rows[0].Reason)
}
func TestHealthSelectionUsesActualHTTPConnectAndPreservesManualRules(t *testing.T) {
	targets := make(chan string, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodConnect, r.Method)
		targets <- r.Host
		conn, _, err := w.(http.Hijacker).Hijack()
		require.NoError(t, err)
		defer conn.Close()
		fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	cfg.Policy.Mode = "direct-first"
	cfg.Policy.RuleVersion = 2
	cfg.Policy.Smart.AutoEnabled = true
	cfg.Policy.PreferredProxyID = "office-id"
	cfg.Outbounds = []OutboundConfig{{ID: "office-id", Name: "office", URL: server.URL}}
	cfg.Rule = []RuleConfig{{Schema: "FINAL", Outbound: BuiltinDirect}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	h := one.health
	h.ctx, h.cancel = context.WithCancel(t.Context())
	defer h.cancel()
	h.network = "test-network"
	one.policy.Load().outbounds.directDial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("controlled direct-path failure")
	}
	message := layeredAnswer("service.example", "8.8.8.8")
	for _, rr := range message.Answer {
		rr.Header().Ttl = 300
	}
	h.resolveLocal = func(context.Context, string) (*dns.Msg, error) { return nil, errors.New("controlled DNS failure") }
	h.resolveProxy = func(context.Context, *runtimeSnapshot, string, string) (*dns.Msg, error) { return message.Copy(), nil }
	e := healthEvent{domain: "service.example", version: one.policy.Load().version}
	h.check(e)
	h.failures[healthKey(e.domain, "")] = time.Now().Add(-31 * time.Second)
	h.tokens = 6
	h.check(e)
	state, err := one.HealthData(HealthQuery{})
	require.NoError(t, err)
	require.Equal(t, "office", state.Entries[0].Temporary[80])
	require.NotContains(t, state.Entries[0].Temporary, uint16(443), "a CONNECT transport without target TLS must not prove port 443")
	reply, err := one.dns.HandleQuery(t.Context(), new(dns.Msg).SetQuestion("service.example.", dns.TypeA), "udp", "client")
	require.NoError(t, err)
	ip := reply.Answer[0].(*dns.A).A
	require.True(t, one.dnsTable.IsLocalIP(ip))
	destination := M.ParseSocksaddr(net.JoinHostPort(ip.String(), "80"))
	target, err := one.flows.resolveDestination(t.Context(), one.policy.Load(), destination, false, nil)
	require.NoError(t, err)
	defer target.release()
	require.Equal(t, "office", target.outbound)
	require.Equal(t, "8.8.8.8:80", target.address)
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN", Pattern: "service.example", Protocol: "tcp", Ports: []uint16{80}, Outbound: BuiltinDirect}, {Schema: "FINAL", Outbound: BuiltinDirect}}
	require.NoError(t, one.Reload(cfg))
	target, err = one.flows.resolveDestination(t.Context(), one.policy.Load(), destination, false, nil)
	require.NoError(t, err)
	defer target.release()
	require.Equal(t, BuiltinDirect, target.outbound)
	require.NotEmpty(t, targets)
}

func TestHealthProxyDNSUsesActualEncryptedProxyTransportAndRejectsInvalidEvidence(t *testing.T) {
	var modeValue atomic.Value
	modeValue.Store("ok")
	resolver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answerMode := modeValue.Load().(string)
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/dns-query", r.URL.Path)
		require.Empty(t, r.Header.Get("Authorization"))
		require.Equal(t, "application/dns-message", r.Header.Get("Content-Type"))
		wire, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		q := new(dns.Msg)
		require.NoError(t, q.Unpack(wire))
		require.Equal(t, "service.example.", q.Question[0].Name)
		if answerMode == "http" {
			w.WriteHeader(503)
			return
		}
		if answerMode == "wire" {
			w.Write([]byte("bad"))
			return
		}
		reply := layeredAnswer(q.Question[0].Name, "8.8.8.8")
		reply.SetReply(q)
		switch answerMode {
		case "private":
			reply = layeredAnswer(q.Question[0].Name, "127.0.0.1")
			reply.SetReply(q)
		case "id":
			reply.Id++
		case "negative":
			reply.Rcode = dns.RcodeNameError
			reply.Answer = nil
		}
		body, err := reply.Pack()
		require.NoError(t, err)
		w.Write(body)
	}))
	defer resolver.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodConnect, r.Method)
		require.Equal(t, "1.1.1.1:443", r.Host)
		remote, err := net.Dial("tcp", resolver.Listener.Addr().String())
		require.NoError(t, err)
		defer remote.Close()
		client, _, err := w.(http.Hijacker).Hijack()
		require.NoError(t, err)
		defer client.Close()
		fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n")
		done := make(chan struct{})
		go func() { io.Copy(remote, client); close(done) }()
		io.Copy(client, remote)
		client.Close()
		<-done
	}))
	defer proxy.Close()
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	cfg.Outbounds = []OutboundConfig{{ID: "office-id", Name: "office", URL: proxy.URL}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	h := one.health
	h.dnsClient = func(transport *http.Transport) *http.Client {
		transport.TLSClientConfig = resolver.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		transport.TLSClientConfig.ServerName = "example.com"
		return &http.Client{Transport: transport, Timeout: time.Second}
	}
	for _, mode := range []string{"ok", "private", "id", "negative", "http", "wire"} {
		t.Run(mode, func(t *testing.T) {
			modeValue.Store(mode)
			h.tokens = 6
			reply, err := h.proxyResolve(t.Context(), one.policy.Load(), "office", "service.example")
			if mode == "ok" {
				require.NoError(t, err)
				require.Equal(t, []string{"8.8.8.8"}, dnsAddresses(reply))
			} else {
				require.Error(t, err)
			}
		})
	}
	h.tokens = 0
	_, err = h.proxyResolve(t.Context(), one.policy.Load(), "office", "service.example")
	require.Error(t, err)
}

func TestHealthCorruptStorageStaysVisibleAndFlowErrorsDoNotIncludeIntentionalRejects(t *testing.T) {
	one, h, _ := healthTestEngine(t)
	one.fakeIPDirectory = t.TempDir()
	require.NoError(t, os.Chmod(one.fakeIPDirectory, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(one.fakeIPDirectory, "connection-health-ledger.json"), []byte("broken"), 0600))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	require.Eventually(t, func() bool { state, err := one.HealthData(HealthQuery{}); return err == nil && state.Error != "" }, time.Second, 5*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	engine, err := FromConfig(cfg)
	require.NoError(t, err)
	defer engine.Close()
	destination := M.ParseSocksaddr("8.8.8.8:8443")
	engine.observeHealthFlow(engine.policy.Load(), "tcp", destination, "direct", "dial", ErrRejected)
	require.Empty(t, engine.health.events)
	engine.observeHealthFlow(engine.policy.Load(), "tcp", destination, "direct", "dial", errors.New("controlled failure"))
	event := <-engine.health.events
	require.Equal(t, "8.8.8.8", event.domain)
	require.Equal(t, uint16(8443), event.result.Port)
	require.Equal(t, "business_failed", event.reason)
	for range cap(h.events) + 1 {
		h.offer(healthEvent{domain: "queue.example"})
	}
	state, _ := one.HealthData(HealthQuery{})
	require.Positive(t, state.Dropped)
}
func TestHealthLateRetestCannotUndoUserAcknowledgement(t *testing.T) {
	one, h, e := healthTestEngine(t)
	entry, err := h.ledger.Observe(e.domain, "", "web_unreachable", HealthResult{Protocol: "tcp", Port: 80, Source: "probe", Status: "failed", Time: time.Now()})
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.probeDial = func(context.Context, string, string, bool, uint64, diagnosticProbePlan) (DiagnosticResult, error) {
		once.Do(func() { close(entered); <-release })
		return DiagnosticResult{Status: "failed"}, nil
	}
	finished := make(chan struct{})
	go func() { h.check(e); close(finished) }()
	<-entered
	_, err = one.HealthAction(HealthAction{Action: "handled", Domain: e.domain, Generation: entry.Generation})
	require.NoError(t, err)
	close(release)
	<-finished
	state, _ := one.HealthData(HealthQuery{})
	require.Equal(t, "history", state.Entries[0].Status)
	require.Equal(t, "user", state.Entries[0].Resolution)
}

func TestHealthProbeRetainsUnknownForUnsampledOrUnconfirmedTargets(t *testing.T) {
	one, h, e := healthTestEngine(t)
	h.probeDial = func(context.Context, string, string, bool, uint64, diagnosticProbePlan) (DiagnosticResult, error) {
		return DiagnosticResult{Status: "failed"}, nil
	}
	result := h.probe(t.Context(), one.policy.Load(), "direct", e.domain, 80, layeredAnswer(e.domain, "8.8.8.8", "9.9.9.9", "1.1.1.1"))
	require.Equal(t, "unknown", result.Status)
	require.Equal(t, "insufficient", result.Stage)
	h.tokens = 6
	result = h.probe(t.Context(), one.policy.Load(), "direct", e.domain, 80, layeredAnswer(e.domain, "127.0.0.1"))
	require.Equal(t, "unknown", result.Status)
	require.Equal(t, "scope", result.Stage)
	result = h.probe(t.Context(), one.policy.Load(), "direct", e.domain, 80, new(dns.Msg))
	require.Equal(t, "dns", result.Stage)
	h.tokens = 0
	result = h.probe(t.Context(), one.policy.Load(), "direct", e.domain, 80, e.message)
	require.Equal(t, "budget", result.Stage)
}
func TestHealthRetestSchedulingAndStorageFailureDoNotEnableAuto(t *testing.T) {
	one, h, e := healthTestEngine(t)
	entry, err := h.ledger.Observe(e.domain, "", "dns_failed", HealthResult{Protocol: "dns", Time: time.Now()})
	require.NoError(t, err)
	_, err = one.HealthAction(HealthAction{Action: "recheck", Domain: e.domain, Generation: entry.Generation})
	require.NoError(t, err)
	require.Equal(t, one.policy.Load().version, h.latest[healthKey(e.domain, "")].version)
	_, err = one.HealthAction(HealthAction{Action: "unsupported", Domain: e.domain, Generation: entry.Generation})
	require.Error(t, err)
	_, err = one.HealthAction(HealthAction{Action: "apply", Domain: e.domain, Generation: entry.Generation + 1})
	require.Error(t, err)
	h.ledger.path = t.TempDir()
	h.check(e)
	state, _ := one.HealthData(HealthQuery{})
	require.NotEmpty(t, state.Error)
	require.Empty(t, h.choices)
	h.invalidate()
	require.Empty(t, h.evidence)
}
func TestRuntimeHealthLedgerExclusiveOwnership(t *testing.T) {
	root := filepath.Join(t.TempDir(), "health")
	ledger, release, err := openRuntimeHealthLedger(root)
	require.NoError(t, err)
	require.NotNil(t, ledger)
	_, _, err = openRuntimeHealthLedger(root)
	require.Error(t, err)
	release()
	_, release, err = openRuntimeHealthLedger(root)
	require.NoError(t, err)
	release()
}

func TestHealthSchedulerRunsWithAutoOffAndInvalidatesChangedNetwork(t *testing.T) {
	one, h, e := healthTestEngine(t)
	one.fakeIPDirectory = filepath.Join(t.TempDir(), "store")
	var network atomic.Value
	network.Store("first-network")
	h.networkSample = func(string) (string, error) { return network.Load().(string), nil }
	e.result.Time = time.Now()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	h.offer(e)
	require.Eventually(t, func() bool {
		state, _ := one.HealthData(HealthQuery{})
		return len(state.Entries) > 0 && len(state.Entries[0].Suggestions) > 0
	}, 3*time.Second, 10*time.Millisecond)
	h.mu.Lock()
	require.Empty(t, h.choices)
	h.networkChecked = time.Now().Add(-6 * time.Second)
	h.mu.Unlock()
	network.Store("second-network")
	require.Eventually(t, func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.network == "second-network" }, 2*time.Second, 10*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
	// Restore unhandled summaries without depending on retained DNS/flow logs.
	next := newConnectionHealth(one)
	one.health = next
	next.networkSample = h.networkSample
	secondCtx, secondCancel := context.WithCancel(t.Context())
	secondDone := make(chan error, 1)
	go func() { secondDone <- next.run(secondCtx) }()
	require.Eventually(t, func() bool { state, _ := one.HealthData(HealthQuery{}); return state.Total == 1 }, time.Second, 10*time.Millisecond)
	secondCancel()
	require.NoError(t, <-secondDone)
}

func TestHealthHotSetRotatesAndPrivateRetestConsentIsOneShot(t *testing.T) {
	one, h, _ := healthTestEngine(t)
	one.fakeIPDirectory = filepath.Join(t.TempDir(), "store")
	h.networkSample = func(string) (string, error) { return "test-network", nil }
	for i := range 512 {
		e := healthEvent{domain: fmt.Sprintf("old-%d.corp", i), scope: "corp", version: one.policy.Load().version}
		key := healthKey(e.domain, e.scope)
		h.latest[key], h.due[key] = e, time.Now().Add(time.Hour)
	}
	var localCalls atomic.Int32
	h.resolveLocal = func(context.Context, string) (*dns.Msg, error) {
		localCalls.Add(1)
		return nil, errors.New("private resolver unavailable")
	}
	h.resolveProxy = func(context.Context, *runtimeSnapshot, string, string) (*dns.Msg, error) {
		t.Error("private retest must not use a public resolver")
		return nil, errors.New("unexpected public lookup")
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	t.Cleanup(func() { cancel(); require.NoError(t, <-done) })
	h.offer(healthEvent{domain: "new.corp", scope: "corp", reason: "dns_failed", version: one.policy.Load().version, result: HealthResult{Protocol: "dns", Status: "failed", Time: time.Now()}})
	var entry HealthIncident
	require.Eventually(t, func() bool {
		state, _ := one.HealthData(HealthQuery{Search: "new.corp"})
		if len(state.Entries) == 0 {
			return false
		}
		entry = state.Entries[0]
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.latest) == 512 && h.latest[healthKey("new.corp", "corp")].domain == "new.corp"
	}, time.Second, 5*time.Millisecond)
	_, err := one.HealthAction(HealthAction{Action: "recheck", Domain: entry.Domain, Scope: entry.Scope, Generation: entry.Generation})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return localCalls.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
	h.mu.Lock()
	require.False(t, h.latest[healthKey(entry.Domain, entry.Scope)].manual)
	h.mu.Unlock()
	state, _ := one.HealthData(HealthQuery{Status: "attention"})
	require.Equal(t, 1, state.Total, "rotating observations must retain the unresolved incident")
}

func TestHealthDNSRecoveryTriesConfiguredCandidatesAfterPreferredFails(t *testing.T) {
	one, h, e := healthTestEngine(t)
	cfg := cloneConfig(one.policy.Load().cfg)
	backup := cfg.Outbounds[0]
	backup.ID, backup.Name = "backup-id", "backup"
	cfg.Outbounds = append(cfg.Outbounds, backup)
	cfg.Policy.Smart.Candidates = []string{backup.ID}
	one.policy.Load().cfg = cfg
	e.message = nil
	h.resolveLocal = func(context.Context, string) (*dns.Msg, error) { return nil, errors.New("native DNS failed") }
	var queried []string
	h.resolveProxy = func(_ context.Context, _ *runtimeSnapshot, outbound, domain string) (*dns.Msg, error) {
		queried = append(queried, outbound)
		if outbound == "backup" {
			return layeredAnswer(domain, "8.8.8.8"), nil
		}
		return nil, errors.New("preferred proxy unavailable")
	}
	h.probeDial = func(_ context.Context, outbound, _ string, _ bool, _ uint64, _ diagnosticProbePlan) (DiagnosticResult, error) {
		status := "failed"
		if outbound == "backup" {
			status = "reachable"
		}
		return DiagnosticResult{Status: status, Stage: "connect"}, nil
	}
	h.check(e)
	require.Equal(t, []string{"office", "backup"}, queried)
	state, err := one.HealthData(HealthQuery{})
	require.NoError(t, err)
	require.Equal(t, "backup", state.Entries[0].Suggestions[80])
	require.Empty(t, h.choices, "recovery evidence does not authorize automatic selection")
}

func TestHealthIgnoresNativeDNSFailureWhenCurrentDomainProxyWorks(t *testing.T) {
	one, h, e := healthTestEngine(t)
	cfg := cloneConfig(one.policy.Load().cfg)
	cfg.Policy.PreferredProxyID = ""
	cfg.Rule = append([]RuleConfig{{Schema: "DOMAIN", Pattern: e.domain, Outbound: "office"}}, cfg.Rule...)
	one.policy.Load().cfg = cfg
	one.policy.Load().rule = NewRule(cfg.Rule, cfg.Outbounds)
	one.policy.Load().rule.protectPolicy(cfg)
	_, err := h.ledger.Observe(e.domain, "", "dns_failed", HealthResult{Protocol: "dns", Source: "business", Status: "failed", DNSCode: "SERVFAIL", Time: time.Now()})
	require.NoError(t, err)
	e.message = nil
	h.resolveLocal = func(context.Context, string) (*dns.Msg, error) { return nil, errors.New("native DNS failed") }
	h.resolveProxy = func(_ context.Context, _ *runtimeSnapshot, outbound, domain string) (*dns.Msg, error) {
		require.Equal(t, "office", outbound, "use the domain rule even without a preferred Smart candidate")
		return layeredAnswer(domain, "8.8.8.8"), nil
	}
	h.check(e)
	state, err := one.HealthData(HealthQuery{Status: "attention"})
	require.NoError(t, err)
	require.Zero(t, state.Total)
	history, err := one.HealthData(HealthQuery{Status: "history"})
	require.NoError(t, err)
	require.Equal(t, "retest", history.Entries[0].Resolution)
	require.Empty(t, h.choices, "a working manual route does not need a temporary override")
	// Model a new event strictly after the recovered generation. Windows can
	// return the same clock tick for adjacent calls to time.Now.
	failureAt := history.Entries[0].ClosedAt.Add(time.Nanosecond)
	// A successful default web port does not hide a separate business failure.
	_, err = h.ledger.Observe(e.domain, "", "business_failed", HealthResult{Protocol: "tcp", Port: 8443, Source: "business", Status: "failed", Time: failureAt})
	require.NoError(t, err)
	h.tokens = 6
	h.probeDial = func(_ context.Context, _ string, target string, _ bool, _ uint64, _ diagnosticProbePlan) (DiagnosticResult, error) {
		status := "reachable"
		if strings.HasSuffix(target, ":8443") {
			status = "failed"
		}
		return DiagnosticResult{Status: status, Stage: "connect"}, nil
	}
	h.check(e)
	state, err = one.HealthData(HealthQuery{Status: "attention"})
	require.NoError(t, err)
	require.Equal(t, 1, state.Total)
	require.Equal(t, "business_failed", state.Entries[0].Reason)
	// Explicit whole-domain blocking resolves the fault as a policy choice.
	cfg.Rule[0].Outbound = BuiltinReject
	one.policy.Load().rule = NewRule(cfg.Rule, cfg.Outbounds)
	one.policy.Load().rule.protectPolicy(cfg)
	h.check(e)
	state, err = one.HealthData(HealthQuery{Status: "attention"})
	require.NoError(t, err)
	require.Zero(t, state.Total)
}

func TestHealthAutoPreferenceCanBeSavedBeforeLayeredRules(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.Smart.AutoEnabled = true
	require.NoError(t, cfg.ValidatePolicy(), "preference must be configurable before the engine or layered rules are enabled")
}

func TestHealthRealProxyReplyClearsDNSFaultWithoutNativeResolution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\nreply")
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	cfg.Outbounds = []OutboundConfig{{ID: "office", Name: "office", URL: server.URL}}
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN", Pattern: "service.example", Outbound: "office"}, {Schema: "FINAL", Outbound: BuiltinDirect}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	_, err = one.health.ledger.Observe("service.example", "", "dns_failed", HealthResult{Protocol: "dns", Source: "business", Status: "failed", Time: time.Now()})
	require.NoError(t, err)
	record := one.dnsTable.Set("service.example", "office")
	client, accepted := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		one.flows.NewConnectionEx(t.Context(), accepted, M.ParseSocksaddr("192.0.2.2:40000"), M.SocksaddrFromNet(&net.TCPAddr{IP: record.IP, Port: 443}), nil)
		close(done)
	}()
	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	payload := make([]byte, 5)
	_, err = io.ReadFull(client, payload)
	require.NoError(t, err)
	require.Equal(t, "reply", string(payload))
	select {
	case event := <-one.health.events:
		require.Equal(t, "reachable", event.result.Status)
		one.health.acceptBusinessSuccess(event)
	case <-time.After(time.Second):
		t.Fatal("missing target reply observation")
	}
	client.Close()
	<-done
	state, err := one.HealthData(HealthQuery{Status: "attention"})
	require.NoError(t, err)
	require.Zero(t, state.Total)
}

func TestHealthReplyCannotHideNewerOrUnrelatedFaults(t *testing.T) {
	for _, scenario := range []string{"newer-dns-failure", "other-business-port", "changed-rule", "stale-configuration", "storage-failure"} {
		t.Run(scenario, func(t *testing.T) {
			one, h, e := healthTestEngine(t)
			cfg := one.policy.Load().cfg
			cfg.Rule = append([]RuleConfig{{Schema: "DOMAIN", Pattern: e.domain, Outbound: "office"}}, cfg.Rule...)
			one.policy.Load().rule = NewRule(cfg.Rule, cfg.Outbounds)
			one.policy.Load().rule.protectPolicy(cfg)
			if scenario == "other-business-port" {
				_, err := h.ledger.Observe(e.domain, "", "business_failed", HealthResult{Protocol: "tcp", Port: 8443, Source: "business", Status: "failed", Time: time.Now()})
				require.NoError(t, err)
			}
			_, err := h.ledger.Observe(e.domain, "", "dns_failed", HealthResult{Protocol: "dns", Source: "business", Status: "failed", Time: time.Now()})
			require.NoError(t, err)
			e.result = HealthResult{Protocol: "tcp", Port: 443, Source: "business", Status: "reachable", Outbound: "office", Time: time.Now()}
			switch scenario {
			case "newer-dns-failure":
				e.result.Time = time.Now().Add(-time.Minute)
			case "changed-rule":
				cfg.Rule[0].Outbound = BuiltinDirect
				one.policy.Load().rule = NewRule(cfg.Rule, cfg.Outbounds)
				one.policy.Load().rule.protectPolicy(cfg)
			case "stale-configuration":
				e.version--
			case "storage-failure":
				h.ledger.path = t.TempDir()
			}
			h.acceptBusinessSuccess(e)
			state, err := one.HealthData(HealthQuery{Status: "attention"})
			require.NoError(t, err)
			require.Equal(t, 1, state.Total)
			if scenario == "storage-failure" {
				require.NotEmpty(t, state.Error)
			}
		})
	}
}
