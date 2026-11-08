package kone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func smartTestEngine(t *testing.T, mode string) (*One, *time.Time) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Policy.RuleVersion = 2
	cfg.Policy.Smart.Enabled = true
	cfg.Policy.Mode = mode
	cfg.Policy.PreferredProxyID = "office-id"
	cfg.Outbounds = []OutboundConfig{{ID: "office-id", Name: "office", URL: "http://127.0.0.1:1"}}
	final := BuiltinDirect
	if mode == "proxy-first" {
		final = "office"
		cfg.Core.AutoRoute = true
	}
	cfg.Rule = []RuleConfig{{Schema: "FINAL", Outbound: final}}
	rule := NewRule(cfg.Rule, cfg.Outbounds)
	rule.protectPolicy(cfg)
	one := &One{dns: &Dns{}}
	one.policy.Store(&runtimeSnapshot{version: 1, configVersion: 7, cfg: cfg, rule: rule})
	now := time.Now()
	one.smart = newSmartCoordinator(one)
	one.smart.now = func() time.Time { return now }
	one.smart.refill = now
	one.smart.network = "test-network"
	one.smart.ctx, one.smart.cancel = context.WithCancel(t.Context())
	one.smart.networkSample = func(string) (string, error) { return "test-network", nil }
	t.Cleanup(one.smart.cancel)
	return one, &now
}
func smartObserve(t *testing.T, one *One, name string, ips ...string) {
	t.Helper()
	message := layeredAnswer(name, ips...)
	for _, rr := range message.Answer {
		rr.Header().Ttl = 300
	}
	snapshot := one.policy.Load()
	one.smart.observe(snapshot, name, &dnsQueryMeta{Origin: DNSOriginBusiness, Resolved: message, Routing: snapshot.rule.DecideDNS(name, message, "", 0)})
}
func smartBatch(t *testing.T, one *One) {
	t.Helper()
	one.smart.schedule(one.smart.now())
	select {
	case work := <-one.smart.queue:
		one.smart.execute(work)
	case <-time.After(time.Second):
		t.Fatal("no scheduled Smart work")
	}
}
func smartVerified() DiagnosticResult {
	return DiagnosticResult{Status: "reachable", Stage: "target_tls", Protocols: DiagnosticProtocols{TLS: DiagnosticCheck{Status: "healthy", Tested: true}}}
}
func TestSmartRequiresSpacedComparableEvidenceAndNeverChangesPolicy(t *testing.T) {
	for _, mode := range []string{"direct-first", "proxy-first"} {
		t.Run(mode, func(t *testing.T) {
			one, now := smartTestEngine(t, mode)
			snapshot := one.policy.Load()
			one.smart.probe = func(_ context.Context, out, ip, name string, v uint64) (DiagnosticResult, error) {
				require.Equal(t, "8.8.8.8", ip)
				require.Equal(t, "service.example", name)
				require.Equal(t, uint64(7), v)
				if mode == "direct-first" && out == BuiltinDirect {
					return DiagnosticResult{Status: "failed", Stage: "connect"}, nil
				}
				return smartVerified(), nil
			}
			smartObserve(t, one, "service.example", "8.8.8.8")
			smartBatch(t, one)
			state, err := one.SmartData()
			require.NoError(t, err)
			require.Equal(t, "rechecking", state.Suggestions[0].Status)
			require.Empty(t, state.Suggestions[0].Action)
			*now = now.Add(31 * time.Second)
			smartBatch(t, one)
			state, err = one.SmartData()
			require.NoError(t, err)
			suggestion := state.Suggestions[0]
			require.Equal(t, "ready", suggestion.Status)
			action := "direct"
			attempts := uint64(2)
			if mode == "direct-first" {
				action = "proxy"
				attempts = 4
			}
			require.Equal(t, action, suggestion.Action)
			require.Equal(t, attempts, state.Attempts)
			preview, err := one.SmartAction(SmartAction{Action: "preview", ID: suggestion.ID, Version: 7})
			require.NoError(t, err)
			require.Equal(t, action, preview.Suggestion.Action)
			require.Same(t, snapshot, one.policy.Load())
			require.Len(t, snapshot.cfg.Rule, 1)
			*now = now.Add(5 * time.Minute)
			_, err = one.SmartAction(SmartAction{Action: "preview", ID: suggestion.ID, Version: 7})
			require.Error(t, err)
		})
	}
}
func TestSmartPublicScopeAndExplicitRules(t *testing.T) {
	one, _ := smartTestEngine(t, "direct-first")
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "192.0.2.1", "198.18.0.1", "169.254.1.1", "224.0.0.1", "240.0.0.1", "::1", "fc00::1", "2001:db8::1", "64:ff9b::808:808", "2002:808:808::1", "3fff::1", "::ffff:127.0.0.1"} {
		require.False(t, smartPublicTarget(one.policy.Load(), netip.MustParseAddr(value)), value)
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		require.True(t, smartPublicTarget(one.policy.Load(), netip.MustParseAddr(value)), value)
	}
	for _, name := range []string{"a.local", "printer", "corp.internal", "service.home.arpa", "hidden.onion"} {
		smartObserve(t, one, name, "8.8.8.8")
	}
	smartObserve(t, one, "private.example", "10.0.0.1")
	snapshot := one.policy.Load()
	snapshot.cfg.Rule = append([]RuleConfig{{Schema: "IP-CIDR", Pattern: "8.8.8.8/32", Outbound: BuiltinReject}}, snapshot.cfg.Rule...)
	snapshot.rule = NewRule(snapshot.cfg.Rule, snapshot.cfg.Outbounds)
	snapshot.rule.protectPolicy(snapshot.cfg)
	smartObserve(t, one, "explicit.example", "8.8.8.8")
	require.Empty(t, one.smart.entries)
}
func TestSmartMixedCandidatesAndUnverifiedProxyCannotRecommend(t *testing.T) {
	for _, scenario := range []string{"direct-sibling", "transport-only", "certificate", "many-candidates"} {
		t.Run(scenario, func(t *testing.T) {
			one, now := smartTestEngine(t, "direct-first")
			one.smart.probe = func(_ context.Context, out, ip, _ string, _ uint64) (DiagnosticResult, error) {
				if scenario == "direct-sibling" && ip == "1.1.1.1" && out == BuiltinDirect {
					return smartVerified(), nil
				}
				if scenario == "certificate" {
					return DiagnosticResult{Status: "failed", Stage: "target_tls", FailureKind: "tls_verification"}, nil
				}
				if out == BuiltinDirect {
					return DiagnosticResult{Status: "failed", Stage: "connect"}, nil
				}
				if scenario == "transport-only" {
					return DiagnosticResult{Status: "unknown", Stage: "proxy_transport"}, nil
				}
				return smartVerified(), nil
			}
			addresses := []string{"8.8.8.8", "1.1.1.1"}
			if scenario == "many-candidates" {
				addresses = append(addresses, "9.9.9.9")
			}
			smartObserve(t, one, "service.example", addresses...)
			smartBatch(t, one)
			*now = now.Add(31 * time.Second)
			smartBatch(t, one)
			state, _ := one.SmartData()
			require.Empty(t, state.Suggestions[0].Action)
		})
	}
}
func TestSmartQueueBudgetCancellationAndHistoryIndependence(t *testing.T) {
	one, now := smartTestEngine(t, "direct-first")
	for i := range 600 {
		smartObserve(t, one, fmt.Sprintf("site%d.example", i), "8.8.8.8")
	}
	require.Len(t, one.smart.entries, 512)
	one.smart.schedule(*now)
	require.Len(t, one.smart.queue, 128)
	require.Positive(t, one.smart.dropped)
	for range 6 {
		require.True(t, one.smart.takeAttempt(t.Context()))
	}
	require.False(t, one.smart.takeAttempt(t.Context()))
	*now = now.Add(2 * time.Second)
	require.True(t, one.smart.takeAttempt(t.Context()))
	require.False(t, one.smart.takeAttempt(t.Context()))
	work := <-one.smart.queue
	one.smart.invalidate()
	require.ErrorIs(t, work.ctx.Err(), context.Canceled)
	one.smart.finish(work, work.entry, "ready", time.Time{})
	state, _ := one.SmartData()
	for _, e := range state.Suggestions {
		require.Equal(t, "expired", e.Status)
	}
	_, err := one.SmartAction(SmartAction{Action: "clear"})
	require.NoError(t, err)
	state, _ = one.SmartData()
	require.Empty(t, state.Suggestions)
	// No DNS history or polling is consulted by the observer.
	require.Nil(t, one.dns.history)
}
func TestSmartIgnoreCancelsInFlightAndRecheckRejectsStaleVersion(t *testing.T) {
	one, now := smartTestEngine(t, "proxy-first")
	smartObserve(t, one, "service.example", "8.8.8.8")
	one.smart.schedule(*now)
	work := <-one.smart.queue
	_, err := one.SmartAction(SmartAction{Action: "ignore", ID: work.entry.ID})
	require.NoError(t, err)
	require.ErrorIs(t, work.ctx.Err(), context.Canceled)
	one.smart.finish(work, work.entry, "ready", time.Time{})
	state, _ := one.SmartData()
	require.Equal(t, "ignored", state.Suggestions[0].Status)
	_, err = one.SmartAction(SmartAction{Action: "recheck", ID: work.entry.ID, Version: 6})
	require.Error(t, err)
	_, err = one.SmartAction(SmartAction{Action: "recheck", ID: work.entry.ID, Version: 7})
	require.NoError(t, err)
	require.False(t, one.smart.entries["service.example"].running)
	one.smart.probe = func(context.Context, string, string, string, uint64) (DiagnosticResult, error) {
		return DiagnosticResult{}, errors.New("owner stopped")
	}
	smartBatch(t, one)
	state, _ = one.SmartData()
	require.Empty(t, state.Suggestions[0].Action)
}
func TestSmartPrivateResolverAndCNAMEAreExcluded(t *testing.T) {
	one, _ := smartTestEngine(t, "proxy-first")
	one.dns.routes = []DNSRouteConfig{{Suffix: "enterprise.example", Servers: []string{"10.0.0.1:53"}}}
	snapshot := one.policy.Load()
	message := layeredAnswer("service.example", "8.8.8.8")
	message.Answer = append(message.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: "service.example.", Ttl: 300}, Target: "private.enterprise.example."})
	one.smart.observe(snapshot, "service.example", &dnsQueryMeta{Origin: DNSOriginBusiness, Resolved: message, Routing: RoutingDecision{DecisionSource: "base-final"}})
	require.Empty(t, one.smart.entries)
	one.smart.observe(snapshot, "service.example", &dnsQueryMeta{Origin: DNSOriginBusiness, Resolved: layeredAnswer("service.example", "8.8.8.8"), Route: "private", Routing: RoutingDecision{DecisionSource: "base-final"}})
	require.Empty(t, one.smart.entries)
}

func TestSmartRateLimitIsThirtyActualAttemptsInAnyMinute(t *testing.T) {
	one, now := smartTestEngine(t, "direct-first")
	for range 6 {
		require.True(t, one.smart.takeAttempt(t.Context()))
	}
	for range 24 {
		*now = now.Add(2 * time.Second)
		require.True(t, one.smart.takeAttempt(t.Context()))
	}
	*now = now.Add(2 * time.Second)
	require.False(t, one.smart.takeAttempt(t.Context()), "burst allowance must not exceed the minute ceiling")
	*now = now.Add(10 * time.Second)
	require.True(t, one.smart.takeAttempt(t.Context()))
}

func TestSmartBusinessDNSIncludesGlobalFakeIPWithoutHistoryOrProbeWait(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := layeredAnswer(r.Question[0].Name, "8.8.8.8")
		reply.SetReply(r)
		for _, rr := range reply.Answer {
			rr.Header().Ttl = 300
		}
		_ = w.WriteMsg(reply)
	})
	server := startDNSListeners(t, handler, handler)
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	loopback := ""
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			loopback = iface.Name
			break
		}
	}
	require.NotEmpty(t, loopback)
	for _, mode := range []string{"direct-first", "proxy-first"} {
		t.Run(mode, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Policy.RuleVersion = 2
			cfg.Policy.Mode = mode
			cfg.Policy.IPv4Only = true
			cfg.Policy.Smart.Enabled = true
			cfg.DNS.Servers = []string{server}
			cfg.DNS.HistoryLimit = 0
			cfg.Outbounds = []OutboundConfig{{ID: "office-id", Name: "office", URL: "socks5://127.0.0.1:1"}}
			final := BuiltinDirect
			if mode == "proxy-first" {
				final = "office"
				cfg.Core.AutoRoute = true
				cfg.Core.OutboundInterface = loopback
			}
			cfg.Rule = []RuleConfig{{Schema: "FINAL", Outbound: final}}
			one, err := FromConfig(cfg)
			require.NoError(t, err)
			defer one.Close()
			s := one.smart
			s.ctx, s.cancel = context.WithCancel(t.Context())
			defer s.cancel()
			s.network = "fixture"
			s.networkSample = func(string) (string, error) { return "fixture", nil }
			reply, err := one.dns.HandleQuery(t.Context(), new(dns.Msg).SetQuestion("observed.example.", dns.TypeA), "udp", "client")
			require.NoError(t, err)
			require.Equal(t, mode == "proxy-first", one.dnsTable.IsLocalIP(reply.Answer[0].(*dns.A).A))
			require.Len(t, s.entries, 1)
			require.Equal(t, []string{"8.8.8.8"}, s.entries["observed.example"].Candidates)
			require.Empty(t, one.DNSQueries())
			_, err = one.dns.HandleQuery(t.Context(), new(dns.Msg).SetQuestion("manual.example.", dns.TypeA), "control", "diagnostic")
			require.NoError(t, err)
			require.Len(t, s.entries, 1)
			started, finished := make(chan struct{}), make(chan struct{})
			s.probe = func(ctx context.Context, _, _, _ string, _ uint64) (DiagnosticResult, error) {
				close(started)
				<-ctx.Done()
				return DiagnosticResult{}, ctx.Err()
			}
			s.schedule(time.Now())
			work := <-s.queue
			go func() { s.execute(work); close(finished) }()
			<-started
			queryCtx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			_, err = one.dns.HandleQuery(queryCtx, new(dns.Msg).SetQuestion("observed.example.", dns.TypeA), "tcp", "client")
			require.NoError(t, err, "DNS must not wait for the blocked probe")
			s.cancel()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("probe did not cancel")
			}
		})
	}
}
func TestSmartAddressRotationAndNetworkChangeInvalidateEvidence(t *testing.T) {
	one, now := smartTestEngine(t, "proxy-first")
	one.smart.probe = func(context.Context, string, string, string, uint64) (DiagnosticResult, error) {
		return smartVerified(), nil
	}
	smartObserve(t, one, "rotating.example", "8.8.8.8")
	smartBatch(t, one)
	smartObserve(t, one, "rotating.example", "1.1.1.1")
	e := one.smart.entries["rotating.example"]
	require.Empty(t, e.Samples)
	require.Equal(t, []string{"1.1.1.1"}, e.Candidates)
	*now = now.Add(31 * time.Second)
	smartBatch(t, one)
	state, _ := one.SmartData()
	require.Empty(t, state.Suggestions[0].Action)
	one.smart.networkSample = func(string) (string, error) { return "new-network", nil }
	*now = now.Add(2 * time.Second)
	_, err := one.SmartAction(SmartAction{Action: "recheck", ID: e.ID, Version: 7})
	require.Error(t, err)
	require.True(t, one.smart.blocked)
	state, _ = one.SmartData()
	require.Equal(t, "network_changed", state.Status)
	require.Equal(t, "expired", state.Suggestions[0].Status)
}

func TestSmartOwnerLoopExcludesOwnedDeviceAndStopsWorkers(t *testing.T) {
	one, _ := smartTestEngine(t, "proxy-first")
	s := one.smart
	s.cancel()
	s.ctx = nil
	s.networkSample = func(tun string) (string, error) { require.Equal(t, "owned-tun", tun); return "test-network", nil }
	started := make(chan struct{})
	s.probe = func(ctx context.Context, _, _, _ string, _ uint64) (DiagnosticResult, error) {
		close(started)
		<-ctx.Done()
		return DiagnosticResult{}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.run(ctx, "owned-tun") }()
	require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.ctx != nil }, time.Second, time.Millisecond)
	smartObserve(t, one, "background.example", "8.8.8.8")
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("owner did not run queued work without a browser")
	}
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
	state, err := one.SmartData()
	require.NoError(t, err)
	require.Equal(t, "paused", state.Status)
	require.Equal(t, "expired", state.Suggestions[0].Status)
}

func TestSmartBudgetDefersWorkAndNetworkFailureCancelsAutomaticProbes(t *testing.T) {
	for _, scenario := range []string{"budget", "network-unknown", "expired-version", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			one, _ := smartTestEngine(t, "direct-first")
			probes := 0
			one.smart.probe = func(context.Context, string, string, string, uint64) (DiagnosticResult, error) {
				probes++
				return smartVerified(), nil
			}
			smartObserve(t, one, "deferred.example", "8.8.8.8")
			one.smart.schedule(one.smart.now())
			work := <-one.smart.queue
			switch scenario {
			case "budget":
				one.smart.tokens = 0
			case "network-unknown":
				one.smart.networkSample = func(string) (string, error) { return "", errors.New("resolver context unavailable") }
			case "expired-version":
				snapshot := *one.policy.Load()
				snapshot.version++
				one.policy.Store(&snapshot)
			case "canceled":
				work.entry.cancel()
			}
			one.smart.execute(work)
			require.Zero(t, probes)
			state, _ := one.SmartData()
			require.Empty(t, state.Suggestions[0].Action)
			if scenario == "budget" {
				require.Equal(t, "budget", state.Suggestions[0].Status)
				require.False(t, one.smart.entries["deferred.example"].due.IsZero())
			}
			if scenario == "network-unknown" {
				require.Equal(t, "network_changed", state.Status)
				require.False(t, one.smart.checkNetwork(true))
				require.Equal(t, "expired", state.Suggestions[0].Status)
			}
		})
	}
}

func TestSmartWidespreadDirectFailureSuppressesProxyRecommendations(t *testing.T) {
	one, now := smartTestEngine(t, "direct-first")
	one.smart.probe = func(_ context.Context, out, _, _ string, _ uint64) (DiagnosticResult, error) {
		if out == BuiltinDirect {
			return DiagnosticResult{Status: "failed", Stage: "connect"}, nil
		}
		return smartVerified(), nil
	}
	for i := range 4 {
		smartObserve(t, one, fmt.Sprintf("outage%d.example", i), "8.8.8.8")
	}
	for round := range 2 {
		if round == 1 {
			*now = now.Add(30 * time.Second)
		}
		one.smart.schedule(*now)
		require.Len(t, one.smart.queue, 4)
		for range 4 {
			one.smart.execute(<-one.smart.queue)
			*now = now.Add(4 * time.Second)
		}
	}
	state, err := one.SmartData()
	require.NoError(t, err)
	require.Equal(t, uint64(16), state.Attempts)
	for _, suggestion := range state.Suggestions {
		require.Empty(t, suggestion.Action)
		require.Equal(t, "network_uncertain", suggestion.Status)
	}
}
