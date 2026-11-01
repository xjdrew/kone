package process

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testQuery(now time.Time) Query {
	return Query{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("198.51.100.1:443"), ObservedAt: now}
}

func TestResolverNeverAttributesGatewayTrafficToLocalProcess(t *testing.T) {
	now := time.Now()
	var calls atomic.Int32
	r := New(Options{Now: func() time.Time { return now }, LocalAddresses: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil }, Lookup: func(context.Context, Query) (Result, error) { calls.Add(1); return Result{}, nil }})
	defer r.Close()
	result := r.resolve(context.Background(), testQuery(now))
	require.Equal(t, "remote", result.Status)
	require.Zero(t, result.PID)
	require.Zero(t, calls.Load())
}

func TestResolverValidatesTimeIdentityPermissionsAndProtocol(t *testing.T) {
	now := time.Now()
	local := func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil }
	lookup := func(context.Context, Query) (Result, error) {
		return Result{Status: "matched", PID: 42, Name: "browser", Path: "/browser", Source: "test_validated_socket", StartedAt: now.Add(-time.Hour)}, nil
	}
	r := New(Options{Now: func() time.Time { return now }, LocalAddresses: local, Lookup: lookup})
	defer r.Close()
	query := testQuery(now)
	result := r.resolve(context.Background(), query)
	require.Equal(t, "matched", result.Status)
	require.Equal(t, uint32(42), result.PID)
	require.Equal(t, now, result.ObservedAt)
	query.ObservedAt = now.Add(-3 * time.Second)
	require.Equal(t, "unknown", r.resolve(context.Background(), query).Status)
	query = testQuery(now)
	query.Protocol = "icmp"
	require.Equal(t, "unknown", r.resolve(context.Background(), query).Status)
	query = testQuery(now)
	query.ObservedAt = now.Add(time.Minute)
	require.Equal(t, "unknown", r.resolve(context.Background(), query).Status)
	r.options.Lookup = func(context.Context, Query) (Result, error) {
		return Result{Status: "matched", PID: 42, Name: "reused", StartedAt: now.Add(time.Second)}, nil
	}
	result = r.resolve(context.Background(), testQuery(now))
	require.Equal(t, "unknown", result.Status)
	require.Zero(t, result.PID, "a reused PID is never copied into unknown attribution")
	r.options.Lookup = func(context.Context, Query) (Result, error) {
		return Result{}, errors.New("access denied private path")
	}
	result = r.resolve(context.Background(), testQuery(now))
	require.Equal(t, "unknown", result.Status)
	require.NotContains(t, result.Reason, "private")
	r.options.LocalAddresses = func() ([]netip.Addr, error) { return nil, errors.New("no permission") }
	require.Equal(t, "unknown", r.resolve(context.Background(), testQuery(now)).Status)
}

func TestResolverQueueIsBoundedAndLookupNeverBlocksForwarding(t *testing.T) {
	now := time.Now()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	r := New(Options{Workers: 1, QueueSize: 1, Timeout: time.Second, LocalAddresses: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil }, Lookup: func(ctx context.Context, _ Query) (Result, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return Result{}, errors.New("gone")
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
	}})
	defer r.Close()
	delivered := make(chan Result, 2)
	deliver := func(result Result) { delivered <- result }
	require.True(t, r.LookupAsync(context.Background(), testQuery(now), deliver))
	<-entered
	require.True(t, r.LookupAsync(context.Background(), testQuery(now), deliver))
	started := time.Now()
	require.False(t, r.LookupAsync(context.Background(), testQuery(now), deliver))
	require.Less(t, time.Since(started), 50*time.Millisecond)
	close(release)
	for range 2 {
		select {
		case result := <-delivered:
			require.Equal(t, "unknown", result.Status)
		case <-time.After(2 * time.Second):
			t.Fatal("queued lookup was lost")
		}
	}
	r.Close()
	require.False(t, r.LookupAsync(context.Background(), testQuery(now), deliver))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.False(t, r.LookupAsync(ctx, testQuery(now), deliver))
}

func TestResolverTimeoutDoesNotLeakProcessIdentity(t *testing.T) {
	now := time.Now()
	r := New(Options{Timeout: time.Millisecond, LocalAddresses: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil }, Lookup: func(ctx context.Context, _ Query) (Result, error) { <-ctx.Done(); return Result{}, ctx.Err() }})
	defer r.Close()
	result := make(chan Result, 1)
	require.True(t, r.LookupAsync(context.Background(), testQuery(now), func(value Result) { result <- value }))
	select {
	case value := <-result:
		require.Equal(t, "unknown", value.Status)
		require.Contains(t, value.Reason, "timed out")
	case <-time.After(time.Second):
		t.Fatal("lookup ignored deadline")
	}
}

func TestIPv6LocalFlowCannotMatchIPv4WildcardSocketOwner(t *testing.T) {
	now := time.Now()
	var lookups atomic.Int32
	r := New(Options{LocalAddresses: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil }, Lookup: func(context.Context, Query) (Result, error) {
		lookups.Add(1)
		return Result{Status: "matched", PID: 42, Name: "wrong IPv4 process", StartedAt: now.Add(-time.Hour)}, nil
	}})
	defer r.Close()
	result := r.resolve(context.Background(), Query{Protocol: "udp", Source: netip.MustParseAddrPort("[2001:db8::1]:1234"), Destination: netip.MustParseAddrPort("[2001:db8::2]:443"), ObservedAt: now})
	require.Equal(t, "unknown", result.Status)
	require.Contains(t, result.Reason, "IPv6")
	require.Zero(t, result.PID)
	require.Zero(t, lookups.Load())
}
