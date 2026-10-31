package kone

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/geoip"
)

func geoIPFixture(t *testing.T, country, version string) ([]byte, string) {
	t.Helper()
	file := geoip.File{Format: 1, Version: version, Source: "https://example.com/data", License: "CC0-1.0", LicenseURL: "https://creativecommons.org/publicdomain/zero/1.0/", PublishedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), Ranges: []geoip.Range{{Start: "192.0.2.0", End: "192.0.2.255", Country: country}}}
	data, err := json.Marshal(file)
	require.NoError(t, err)
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:])
}

func geoIPEngine(t *testing.T, options ...Option) *One {
	t.Helper()
	cleanProxyEnv(t)
	cfg := parseTestConfig(t, "[[rules]]\ntype='GEOIP'\npattern='CN'\noutbound='reject'\n[[rules]]\ntype='FINAL'\noutbound='direct'\n")
	one, err := FromConfig(cfg, options...)
	require.NoError(t, err)
	return one
}

func TestGeoIPAtomicPolicyPublicationReloadAndRollback(t *testing.T) {
	one := geoIPEngine(t)
	old := one.policy.Load()
	address := netip.MustParseAddr("192.0.2.1")
	require.Equal(t, BuiltinDirect, old.rule.Proxy(address))
	cn, cnSHA := geoIPFixture(t, "CN", "v1")
	require.NoError(t, one.ApplyGeoIP(cn, cnSHA, old.version))
	first := one.policy.Load()
	require.Equal(t, old.version+1, first.version)
	require.Equal(t, BuiltinReject, first.rule.Proxy(address))
	require.Equal(t, BuiltinDirect, old.rule.Proxy(address), "old sessions retain their data version")
	decision, err := one.ExplainDecision("192.0.2.1:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, "v1", decision.GeoIPVersion)
	require.Equal(t, cnSHA, decision.GeoIPSHA256)
	require.NoError(t, one.Reload(one.Snapshot().Config))
	reloaded := one.policy.Load()
	require.Same(t, first.geoIP, reloaded.geoIP)
	require.Equal(t, BuiltinReject, reloaded.rule.Proxy(address))
	us, usSHA := geoIPFixture(t, "US", "v2")
	require.ErrorIs(t, one.ApplyGeoIP(us, usSHA, old.version), ErrGeoIPConflict)
	require.Same(t, reloaded, one.policy.Load())
	require.Error(t, one.ApplyGeoIP([]byte("corrupt"), usSHA, reloaded.version))
	require.Same(t, reloaded, one.policy.Load())
	require.NoError(t, one.ApplyGeoIP(us, usSHA, reloaded.version))
	require.Equal(t, BuiltinDirect, one.policy.Load().rule.Proxy(address))
	require.Equal(t, BuiltinReject, first.rule.Proxy(address))
	require.NoError(t, one.RollbackGeoIP(one.policy.Load().version))
	require.Equal(t, cnSHA, one.GeoIPStatus().Current.SHA256)
	require.Equal(t, usSHA, one.GeoIPStatus().Previous.SHA256)
	require.ErrorIs(t, one.RollbackGeoIP(old.version), ErrGeoIPConflict)
	before := one.policy.Load()
	require.NoError(t, one.ApplyGeoIP(cn, cnSHA, before.version))
	require.Same(t, before, one.policy.Load(), "same content is idempotent")
}

func TestGeoIPInitialDatabaseAndValidatedBuiltinRestore(t *testing.T) {
	data, digest := geoIPFixture(t, "CN", "v1")
	database, err := geoip.Load(bytes.NewReader(data), digest)
	require.NoError(t, err)
	one := geoIPEngine(t, WithGeoIPDatabase(database))
	require.Equal(t, digest, one.GeoIPStatus().Current.SHA256)
	decision, err := ExplainRoutingWithGeoIP(one.Snapshot().Config, database, "192.0.2.1:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, BuiltinReject, decision.Outbound)
	require.Equal(t, digest, decision.GeoIPSHA256)
	require.Error(t, one.RollbackGeoIP(one.GeoIPStatus().PolicyVersion))
	require.NoError(t, one.ApplyGeoIPDatabase(geoip.Builtin(), one.GeoIPStatus().PolicyVersion))
	require.True(t, one.GeoIPStatus().Current.Builtin)
	require.Error(t, one.ApplyGeoIPDatabase(nil, one.GeoIPStatus().PolicyVersion))
	require.Error(t, WithGeoIPDatabase(nil)(one))
	require.NoError(t, one.Close())
	require.ErrorContains(t, one.ApplyGeoIP(data, digest, one.GeoIPStatus().PolicyVersion), "closed")
	var zero *One
	require.True(t, zero.GeoIPStatus().Current.Builtin)
}

func TestGeoIPConcurrentSnapshotReadersAndPublication(t *testing.T) {
	one := geoIPEngine(t)
	data, digest := geoIPFixture(t, "CN", "v1")
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				snapshot := one.policy.Load()
				decision := snapshot.rule.Decide(netip.MustParseAddr("192.0.2.1"), "tcp", 443)
				if decision.GeoIPSHA256 != snapshot.geoIP.Metadata().SHA256 {
					t.Error("rule and data versions differ within a policy snapshot")
				}
			}
		}()
	}
	require.NoError(t, one.ApplyGeoIP(data, digest, one.GeoIPStatus().PolicyVersion))
	workers.Wait()
}
