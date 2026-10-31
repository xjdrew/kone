package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/geoip"
	"github.com/xjdrew/kone/pkg/kone"
)

// The public import/persistence/routing chain needs no TUN or host changes.
func TestGeoIPImportRestartAndRollback(t *testing.T) {
	for _, key := range []string{"http_proxy", "https_proxy", "socks_proxy", "HTTP_PROXY", "HTTPS_PROXY", "SOCKS_PROXY"} {
		t.Setenv(key, "")
	}
	directory := t.TempDir()
	repository, err := geoip.OpenRepository(directory)
	require.NoError(t, err)
	configuration, err := kone.ParseConfig([]byte("[dns]\nservers=['127.0.0.1:53']\n[[rules]]\ntype='GEOIP'\npattern='CN'\noutbound='reject'\n[[rules]]\ntype='FINAL'\noutbound='direct'"))
	require.NoError(t, err)
	one, err := kone.FromConfig(configuration, kone.WithGeoIPDatabase(repository.Current()))
	require.NoError(t, err)
	file := geoip.File{Format: 1, Version: "fixture-2024", Source: "https://example.com/data", License: "CC0-1.0", LicenseURL: "https://creativecommons.org/publicdomain/zero/1.0/", PublishedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), Ranges: []geoip.Range{{Start: "192.0.2.0", End: "192.0.2.255", Country: "CN"}}}
	data, err := json.Marshal(file)
	require.NoError(t, err)
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	_, err = repository.Install(data, digest)
	require.NoError(t, err)
	require.NoError(t, one.ApplyGeoIP(data, digest, one.GeoIPStatus().PolicyVersion))
	decision, err := one.ExplainDecision("192.0.2.1:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, kone.BuiltinReject, decision.Outbound)
	require.Equal(t, digest, decision.GeoIPSHA256)
	require.NoError(t, one.Close())
	reopened, err := geoip.OpenRepository(directory)
	require.NoError(t, err)
	restarted, err := kone.FromConfig(configuration, kone.WithGeoIPDatabase(reopened.Current()))
	require.NoError(t, err)
	defer restarted.Close()
	decision, err = restarted.ExplainDecision("192.0.2.1:443", "udp", 0)
	require.ErrorIs(t, err, kone.ErrRejected)
	require.Equal(t, digest, decision.GeoIPSHA256)
	before := restarted.GeoIPStatus()
	_, err = reopened.Install([]byte("corrupted update"), digest)
	require.Error(t, err)
	require.Equal(t, before.Current.SHA256, reopened.Current().Metadata().SHA256)
	previous, err := reopened.Rollback()
	require.NoError(t, err)
	require.NoError(t, restarted.ApplyGeoIPDatabase(previous, before.PolicyVersion))
	decision, err = restarted.ExplainDecision("192.0.2.1:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, kone.BuiltinDirect, decision.Outbound)
	require.True(t, restarted.GeoIPStatus().Current.Builtin)
}
