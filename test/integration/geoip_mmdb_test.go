package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/geoip"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestMMDBLocalConfigPersistenceIPv6RoutingAndRollback(t *testing.T) {
	// Synthetic documentation prefixes exercise the actual MMDB parser, CLI
	// source selection and routing snapshots without external data or host TUN.
	for _, key := range []string{"http_proxy", "https_proxy", "socks_proxy", "HTTP_PROXY", "HTTPS_PROXY", "SOCKS_PROXY"} {
		t.Setenv(key, "")
	}
	tree, err := mmdbwriter.New(mmdbwriter.Options{IPVersion: 6, IncludeReservedNetworks: true, DatabaseType: "Synthetic-Country", Description: map[string]string{"en": "Synthetic test data"}, Languages: []string{"en"}, BuildEpoch: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix()})
	require.NoError(t, err)
	for _, prefix := range []string{"192.0.2.0/24", "2001:db8::/32"} {
		_, network, err := net.ParseCIDR(prefix)
		require.NoError(t, err)
		require.NoError(t, tree.Insert(network, mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String("CN")}}))
	}
	var output bytes.Buffer
	_, err = tree.WriteTo(&output)
	require.NoError(t, err)
	data := output.Bytes()
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	directory := t.TempDir()
	filename := filepath.Join(directory, "kone.toml")
	require.NoError(t, os.WriteFile(filepath.Join(directory, "country.mmdb"), data, 0600))
	configuration := fmt.Sprintf("[core]\nipv6-network='fd42:4b4f:4e45::1/64'\n[dns]\nservers=['127.0.0.1:5353']\n[geoip]\nprovider='dbip-lite'\nfile='country.mmdb'\nsha256='%s'\n[[rules]]\ntype='GEOIP'\npattern='CN'\noutbound='reject'\n[[rules]]\ntype='FINAL'\noutbound='direct'\n", digest)
	require.NoError(t, os.WriteFile(filename, []byte(configuration), 0600))
	cfg, err := kone.ParseConfig(filename)
	require.NoError(t, err)
	engine, err := kone.FromConfig(cfg)
	require.NoError(t, err)
	defer engine.Close()
	for _, target := range []string{"192.0.2.1:443", "[2001:db8::1]:443"} {
		decision, err := engine.ExplainDecision(target, "tcp", 0)
		require.NoError(t, err)
		require.Equal(t, kone.BuiltinReject, decision.Outbound)
		require.Equal(t, digest, decision.GeoIPSHA256)
	}
	repository, err := geoip.OpenRepository(filepath.Join(directory, "repository"))
	require.NoError(t, err)
	database, err := repository.InstallMMDB(data, digest, "dbip-lite")
	require.NoError(t, err)
	managed := kone.DefaultConfig()
	managed.Core = cfg.Core
	managed.DNS.Servers = []string{"127.0.0.1:5353"}
	managed.Rule = cfg.Rule
	restarted, err := kone.FromConfig(managed, kone.WithGeoIPDatabase(database))
	require.NoError(t, err)
	defer restarted.Close()
	before := restarted.GeoIPStatus()
	reopened, err := geoip.OpenRepository(filepath.Join(directory, "repository"))
	require.NoError(t, err)
	require.Equal(t, digest, reopened.Current().Metadata().SHA256)
	require.True(t, reopened.Current().Metadata().IPv6)
	previous, err := reopened.Rollback()
	require.NoError(t, err)
	require.NoError(t, restarted.ApplyGeoIPDatabase(previous, before.PolicyVersion))
	decision, err := restarted.ExplainDecision("[2001:db8::1]:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, kone.BuiltinDirect, decision.Outbound)
	require.True(t, restarted.GeoIPStatus().Current.Builtin)
	// The original engine still holds the old MMDB snapshot after replacement.
	decision, err = engine.ExplainDecision("[2001:db8::1]:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, kone.BuiltinReject, decision.Outbound)
	require.NoError(t, os.WriteFile(filepath.Join(directory, "country.mmdb"), []byte("corrupt"), 0600))
	_, err = kone.FromConfig(cfg)
	require.Error(t, err)
}
