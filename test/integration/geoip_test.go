package integration

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
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

func TestFullBundledDBIPJSONCanBeValidatedAndImported(t *testing.T) {
	manifestBytes, err := os.ReadFile(filepath.Join("..", "..", "pkg", "geoip", "data", "dbip-country-lite-2026-10.ipv4.json"))
	require.NoError(t, err)
	var manifest struct {
		JSONSHA256 string `json:"json_sha256"`
		JSONBytes  int    `json:"json_bytes"`
		Ranges     int    `json:"ranges"`
	}
	require.NoError(t, json.Unmarshal(manifestBytes, &manifest))
	packed, err := os.Open(filepath.Join("..", "..", "pkg", "geoip", "data", "dbip-country-lite-2026-10.ipv4.bin.gz"))
	require.NoError(t, err)
	defer packed.Close()
	reader, err := gzip.NewReader(packed)
	require.NoError(t, err)
	defer reader.Close()
	metadata := geoip.Builtin().Metadata()
	file := geoip.File{Format: 1, Version: metadata.Version, Source: metadata.Source, License: metadata.License, LicenseURL: metadata.LicenseURL, PublishedAt: metadata.PublishedAt, Ranges: make(geoip.Ranges, manifest.Ranges)}
	var entry [10]byte
	for i := range file.Ranges {
		if _, err := io.ReadFull(reader, entry[:]); err != nil {
			t.Fatalf("read complete bundled range %d: %v", i+1, err)
		}
		start, end := [4]byte{}, [4]byte{}
		binary.BigEndian.PutUint32(start[:], binary.BigEndian.Uint32(entry[:4]))
		binary.BigEndian.PutUint32(end[:], binary.BigEndian.Uint32(entry[4:8]))
		file.Ranges[i] = geoip.Range{Start: netip.AddrFrom4(start).String(), End: netip.AddrFrom4(end).String(), Country: string(entry[8:10])}
	}
	var extra [1]byte
	_, err = io.ReadFull(reader, extra[:])
	require.ErrorIs(t, err, io.EOF)
	data, err := json.Marshal(file)
	require.NoError(t, err)
	data = append(data, '\n')
	require.Len(t, data, manifest.JSONBytes)
	digest := sha256.Sum256(data)
	require.Equal(t, manifest.JSONSHA256, hex.EncodeToString(digest[:]), "Go's independent full conversion must reproduce the Node generator's import bytes")
	database, err := geoip.Load(bytes.NewReader(data), manifest.JSONSHA256)
	require.NoError(t, err, "the full official IPv4 source must fit the bounded public import format")
	require.Equal(t, 362122, database.Metadata().Ranges)
	for _, address := range []string{"8.8.8.8", "114.114.114.114", "1.208.0.0", "192.168.0.1", "255.255.255.255"} {
		require.Equal(t, geoip.QueryCountryByString(address), database.Country(netip.MustParseAddr(address)))
	}
}

func TestBundledGeoIPAttributionAndRoutingShareOneSnapshot(t *testing.T) {
	for _, key := range []string{"http_proxy", "https_proxy", "socks_proxy", "HTTP_PROXY", "HTTPS_PROXY", "SOCKS_PROXY"} {
		t.Setenv(key, "")
	}
	configuration, err := kone.ParseConfig([]byte("[dns]\nservers=['127.0.0.1:53']\n[[rules]]\ntype='GEOIP'\npattern='US'\noutbound='reject'\n[[rules]]\ntype='FINAL'\noutbound='direct'"))
	require.NoError(t, err)
	one, err := kone.FromConfig(configuration)
	require.NoError(t, err)
	defer one.Close()
	builtin := geoip.Builtin()
	status := one.GeoIPStatus().Current
	require.Equal(t, "db-ip-country-lite-2026-10", status.Version)
	require.Equal(t, "CC-BY-4.0", status.License)
	require.Equal(t, 362122, status.Ranges)
	require.Equal(t, builtin.Metadata().SourceSHA256, status.SourceSHA256)
	require.Equal(t, "US", geoip.QueryCountryByString("8.8.8.8"))
	require.Equal(t, "US", builtin.Country(netip.MustParseAddr("8.8.8.8")))
	decision, err := one.ExplainDecision("8.8.8.8:443", "tcp", 0)
	require.NoError(t, err)
	require.Equal(t, kone.BuiltinReject, decision.Outbound)
	require.Equal(t, status.SHA256, decision.GeoIPSHA256)
	require.Equal(t, status.Version, decision.GeoIPVersion)
	require.Empty(t, builtin.Country(netip.MustParseAddr("2001:db8::1")), "country data has an explicit IPv4-only scope")
	require.Empty(t, geoip.QueryCountryByString("192.168.0.1"), "the provider's unknown-country range stays unknown")
}
