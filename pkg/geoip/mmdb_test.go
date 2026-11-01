package geoip

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	maxminddb "github.com/oschwald/maxminddb-golang/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mmdbFixture(t testing.TB, provider, country string) ([]byte, string) {
	t.Helper()
	return mmdbFixtureBuildEpoch(t, provider, country, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
}

func mmdbFixtureBuildEpoch(t testing.TB, provider, country string, epoch int64) ([]byte, string) {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{IPVersion: 6, IncludeReservedNetworks: true, DatabaseType: "Synthetic-Country-Test", Description: map[string]string{"en": "Synthetic country test data"}, Languages: []string{"en"}, BuildEpoch: epoch})
	require.NoError(t, err)
	var record mmdbtype.Map
	if provider == "ipinfo-lite" {
		record = mmdbtype.Map{"country_code": mmdbtype.String(country), "country": mmdbtype.String("Synthetic country")}
	} else {
		record = mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(country)}}
	}
	for _, prefix := range []string{"192.0.2.0/24", "2001:db8::/32"} {
		_, network, err := net.ParseCIDR(prefix)
		require.NoError(t, err)
		require.NoError(t, tree.Insert(network, record))
	}
	var output bytes.Buffer
	_, err = tree.WriteTo(&output)
	require.NoError(t, err)
	data := output.Bytes()
	parsed, err := maxminddb.OpenBytes(data)
	require.NoError(t, err)
	require.NoError(t, parsed.Verify())
	require.NoError(t, parsed.Close())
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:])
}

func TestMMDBProvidersLookupBothFamiliesAndRetainImmutableBytes(t *testing.T) {
	for _, provider := range Providers() {
		t.Run(provider.ID, func(t *testing.T) {
			data, digest := mmdbFixture(t, provider.ID, "CN")
			db, err := LoadMMDB(bytes.NewReader(data), digest, provider.ID)
			require.NoError(t, err)
			for _, address := range []string{"192.0.2.7", "::ffff:192.0.2.7", "2001:db8::7"} {
				require.Equal(t, "CN", db.Country(netip.MustParseAddr(address)))
			}
			require.Empty(t, db.Country(netip.MustParseAddr("198.51.100.1")))
			require.Empty(t, db.Country(netip.Addr{}))
			require.Equal(t, provider.ID, db.Metadata().Provider)
			require.True(t, db.Metadata().IPv6)
			require.Equal(t, "mmdb", db.Metadata().Format)
			data[0] ^= 0xff
			copy := db.Bytes()
			copy[0] ^= 0xff
			require.Equal(t, "CN", db.Country(netip.MustParseAddr("2001:db8::7")))
			var tasks sync.WaitGroup
			for range 8 {
				tasks.Go(func() {
					for range 100 {
						assert.Equal(t, "CN", db.Country(netip.MustParseAddr("2001:db8::7")))
					}
				})
			}
			tasks.Wait()
		})
	}
	copy := Providers()
	copy[0].Name = "changed"
	copy[0].Formats[0] = "changed"
	require.NotEqual(t, "changed", Providers()[0].Name)
	require.Equal(t, "mmdb", Providers()[0].Formats[0])
}

func TestMMDBValidationRejectsChecksumCorruptionAndWrongCountrySchema(t *testing.T) {
	data, digest := mmdbFixture(t, "ipinfo-lite", "US")
	_, err := LoadMMDB(bytes.NewReader(data), digest, "unknown")
	require.Error(t, err)
	_, err = LoadMMDB(bytes.NewReader(data), "bad", "ipinfo-lite")
	require.Error(t, err)
	_, err = LoadMMDB(bytes.NewReader(data), string(bytes.Repeat([]byte{'0'}, 64)), "ipinfo-lite")
	require.ErrorContains(t, err, "SHA256 mismatch")
	_, err = LoadMMDB(bytes.NewReader(data), digest, "dbip-lite")
	require.Error(t, err)
	broken := []byte("not a database")
	brokenDigest := sha256.Sum256(broken)
	_, err = LoadMMDB(bytes.NewReader(broken), hex.EncodeToString(brokenDigest[:]), "ipinfo-lite")
	require.Error(t, err)
	for _, country := range []string{"usa", "U", "USX", "ZZ", ""} {
		bad, sum := mmdbFixture(t, "ipinfo-lite", country)
		_, err := LoadMMDB(bytes.NewReader(bad), sum, "ipinfo-lite")
		require.Error(t, err)
	}
	bad := bytes.Clone(data)
	bad[0] ^= 0xff
	badDigest := sha256.Sum256(bad)
	_, err = LoadMMDB(bytes.NewReader(bad), hex.EncodeToString(badDigest[:]), "ipinfo-lite")
	require.Error(t, err)
}

func TestMMDBRepositoryPersistsRollsBackAndKeepsActiveSnapshots(t *testing.T) {
	directory := t.TempDir()
	repo, err := OpenRepository(directory)
	require.NoError(t, err)
	data, digest := mmdbFixture(t, "ipinfo-lite", "CN")
	first, err := repo.InstallMMDB(data, digest, "ipinfo-lite")
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(directory, digest+".mmdb"))
	secondData, secondDigest := mmdbFixture(t, "dbip-lite", "US")
	_, err = repo.InstallMMDB(secondData, secondDigest, "dbip-lite")
	require.NoError(t, err)
	reopened, err := OpenRepository(directory)
	require.NoError(t, err)
	require.Equal(t, "US", reopened.Current().Country(netip.MustParseAddr("2001:db8::1")))
	_, err = reopened.Rollback()
	require.NoError(t, err)
	require.Equal(t, digest, reopened.Current().Metadata().SHA256)
	jsonData, jsonDigest := fixtureBytes(t, fixtureFile("FR", "json"))
	_, err = reopened.Install(jsonData, jsonDigest)
	require.NoError(t, err)
	require.Equal(t, "CN", first.Country(netip.MustParseAddr("2001:db8::1")))
	require.NoFileExists(t, filepath.Join(directory, secondDigest+".mmdb"))
	require.NoError(t, os.WriteFile(filepath.Join(directory, jsonDigest+".json"), []byte("corrupt"), 0600))
	restored, err := RecoverPrevious(directory)
	require.NoError(t, err)
	require.Equal(t, digest, restored.Current().Metadata().SHA256)
	_, err = restored.InstallMMDB(data, digest, "ipinfo-lite")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, digest+".mmdb"), []byte("corrupt"), 0600))
	_, err = OpenRepository(directory)
	require.Error(t, err)
}

func TestMMDBRepositoryRejectsProviderRelabelingForIdenticalBytes(t *testing.T) {
	repo, err := OpenRepository(t.TempDir())
	require.NoError(t, err)
	data, digest := mmdbFixture(t, "dbip-lite", "CN")
	_, err = repo.InstallMMDB(data, digest, "dbip-lite")
	require.NoError(t, err)
	manifestPath := filepath.Join(repo.directory, "manifest.json")
	before, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	_, err = repo.InstallMMDB(data, digest, "maxmind-geolite2")
	require.ErrorContains(t, err, "different provider")
	require.Equal(t, "dbip-lite", repo.Current().Metadata().Provider)
	after, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestMMDBRejectsUnreasonableBuildEpochs(t *testing.T) {
	for _, epoch := range []int64{time.Date(1989, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), time.Now().Add(72 * time.Hour).Unix()} {
		data, digest := mmdbFixtureBuildEpoch(t, "ipinfo-lite", "CN", epoch)
		_, err := LoadMMDB(bytes.NewReader(data), digest, "ipinfo-lite")
		require.ErrorContains(t, err, "build time")
	}
}

func TestMMDBManifestRejectsUnboundOrUnrecognizedSchemas(t *testing.T) {
	current, previous, unrelated := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	for _, raw := range []string{
		`{"format":1,"current":"` + current + `","mmdb_providers":{"` + current + `":"dbip-lite"}}`,
		`{"format":2,"current":"` + current + `","mmdb_providers":{"` + current + `":"unknown"}}`,
		`{"format":2,"current":"` + current + `","mmdb_providers":{"../outside":"dbip-lite"}}`,
		`{"format":2,"current":"` + current + `","mmdb_providers":{"` + unrelated + `":"dbip-lite"}}`,
		`{"format":2,"current":"` + current + `","previous":"` + previous + `","mmdb_providers":{"` + current + `":"dbip-lite","` + previous + `":"ipinfo-lite","` + unrelated + `":"maxmind-geolite2"}}`,
	} {
		directory := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(directory, "manifest.json"), []byte(raw), 0600))
		_, err := OpenRepository(directory)
		require.ErrorContains(t, err, "manifest")
	}
}

func BenchmarkSyntheticMMDBCountryLookup(b *testing.B) {
	data, digest := mmdbFixture(b, "ipinfo-lite", "CN")
	database, err := LoadMMDB(bytes.NewReader(data), digest, "ipinfo-lite")
	require.NoError(b, err)
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("198.51.100.1")}
	b.ReportAllocs()
	b.ResetTimer()
	b.ReportMetric(float64(database.Metadata().Ranges), "networks")
	for i := 0; i < b.N; i++ {
		benchmarkDatabaseCountry = database.Country(addresses[i%len(addresses)])
	}
}
