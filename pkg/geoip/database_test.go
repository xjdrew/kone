package geoip

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func fixtureFile(country, version string) File {
	return File{Format: 1, Version: version, Source: "https://example.com/data", License: "CC0-1.0", LicenseURL: "https://creativecommons.org/publicdomain/zero/1.0/", PublishedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), Ranges: []Range{{Start: "192.0.2.0", End: "192.0.2.255", Country: country}}}
}

func fixtureBytes(t *testing.T, file File) ([]byte, string) {
	t.Helper()
	data, err := json.Marshal(file)
	require.NoError(t, err)
	return data, digestOf(data)
}

func digestOf(data []byte) string { hash := sha256.Sum256(data); return hex.EncodeToString(hash[:]) }

func TestDatabaseValidationAndImmutability(t *testing.T) {
	data, digest := fixtureBytes(t, fixtureFile("CN", "2024-01-01"))
	database, err := Load(bytes.NewReader(data), digest)
	require.NoError(t, err)
	require.Equal(t, "CN", database.Country(netip.MustParseAddr("192.0.2.0")))
	require.Equal(t, "CN", database.Country(netip.MustParseAddr("192.0.2.255")))
	require.Equal(t, "CN", database.Country(netip.MustParseAddr("::ffff:192.0.2.1")))
	for _, address := range []netip.Addr{{}, netip.MustParseAddr("192.0.3.0"), netip.MustParseAddr("2001:db8::1")} {
		require.Empty(t, database.Country(address))
	}
	require.Equal(t, digest, database.Metadata().SHA256)
	require.False(t, database.Metadata().Builtin)
	require.Positive(t, database.Metadata().Ranges)
	copy := database.Bytes()
	copy[0] = '!'
	require.Equal(t, byte('{'), database.Bytes()[0])
	data[0] = '!'
	require.Equal(t, byte('{'), database.Bytes()[0], "validated database owns its immutable byte snapshot")
	_, err = Load(bytes.NewReader(database.Bytes()), strings.Repeat("0", 64))
	require.ErrorContains(t, err, "SHA256 mismatch")
	_, err = Load(bytes.NewReader(database.Bytes()), "")
	require.Error(t, err)
	_, err = Load(strings.NewReader(strings.Repeat(" ", MaxFileSize+1)), digest)
	require.ErrorContains(t, err, "32 MiB")
}

func TestDatabaseRejectsMalformedImports(t *testing.T) {
	for name, change := range map[string]func(*File){
		"format": func(f *File) { f.Format = 2 }, "empty version": func(f *File) { f.Version = "" },
		"license": func(f *File) { f.License = "" }, "source": func(f *File) { f.Source = "http://example.com/data" },
		"credentials":    func(f *File) { f.Source = "https://private:password@example.com/data" },
		"license source": func(f *File) { f.LicenseURL = "not-a-url" },
		"time":           func(f *File) { f.PublishedAt = time.Time{} }, "future": func(f *File) { f.PublishedAt = time.Now().Add(48 * time.Hour) },
		"empty": func(f *File) { f.Ranges = nil }, "ipv6": func(f *File) { f.Ranges[0].Start = "2001:db8::1" },
		"reversed": func(f *File) { f.Ranges[0].End = "192.0.1.0" }, "country": func(f *File) { f.Ranges[0].Country = "cn" },
		"overlap": func(f *File) { f.Ranges = append(f.Ranges, f.Ranges[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			file := fixtureFile("CN", "v1")
			change(&file)
			data, digest := fixtureBytes(t, file)
			_, err := Load(bytes.NewReader(data), digest)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "password")
		})
	}
	valid, _ := fixtureBytes(t, fixtureFile("CN", "v1"))
	for _, bad := range [][]byte{
		[]byte(`{"format":1,"format":1}`), append(append([]byte(nil), valid...), []byte(` {}`)...),
		[]byte(strings.Replace(string(valid), `"format":1`, `"FORMAT":1`, 1)),
		[]byte(strings.Replace(string(valid), `"format":1`, `"format":1,"unknown":1`, 1)),
		[]byte(`{"format":1,"ranges":[{"start":"192.0.2.0","start":"192.0.2.1"}]}`),
	} {
		_, err := Load(bytes.NewReader(bad), digestOf(bad))
		require.Error(t, err)
	}
}

func TestBuiltinDatabasePreservesLegacyQueries(t *testing.T) {
	database := Builtin()
	require.Same(t, database, Builtin())
	require.True(t, database.Metadata().Builtin)
	require.Equal(t, "unknown", database.Metadata().License)
	require.True(t, database.Metadata().PublishedAt.IsZero())
	for address, country := range cases {
		require.Equal(t, country, database.Country(netip.MustParseAddr(address)))
	}
	var zero *Database
	require.Empty(t, zero.Country(netip.Addr{}))
	require.Empty(t, zero.Metadata().SHA256)
	require.Nil(t, zero.Bytes())
}

func TestRepositoryPersistenceRollbackAndFailureRetainsCurrent(t *testing.T) {
	directory := t.TempDir()
	r, err := OpenRepository(directory)
	require.NoError(t, err)
	require.True(t, r.Current().Metadata().Builtin)
	_, err = r.Rollback()
	require.Error(t, err)
	first, firstSHA := fixtureBytes(t, fixtureFile("CN", "v1"))
	old, err := r.Install(first, firstSHA)
	require.NoError(t, err)
	second, secondSHA := fixtureBytes(t, fixtureFile("US", "v2"))
	current, err := r.Install(second, secondSHA)
	require.NoError(t, err)
	require.Equal(t, "CN", old.Country(netip.MustParseAddr("192.0.2.1")))
	require.Equal(t, "US", current.Country(netip.MustParseAddr("192.0.2.1")))
	reopened, err := OpenRepository(directory)
	require.NoError(t, err)
	require.Equal(t, secondSHA, reopened.Current().Metadata().SHA256)
	require.Equal(t, firstSHA, reopened.Previous().Metadata().SHA256)
	rolled, err := reopened.Rollback()
	require.NoError(t, err)
	require.Equal(t, firstSHA, rolled.Metadata().SHA256)
	_, err = reopened.Install([]byte("corrupt"), secondSHA)
	require.Error(t, err)
	require.Equal(t, firstSHA, reopened.Current().Metadata().SHA256)
	require.NoError(t, os.WriteFile(filepath.Join(directory, firstSHA+".json"), []byte("damaged"), 0600))
	_, err = OpenRepository(directory)
	require.ErrorContains(t, err, "active GeoIP data is invalid")
	recovered, err := RecoverPrevious(directory)
	require.NoError(t, err)
	require.Equal(t, secondSHA, recovered.Current().Metadata().SHA256)
	require.Nil(t, recovered.Previous())
	reopened, err = OpenRepository(directory)
	require.NoError(t, err)
	require.Equal(t, secondSHA, reopened.Current().Metadata().SHA256)
}

func TestRepositoryDoesNotPublishWhenManifestWriteFails(t *testing.T) {
	directory := t.TempDir()
	r, err := OpenRepository(directory)
	require.NoError(t, err)
	require.NoError(t, os.Mkdir(filepath.Join(directory, "manifest.json"), 0700))
	data, digest := fixtureBytes(t, fixtureFile("CN", "v1"))
	_, err = r.Install(data, digest)
	require.Error(t, err)
	require.True(t, r.Current().Metadata().Builtin)
	_, err = os.Stat(filepath.Join(directory, digest+".json"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestDatabaseConcurrentQueriesAndRepositoryPublication(t *testing.T) {
	r, err := OpenRepository(t.TempDir())
	require.NoError(t, err)
	data, digest := fixtureBytes(t, fixtureFile("CN", "v1"))
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				database := r.Current()
				database.Country(netip.MustParseAddr("192.0.2.1"))
				database.Metadata()
			}
		}()
	}
	_, err = r.Install(data, digest)
	require.NoError(t, err)
	workers.Wait()
}

var benchmarkDatabaseCountry string

func BenchmarkImmutableDatabaseLookup(b *testing.B) {
	database := Builtin()
	addresses := []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("114.114.114.114"), netip.MustParseAddr("192.168.1.1")}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkDatabaseCountry = database.Country(addresses[i%len(addresses)])
	}
}
