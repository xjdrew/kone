package geoip

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func builtinTestData(t *testing.T, records []addressRange) ([]byte, builtinManifest) {
	t.Helper()
	packed := make([]byte, len(records)*10)
	for i, record := range records {
		binary.BigEndian.PutUint32(packed[i*10:], record.start)
		binary.BigEndian.PutUint32(packed[i*10+4:], record.end)
		copy(packed[i*10+8:], record.country)
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	_, err := writer.Write(packed)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	data := buffer.Bytes()
	digest := sha256.Sum256(data)
	packedDigest := sha256.Sum256(packed)
	return data, builtinManifest{Format: 1, Version: "fixture-2024-01", Source: "https://example.com/fixture.csv.gz", License: "CC-BY-4.0", LicenseURL: "https://creativecommons.org/licenses/by/4.0/", PublishedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), SourceSHA256: hex.EncodeToString(digest[:]), Ranges: len(records), PackedBytes: len(packed), PackedSHA256: hex.EncodeToString(packedDigest[:]), GzipBytes: len(data), GzipSHA256: hex.EncodeToString(digest[:])}
}

func TestBundledDecoderIntegrityBoundsAndUnknownCountries(t *testing.T) {
	data, metadata := builtinTestData(t, []addressRange{{start: 0, end: 255, country: "ZZ"}, {start: 256, end: 511, country: "CN"}})
	database, err := decodeBuiltin(data, metadata)
	require.NoError(t, err)
	require.Empty(t, database.Country(netip.MustParseAddr("0.0.0.1")))
	require.Equal(t, "CN", database.Country(netip.MustParseAddr("0.0.1.1")))
	require.Empty(t, database.Country(netip.MustParseAddr("2001:db8::1")))
	for _, mutate := range []func(*builtinManifest){
		func(m *builtinManifest) { m.Format = 2 },
		func(m *builtinManifest) { m.Ranges = MaxRanges + 1 },
		func(m *builtinManifest) { m.PackedBytes++ },
		func(m *builtinManifest) { m.GzipBytes++ },
		func(m *builtinManifest) { m.SourceSHA256 = "invalid" },
		func(m *builtinManifest) { m.PublishedAt = time.Time{} },
	} {
		bad := metadata
		mutate(&bad)
		_, err := decodeBuiltin(data, bad)
		require.ErrorContains(t, err, "manifest")
	}
	bad := metadata
	bad.PackedSHA256 = metadata.GzipSHA256
	_, err = decodeBuiltin(data, bad)
	require.ErrorContains(t, err, "packed SHA256 mismatch")
	changed := bytes.Clone(data)
	changed[len(changed)-1] ^= 1
	_, err = decodeBuiltin(changed, metadata)
	require.ErrorContains(t, err, "gzip SHA256 mismatch")
	digest := sha256.Sum256(changed)
	bad = metadata
	bad.GzipSHA256 = hex.EncodeToString(digest[:])
	_, err = decodeBuiltin(changed, bad)
	require.ErrorContains(t, err, "checksum failure")
	invalid := []byte("not gzip")
	digest = sha256.Sum256(invalid)
	bad = metadata
	bad.GzipBytes, bad.GzipSHA256 = len(invalid), hex.EncodeToString(digest[:])
	_, err = decodeBuiltin(invalid, bad)
	require.ErrorContains(t, err, "read bundled GeoIP gzip")
	bad = metadata
	bad.Ranges, bad.PackedBytes = 1, 10
	_, err = decodeBuiltin(data, bad)
	require.ErrorContains(t, err, "size/checksum failure")
	for _, records := range [][]addressRange{
		{{start: 2, end: 1, country: "CN"}},
		{{start: 1, end: 3, country: "CN"}, {start: 3, end: 4, country: "US"}},
		{{start: 1, end: 2, country: "cn"}},
	} {
		data, metadata := builtinTestData(t, records)
		_, err := decodeBuiltin(data, metadata)
		require.ErrorContains(t, err, "invalid bundled GeoIP range")
	}
}

func TestBundledDatasetStartupMemoryAndPublicQueryConsistency(t *testing.T) {
	var metadata builtinManifest
	require.NoError(t, json.Unmarshal(builtinManifestJSON, &metadata))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	database, err := decodeBuiltin(builtinCompressed, metadata)
	require.NoError(t, err)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	// A structural allocation budget is stable across CPU speeds. Timings are
	// evidence for this runner only; they are never labelled as Raspberry Pi data.
	require.Less(t, allocated, uint64(32<<20))
	t.Logf("GeoIP decode=%s allocated=%d compressed=%d range_table=%d pointer_bytes=%d ranges=%d", elapsed, allocated, len(builtinCompressed), uintptr(len(database.ranges))*unsafe.Sizeof(addressRange{}), unsafe.Sizeof(uintptr(0)), len(database.ranges))
	for i := 0; i < len(database.ranges); i += 997 {
		entry := database.ranges[i]
		expected := entry.country
		if expected == "ZZ" {
			expected = ""
		}
		require.Equal(t, expected, QueryCountry(entry.start))
		require.Equal(t, expected, QueryCountry(entry.end))
	}
	require.Equal(t, metadata.PackedSHA256, Builtin().Metadata().SHA256)
}

func BenchmarkBuiltinDecode(b *testing.B) {
	var metadata builtinManifest
	if err := json.Unmarshal(builtinManifestJSON, &metadata); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(metadata.PackedBytes))
	b.ResetTimer()
	for range b.N {
		database, err := decodeBuiltin(builtinCompressed, metadata)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkCountry = database.Country(netip.MustParseAddr("8.8.8.8"))
	}
}
