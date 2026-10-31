package geoip

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

//go:embed data/dbip-country-lite-2026-10.ipv4.bin.gz
var builtinCompressed []byte

//go:embed data/dbip-country-lite-2026-10.ipv4.json
var builtinManifestJSON []byte

type builtinManifest struct {
	Format       int       `json:"format"`
	Version      string    `json:"version"`
	Source       string    `json:"source"`
	License      string    `json:"license"`
	LicenseURL   string    `json:"license_url"`
	PublishedAt  time.Time `json:"published_at"`
	SourceSHA256 string    `json:"source_sha256"`
	Ranges       int       `json:"ranges"`
	PackedBytes  int       `json:"packed_bytes"`
	PackedSHA256 string    `json:"packed_sha256"`
	GzipBytes    int       `json:"gzip_bytes"`
	GzipSHA256   string    `json:"gzip_sha256"`
}

func decodeBuiltin(data []byte, manifest builtinManifest) (*Database, error) {
	if manifest.Format != 1 || manifest.Ranges <= 0 || manifest.Ranges > MaxRanges || manifest.PackedBytes != manifest.Ranges*10 || len(data) > 16<<20 || len(data) != manifest.GzipBytes || !validDigest(manifest.SourceSHA256) || !validDigest(manifest.PackedSHA256) || !validDigest(manifest.GzipSHA256) || !validMetadataText(manifest.Version, 128) || !validMetadataText(manifest.License, 128) || !metadataURL(manifest.Source) || !metadataURL(manifest.LicenseURL) || manifest.PublishedAt.IsZero() {
		return nil, errors.New("invalid bundled GeoIP manifest")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != manifest.GzipSHA256 {
		return nil, errors.New("bundled GeoIP gzip SHA256 mismatch")
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("read bundled GeoIP gzip: %w", err)
	}
	packed := make([]byte, manifest.PackedBytes)
	_, readErr := io.ReadFull(reader, packed)
	var extra [1]byte
	_, tailErr := io.ReadFull(reader, extra[:])
	closeErr := reader.Close()
	if readErr != nil || tailErr != io.EOF || closeErr != nil {
		return nil, errors.New("bundled GeoIP gzip size/checksum failure")
	}
	digest = sha256.Sum256(packed)
	if hex.EncodeToString(digest[:]) != manifest.PackedSHA256 {
		return nil, errors.New("bundled GeoIP packed SHA256 mismatch")
	}
	ranges := make([]addressRange, manifest.Ranges)
	// Reuse at most 676 two-letter strings across every range. This avoids
	// hundreds of thousands of tiny country allocations on small gateways.
	countries := make(map[uint16]string)
	for i := range ranges {
		entry := packed[i*10 : (i+1)*10]
		start, end := binary.BigEndian.Uint32(entry[:4]), binary.BigEndian.Uint32(entry[4:8])
		if start > end || i > 0 && start <= ranges[i-1].end || entry[8] < 'A' || entry[8] > 'Z' || entry[9] < 'A' || entry[9] > 'Z' {
			return nil, fmt.Errorf("invalid bundled GeoIP range %d", i+1)
		}
		code := binary.BigEndian.Uint16(entry[8:])
		country, found := countries[code]
		if !found {
			country = string(entry[8:])
			countries[code] = country
		}
		ranges[i] = addressRange{start: start, end: end, country: country}
	}
	return &Database{ranges: ranges, metadata: Metadata{Version: manifest.Version, Source: manifest.Source, License: manifest.License, LicenseURL: manifest.LicenseURL, PublishedAt: manifest.PublishedAt, LoadedAt: time.Now().UTC(), SHA256: manifest.PackedSHA256, SourceSHA256: manifest.SourceSHA256, Ranges: len(ranges), Builtin: true, Provenance: "DB-IP Country Lite; complete IPv4 extraction from the official monthly CSV; IPv6 excluded; ZZ is unknown; see licenses/DB-IP.md"}}, nil
}

var builtinOnce sync.Once
var builtinDatabase *Database

// Builtin returns the same checked, immutable DB-IP IPv4 snapshot for all public
// and rule-engine queries. It performs no filesystem or network operations.
func Builtin() *Database {
	builtinOnce.Do(func() {
		var manifest builtinManifest
		if err := json.Unmarshal(builtinManifestJSON, &manifest); err != nil {
			panic("invalid bundled GeoIP manifest JSON")
		}
		var err error
		builtinDatabase, err = decodeBuiltin(builtinCompressed, manifest)
		if err != nil {
			panic(err)
		}
	})
	return builtinDatabase
}
