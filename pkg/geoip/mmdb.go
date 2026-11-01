package geoip

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

const MaxMMDBFileSize = 64 << 20
const maxMMDBNetworks = 8_000_000

func mmdbCountry(result maxminddb.Result, provider string) (string, error) {
	var country string
	var err error
	if provider == "ipinfo-lite" {
		err = result.DecodePath(&country, "country_code")
	} else {
		err = result.DecodePath(&country, "country", "iso_code")
	}
	if err != nil {
		return "", errors.New("GeoIP record has an invalid country schema")
	}
	if country != "" && (len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z') {
		return "", errors.New("GeoIP country must be a two-letter uppercase code")
	}
	return country, nil
}

// LoadMMDB validates and retains an owned byte buffer. It does not mmap a
// replaceable file or close readers still retained by older routing snapshots.
func LoadMMDB(reader io.Reader, expectedSHA256, providerID string) (*Database, error) {
	provider, ok := FindProvider(providerID)
	if !ok {
		return nil, errors.New("select dbip-lite, ipinfo-lite or maxmind-geolite2 for an MMDB database")
	}
	if !validDigest(expectedSHA256) {
		return nil, errors.New("GeoIP requires an expected lowercase SHA256 digest")
	}
	data, err := io.ReadAll(io.LimitReader(reader, MaxMMDBFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read MMDB: %w", err)
	}
	if len(data) > MaxMMDBFileSize {
		return nil, errors.New("GeoIP MMDB exceeds 64 MiB limit")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return nil, errors.New("GeoIP SHA256 mismatch")
	}
	db, err := maxminddb.OpenBytes(data)
	if err != nil {
		return nil, errors.New("invalid GeoIP MMDB structure")
	}
	valid := false
	defer func() {
		if !valid {
			_ = db.Close()
		}
	}()
	if err := db.Verify(); err != nil {
		return nil, errors.New("GeoIP MMDB integrity verification failed")
	}
	published := db.Metadata.BuildTime().UTC()
	if published.Year() < 1990 || published.After(time.Now().Add(24*time.Hour)) {
		return nil, errors.New("invalid GeoIP MMDB build time")
	}
	count, countries := 0, 0
	ipv4, ipv6 := false, false
	for result := range db.Networks() {
		count++
		if count > maxMMDBNetworks {
			return nil, errors.New("GeoIP MMDB network count exceeds limit")
		}
		country, err := mmdbCountry(result, providerID)
		if err != nil {
			return nil, err
		}
		if country != "" && country != "ZZ" {
			countries++
			ipv4 = ipv4 || result.Prefix().Addr().Is4()
			ipv6 = ipv6 || result.Prefix().Addr().Is6()
		}
	}
	if countries == 0 {
		return nil, errors.New("GeoIP MMDB contains no country records for the selected provider")
	}
	metadata := Metadata{Provider: providerID, Format: "mmdb", IPv4: ipv4, IPv6: ipv6,
		Version: providerID + "-" + published.Format("2006-01-02"), Source: provider.Source, License: provider.License,
		LicenseURL: provider.LicenseURL, PublishedAt: published, LoadedAt: time.Now().UTC(), SHA256: expectedSHA256,
		Ranges: count, Provenance: "publisher/schema selected by the importer; MMDB structure and checksum verified, publisher identity not certified"}
	valid = true
	return &Database{metadata: metadata, data: data, mmdb: db}, nil
}
