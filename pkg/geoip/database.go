package geoip

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const MaxFileSize = 32 << 20
const MaxRanges = 250000

type Range struct {
	Start   string `json:"start"`
	End     string `json:"end"`
	Country string `json:"country"`
}

type Ranges []Range

func (r *Ranges) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return errors.New("GeoIP ranges must be an array")
	}
	var entries Ranges
	for decoder.More() {
		if len(entries) >= MaxRanges {
			return errors.New("GeoIP range count exceeds limit")
		}
		var entry Range
		if err := decoder.Decode(&entry); err != nil {
			return err
		}
		entries = append(entries, entry)
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	*r = entries
	return nil
}

// File is a provider-independent, IPv4-only import format. Source and license
// describe the submitted data; KONE does not certify the provider's claims.
type File struct {
	Format      int       `json:"format"`
	Version     string    `json:"version"`
	Source      string    `json:"source"`
	License     string    `json:"license"`
	LicenseURL  string    `json:"license_url"`
	PublishedAt time.Time `json:"published_at"`
	Ranges      Ranges    `json:"ranges"`
}

type Metadata struct {
	Version     string    `json:"version"`
	Source      string    `json:"source"`
	License     string    `json:"license"`
	LicenseURL  string    `json:"license_url,omitempty"`
	PublishedAt time.Time `json:"published_at"`
	LoadedAt    time.Time `json:"loaded_at"`
	SHA256      string    `json:"sha256"`
	Ranges      int       `json:"ranges"`
	Builtin     bool      `json:"builtin"`
	Provenance  string    `json:"provenance"`
}

type addressRange struct {
	start, end uint32
	country    string
}

// Database is immutable after validation. Snapshots retain this pointer so a
// live update cannot change the meaning of an already-selected rule version.
type Database struct {
	metadata Metadata
	ranges   []addressRange
	data     []byte
}

func (d *Database) Metadata() Metadata {
	if d == nil {
		return Metadata{}
	}
	return d.metadata
}

func (d *Database) Bytes() []byte {
	if d == nil {
		return nil
	}
	return bytes.Clone(d.data)
}

func (d *Database) Country(address netip.Addr) string {
	if d == nil || !address.IsValid() || !address.Unmap().Is4() {
		return ""
	}
	raw := address.Unmap().As4()
	value := binary.BigEndian.Uint32(raw[:])
	i := sort.Search(len(d.ranges), func(i int) bool { return d.ranges[i].end >= value })
	if i < len(d.ranges) && d.ranges[i].start <= value {
		return d.ranges[i].country
	}
	return ""
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validMetadataText(value string, max int) bool {
	if value == "" || len(value) > max || strings.TrimSpace(value) != value {
		return false
	}
	for _, ch := range value {
		if ch < 32 || ch == 127 {
			return false
		}
	}
	return true
}

func metadataURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && len(value) <= 2048 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !strings.ContainsAny(value, "\x00\r\n\t ")
}

// rejectDuplicateKeys enforces JSON object uniqueness and a small nesting bound.
// encoding/json otherwise silently accepts the last occurrence of a key.
func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var value func(int) error
	value = func(depth int) error {
		if depth > 8 {
			return errors.New("GeoIP JSON nesting exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, structured := token.(json.Delim)
		if !structured {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for decoder.More() {
				token, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok || key != strings.ToLower(key) || keys[key] {
					return errors.New("GeoIP JSON contains a duplicate object key")
				}
				keys[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid GeoIP JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("GeoIP file must contain one JSON object")
	}
	return nil
}

// Load verifies the SHA256 of the exact bytes before parsing. Import is entirely
// local: metadata URLs are identifiers and are never fetched automatically.
func Load(reader io.Reader, expectedSHA256 string) (*Database, error) {
	if !validDigest(expectedSHA256) {
		return nil, errors.New("GeoIP requires an expected lowercase SHA256 digest")
	}
	data, err := io.ReadAll(io.LimitReader(reader, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read GeoIP file: %w", err)
	}
	if len(data) > MaxFileSize {
		return nil, errors.New("GeoIP file exceeds 32 MiB limit")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("GeoIP file must be valid UTF-8")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return nil, errors.New("GeoIP SHA256 mismatch")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, errors.New("invalid or duplicate GeoIP JSON fields")
	}
	var file File
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, errors.New("invalid GeoIP JSON structure")
	}
	if file.Format != 1 || !validMetadataText(file.Version, 128) || !validMetadataText(file.License, 128) || !metadataURL(file.Source) || !metadataURL(file.LicenseURL) || file.PublishedAt.IsZero() || file.PublishedAt.After(time.Now().Add(24*time.Hour)) {
		return nil, errors.New("invalid GeoIP format, version, source, license or publication time")
	}
	if len(file.Ranges) == 0 || len(file.Ranges) > MaxRanges {
		return nil, errors.New("GeoIP must contain 1..250000 sorted IPv4 ranges")
	}
	ranges := make([]addressRange, len(file.Ranges))
	for i, entry := range file.Ranges {
		start, firstErr := netip.ParseAddr(entry.Start)
		end, lastErr := netip.ParseAddr(entry.End)
		if firstErr != nil || lastErr != nil || !start.Is4() || !end.Is4() || start.String() != entry.Start || end.String() != entry.End {
			return nil, fmt.Errorf("GeoIP range %d requires canonical IPv4 addresses", i+1)
		}
		if len(entry.Country) != 2 || entry.Country[0] < 'A' || entry.Country[0] > 'Z' || entry.Country[1] < 'A' || entry.Country[1] > 'Z' {
			return nil, fmt.Errorf("GeoIP range %d requires a two-letter uppercase country code", i+1)
		}
		ranges[i] = addressRange{start: binary.BigEndian.Uint32(start.AsSlice()), end: binary.BigEndian.Uint32(end.AsSlice()), country: entry.Country}
		if ranges[i].start > ranges[i].end || i > 0 && ranges[i].start <= ranges[i-1].end {
			return nil, fmt.Errorf("GeoIP range %d is reversed, unsorted or overlapping", i+1)
		}
	}
	return &Database{metadata: Metadata{Version: file.Version, Source: file.Source, License: file.License, LicenseURL: file.LicenseURL, PublishedAt: file.PublishedAt, LoadedAt: time.Now().UTC(), SHA256: expectedSHA256, Ranges: len(ranges), Provenance: "provided metadata; source and license not independently certified"}, ranges: ranges, data: data}, nil
}

var builtinOnce sync.Once
var builtinDatabase *Database

// Builtin keeps the historical table available and labels its provenance
// honestly; the repository does not establish its original source or license.
func Builtin() *Database {
	builtinOnce.Do(func() {
		ranges := make([]addressRange, len(geoIP))
		hash := sha256.New()
		var boundary [8]byte
		for i, entry := range geoIP {
			ranges[i] = addressRange{entry.Start, entry.End, entry.Name}
			binary.BigEndian.PutUint32(boundary[:4], entry.Start)
			binary.BigEndian.PutUint32(boundary[4:], entry.End)
			hash.Write(boundary[:])
			hash.Write([]byte(entry.Name))
		}
		builtinDatabase = &Database{metadata: Metadata{Version: "legacy-bundled", Source: "legacy embedded table; generated by github.com/xjdrew/mmconvertor", License: "unknown", SHA256: hex.EncodeToString(hash.Sum(nil)), Ranges: len(ranges), Builtin: true, Provenance: "original dataset source, publication time and license are not established"}, ranges: ranges}
	})
	return builtinDatabase
}
