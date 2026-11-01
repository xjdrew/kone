package kone

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/xjdrew/kone/pkg/geoip"
)

// GeoIPConfig selects a local CLI dataset. Managed mode owns its uploaded
// database repository and never reads a path supplied by a remote browser.
type GeoIPConfig struct {
	Provider string `toml:"provider"`
	File     string `toml:"file,omitempty"`
	SHA256   string `toml:"sha256,omitempty"`
}

// ValidateGeoIPFile checks the configured dataset without opening a TUN or
// changing host networking. Normal startup also performs this validation.
func (cfg *KoneConfig) ValidateGeoIPFile() error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	filename, _ := cfg.source.(string)
	_, err := cfg.GeoIP.load(filename)
	return err
}

func (cfg GeoIPConfig) Validate() error {
	if cfg.Provider == "" || cfg.Provider == "builtin" {
		if cfg.File != "" || cfg.SHA256 != "" {
			return errors.New("geoip.file requires a dataset provider; builtin has no file or checksum")
		}
		return nil
	}
	_, known := geoip.FindProvider(cfg.Provider)
	if cfg.Provider != "kone-json" && !known {
		return errors.New("geoip.provider must be builtin, kone-json, dbip-lite, ipinfo-lite or maxmind-geolite2")
	}
	if cfg.File == "" || strings.ContainsAny(cfg.File, "\x00\r\n\t") || strings.Contains(cfg.File, "://") || strings.HasPrefix(cfg.File, `\\`) || strings.HasPrefix(cfg.File, "//") {
		return errors.New("geoip.file must name a regular local dataset file")
	}
	if len(cfg.SHA256) != 64 || strings.ToLower(cfg.SHA256) != cfg.SHA256 {
		return errors.New("geoip.sha256 must be a complete lowercase SHA256 digest")
	}
	if _, err := hex.DecodeString(cfg.SHA256); err != nil {
		return errors.New("geoip.sha256 must be a complete lowercase SHA256 digest")
	}
	return nil
}

func (cfg GeoIPConfig) load(configFile string) (*geoip.Database, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Provider == "" || cfg.Provider == "builtin" {
		return geoip.Builtin(), nil
	}
	filename := cfg.File
	if !filepath.IsAbs(filename) && configFile != "" {
		filename = filepath.Join(filepath.Dir(configFile), filename)
	}
	limit := int64(geoip.MaxMMDBFileSize)
	if cfg.Provider == "kone-json" {
		limit = geoip.MaxFileSize
	}
	before, err := os.Lstat(filename)
	if err != nil || !before.Mode().IsRegular() || before.Size() > limit {
		return nil, errors.New("configured GeoIP database is absent or not a regular local file within the format size limit")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("cannot open the configured GeoIP database")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || !os.SameFile(before, info) {
		return nil, errors.New("configured GeoIP database is not a regular file within the format size limit")
	}
	if cfg.Provider == "kone-json" {
		return geoip.Load(file, cfg.SHA256)
	}
	return geoip.LoadMMDB(file, cfg.SHA256, cfg.Provider)
}
