package kone

import (
	"bytes"
	"errors"

	"github.com/xjdrew/kone/pkg/geoip"
)

var ErrGeoIPConflict = errors.New("policy changed; reload the current version before changing GeoIP data")

type GeoIPRuntimeStatus struct {
	PolicyVersion uint64          `json:"policy_version"`
	Current       geoip.Metadata  `json:"current"`
	Previous      *geoip.Metadata `json:"previous,omitempty"`
}

func WithGeoIPDatabase(database *geoip.Database) Option {
	return func(one *One) error {
		if database == nil || database.Metadata().Ranges == 0 || len(database.Metadata().SHA256) != 64 {
			return errors.New("GeoIP database is not initialized")
		}
		one.initialGeoIP = database
		return nil
	}
}

func (one *One) GeoIPStatus() GeoIPRuntimeStatus {
	if one == nil {
		return GeoIPRuntimeStatus{Current: geoip.Builtin().Metadata()}
	}
	snapshot := one.policy.Load()
	if snapshot == nil {
		return GeoIPRuntimeStatus{Current: geoip.Builtin().Metadata()}
	}
	status := GeoIPRuntimeStatus{PolicyVersion: snapshot.version, Current: snapshot.geoIP.Metadata()}
	if snapshot.previousGeoIP != nil {
		metadata := snapshot.previousGeoIP.Metadata()
		status.Previous = &metadata
	}
	return status
}

// ApplyGeoIP only publishes validated local bytes. Validation/file acquisition
// precedes publication; any error leaves the entire active policy unchanged.
// Persistence belongs to the owner/controller's geoip.Repository transaction.
func (one *One) ApplyGeoIP(data []byte, expectedSHA256 string, baseVersion uint64) error {
	database, err := geoip.Load(bytes.NewReader(data), expectedSHA256)
	if err != nil {
		return err
	}
	return one.ApplyGeoIPDatabase(database, baseVersion)
}

func (one *One) ApplyGeoIPDatabase(database *geoip.Database, baseVersion uint64) error {
	if database == nil || database.Metadata().Ranges == 0 || len(database.Metadata().SHA256) != 64 {
		return errors.New("GeoIP database is not initialized")
	}
	one.reloadMu.Lock()
	defer one.reloadMu.Unlock()
	return one.publishGeoIP(database, baseVersion)
}

func (one *One) publishGeoIP(database *geoip.Database, baseVersion uint64) error {
	one.mu.Lock()
	closed := one.closed
	one.mu.Unlock()
	if closed {
		return errors.New("engine is closed")
	}
	old := one.policy.Load()
	if old == nil || old.version != baseVersion {
		return ErrGeoIPConflict
	}
	if old.geoIP != nil && old.geoIP.Metadata().SHA256 == database.Metadata().SHA256 {
		return nil
	}
	rule := NewRuleWithGeoIP(old.cfg.Rule, old.cfg.Outbounds, database)
	old.outbounds.bypassEndpoints(rule)
	one.policy.Store(&runtimeSnapshot{version: old.version + 1, configVersion: old.configVersion, cfg: old.cfg, rule: rule, outbounds: old.outbounds, geoIP: database, previousGeoIP: old.geoIP})
	one.clearDirectDNSCaches()
	return nil
}

func (one *One) RollbackGeoIP(baseVersion uint64) error {
	one.reloadMu.Lock()
	defer one.reloadMu.Unlock()
	old := one.policy.Load()
	if old == nil || old.version != baseVersion {
		return ErrGeoIPConflict
	}
	if old.previousGeoIP == nil {
		return errors.New("no previous GeoIP data is available")
	}
	return one.publishGeoIP(old.previousGeoIP, baseVersion)
}
