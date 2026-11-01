package control

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/xjdrew/kone/pkg/geoip"
)

// ResetConfiguration restores managed settings without starting capture or
// changing host networking. Keep the local password and local sessions intact.
func (c *Controller) ResetConfiguration(ctx context.Context, base uint64) (map[string]any, error) {
	c.actions.Lock()
	defer c.actions.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	current := cloneDocument(c.doc)
	locked := c.captureLocked() || c.state == "running" || c.state == "degraded" || c.state == "stopping"
	closed := c.closed
	repair := c.configError != ""
	c.mu.Unlock()
	if closed {
		return nil, errors.New("application is stopping")
	}
	if base != current.Version {
		return nil, ErrConflict
	}
	if locked {
		return nil, ErrCaptureLocked
	}
	if disk, readErr := readDocument(c.settingsPath()); readErr == nil && !sameDocument(disk, current) {
		return nil, ErrConflict
	} else if readErr != nil && !repair {
		return nil, errors.New("saved settings changed or became unreadable; reload before saving")
	}
	defaults := managementDefaults()
	if err := defaults.Validate(); err != nil {
		return nil, err
	}
	if err := c.inspectAndClearRecovery(ctx, true, current.Config); err != nil {
		return nil, err
	}
	// Save publishes settings atomically and cannot fail after that publication
	// while capture is paused. Never rewrite its files on error: a failed save
	// may have detected an external edit that must be preserved.
	manifestPath := filepath.Join(c.directory, "geoip", "manifest.json")
	manifest, readErr := os.ReadFile(manifestPath)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}
	geoIPChanged, loggingChanged := false, false
	rollback := func(cause error) (map[string]any, error) {
		if geoIPChanged {
			var restoreErr error
			if manifest != nil {
				restoreErr = atomicWrite(manifestPath, manifest)
			} else {
				restoreErr = os.Remove(manifestPath)
				if errors.Is(restoreErr, os.ErrNotExist) {
					restoreErr = nil
				}
			}
			cause = errors.Join(cause, restoreErr)
		}
		if loggingChanged {
			cause = errors.Join(cause, c.configureLogging(current.Config.General))
		}
		return nil, cause
	}
	if err := geoip.ResetBuiltin(filepath.Join(c.directory, "geoip")); err != nil {
		return rollback(err)
	}
	geoIPChanged = true
	if c.configureLogging != nil {
		loggingChanged = true
		if err := c.configureLogging(defaults.General); err != nil {
			return rollback(err)
		}
	}
	confirmed := false
	value, err := c.saveLocked(SaveRequest{BaseVersion: base, Config: jsonConfig(defaults), Inbound: Inbound{ID: current.Inbound.ID, Name: "TUN", Enabled: true}, DirectOnlyConfirmed: &confirmed})
	if err != nil {
		return rollback(err)
	}
	c.mu.Lock()
	lan := c.lan
	c.lan = nil
	for key, session := range c.sessions {
		if session.Remote {
			delete(c.sessions, key)
		}
	}
	c.pairs = map[string]Pairing{}
	c.health = nil
	c.state, c.lastError = "paused", ""
	c.mu.Unlock()
	if lan != nil {
		lan.close()
	}
	c.logEvent(slog.LevelInfo, "All managed settings reset to defaults", slog.String("stage", "reset"), slog.Uint64("saved_version", base+1))
	return value, nil
}
