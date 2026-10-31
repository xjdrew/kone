package kone

import "errors"

// SetConfigVersion binds the persistent owner revision before capture begins.
// Call ReloadVersion for an already running engine.
func (one *One) SetConfigVersion(revision uint64) error {
	if revision == 0 {
		return errors.New("configuration version must be positive")
	}
	one.reloadMu.Lock()
	defer one.reloadMu.Unlock()
	one.mu.Lock()
	defer one.mu.Unlock()
	if one.started || one.closed {
		return errors.New("initial configuration version must be set before Run")
	}
	old := one.policy.Load()
	next := *old
	next.configVersion = revision
	one.policy.Store(&next)
	return nil
}
