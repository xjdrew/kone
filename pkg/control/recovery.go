package control

import (
	"context"
	"errors"
)

// Recovery never deletes an interface just because its name looks familiar.
// Kernel-owned transient TUN resources normally disappear with the old process;
// surviving resources require verifiable ownership before automatic mutation.
func (c *Controller) Recover(ctx context.Context) error {
	c.actions.Lock()
	defer c.actions.Unlock()
	c.mu.Lock()
	active := c.engine != nil
	c.mu.Unlock()
	if active {
		return errors.New("pause capture before inspecting recovery")
	}
	report, err := c.InspectRecovery(ctx)
	if err == nil && report.Required && !report.CanClear {
		err = errors.New(report.NextAction)
	}
	if err == nil && report.Required {
		err = c.removeRecoveryJournal(report.RunID)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.state = "recovery_required"
		c.lastError = err.Error()
		return err
	}
	c.state, c.lastError = "paused", ""
	return nil
}
