package control

import (
	"context"
	"errors"

	"github.com/xjdrew/kone/pkg/kone"
)

// Recovery never deletes an interface just because its name looks familiar.
// Kernel-owned transient TUN resources normally disappear with the old process;
// surviving resources require verifiable ownership before automatic mutation.
func (c *Controller) Recover(ctx context.Context) error {
	c.actions.Lock()
	defer c.actions.Unlock()
	c.mu.Lock()
	active := c.engine != nil || c.captureLocked() || c.state == "running" || c.state == "degraded" || c.state == "stopping" || c.state == "preflight"
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return errors.New("application is stopping")
	}
	if active {
		return errors.New("pause capture before inspecting recovery")
	}
	report, err := c.InspectRecovery(ctx)
	if err == nil {
		recoverDNS := c.recoverSystemDNS
		if recoverDNS == nil {
			recoverDNS = kone.RecoverSystemDNS
		}
		for _, lease := range report.SystemDNS {
			if !lease.CanRecover {
				continue
			}
			if err = ctx.Err(); err != nil {
				break
			}
			if err = recoverDNS(ctx, lease.ID); err != nil {
				break
			}
		}
		if err == nil {
			report, err = c.InspectRecovery(ctx)
		}
	}
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
