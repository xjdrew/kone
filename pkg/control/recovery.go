package control

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/xjdrew/kone/pkg/kone"
)

var errAutomaticRecovery = errors.New("Could not restore the previous capture automatically; check the host network and runtime logs, then retry")
var errSystemDNSRecoveryRequired = errors.New("Previous Windows system DNS requires explicit recovery from the local console; inspect the DNS lease, confirm recovery and authorize administrator access")

// Recovery never deletes an interface just because its name looks familiar.
// Kernel-owned transient TUN resources normally disappear with the old process;
// surviving resources require verifiable ownership before automatic mutation.
func (c *Controller) Recover(ctx context.Context) error {
	c.actions.Lock()
	defer c.actions.Unlock()
	c.mu.Lock()
	active := c.engine != nil || c.captureLocked() || c.state == "running" || c.state == "degraded" || c.state == "stopping" || c.state == "preflight"
	closed := c.closed
	cfg := cloneDocument(c.doc).Config
	c.mu.Unlock()
	if closed {
		return errors.New("application is stopping")
	}
	if active {
		return errors.New("pause capture before inspecting recovery")
	}
	err := c.inspectAndClearRecovery(ctx, false, cfg)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.state = "paused"
		c.lastError = err.Error()
		return err
	}
	c.state, c.lastError = "paused", ""
	return nil
}

// Caller holds c.actions and has verified that capture is inactive. This only
// clears records whose metadata proves capture settings were never applied or
// whose transient device has disappeared; it never deletes an inferred device.
func (c *Controller) inspectAndClearRecovery(ctx context.Context, automatic bool, cfg *kone.KoneConfig) error {
	c.logEvent(slog.LevelInfo, "Checking previous capture resources", slog.String("stage", "recovery"), slog.Bool("automatic", automatic))
	report, err := c.InspectRecovery(ctx)
	for _, item := range report.Items {
		level := slog.LevelInfo
		if !report.CanClear || item.Status == "unverified" {
			level = slog.LevelWarn
		}
		c.logEvent(level, "Previous capture resource inspected", slog.String("stage", "recovery"), slog.Bool("automatic", automatic), slog.String("run_id", report.RunID), slog.String("ownership", report.Ownership), slog.String("kind", item.Kind), slog.String("identity", item.Identity), slog.String("status", item.Status), slog.String("detail", safeMessage(errors.New(item.Message), cfg)))
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && len(report.SystemDNS) > 0 {
		if automatic {
			// A machine-wide NRPT mutation is deliberately outside automatic
			// capture-record maintenance, including when resetting settings.
			err = errSystemDNSRecoveryRequired
		} else {
			initialRunID := report.RunID
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
				c.logEvent(slog.LevelInfo, "Restoring explicitly confirmed machine DNS lease", slog.String("stage", "recovery"), slog.Bool("automatic", false), slog.String("lease_id", lease.ID))
				if err = recoverDNS(ctx, lease.ID); err != nil {
					break
				}
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				report, err = c.InspectRecovery(ctx)
				if err == nil && report.RunID != "" && report.RunID != initialRunID {
					err = errors.New("the capture recovery record changed during DNS restoration")
				}
			}
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && report.Required && !report.CanClear {
		err = errors.New(report.NextAction)
	}
	if err == nil && report.Required {
		err = c.removeRecoveryJournal(report.RunID)
		if err == nil {
			// Conditional removal preserves a replacement epoch. Do not report
			// success or proceed into startup while a newer record remains.
			if _, statErr := os.Stat(c.journalPath()); statErr == nil {
				err = errors.New("the capture recovery record changed during cleanup")
			} else if !errors.Is(statErr, os.ErrNotExist) {
				err = statErr
			}
		}
	}
	if err != nil {
		c.logEvent(slog.LevelError, "Previous capture cleanup could not be completed", slog.String("stage", "recovery"), slog.Bool("automatic", automatic), slog.String("run_id", report.RunID), slog.String("ownership", report.Ownership), slog.String("error", safeMessage(err, cfg)))
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if errors.Is(err, errSystemDNSRecoveryRequired) {
			return err
		}
		if automatic {
			return errAutomaticRecovery
		}
		return errors.New(safeMessage(err, cfg))
	}
	message := "No previous capture resources require cleanup"
	if report.Required {
		message = "Previous capture recovery record cleared automatically"
		if !automatic {
			message = "Previous capture recovery record cleared"
		}
	}
	c.logEvent(slog.LevelInfo, message, slog.String("stage", "recovery"), slog.Bool("automatic", automatic), slog.String("run_id", report.RunID), slog.String("ownership", report.Ownership))
	return nil
}
