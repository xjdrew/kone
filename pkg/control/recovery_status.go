package control

import "context"

// RecoveryStatus keeps partial inspection evidence visible even when a record
// cannot be read. Eligibility is advisory; Recover revalidates under actions.
type RecoveryStatus struct {
	RecoveryReport
	Active          bool   `json:"capture_active"`
	CanRecover      bool   `json:"can_recover"`
	Blocker         string `json:"blocker"`
	InspectionError string `json:"inspection_error,omitempty"`
}

func recoveryStatus(report RecoveryReport, active bool, inspectionError string) RecoveryStatus {
	view := RecoveryStatus{RecoveryReport: report, Active: active, InspectionError: inspectionError}
	switch {
	case active:
		view.Blocker = "active"
	case inspectionError != "":
		view.Blocker = "inspection_failed"
	case !report.Required:
		view.Blocker = "clear"
	default:
		view.CanRecover = report.CanClear
		if len(report.SystemDNS) > 0 {
			view.CanRecover = true
			for _, lease := range report.SystemDNS {
				view.CanRecover = view.CanRecover && lease.CanRecover
			}
			for _, item := range report.Items {
				if item.Kind == "tun" && item.Status != "absent" || item.Kind == "journal" && item.Status == "invalid" {
					view.CanRecover = false
				}
			}
		}
		if view.CanRecover {
			view.Blocker = "ready"
		} else {
			view.Blocker = "unverified"
		}
	}
	return view
}
func (c *Controller) RecoveryStatus(ctx context.Context) RecoveryStatus {
	c.mu.Lock()
	active := c.engine != nil || c.captureLocked() || c.state == "running" || c.state == "degraded" || c.state == "stopping" || c.state == "preflight"
	cfg := cloneDocument(c.doc).Config
	c.mu.Unlock()
	report, err := c.InspectRecovery(ctx)
	detail := ""
	if err != nil {
		detail = safeMessage(err, cfg)
	}
	return recoveryStatus(report, active, detail)
}
