package kone

// SystemDNSRecoveryEntry describes a machine-level resolver lease. It contains
// ownership metadata only, never a user configuration or upstream credentials.
type SystemDNSRecoveryEntry struct {
	ID          string `json:"id"`
	DeviceName  string `json:"device_name"`
	DeviceIndex int    `json:"device_index"`
	RuleName    string `json:"rule_name,omitempty"`
	Status      string `json:"status"`
	CanRecover  bool   `json:"can_recover"`
	Message     string `json:"message"`
}
