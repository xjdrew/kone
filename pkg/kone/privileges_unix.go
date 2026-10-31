//go:build linux || darwin

package kone

// Unix permissions depend on the device and process capabilities. Preserve the
// native open error rather than requiring a particular user ID.
func checkNetworkPrivileges() error { return nil }
