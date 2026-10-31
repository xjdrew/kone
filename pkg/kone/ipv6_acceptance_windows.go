//go:build windows && kone_ipv6_acceptance

package kone

// This temporary tag is used only by the disposable Windows native acceptance
// binary. Product capability remains disabled until both stacks pass that gate.
func ipv6AcceptanceEnabled() bool { return true }
