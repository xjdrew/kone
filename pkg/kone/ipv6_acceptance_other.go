//go:build !windows || !kone_ipv6_acceptance

package kone

func ipv6AcceptanceEnabled() bool { return false }
