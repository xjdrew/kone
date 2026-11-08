//go:build !linux

package kone

import "github.com/xjdrew/kone/pkg/dnsconfig"

func readPlatformDNSConfig() *dnsconfig.DnsConfig { return dnsconfig.ReadDnsConfig() }

func SystemDNSNeedsAuthorization(DNSConfig) bool { return false }
