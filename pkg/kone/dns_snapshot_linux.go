package kone

import (
	"errors"
	"os"

	"github.com/xjdrew/kone/pkg/dnsconfig"
)

func readPlatformDNSConfig() *dnsconfig.DnsConfig {
	base := dnsconfig.ReadDnsConfig()
	// Unlike libc defaults, an empty file is not evidence of a running localhost
	// resolver. Report it as undiscovered so the explicit fallback is visible.
	store := hostResolvFile()
	data, err := readSystemResolverFile(store.path)
	if err != nil {
		base.Err = err
		return base
	}
	record, recordErr := store.readRecord()
	if recordErr == nil && resolverHash(data) == record.OwnedHash {
		data, err = readSystemResolverFile(store.backup(record))
		if err != nil {
			base.Err = err
			return base
		}
	} else if recordErr != nil && !errors.Is(recordErr, os.ErrNotExist) {
		base.Err = recordErr
		return base
	}
	base.Servers = resolvFileServers(data)
	return base
}

func SystemDNSNeedsAuthorization(cfg DNSConfig) bool {
	if !cfg.SystemEnabled() || os.Geteuid() == 0 {
		return false
	}
	data, err := readSystemResolverFile("/etc/resolv.conf")
	return err != nil || !resolvedStubConfigured(data)
}
