package kone

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
)

// WithFakeIPDirectory is an embedding/test override. Managed clients cannot
// choose a privileged filesystem path through configuration or helper IPC.
func WithFakeIPDirectory(directory string) Option {
	return func(one *One) error {
		if !filepath.IsAbs(directory) {
			return errors.New("Fake-IP storage directory must be absolute")
		}
		one.fakeIPDirectory = directory
		return nil
	}
}
func (one *One) protectRule(rule *Rule, cfg *KoneConfig) {
	rule.protectPolicy(cfg)
	rule.retired = append(rule.retired, one.retiredPools...)
}
func (one *One) restoreFakeIPOwnership() error {
	one.reloadMu.Lock()
	defer one.reloadMu.Unlock()
	directory := one.fakeIPDirectory
	var err error
	if directory == "" {
		directory, err = fakeLedgerHostDirectory()
		if err != nil {
			return err
		}
	}
	ledger, err := openFakeIPLedger(directory)
	if err != nil {
		return err
	}
	one.fakeIPLedger = ledger
	snapshot := one.policy.Load()
	active := map[string]bool{one.dnsTable.ipNet.String(): true}
	if one.dnsTable6 != nil {
		active[one.dnsTable6.ipNet.String()] = true
	}
	for _, raw := range snapshot.cfg.DNS.RetiredPools {
		if err := ledger.retire(raw); err != nil {
			return err
		}
	}
	for _, table := range []*DnsTable{one.dnsTable, one.dnsTable6} {
		if table == nil {
			continue
		}
		table.recordsLock.Lock()
		if len(table.records) > 0 {
			err = errors.New("cannot attach persistent ownership after virtual answers were allocated")
		} else {
			err = ledger.register(table)
		}
		table.recordsLock.Unlock()
		if err != nil {
			return err
		}
	}
	retired := []netip.Prefix{}
	for raw := range ledger.pools {
		if !active[raw] {
			retired = append(retired, netip.MustParsePrefix(raw))
		}
	}
	slices.SortFunc(retired, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	// A historical pool must remain captured and explicitly rejected. Never
	// silently route old cached addresses into a newly conflicting real LAN.
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, prefix := range retired {
		for _, value := range addresses {
			address, err := netip.ParsePrefix(value.String())
			if err == nil && address.Overlaps(prefix) {
				return fmt.Errorf("retired Fake-IP pool %s conflicts with local network %s", prefix, address.Masked())
			}
		}
	}
	one.retiredPools = retired
	next := *snapshot
	next.rule = NewRuleWithGeoIP(snapshot.cfg.Rule, snapshot.cfg.Outbounds, snapshot.geoIP)
	one.protectRule(next.rule, snapshot.cfg)
	snapshot.outbounds.bypassEndpoints(next.rule)
	one.policy.Store(&next)
	return nil
}
func (l *fakeIPLedger) retire(key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if pool := l.pools[key]; pool != nil {
		// A verified old generation keeps its identities and can later be opened
		// again. Only unknown legacy generations become permanent tombstones.
		return nil
	}
	if len(l.pools) >= fakeLedgerPoolLimit {
		return errors.New("Fake-IP pool generation limit reached")
	}
	prefix, err := netip.ParsePrefix(key)
	if err != nil || prefix != prefix.Masked() {
		return errors.New("invalid retired pool")
	}
	for raw := range l.pools {
		if netip.MustParsePrefix(raw).Overlaps(prefix) {
			return errors.New("retired Fake-IP pool overlaps an existing generation")
		}
	}
	entry := fakeLedgerEntry{Kind: "retire", Pool: key}
	if err := l.append(entry); err != nil {
		return err
	}
	return l.apply(entry)
}

type FakeIPPoolStatus struct {
	StorageBytes int64  `json:"storage_bytes"`
	StorageLimit int64  `json:"storage_limit"`
	Prefix       string `json:"prefix"`
	Persistent   bool   `json:"persistent"`
	Used         int    `json:"used"`
	Capacity     int    `json:"capacity"`
	Warning      bool   `json:"warning"`
	Error        string `json:"error,omitempty"`
}

func (table *DnsTable) ownershipStatus() FakeIPPoolStatus {
	table.recordsLock.Lock()
	defer table.recordsLock.Unlock()
	capacity, used := table.ipPool.Capacity(), len(table.records)
	if table.ledger != nil {
		used = len(table.owners)
	}
	reserved := 0
	for _, occupied := range table.ipPool.flags {
		if occupied {
			reserved++
		}
	}
	capacity -= reserved - used
	status := FakeIPPoolStatus{Prefix: table.ipNet.String(), Persistent: table.ledger != nil, Used: used, Capacity: capacity, Warning: capacity <= 0 || used*5 >= capacity*4}
	if table.ledger != nil {
		table.ledger.mu.Lock()
		status.StorageBytes = table.ledger.size
		status.StorageLimit = fakeLedgerLimit
		status.Warning = status.Warning || status.StorageBytes*5 >= status.StorageLimit*4
		table.ledger.mu.Unlock()
	}
	if table.ownershipError != nil {
		status.Error = table.ownershipError.Error()
	}
	return status
}

// A volatile allocator must not reuse addresses that this host has already
// published durably, even if a user disables the new option or opens an older
// profile. A non-overlapping legacy pool remains usable.
func (one *One) verifyVolatileFakeIPPools() error {
	directory := one.fakeIPDirectory
	var err error
	if directory == "" {
		root, rootErr := fakeLedgerRootDirectory()
		if rootErr != nil {
			return rootErr
		}
		if _, statErr := os.Lstat(root); errors.Is(statErr, os.ErrNotExist) {
			return nil
		} else if statErr != nil {
			return statErr
		}
		directory, err = fakeLedgerHostDirectory()
		if err != nil {
			return err
		}
	}
	if _, err = os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	ledger, err := openFakeIPLedger(directory)
	if err != nil {
		return err
	}
	retain := false
	defer func() {
		if !retain {
			ledger.Close()
		}
	}()
	for raw := range ledger.pools {
		prefix := netip.MustParsePrefix(raw)
		for _, value := range []string{one.policy.Load().cfg.Core.Network, one.policy.Load().cfg.Core.IPv6Network} {
			if active, e := netip.ParsePrefix(value); e == nil && active.Overlaps(prefix) {
				return errors.New("this Fake-IP pool has durable ownership; enable persistent-fake-ip or explicitly migrate to a fresh pool")
			}
		}
	}
	one.fakeIPLedger = ledger
	retain = true
	return nil
}
