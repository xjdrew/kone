package kone

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func ledgerTable(t *testing.T, network string) *DnsTable {
	t.Helper()
	ip, subnet, err := net.ParseCIDR(network)
	require.NoError(t, err)
	return NewDnsTable(ip, subnet)
}
func TestFakeIPLedgerKeepsOwnershipAcrossExpiryReverseOrderAndRestart(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ledger")
	// Unix temp directories are private; Windows verifies and narrows the ACL.
	ledger, err := openFakeIPLedger(directory)
	require.NoError(t, err)
	table := ledgerTable(t, "10.203.0.1/16")
	require.NoError(t, ledger.register(table))
	first := table.Set("site-120.example", "office")
	second := table.Set("site-201.example", "office")
	require.NotEqual(t, first.IP, second.IP)
	// Force the cache eviction threshold without releasing durable identity.
	for i := 0; i < 1100; i++ {
		table.records[first.Hostname+string(rune(i+256))] = &DomainRecord{IP: first.IP, Expires: time.Time{}}
	}
	table.records[first.Hostname].Expires = time.Time{}
	table.clearExpiredDomain(time.Now())
	require.Equal(t, first.IP, table.GetByIP(first.IP).IP)
	_, err = openFakeIPLedger(directory)
	require.ErrorContains(t, err, "another KONE capture")
	require.NoError(t, ledger.Close())
	restored, err := openFakeIPLedger(directory)
	require.NoError(t, err)
	defer restored.Close()
	next := ledgerTable(t, "10.203.0.1/16")
	require.NoError(t, restored.register(next))
	require.Equal(t, second.IP, next.Set("site-201.example", "direct").IP)
	require.Equal(t, first.IP, next.Set("site-120.example", "reject").IP)
	require.Nil(t, next.GetByIP(first.IP).resolved, "route actions and real DNS evidence are not restored")
}
func TestFakeIPLedgerRejectsCorruptionAndRecoversOnlyIncompleteTail(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ledger")
	ledger, err := openFakeIPLedger(directory)
	require.NoError(t, err)
	table := ledgerTable(t, "10.203.0.1/24")
	require.NoError(t, ledger.register(table))
	record := table.Set("saved.example", "direct")
	require.NotNil(t, record)
	require.NoError(t, ledger.Close())
	path := filepath.Join(directory, "ownership-v1.jsonl")
	original, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, append(append([]byte(nil), original...), []byte(`{"version":1`)...), 0600))
	restored, err := openFakeIPLedger(directory)
	require.NoError(t, err)
	next := ledgerTable(t, "10.203.0.1/24")
	require.NoError(t, restored.register(next))
	require.Equal(t, record.IP, next.Set("saved.example", "direct").IP)
	require.NoError(t, restored.Close())
	actual, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, actual)
	corrupt := append([]byte(nil), original...)
	corrupt[len(corrupt)-8] = '!'
	require.NoError(t, os.WriteFile(path, corrupt, 0600))
	_, err = openFakeIPLedger(directory)
	require.ErrorContains(t, err, "integrity")
	// Failed open must release its lock, so a restored verified backup can open.
	require.NoError(t, os.WriteFile(path, original, 0600))
	restored, err = openFakeIPLedger(directory)
	require.NoError(t, err)
	require.NoError(t, restored.Close())
}
func TestFakeIPLedgerCapacityAndCommitFailureNeverPublishNewIdentity(t *testing.T) {
	ledger, err := openFakeIPLedger(filepath.Join(t.TempDir(), "ledger"))
	require.NoError(t, err)
	defer ledger.Close()
	table := ledgerTable(t, "10.203.0.1/30")
	require.NoError(t, ledger.register(table))
	first := table.Set("first.example", "direct")
	require.NotNil(t, first)
	require.Nil(t, table.Set("overflow.example", "direct"))
	status := table.ownershipStatus()
	require.True(t, status.Persistent)
	require.True(t, status.Warning)
	require.Equal(t, 1, status.Used)
	require.Positive(t, status.StorageBytes)
	require.Equal(t, int64(fakeLedgerLimit), status.StorageLimit)
	require.Equal(t, first.IP, table.Set("first.example", "direct").IP)
	other := ledgerTable(t, "10.204.0.1/24")
	require.NoError(t, ledger.register(other))
	require.NoError(t, ledger.file.Close())
	require.Nil(t, other.Set("uncommitted.example", "office"))
	require.Empty(t, other.owners)
	require.Empty(t, other.Snapshot())
	require.Error(t, other.ownershipError)
	require.NotEmpty(t, other.ownershipStatus().Error)
}

func TestFakeIPRuntimeRestoresAcrossEnginesAndRejectsRetiredPools(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ledger")
	var first net.IP
	for attempt := 0; attempt < 2; attempt++ {
		network := newMemoryNetwork()
		one := lifecycleEngine(t, network, new(loopSockets))
		snapshot := *one.policy.Load()
		snapshot.cfg = cloneConfig(snapshot.cfg)
		snapshot.cfg.Policy.RuleVersion = 2
		snapshot.cfg.DNS.PersistentFakeIP = true
		snapshot.cfg.DNS.RetiredPools = []string{"10.207.0.0/16"}
		one.policy.Store(&snapshot)
		one.fakeIPDirectory = directory
		done := make(chan error, 1)
		go func() { done <- one.Run(t.Context()) }()
		select {
		case <-one.Ready():
		case err := <-done:
			t.Fatalf("capture failed: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("capture startup timed out")
		}
		record := one.dnsTable.Set("persisted.example", "direct")
		require.NotNil(t, record)
		if attempt == 0 {
			first = record.IP
		} else {
			require.Equal(t, first, record.IP)
		}
		decision := one.policy.Load().rule.Decide(net.ParseIP("10.207.0.45"), "tcp", 443)
		require.Equal(t, "protected:retired-fake-ip", decision.RuleID)
		require.Equal(t, BuiltinReject, decision.Outbound)
		require.Contains(t, captureRoutes(snapshot.cfg.Core, one.policy.Load().rule), "10.207.0.0/16")
		one.ClearDNSCache()
		require.Equal(t, first, one.dnsTable.GetByIP(first).IP)
		require.NoError(t, one.Close())
		require.NoError(t, <-done)
	}
	ledger, err := openFakeIPLedger(directory)
	require.NoError(t, err)
	defer ledger.Close()
	require.ErrorContains(t, ledger.register(ledgerTable(t, "10.207.0.1/16")), "migration")
	require.ErrorContains(t, ledger.register(ledgerTable(t, "10.207.0.1/24")), "overlaps")
}

func TestFakeIPLedgerRefusesMissingOrRolledBackState(t *testing.T) {
	for _, scenario := range []string{"missing-ledger", "missing-head", "older-ledger"} {
		t.Run(scenario, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "ledger")
			ledger, err := openFakeIPLedger(directory)
			require.NoError(t, err)
			table := ledgerTable(t, "10.203.0.1/24")
			require.NoError(t, ledger.register(table))
			original, err := os.ReadFile(filepath.Join(directory, "ownership-v1.jsonl"))
			require.NoError(t, err)
			require.NotNil(t, table.Set("published.example", "direct"))
			require.NoError(t, ledger.Close())
			switch scenario {
			case "missing-ledger":
				require.NoError(t, os.Remove(filepath.Join(directory, "ownership-v1.jsonl")))
			case "missing-head":
				require.NoError(t, os.Remove(filepath.Join(directory, "committed-head")))
			case "older-ledger":
				require.NoError(t, os.WriteFile(filepath.Join(directory, "ownership-v1.jsonl"), original, 0600))
			}
			_, err = openFakeIPLedger(directory)
			require.Error(t, err)
		})
	}
}
func TestFakeIPPersistentPoolCannotBeReopenedAsVolatile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ledger")
	ledger, err := openFakeIPLedger(directory)
	require.NoError(t, err)
	table := ledgerTable(t, "10.203.0.1/24")
	require.NoError(t, ledger.register(table))
	require.NotNil(t, table.Set("saved.example", "direct"))
	require.NoError(t, ledger.Close())
	one := lifecycleEngine(t, newMemoryNetwork(), new(loopSockets))
	one.fakeIPDirectory = directory
	snapshot := *one.policy.Load()
	snapshot.cfg = cloneConfig(snapshot.cfg)
	snapshot.cfg.Core.Network = "10.203.0.1/24"
	one.policy.Store(&snapshot)
	require.ErrorContains(t, one.verifyVolatileFakeIPPools(), "durable ownership")
	snapshot.cfg.Core.Network = "10.204.0.1/24"
	require.NoError(t, one.verifyVolatileFakeIPPools())
	require.NoError(t, one.Close())
	// Closing an unstarted engine must release its retained host ledger lock.
	reopened, err := openFakeIPLedger(directory)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
}

func TestFakeIPLedgerProcessCrashRetainsPublishedIdentity(t *testing.T) {
	if directory := os.Getenv("KONE_TEST_FAKE_IP_CRASH_DIRECTORY"); directory != "" {
		ledger, err := openFakeIPLedger(directory)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		table := ledgerTable(t, "10.203.0.1/24")
		if err = ledger.register(table); err != nil {
			os.Exit(3)
		}
		record := table.Set("published.example", "office")
		if record == nil {
			os.Exit(4)
		}
		fmt.Print(record.IP.String())
		os.Exit(0) // Deliberately omit Close and cleanup.
	}
	directory := filepath.Join(t.TempDir(), "ledger")
	child := exec.Command(os.Args[0], "-test.run=^TestFakeIPLedgerProcessCrashRetainsPublishedIdentity$")
	child.Env = append(os.Environ(), "KONE_TEST_FAKE_IP_CRASH_DIRECTORY="+directory)
	output, err := child.CombinedOutput()
	require.NoError(t, err, string(output))
	ledger, err := openFakeIPLedger(directory)
	require.NoError(t, err)
	defer ledger.Close()
	table := ledgerTable(t, "10.203.0.1/24")
	require.NoError(t, ledger.register(table))
	require.Equal(t, strings.TrimSpace(string(output)), table.Set("published.example", "direct").IP.String())
	require.NotEqual(t, strings.TrimSpace(string(output)), table.Set("another.example", "direct").IP.String())
}

func TestFakeIPMigrationExcludesBothFamiliesAndRefusesExhaustion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Core.IPv6Network = "fd7a:204::1/112"
	cfg.DNS.RetiredPools = []string{"10.193.0.0/16", "fd7a:204:1::/112"}
	ipv4, ipv6, err := FreshFakeIPNetworks(cfg)
	require.NoError(t, err)
	for _, raw := range []string{ipv4, ipv6} {
		candidate := netip.MustParsePrefix(raw)
		for _, old := range append(cfg.DNS.RetiredPools, cfg.Core.Network, cfg.Core.IPv6Network) {
			require.False(t, candidate.Overlaps(netip.MustParsePrefix(old)))
		}
	}
	cfg.DNS.RetiredPools = []string{"fd7a:204::/32"}
	_, _, err = FreshFakeIPNetworks(cfg)
	require.ErrorContains(t, err, "IPv6")
	cfg.DNS.RetiredPools = []string{"10.0.0.0/8"}
	_, _, err = FreshFakeIPNetworks(cfg)
	require.ErrorContains(t, err, "IPv4")
	cfg = DefaultConfig()
	_, err = FromConfig(cfg, WithFakeIPDirectory("relative"))
	require.ErrorContains(t, err, "absolute")
	one, err := FromConfig(cfg, WithFakeIPDirectory(filepath.Join(t.TempDir(), "ledger")))
	require.NoError(t, err)
	require.NoError(t, one.Close())
}

func TestFakeIPGenerationAndStorageLimitsPreservePublishedOwners(t *testing.T) {
	ledger, err := openFakeIPLedger(filepath.Join(t.TempDir(), "ledger"))
	require.NoError(t, err)
	defer ledger.Close()
	table := ledgerTable(t, "10.203.0.1/24")
	require.NoError(t, ledger.register(table))
	first := table.Set("saved.example", "direct")
	require.NotNil(t, first)
	require.ErrorContains(t, ledger.retire("not a pool"), "invalid")
	require.ErrorContains(t, ledger.retire("10.203.0.0/25"), "overlaps")
	for i := 0; i < fakeLedgerPoolLimit-1; i++ {
		require.NoError(t, ledger.retire(fmt.Sprintf("10.%d.0.0/24", 210+i)))
	}
	require.ErrorContains(t, ledger.retire("10.220.0.0/24"), "limit")
	require.ErrorContains(t, ledger.register(ledgerTable(t, "10.220.0.1/24")), "limit")
	ledger.size = fakeLedgerLimit // Simulate the persisted-byte limit without a 64 MiB fixture.
	require.Nil(t, table.Set("capacity.example", "direct"))
	require.Contains(t, table.ownershipStatus().Error, "capacity")
	require.Equal(t, first.IP, table.Set("saved.example", "office").IP)
	require.NoError(t, ledger.Close())
	restored, err := openFakeIPLedger(ledger.directory)
	require.NoError(t, err)
	defer restored.Close()
	next := ledgerTable(t, "10.203.0.1/24")
	require.NoError(t, restored.register(next))
	require.Equal(t, first.IP, next.Set("saved.example", "direct").IP)
	require.NotContains(t, next.owners, "capacity.example")
}
