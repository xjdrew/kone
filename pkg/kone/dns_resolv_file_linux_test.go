package kone

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func resolverStore(t *testing.T, link bool) (resolvFileStore, string, []byte) {
	t.Helper()
	root := t.TempDir()
	original := []byte("# original\nnameserver 192.0.2.53\nsearch corp.example\noptions edns0\n")
	path := filepath.Join(root, "resolv.conf")
	target := path
	if link {
		target = filepath.Join(root, "shared.conf")
		require.NoError(t, os.WriteFile(target, original, 0644))
		require.NoError(t, os.Symlink("shared.conf", path))
	} else {
		require.NoError(t, os.WriteFile(path, original, 0644))
	}
	return resolvFileStore{path: path, directory: filepath.Join(root, "leases"), uid: os.Geteuid()}, target, original
}
func TestHostDNSFileLeaseRestoresOriginalFileAndWSLSymlink(t *testing.T) {
	for _, link := range []bool{false, true} {
		t.Run(map[bool]string{false: "regular", true: "shared symlink"}[link], func(t *testing.T) {
			store, target, original := resolverStore(t, link)
			cleanup, failures, err := store.acquire(t.Context(), "10.192.0.1")
			require.NoError(t, err)
			require.NotNil(t, failures)
			t.Cleanup(func() {
				if _, err := store.readRecord(); err == nil {
					_ = cleanup(context.Background())
				}
			})
			info, err := os.Lstat(store.path)
			require.NoError(t, err)
			require.True(t, info.Mode().IsRegular())
			data, err := os.ReadFile(store.path)
			require.NoError(t, err)
			require.Contains(t, string(data), "nameserver 10.192.0.1\n")
			require.NotContains(t, string(data), "nameserver 192.0.2.53")
			require.Contains(t, string(data), "search corp.example")
			if link {
				shared, err := os.ReadFile(target)
				require.NoError(t, err)
				require.Equal(t, original, shared, "the shared WSL file is never rewritten")
			}
			entries, err := store.inspect(t.Context())
			require.NoError(t, err)
			require.Len(t, entries, 1)
			require.Equal(t, "active", entries[0].Status)
			require.False(t, entries[0].CanRecover)
			record, err := store.readRecord()
			require.NoError(t, err)
			require.ErrorContains(t, store.restore(record, true), "still running")
			_, _, err = store.acquire(t.Context(), "10.192.0.1")
			require.ErrorContains(t, err, "recovery")
			require.NoError(t, cleanup(context.Background()))
			restored, err := os.ReadFile(store.path)
			require.NoError(t, err)
			require.Equal(t, original, restored)
			if link {
				destination, err := os.Readlink(store.path)
				require.NoError(t, err)
				require.Equal(t, "shared.conf", destination)
			}
			entries, err = store.inspect(t.Context())
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}
func TestHostDNSLeaseDetectsExternalChangeAndKeepsIt(t *testing.T) {
	store, _, _ := resolverStore(t, false)
	cleanup, failures, err := store.acquire(t.Context(), "10.192.0.1")
	require.NoError(t, err)
	replacement := []byte("nameserver 192.0.2.99\n")
	require.NoError(t, os.WriteFile(store.path, replacement, 0644))
	select {
	case err := <-failures:
		require.ErrorContains(t, err, "another manager")
	case <-time.After(2 * time.Second):
		t.Fatal("external DNS change was not observed")
	}
	require.ErrorContains(t, cleanup(context.Background()), "externally")
	data, err := os.ReadFile(store.path)
	require.NoError(t, err)
	require.Equal(t, replacement, data)
	entries, err := store.inspect(t.Context())
	require.NoError(t, err)
	require.Equal(t, "external_change", entries[0].Status)
	require.False(t, entries[0].CanRecover)
}
func TestHostDNSOrphanRecoveryAndTamperedBackup(t *testing.T) {
	for _, tampered := range []bool{false, true} {
		t.Run(map[bool]string{false: "recover", true: "tampered backup"}[tampered], func(t *testing.T) {
			store, _, original := resolverStore(t, true)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			_, _, err := store.acquire(ctx, "10.192.0.1")
			require.NoError(t, err)
			cancel()
			record, err := store.readRecord()
			require.NoError(t, err)
			record.PID = 999999999
			encoded, err := json.Marshal(record)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(store.directory, "lease.json"), encoded, 0644))
			entries, err := store.inspect(t.Context())
			require.NoError(t, err)
			require.Equal(t, "orphaned", entries[0].Status)
			require.True(t, entries[0].CanRecover)
			if tampered {
				require.NoError(t, os.WriteFile(store.backup(record), []byte("bad"), 0600))
				require.ErrorContains(t, store.restore(record, true), "backup")
				return
			}
			require.NoError(t, store.restore(record, true))
			data, err := os.ReadFile(store.path)
			require.NoError(t, err)
			require.Equal(t, original, data)
		})
	}
}
func TestHostDNSLeaseBoundaries(t *testing.T) {
	store, _, _ := resolverStore(t, false)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, store.check(ctx), context.Canceled)
	_, _, err := store.acquire(t.Context(), "invalid")
	require.Error(t, err)
	require.NoError(t, os.MkdirAll(store.directory, 0755))
	require.NoError(t, os.Chmod(store.directory, 0777))
	_, err = store.readRecord()
	require.ErrorContains(t, err, "untrusted")
	require.NoError(t, os.Chmod(store.directory, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(store.directory, "lease.json"), []byte("invalid json"), 0644))
	_, err = store.readRecord()
	require.ErrorContains(t, err, "invalid")
	require.Equal(t, []string{"192.0.2.1:53", "[2001:db8::1]:53"}, resolvFileServers([]byte("nameserver 192.0.2.1\nnameserver 2001:db8::1\nnameserver bad.host\n")))
	require.Error(t, checkResolvFileDNS(t.Context(), DNSConfig{ListenPort: 5353}))
	require.Error(t, RecoverSystemDNS(ctx, "unused"))
	_, err = resolverProcessStart(-1)
	require.True(t, errors.Is(err, os.ErrNotExist))
}

func TestHostDNSLeaseRestoresAbsentEntryAndRecoversAfterReboot(t *testing.T) {
	store, _, _ := resolverStore(t, false)
	require.NoError(t, os.Remove(store.path))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, _, err := store.acquire(ctx, "10.192.0.1")
	require.NoError(t, err)
	cancel()
	record, err := store.readRecord()
	require.NoError(t, err)
	require.True(t, record.Absent)
	record.BootID = "a-previous-boot"
	record.Namespace = "a-previous-namespace"
	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(store.directory, "lease.json"), encoded, 0644))
	entries, err := store.inspect(t.Context())
	require.NoError(t, err)
	require.Equal(t, "orphaned", entries[0].Status)
	require.True(t, entries[0].CanRecover)
	require.NoError(t, store.restore(record, true))
	_, err = os.Lstat(store.path)
	require.ErrorIs(t, err, os.ErrNotExist)
}

type fixtureFileDNSNetwork struct {
	*memoryNetwork
	store resolvFileStore
}

func (n *fixtureFileDNSNetwork) CheckSystemDNS(ctx context.Context, _ DNSConfig) error {
	return n.store.check(ctx)
}
func (n *fixtureFileDNSNetwork) ConfigureSystemDNS(ctx context.Context, d Device, c CoreConfig, cfg DNSConfig) (Cleanup, error) {
	cleanup, _, err := n.ConfigureSystemDNSLease(ctx, d, c, cfg)
	return cleanup, err
}
func (n *fixtureFileDNSNetwork) ConfigureSystemDNSLease(ctx context.Context, _ Device, _ CoreConfig, _ DNSConfig) (Cleanup, <-chan error, error) {
	return n.store.acquire(ctx, "10.192.0.1")
}
func TestHostDNSFileLeaseFollowsCaptureLifecycle(t *testing.T) {
	store, _, original := resolverStore(t, true)
	network := newMemoryNetwork()
	one := lifecycleEngine(t, network, new(loopSockets))
	one.network = &fixtureFileDNSNetwork{network, store}
	snapshot := *one.policy.Load()
	snapshot.cfg = cloneConfig(snapshot.cfg)
	snapshot.cfg.DNS.Mode = "host"
	one.policy.Store(&snapshot)
	t.Cleanup(func() { _ = one.Close() })
	done := make(chan error, 1)
	go func() { done <- one.Run(t.Context()) }()
	select {
	case <-one.Ready():
	case err := <-done:
		t.Fatalf("capture failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("capture did not start")
	}
	require.True(t, one.DNSStatus().SystemActive)
	require.True(t, one.DNSStatus().SystemRequested)
	require.NoError(t, one.Close())
	require.NoError(t, <-done)
	require.False(t, one.DNSStatus().SystemActive)
	restored, err := os.ReadFile(store.path)
	require.NoError(t, err)
	require.Equal(t, original, restored)
}
