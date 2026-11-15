package kone

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// The original symlink target is never modified (WSL shares /mnt/wsl/resolv.conf).
// A local regular file replaces /etc/resolv.conf for the lifetime of capture.
// A private backup and read-only ownership record precede every replacement.
type resolvFileStore struct {
	path, directory string
	uid             int
	verifyNamespace func() error
}
type resolvFileRecord struct {
	ID           string `json:"id"`
	PID          int    `json:"pid"`
	ProcessStart string `json:"process_start"`
	Namespace    string `json:"namespace"`
	BootID       string `json:"boot_id"`
	OriginalHash string `json:"original_hash"`
	OwnedHash    string `json:"owned_hash"`
	Link         string `json:"link,omitempty"`
	Absent       bool   `json:"absent,omitempty"`
	Mode         uint32 `json:"mode"`
	UID          int    `json:"uid"`
	GID          int    `json:"gid"`
}

func hostResolvFile() resolvFileStore {
	return resolvFileStore{path: "/etc/resolv.conf", directory: "/var/lib/kone/dns", uid: 0, verifyNamespace: verifyResolverFileNamespace}
}
func verifyResolverFileNamespace() error {
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if os.IsPermission(err) && os.Geteuid() != 0 {
		return nil
	} // Rechecked by the authorized helper.
	if err != nil {
		return err
	}
	if self != init {
		// A private mount namespace must also own a different /etc directory;
		// binding only resolv.conf does not make replacing its directory entry safe.
		local, localErr := os.Stat("/etc")
		host, hostErr := os.Stat("/proc/1/root/etc")
		if localErr != nil || hostErr != nil || os.SameFile(local, host) {
			return errors.New("resolver file is not isolated from the host network namespace")
		}
	}
	return nil
}
func resolverSameBoot(record resolvFileRecord) (bool, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(data)) == record.BootID, err
}
func resolverHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func resolverProcessStart(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return "", errors.New("invalid process identity")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 {
		return "", errors.New("incomplete process identity")
	}
	return fields[19], nil
}
func (s resolvFileStore) readCurrent() ([]byte, error) {
	data, err := readSystemResolverFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}
func (s resolvFileStore) verifyEntry(expected []byte, record resolvFileRecord) error {
	info, err := os.Lstat(s.path)
	original := resolverHash(expected) == record.OriginalHash
	if original && record.Absent {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("resolver entry was created externally")
	}
	if err != nil {
		return err
	}
	if original && record.Link != "" {
		link, err := os.Readlink(s.path)
		if err != nil || link != record.Link {
			return errors.New("resolver symlink changed externally")
		}
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || int(stat.Uid) != record.UID || int(stat.Gid) != record.GID {
		return errors.New("resolver entry ownership changed externally")
	}
	return nil
}
func (s resolvFileStore) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.verifyNamespace != nil {
		if err := s.verifyNamespace(); err != nil {
			return err
		}
	}
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		return errors.New("system resolver must be a regular file or symlink")
	}
	data, err := s.readCurrent()
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("system resolver file exceeds size limit")
	}
	// Resolving applications cannot express a nonstandard DNS port in this file.
	return nil
}
func (s resolvFileStore) readRecord() (resolvFileRecord, error) {
	var record resolvFileRecord
	info, err := os.Lstat(s.directory)
	if err != nil {
		return record, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || int(stat.Uid) != s.uid || info.Mode().Perm()&0022 != 0 {
		return record, errors.New("untrusted DNS lease directory")
	}
	path := filepath.Join(s.directory, "lease.json")
	info, err = os.Lstat(path)
	if err != nil {
		return record, err
	}
	stat, ok = info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || int(stat.Uid) != s.uid || info.Mode().Perm()&0022 != 0 || info.Size() > 16384 {
		return record, errors.New("untrusted DNS lease record")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	if json.Unmarshal(data, &record) != nil {
		return record, errors.New("invalid DNS lease record")
	}
	id, err := hex.DecodeString(record.ID)
	if err != nil || len(id) != 16 || record.PID < 1 || record.ProcessStart == "" || record.BootID == "" || record.OriginalHash == "" || record.OwnedHash == "" {
		return record, errors.New("invalid DNS lease identity")
	}
	return record, nil
}
func (s resolvFileStore) backup(record resolvFileRecord) string {
	return filepath.Join(s.directory, record.ID+".original")
}
func writeResolverFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	return errors.Join(writeErr, syncErr, f.Close())
}

func syncResolverDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
func (s resolvFileStore) replace(expected []byte, data []byte, link string, record resolvFileRecord) error {
	if err := s.verifyEntry(expected, record); err != nil {
		return err
	}
	current, err := s.readCurrent()
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return errors.New("system DNS changed externally; preserving it")
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".kone-dns-*")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if link != "" {
		if err := temporary.Close(); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := os.Symlink(link, path); err != nil {
			return err
		}
		if err := os.Lchown(path, record.UID, record.GID); err != nil {
			return err
		}
	} else {
		_, writeErr := temporary.Write(data)
		err = errors.Join(writeErr, temporary.Chown(record.UID, record.GID), temporary.Chmod(os.FileMode(record.Mode)), temporary.Sync(), temporary.Close())
		if err != nil {
			return err
		}
	}
	// Recheck immediately before the atomic rename. Never follow or write through
	// a symlink supplied by an external resolver manager.
	current, err = s.readCurrent()
	if err != nil || !bytes.Equal(current, expected) {
		return errors.New("system DNS changed before replacement")
	}
	if err := s.verifyEntry(expected, record); err != nil {
		return err
	}
	if err := os.Rename(path, s.path); err != nil {
		return fmt.Errorf("replace local resolver entry: %w", err)
	}
	return syncResolverDirectory(filepath.Dir(s.path))
}
func (s resolvFileStore) acquire(ctx context.Context, address string) (Cleanup, <-chan error, error) {
	if os.Geteuid() != s.uid {
		return nil, nil, errors.New("Host DNS requires administrator authorization to replace the local resolver entry")
	}
	if err := s.check(ctx); err != nil {
		return nil, nil, err
	}
	if net.ParseIP(address) == nil {
		return nil, nil, errors.New("invalid local DNS address")
	}
	if err := os.MkdirAll(s.directory, 0755); err != nil {
		return nil, nil, err
	}
	if _, err := s.readRecord(); err == nil {
		return nil, nil, errors.New("previous system DNS lease requires recovery")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	original, err := s.readCurrent()
	if err != nil {
		return nil, nil, err
	}
	info, statErr := os.Lstat(s.path)
	absent := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !absent {
		return nil, nil, statErr
	}
	token := make([]byte, 16)
	if _, err = rand.Read(token); err != nil {
		return nil, nil, err
	}
	record := resolvFileRecord{ID: hex.EncodeToString(token), PID: os.Getpid(), OriginalHash: resolverHash(original), Mode: 0644, UID: os.Geteuid(), GID: os.Getegid(), Absent: absent}
	if !absent {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, nil, errors.New("resolver ownership is unavailable")
		}
		record.Mode, record.UID, record.GID = uint32(info.Mode().Perm()), int(stat.Uid), int(stat.Gid)
	}
	record.ProcessStart, err = resolverProcessStart(record.PID)
	if err != nil {
		return nil, nil, err
	}
	boot, bootErr := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if bootErr != nil {
		return nil, nil, bootErr
	}
	record.BootID = strings.TrimSpace(string(boot))
	record.Namespace, err = os.Readlink("/proc/self/ns/net")
	if err != nil {
		return nil, nil, err
	}
	if !absent && info.Mode()&os.ModeSymlink != 0 {
		record.Link, err = os.Readlink(s.path)
		if err != nil {
			return nil, nil, err
		}
		record.Mode = 0644
	}
	var owned strings.Builder
	fmt.Fprintf(&owned, "# KONE DNS lease %s\nnameserver %s\n", record.ID, address)
	for _, line := range strings.Split(string(original), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "nameserver" {
			continue
		}
		if line != "" {
			owned.WriteString(line + "\n")
		}
	}
	replacement := []byte(owned.String())
	record.OwnedHash = resolverHash(replacement)
	if err := writeResolverFile(s.backup(record), original, 0600); err != nil {
		return nil, nil, err
	}
	encoded, _ := json.Marshal(record)
	if err := writeResolverFile(filepath.Join(s.directory, "lease.json"), encoded, 0644); err != nil {
		os.Remove(s.backup(record))
		return nil, nil, err
	}
	// Persist the backup and journal entries before changing OS DNS. A file
	// fsync alone does not make a newly created directory entry durable.
	if err := syncResolverDirectory(s.directory); err != nil {
		return nil, nil, err
	}
	// Keep the journal on an uncertain replacement result, so recovery can
	// distinguish an untouched entry from an owned entry after a crash.
	if err := s.replace(original, replacement, "", record); err != nil {
		return func(context.Context) error { return s.restore(record, false) }, nil, err
	}
	failures := make(chan error, 1)
	watchCtx, stop := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
				current, err := s.readCurrent()
				if err != nil || resolverHash(current) != record.OwnedHash {
					failures <- errors.New("system DNS was changed by another manager")
					return
				}
			}
		}
	}()
	cleanup := func(context.Context) error { stop(); return s.restore(record, false) }
	return cleanup, failures, nil
}
func (s resolvFileStore) restore(record resolvFileRecord, orphanOnly bool) error {
	current, err := s.readRecord()
	if err != nil {
		return err
	}
	if current.ID != record.ID {
		return errors.New("DNS lease ownership changed")
	}
	namespace, err := os.Readlink("/proc/self/ns/net")
	sameBoot, bootErr := resolverSameBoot(record)
	if bootErr != nil {
		return bootErr
	}
	if err != nil || sameBoot && namespace != record.Namespace {
		return errors.New("DNS lease belongs to another network namespace")
	}
	if orphanOnly && sameBoot {
		start, err := resolverProcessStart(record.PID)
		if err == nil && start == record.ProcessStart {
			return errors.New("DNS lease owner is still running")
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	data, err := s.readCurrent()
	if err != nil {
		return err
	}
	if resolverHash(data) == record.OwnedHash {
		original, err := readSystemResolverFile(s.backup(record))
		if err != nil {
			return err
		}
		if resolverHash(original) != record.OriginalHash {
			return errors.New("DNS backup does not match its ownership record")
		}
		if record.Absent {
			if err := s.verifyEntry(data, record); err != nil {
				return err
			}
			if err := os.Remove(s.path); err != nil {
				return err
			}
		} else if err := s.replace(data, original, record.Link, record); err != nil {
			return err
		}
	} else if resolverHash(data) != record.OriginalHash {
		return errors.New("system DNS changed externally; original backup retained for inspection")
	}
	if err := os.Remove(filepath.Join(s.directory, "lease.json")); err != nil {
		return err
	}
	return errors.Join(os.Remove(s.backup(record)), syncResolverDirectory(s.directory))
}
func (s resolvFileStore) inspect(ctx context.Context) ([]SystemDNSRecoveryEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	record, err := s.readRecord()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entry := SystemDNSRecoveryEntry{ID: record.ID, RuleName: "resolv.conf", Status: "orphaned", CanRecover: true, Message: "Restore the owned local DNS entry and its original file or symlink"}
	namespace, err := os.Readlink("/proc/self/ns/net")
	sameBoot, bootErr := resolverSameBoot(record)
	if bootErr != nil {
		return nil, bootErr
	}
	if err != nil || sameBoot && namespace != record.Namespace {
		entry.Status, entry.CanRecover = "different_namespace", false
	}
	start, err := resolverProcessStart(record.PID)
	if sameBoot && err == nil && start == record.ProcessStart {
		entry.Status, entry.CanRecover = "active", false
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	data, err := s.readCurrent()
	if err != nil {
		return nil, err
	}
	if hash := resolverHash(data); hash != record.OwnedHash && hash != record.OriginalHash {
		entry.Status, entry.CanRecover = "external_change", false
		entry.Message = "System DNS changed externally; preserve current settings and inspect the original backup"
	}
	return []SystemDNSRecoveryEntry{entry}, nil
}
func InspectSystemDNSRecovery(ctx context.Context) ([]SystemDNSRecoveryEntry, error) {
	return hostResolvFile().inspect(ctx)
}
func RecoverSystemDNS(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store := hostResolvFile()
	record, err := store.readRecord()
	if err != nil {
		return err
	}
	if record.ID != id {
		return errors.New("unknown DNS lease")
	}
	return store.restore(record, true)
}

// Linux file mode uses the same fixed port understood by resolv.conf clients.
func checkResolvFileDNS(ctx context.Context, cfg DNSConfig) error {
	if cfg.ListenPort != 53 {
		return errors.New("Host DNS on this Linux resolver requires dns.listen-port = 53")
	}
	return hostResolvFile().check(ctx)
}

// Retain only numeric nameserver entries; do not accept a recursive hostname.
func resolvFileServers(data []byte) []string {
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if value, err := normalizeDNSServer(fields[1]); err == nil {
			servers = append(servers, value)
		}
	}
	return servers
}
