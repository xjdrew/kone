package kone

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const fakeLedgerLimit = 64 << 20
const fakeLedgerPoolLimit = 8

type fakeLedgerEntry struct {
	Kind     string   `json:"kind"`
	Pool     string   `json:"pool,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	Address  string   `json:"address,omitempty"`
	Reserved []string `json:"reserved,omitempty"`
}
type fakeLedgerLine struct {
	Version  int             `json:"version"`
	Previous string          `json:"previous"`
	Entry    fakeLedgerEntry `json:"entry"`
	Hash     string          `json:"hash"`
}
type fakeLedgerPool struct {
	allocator *DnsIPPool
	reserved  []string
	owners    map[string]netip.Addr
	reverse   map[netip.Addr]string
	retired   bool
}

// The ledger stores identity only. DNS answers, rules and network evidence are
// deliberately absent. Its lock belongs to the running network owner, not a UI.
type fakeIPLedger struct {
	directory string
	mu        sync.Mutex
	file      *os.File
	lock      *os.File
	pools     map[string]*fakeLedgerPool
	hash      string
	size      int64
	failure   error
}

func fakeLineHash(line fakeLedgerLine) string {
	line.Hash = ""
	data, _ := json.Marshal(line)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func openFakeIPLedger(directory string) (ledger *fakeIPLedger, err error) {
	if err = os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	if err = verifyFakeLedgerPath(directory, true); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(directory, "owner.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = verifyFakeLedgerPath(filepath.Join(directory, "owner.lock"), false); err != nil {
		lock.Close()
		return nil, err
	}
	if err = lockFakeLedger(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("another KONE capture owns the Fake-IP ledger: %w", err)
	}
	ledger = &fakeIPLedger{directory: directory, lock: lock, pools: map[string]*fakeLedgerPool{}}
	opened := ledger
	defer func() {
		if err != nil {
			opened.Close()
		}
	}()
	marker := make([]byte, 64)
	n, markerErr := lock.ReadAt(marker, 0)
	if markerErr != nil && markerErr != io.EOF {
		return nil, markerErr
	}
	initialized := n > 0
	if initialized && string(marker[:n]) != "KONE Fake-IP ownership v1\n" {
		return nil, errors.New("invalid Fake-IP ownership marker")
	}
	if initialized {
		for _, name := range []string{"ownership-v1.jsonl", "committed-head"} {
			if err = verifyFakeLedgerPath(filepath.Join(directory, name), false); err != nil {
				return nil, fmt.Errorf("missing or invalid Fake-IP ownership state; restore a complete verified backup: %w", err)
			}
		}
	} else {
		if _, err = lock.WriteAt([]byte("KONE Fake-IP ownership v1\n"), 0); err != nil {
			return nil, err
		}
		if err = syncFakeLedgerFile(lock); err != nil {
			return nil, err
		}
	}
	path := filepath.Join(directory, "ownership-v1.jsonl")
	file, openErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	created := openErr == nil
	if errors.Is(openErr, os.ErrExist) {
		if err = verifyFakeLedgerPath(path, false); err != nil {
			return nil, err
		}
		file, openErr = os.OpenFile(path, os.O_RDWR, 0600)
	}
	if openErr != nil {
		return nil, openErr
	}
	ledger.file = file
	if err = verifyFakeLedgerPath(path, false); err != nil {
		return nil, err
	}
	if created {
		if err = ledger.append(fakeLedgerEntry{Kind: "header"}); err != nil {
			return nil, err
		}
		if err = syncFakeLedgerParents(directory); err != nil {
			return nil, err
		}
	} else {
		if err = ledger.restore(); err != nil {
			return nil, err
		}
	}
	return ledger, nil
}
func (l *fakeIPLedger) restore() error {
	info, err := l.file.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 || info.Size() > fakeLedgerLimit {
		return errors.New("invalid Fake-IP ledger size; preserve the file and repair ownership state")
	}
	checkpoint, err := os.ReadFile(filepath.Join(l.directory, "committed-head"))
	if err != nil || len(checkpoint) != 64 {
		return errors.New("missing or invalid Fake-IP committed head")
	}
	checkpointFound := false
	reader := bufio.NewReaderSize(io.LimitReader(l.file, fakeLedgerLimit+1), 4096)
	var offset int64
	first := true
	for {
		data, readErr := reader.ReadSlice('\n')
		if len(data) > 4096 {
			return errors.New("Fake-IP ledger record exceeds bound")
		}
		if readErr == io.EOF {
			if !checkpointFound {
				return errors.New("Fake-IP ownership state is older than its committed head; restore the complete latest state")
			}
			if len(data) > 0 {
				// An uncommitted partial append cannot have been published. Keep the
				// verified prefix; complete records with bad checksums never get dropped.
				if first {
					return errors.New("incomplete Fake-IP ledger header")
				}
				if err := l.file.Truncate(offset); err != nil {
					return err
				}
				if err := syncFakeLedgerFile(l.file); err != nil {
					return err
				}
			}
			break
		}
		if readErr != nil {
			return readErr
		}
		var line fakeLedgerLine
		if json.Unmarshal(data, &line) != nil || line.Version != 1 || line.Previous != l.hash || line.Hash != fakeLineHash(line) {
			return errors.New("Fake-IP ledger integrity check failed")
		}
		if first && line.Entry.Kind != "header" || !first && line.Entry.Kind == "header" {
			return errors.New("invalid Fake-IP ledger header order")
		}
		if err := l.apply(line.Entry); err != nil {
			return err
		}
		l.hash = line.Hash
		if l.hash == string(checkpoint) {
			checkpointFound = true
		}
		offset += int64(len(data))
		first = false
	}
	if first {
		return errors.New("empty Fake-IP ledger")
	}
	l.size = offset
	_, err = l.file.Seek(offset, io.SeekStart)
	return err
}
func (l *fakeIPLedger) apply(entry fakeLedgerEntry) error {
	if entry.Kind == "header" {
		return nil
	}
	prefix, err := netip.ParsePrefix(entry.Pool)
	if err != nil || prefix != prefix.Masked() {
		return errors.New("invalid Fake-IP ledger pool")
	}
	pool := l.pools[entry.Pool]
	switch entry.Kind {
	case "pool":
		if pool != nil || len(l.pools) >= fakeLedgerPoolLimit || len(entry.Reserved) > 8 {
			return errors.New("duplicate or excessive Fake-IP pool")
		}
		allocator := NewDnsIPPool(prefix)
		if allocator.Capacity() == 0 {
			return errors.New("unsupported Fake-IP ledger pool")
		}
		for _, raw := range entry.Reserved {
			address, err := netip.ParseAddr(raw)
			if err != nil || !prefix.Contains(address) {
				return errors.New("invalid reserved Fake-IP address")
			}
		}
		l.pools[entry.Pool] = &fakeLedgerPool{allocator: allocator, reserved: append([]string(nil), entry.Reserved...), owners: map[string]netip.Addr{}, reverse: map[netip.Addr]string{}}
	case "retire":
		if pool == nil {
			if len(l.pools) >= fakeLedgerPoolLimit {
				return errors.New("too many Fake-IP generations")
			}
			pool = &fakeLedgerPool{allocator: NewDnsIPPool(prefix), owners: map[string]netip.Addr{}, reverse: map[netip.Addr]string{}}
			l.pools[entry.Pool] = pool
		}
		pool.retired = true
	case "bind":
		if pool == nil || pool.retired || !validDNSSuffix(entry.Domain) || len(entry.Domain) > 253 || normalizeDomain(entry.Domain) != entry.Domain || strings.ContainsAny(entry.Domain, "\x00\r\n\t /\\") {
			return errors.New("invalid Fake-IP binding")
		}
		address, err := netip.ParseAddr(entry.Address)
		if err != nil || !pool.allocator.Contains(address) {
			return errors.New("Fake-IP binding lies outside its pool")
		}
		for _, reserved := range pool.reserved {
			if address.String() == reserved {
				return errors.New("Fake-IP binding uses a reserved address")
			}
		}
		if _, ok := pool.owners[entry.Domain]; ok {
			return errors.New("duplicate Fake-IP domain ownership")
		}
		if _, ok := pool.reverse[address]; ok {
			return errors.New("duplicate Fake-IP address ownership")
		}
		pool.owners[entry.Domain], pool.reverse[address] = address, entry.Domain
	default:
		return errors.New("unsupported Fake-IP ledger record")
	}
	return nil
}
func (l *fakeIPLedger) append(entry fakeLedgerEntry) error {
	if l.failure != nil {
		return l.failure
	}
	line := fakeLedgerLine{Version: 1, Previous: l.hash, Entry: entry}
	line.Hash = fakeLineHash(line)
	data, err := json.Marshal(line)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if l.size+int64(len(data)) > fakeLedgerLimit {
		return errors.New("Fake-IP ledger capacity exhausted; existing identities are retained")
	}
	if _, err = l.file.Write(data); err == nil {
		err = syncFakeLedgerFile(l.file)
	}
	if err == nil {
		err = l.checkpoint(line.Hash)
	}
	if err != nil {
		l.failure = fmt.Errorf("Fake-IP ownership could not be committed: %w", err)
		return l.failure
	}
	l.hash = line.Hash
	l.size += int64(len(data))
	return nil
}
func (l *fakeIPLedger) register(table *DnsTable) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := table.ipNet.String()
	pool := l.pools[key]
	reserved := []string{}
	for index, used := range table.ipPool.flags {
		if used {
			reserved = append(reserved, table.ipPool.address(index).String())
		}
	}
	if pool == nil {
		for raw := range l.pools {
			if netip.MustParsePrefix(raw).Overlaps(table.ipNet) {
				return errors.New("new Fake-IP pool overlaps an existing generation")
			}
		}
		entry := fakeLedgerEntry{Kind: "pool", Pool: key, Reserved: reserved}
		if len(l.pools) >= fakeLedgerPoolLimit {
			return errors.New("Fake-IP pool generation limit reached")
		}
		if err := l.append(entry); err != nil {
			return err
		}
		if err := l.apply(entry); err != nil {
			return err
		}
		pool = l.pools[key]
	} else if strings.Join(pool.reserved, "|") != strings.Join(reserved, "|") || pool.retired {
		return errors.New("Fake-IP pool identity or reserved addresses changed; an explicit pool migration is required")
	}
	for domain, address := range pool.owners {
		if index, ok := table.ipPool.index(address); !ok || table.ipPool.flags[index] {
			return errors.New("Fake-IP ledger contains conflicting ownership")
		}
		table.ipPool.reserve(address)
		table.owners[domain] = address
		table.ip2Domain[address.String()] = domain
	}
	table.ledger = l
	return nil
}
func (l *fakeIPLedger) commit(pool, domain string, address netip.Addr) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.pools[pool]
	if state == nil || state.retired || !validDNSSuffix(domain) || len(domain) > 253 || normalizeDomain(domain) != domain || strings.ContainsAny(domain, "\x00\r\n\t /\\") || !state.allocator.Contains(address) {
		return errors.New("invalid Fake-IP ownership request")
	}
	if _, ok := state.owners[domain]; ok {
		return errors.New("domain already owns a Fake-IP")
	}
	if _, ok := state.reverse[address]; ok {
		return errors.New("Fake-IP already belongs to another domain")
	}
	for _, reserved := range state.reserved {
		if reserved == address.String() {
			return errors.New("reserved Fake-IP cannot be published")
		}
	}
	entry := fakeLedgerEntry{Kind: "bind", Pool: pool, Domain: domain, Address: address.String()}
	if err := l.append(entry); err != nil {
		return err
	}
	return l.apply(entry)
}
func (l *fakeIPLedger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var err error
	if l.failure == nil {
		l.failure = os.ErrClosed
	}
	if l.file != nil {
		err = l.file.Close()
		l.file = nil
	}
	if l.lock != nil {
		err = errors.Join(err, unlockFakeLedger(l.lock), l.lock.Close())
		l.lock = nil
	}
	return err
}
