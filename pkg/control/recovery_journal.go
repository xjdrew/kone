package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/xjdrew/kone/pkg/kone"
)

// Serialize journal replacement and conditional removal. The application
// instance lock separately prevents two processes sharing a settings store.
var recoveryJournalMu sync.Mutex

const recoveryJournalVersion = 1

type recoveryJournal struct {
	Version        int       `json:"version"`
	RunID          string    `json:"run_id"`
	PID            int       `json:"pid"`
	StartedAt      time.Time `json:"started_at"`
	Platform       string    `json:"platform"`
	RequestedName  string    `json:"requested_name,omitempty"`
	DeviceName     string    `json:"device_name,omitempty"`
	DeviceIndex    int       `json:"device_index,omitempty"`
	DeviceRecorded bool      `json:"device_recorded"`
	Network        string    `json:"network"`
	AutoRoute      bool      `json:"auto_route"`
	Legacy         bool      `json:"legacy,omitempty"`
}

type RecoveryItem struct {
	Kind     string `json:"kind"`
	Identity string `json:"identity,omitempty"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

type RecoveryReport struct {
	Required   bool           `json:"required"`
	RunID      string         `json:"run_id,omitempty"`
	RecordedAt time.Time      `json:"recorded_at,omitempty"`
	Ownership  string         `json:"ownership"`
	CanClear   bool           `json:"can_clear"`
	Items      []RecoveryItem `json:"items"`
	NextAction string         `json:"next_action,omitempty"`
}

func validRunID(id string) bool {
	if len(id) < 8 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// writeRecoveryJournal records only ownership and capture scope. Proxy URLs,
// credentials and complete user configurations never enter this journal.
func (c *Controller) writeRecoveryJournal(cfg *kone.KoneConfig, runID string) error {
	if cfg == nil || !validRunID(runID) {
		return errors.New("invalid capture journal identity")
	}
	recoveryJournalMu.Lock()
	defer recoveryJournalMu.Unlock()
	if _, err := os.Stat(c.journalPath()); err == nil {
		return errors.New("a previous capture journal requires inspection")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	record := recoveryJournal{Version: recoveryJournalVersion, RunID: runID, PID: os.Getpid(), StartedAt: c.now(), Platform: runtime.GOOS, RequestedName: cfg.Core.Tun, Network: cfg.Core.Network, AutoRoute: cfg.Core.AutoRoute}
	return c.saveRecoveryJournal(record)
}

func (c *Controller) saveRecoveryJournal(record recoveryJournal) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return atomicWrite(c.journalPath(), data)
}

// recordRecoveryDevice runs after exclusive device creation and before any
// interface configuration or route changes.
func (c *Controller) recordRecoveryDevice(runID, name string, index int) error {
	if name == "" || len(name) > 256 || strings.ContainsAny(name, "\r\n\x00") || index <= 0 {
		return errors.New("invalid created device identity")
	}
	recoveryJournalMu.Lock()
	defer recoveryJournalMu.Unlock()
	record, err := c.readRecoveryJournal(false)
	if err != nil {
		return err
	}
	if record.RunID != runID {
		return errors.New("capture journal belongs to another run")
	}
	if record.DeviceRecorded && (record.DeviceName != name || record.DeviceIndex != index) {
		return errors.New("capture device identity changed during startup")
	}
	record.DeviceName, record.DeviceIndex, record.DeviceRecorded = name, index, true
	return c.saveRecoveryJournal(record)
}

// removeRecoveryJournal cannot delete a newer run's journal when an old run
// finishes asynchronously. Missing or replaced epochs are an idempotent no-op.
func (c *Controller) removeRecoveryJournal(runID string) error {
	recoveryJournalMu.Lock()
	defer recoveryJournalMu.Unlock()
	record, err := c.readRecoveryJournal(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if record.RunID != runID {
		return nil
	}
	return os.Remove(c.journalPath())
}

func (c *Controller) readRecoveryJournal(migrate bool) (recoveryJournal, error) {
	var record recoveryJournal
	file, err := os.Open(c.journalPath())
	if err != nil {
		return record, err
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	// Close before any migration replaces the file: Windows does not permit
	// atomic replacement while this read handle is still open.
	err = errors.Join(err, file.Close())
	if err != nil {
		return record, err
	}
	if len(data) > 65536 {
		return record, errors.New("recovery journal is too large; inspect the local file")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&record)
	if err == nil {
		if trailing := decoder.Decode(new(any)); !errors.Is(trailing, io.EOF) {
			err = errors.New("trailing recovery journal data")
		}
	}
	if err == nil && record.Version == recoveryJournalVersion && validRunID(record.RunID) && record.Platform != "" && !record.StartedAt.IsZero() {
		if record.DeviceRecorded && (record.DeviceName == "" || record.DeviceIndex <= 0) {
			return recoveryJournal{}, errors.New("recovery journal has an incomplete device identity")
		}
		return record, nil
	}
	// Earlier builds wrote TOML containing complete proxy credentials. Migrate
	// valid records to minimal metadata without inferring created device identity.
	if migrate {
		if cfg, e := kone.ParseManagedConfig(data); e == nil {
			record = recoveryJournal{Version: recoveryJournalVersion, RunID: randomToken(), StartedAt: c.now(), Platform: runtime.GOOS, RequestedName: cfg.Core.Tun, Network: cfg.Core.Network, AutoRoute: cfg.Core.AutoRoute, Legacy: true}
			if e = c.saveRecoveryJournal(record); e != nil {
				return recoveryJournal{}, e
			}
			return record, nil
		}
	}
	return recoveryJournal{}, errors.New("recovery journal is invalid; inspect the local file without sharing its contents")
}

// InspectRecovery never changes system networking. A matching name or index is
// deliberately insufficient evidence to delete a surviving interface.
func (c *Controller) InspectRecovery(ctx context.Context) (RecoveryReport, error) {
	return c.inspectRecovery(ctx, net.Interfaces)
}

func (c *Controller) inspectRecovery(ctx context.Context, interfaces func() ([]net.Interface, error)) (RecoveryReport, error) {
	report := RecoveryReport{Ownership: "none", Items: []RecoveryItem{}}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	recoveryJournalMu.Lock()
	record, err := c.readRecoveryJournal(true)
	recoveryJournalMu.Unlock()
	if errors.Is(err, os.ErrNotExist) {
		return report, nil
	}
	report.Required = true
	if err != nil {
		report.Ownership = "unverified"
		report.Items = append(report.Items, RecoveryItem{Kind: "journal", Status: "invalid", Message: err.Error()})
		report.NextAction = "Inspect the local recovery record; automatic network changes are blocked"
		return report, err
	}
	report.RunID, report.RecordedAt = record.RunID, record.StartedAt
	if record.Platform != runtime.GOOS || record.Legacy {
		report.Ownership = "unverified"
		report.Items = append(report.Items, RecoveryItem{Kind: "tun", Identity: record.RequestedName, Status: "identity_unknown", Message: "The actual created interface was not durably recorded; the requested name is insufficient proof of ownership"})
		report.NextAction = "Inspect the previous capture on this host; KONE will not delete an interface with uncertain ownership"
		return report, nil
	}
	if !record.DeviceRecorded {
		// Device identity is durably acknowledged before Configure, routing or
		// firewall setup. An interrupted startup without that acknowledgement
		// cannot have applied capture settings. Clear only the journal: even a
		// partially opened device must never be guessed by its requested name.
		report.Ownership = "not_configured"
		report.Items = append(report.Items, RecoveryItem{Kind: "capture", Status: "not_configured", Message: "Startup stopped before device ownership was recorded; no capture network settings were applied"})
		report.CanClear = true
		report.NextAction = "Clear the interrupted startup record, then run preflight before enabling capture"
		return report, nil
	}
	values, err := interfaces()
	if err != nil {
		return report, fmt.Errorf("inspect recovery interfaces: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	report.Ownership = "recorded"
	for _, value := range values {
		if value.Name == record.DeviceName || value.Index == record.DeviceIndex {
			status := "still_present"
			if value.Name != record.DeviceName || value.Index != record.DeviceIndex {
				status = "identity_changed"
			}
			report.Items = append(report.Items, RecoveryItem{Kind: "tun", Identity: record.DeviceName, Status: status, Message: "An interface with this name or index remains; matching identifiers do not authorize deleting it"})
			report.NextAction = "Inspect the remaining interface and external network changes on this host before retrying"
			return report, nil
		}
	}
	report.Items = append(report.Items, RecoveryItem{Kind: "tun", Identity: record.DeviceName, Status: "absent", Message: "The recorded transient interface is absent"})
	if record.Platform == "windows" {
		// A program-scoped firewall exception cannot capture traffic without
		// the TUN. Preserve it rather than deleting an unverified rule, but do
		// not make this advisory prevent clearing a completed capture forever.
		report.Items = append(report.Items, RecoveryItem{Kind: "firewall", Status: "unverified", Message: "A program-scoped firewall exception may remain; it is preserved because its ownership cannot be verified and does not capture traffic without the absent TUN"})
	}
	// Address, route and DNS changes are scoped to the transient device.
	report.Items = append(report.Items, RecoveryItem{Kind: "routes", Status: "released_with_device", Message: "Device-scoped capture routes were released with the absent transient interface"})
	report.CanClear = true
	report.NextAction = "Clear the completed recovery record, then run preflight before enabling capture"
	return report, nil
}
