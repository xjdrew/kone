// Package logstore provides an instance-owned, bounded runtime log history.
package logstore

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	DefaultCapacity = 1000
	DefaultMaxBytes = 4 << 20
	MaxLimit        = 200
	MaxRecordBytes  = 16 << 10
)

type Options struct{ Capacity, MaxBytes int }
type Record struct {
	ID      uint64         `json:"id,string"`
	Time    time.Time      `json:"time"`
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Attrs   map[string]any `json:"attrs"`
	Source  string         `json:"source"`
}
type Query struct {
	After    uint64
	Before   uint64
	From     time.Time
	To       time.Time
	Limit    int
	MinLevel string
	Source   string
	Tail     bool
}
type Page struct {
	Records      []Record `json:"records"`
	NextCursor   uint64   `json:"next_cursor,string"`
	OldestCursor uint64   `json:"oldest_cursor,string"`
	Dropped      uint64   `json:"dropped"`
	Gap          bool     `json:"gap"`
	HasMore      bool     `json:"has_more"`
	Capacity     int      `json:"capacity"`
	Bytes        int      `json:"bytes"`
}
type RemoteStatus struct {
	Connected bool   `json:"connected"`
	Dropped   uint64 `json:"dropped"`
	Error     string `json:"error,omitempty"`
}
type storedRecord struct {
	record Record
	size   int
}
type Store struct {
	mu                        sync.Mutex
	entries                   []storedRecord
	capacity, maxBytes, bytes int
	sequence, dropped         uint64
	changed                   chan struct{}
}

func New() *Store { return NewWithOptions(Options{}) }
func NewWithOptions(options Options) *Store {
	if options.Capacity <= 0 || options.Capacity > DefaultCapacity {
		options.Capacity = DefaultCapacity
	}
	if options.MaxBytes <= 0 || options.MaxBytes > DefaultMaxBytes {
		options.MaxBytes = DefaultMaxBytes
	}
	return &Store{capacity: options.Capacity, maxBytes: options.MaxBytes, changed: make(chan struct{}, 1)}
}
func (s *Store) Changed() <-chan struct{} { return s.changed }
func (s *Store) Append(record Record) {
	if s == nil {
		return
	}
	record = sanitizeRecord(record)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequence++
	record.ID = s.sequence
	data, _ := json.Marshal(record)
	size := len(data)
	if size > MaxRecordBytes || size > s.maxBytes {
		record.Attrs = map[string]any{"truncated": true}
		record.Message = bounded(record.Message, 256)
		data, _ = json.Marshal(record)
		size = len(data)
	}
	if size > s.maxBytes {
		s.dropped++
		return
	}
	for len(s.entries) > 0 && (len(s.entries) >= s.capacity || s.bytes+size > s.maxBytes) {
		s.bytes -= s.entries[0].size
		s.entries[0] = storedRecord{}
		s.entries = s.entries[1:]
		s.dropped++
	}
	s.entries = append(s.entries, storedRecord{record, size})
	s.bytes += size
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

func normalizeQuery(query Query) (Query, slog.Level, error) {
	if query.Limit == 0 {
		query.Limit = 100
	}
	if query.Limit < 1 || query.Limit > MaxLimit || len(query.Source) > 64 || query.After != 0 && query.Before != 0 || !query.From.IsZero() && !query.To.IsZero() && query.From.After(query.To) {
		return query, 0, errors.New("invalid log query bounds")
	}
	if query.Before != 0 {
		query.Tail = true
	}
	level := slog.LevelDebug
	switch strings.ToLower(query.MinLevel) {
	case "", "debug":
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return query, 0, errors.New("invalid log minimum level")
	}
	return query, level, nil
}
func (s *Store) Query(query Query) (Page, error) {
	query, minimum, err := normalizeQuery(query)
	if err != nil {
		return Page{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	page := Page{Records: []Record{}, NextCursor: query.After, Dropped: s.dropped, Capacity: s.capacity, Bytes: s.bytes, OldestCursor: s.sequence + 1}
	if len(s.entries) > 0 {
		page.OldestCursor = s.entries[0].record.ID
	}
	if query.After > s.sequence {
		query.After = 0
		page.Gap = true
		page.NextCursor = 0
	}
	if query.After < page.OldestCursor-1 {
		page.Gap = true
	}
	matches := func(record Record) bool {
		var level slog.Level
		if level.UnmarshalText([]byte(record.Level)) != nil {
			level = slog.LevelInfo
		}
		return level >= minimum && (query.Source == "" || record.Source == query.Source) && (query.From.IsZero() || !record.Time.Before(query.From)) && (query.To.IsZero() || !record.Time.After(query.To))
	}
	if query.Tail {
		for i := len(s.entries) - 1; i >= 0; i-- {
			record := s.entries[i].record
			if query.Before != 0 && record.ID >= query.Before || !matches(record) {
				continue
			}
			if len(page.Records) == query.Limit {
				page.HasMore = true
				break
			}
			page.Records = append(page.Records, cloneRecord(record))
		}
		slices.Reverse(page.Records)
		page.NextCursor = s.sequence
		return page, nil
	}
	for i, value := range s.entries {
		record := value.record
		if record.ID <= query.After {
			continue
		}
		page.NextCursor = record.ID
		if !matches(record) {
			continue
		}
		page.Records = append(page.Records, cloneRecord(record))
		if len(page.Records) >= query.Limit {
			page.HasMore = i < len(s.entries)-1
			break
		}
	}
	if !page.HasMore {
		page.NextCursor = s.sequence
	}
	return page, nil
}

func cloneRecord(record Record) Record {
	data, _ := json.Marshal(record.Attrs)
	record.Attrs = map[string]any{}
	_ = json.Unmarshal(data, &record.Attrs)
	return record
}

type textWriter struct {
	store  *Store
	source string
}

func (s *Store) Writer(source string) io.Writer { return textWriter{s, source} }
func (w textWriter) Write(data []byte) (int, error) {
	// stderr messages are bounded before sanitizing; stdout/bootstrap output is
	// never connected here by the application entrypoint.
	text := string(data[:min(len(data), MaxRecordBytes)])
	for _, line := range strings.Split(text, "\n") {
		if line != "" {
			w.store.Append(Record{Time: time.Now(), Level: "ERROR", Message: line, Source: w.source})
		}
	}
	return len(data), nil
}
