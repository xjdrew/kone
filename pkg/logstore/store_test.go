package logstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func page(t *testing.T, s *Store, q Query) Page {
	t.Helper()
	v, err := s.Query(q)
	require.NoError(t, err)
	return v
}

func TestCursorPaginationTailFiltersAndBoundedRetention(t *testing.T) {
	s := NewWithOptions(Options{Capacity: 3})
	for i := range 5 {
		s.Append(Record{Level: []string{"INFO", "WARN", "ERROR", "DEBUG", "WARN"}[i], Message: fmt.Sprint(i), Source: []string{"management", "helper"}[i%2]})
	}
	first := page(t, s, Query{Limit: 2})
	require.Equal(t, uint64(3), first.OldestCursor)
	require.Equal(t, uint64(2), first.Dropped)
	require.True(t, first.Gap)
	require.True(t, first.HasMore)
	require.Equal(t, uint64(4), first.NextCursor)
	require.Equal(t, []string{"2", "3"}, []string{first.Records[0].Message, first.Records[1].Message})
	next := page(t, s, Query{After: first.NextCursor})
	require.Len(t, next.Records, 1)
	require.Equal(t, uint64(5), next.NextCursor)
	require.False(t, next.HasMore)
	tail := page(t, s, Query{Tail: true, Limit: 1})
	require.Equal(t, "4", tail.Records[0].Message)
	require.Equal(t, uint64(5), tail.NextCursor)
	filtered := page(t, s, Query{Tail: true, MinLevel: "error"})
	require.Len(t, filtered.Records, 1)
	require.Equal(t, "ERROR", filtered.Records[0].Level)
	require.Empty(t, page(t, s, Query{Source: "missing"}).Records)
	require.Equal(t, uint64(5), page(t, s, Query{Source: "missing"}).NextCursor)
	require.Equal(t, "helper", page(t, s, Query{Source: "helper"}).Records[0].Source)
	reset := page(t, s, Query{After: 99})
	require.True(t, reset.Gap)
	require.Len(t, reset.Records, 3)
	first.Records[0].Attrs["changed"] = true
	require.NotContains(t, page(t, s, Query{}).Records[0].Attrs, "changed")
	require.NotEmpty(t, s.Changed())
	for _, q := range []Query{{Limit: -1}, {Limit: 201}, {MinLevel: "trace"}, {Source: strings.Repeat("s", 65)}} {
		_, err := s.Query(q)
		require.Error(t, err)
	}
	for _, level := range []string{"debug", "info", "warn", "error", ""} {
		page(t, s, Query{MinLevel: level})
	}
}

func TestByteBudgetOversizedRecordsAndNotificationDoNotBlock(t *testing.T) {
	s := NewWithOptions(Options{Capacity: 2, MaxBytes: 700})
	for range 10 {
		s.Append(Record{Message: strings.Repeat("x", 150)})
	}
	v := page(t, s, Query{})
	require.LessOrEqual(t, v.Bytes, 700)
	require.LessOrEqual(t, len(v.Records), 2)
	require.Greater(t, v.Dropped, uint64(0))
	attrs := map[string]any{}
	for i := range 100 {
		attrs[fmt.Sprintf("field%d", i)] = strings.Repeat("v", 2048)
	}
	s.Append(Record{Message: "large attributes", Attrs: attrs})
	v = page(t, s, Query{Tail: true, Limit: 1})
	require.Equal(t, true, v.Records[0].Attrs["truncated"])
	tiny := NewWithOptions(Options{MaxBytes: 1})
	tiny.Append(Record{Message: "cannot fit"})
	v = page(t, tiny, Query{})
	require.Empty(t, v.Records)
	require.Equal(t, uint64(1), v.Dropped)
	require.True(t, v.Gap)
	defaults := NewWithOptions(Options{Capacity: 2000, MaxBytes: 5 << 20})
	require.Equal(t, DefaultCapacity, page(t, defaults, Query{}).Capacity)
	var empty *Store
	empty.Append(Record{})
}

func TestSecretsAreRemovedFromMessagesAttributesAndForwardedOutput(t *testing.T) {
	var output bytes.Buffer
	s := New()
	logger := slog.New(s.Handler(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}), "management")).With("service", "kone")
	logger.WithGroup("request").Error("upstream https://alice:s3cret@proxy.example/?token=private-token",
		"password", "dont-show", "authorization", "Bearer aaa.bbb.ccc", "cookie", "session=private-cookie",
		"nested", map[string]any{"access_token": "private-access", "url": "socks5://bob:password@localhost:1080", "safe": "visible"},
		"error", errors.New("Authorization: Bearer hidden-auth\npassword='hidden value'"))
	v := page(t, s, Query{})
	require.Len(t, v.Records, 1)
	require.Equal(t, "kone", v.Records[0].Attrs["service"], "With attributes retain their original group")
	encoded, err := json.Marshal(v)
	require.NoError(t, err)
	combined := string(encoded) + output.String()
	for _, secret := range []string{"alice", "s3cret", "private-token", "dont-show", "aaa.bbb.ccc", "private-cookie", "private-access", "bob:password", "hidden-auth", "hidden value"} {
		require.NotContains(t, combined, secret)
	}
	require.Contains(t, combined, "visible")
	require.Contains(t, combined, "[redacted]")
	for _, text := range []string{"token=one&password=two", "https://user:pass@example.test/path", "Basic c2VjcmV0", "Cookie: session=hidden"} {
		require.Contains(t, RedactText(text), "[redacted]")
	}
	require.Equal(t, "[log text exceeded limit]", RedactText("http://user:"+strings.Repeat("secret", 2000)+"@host"))
}

func TestDynamicAttributeKeysAndQuotedJSONCredentialsAreRedacted(t *testing.T) {
	s := New()
	urlKey := "https://alice:key-password@example.invalid"
	s.Append(Record{Message: `{"password":"hunter2","token":"private-token","database_password":"prefix-secret","password2":"escaped\"tail-secret"}`, Attrs: map[string]any{
		urlKey:   "value",
		"nested": map[string]any{urlKey: "value"},
		"group":  slog.GroupValue(slog.String(urlKey, "value")),
		"struct": struct {
			Value string `json:"https://alice:key-password@example.invalid"`
		}{Value: "value"},
	}})
	for _, message := range []string{`{"Cookie":"session=private-cookie"}`, `{"Authorization":"Bearer hidden-auth"}`, `{'password':'single-secret'}`, `{"password":"a\\b\\\"escaped-secret"}`} {
		s.Append(Record{Message: message})
	}
	data, err := json.Marshal(page(t, s, Query{}))
	require.NoError(t, err)
	for _, secret := range []string{"alice", "key-password", "hunter2", "private-token", "prefix-secret", "tail-secret", "private-cookie", "hidden-auth", "single-secret", "escaped-secret"} {
		require.NotContains(t, string(data), secret)
	}
	require.Contains(t, string(data), "[redacted]")
}

type panicError struct{}

func (panicError) Error() string { panic("must not crash logging") }

type brokenValuer struct{}

func (brokenValuer) LogValue() slog.Value { panic("slog resolves panic") }

type testValue struct {
	Password string
	Public   string `json:"public"`
	Hidden   string `json:"-"`
	hidden   string
}

func TestUntrustedValuesHaveDepthWidthTextAndTypeBounds(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	wide := map[string]any{}
	for i := range 40 {
		wide[fmt.Sprint(i)] = i
	}
	largeGroups := []slog.Attr{}
	for i := range 40 {
		largeGroups = append(largeGroups, slog.Int(fmt.Sprint(i), i))
	}
	values := map[string]any{
		"nil": nil, "bool": true, "int": int64(-4), "uint": uint64(8), "float": 1.5, "nan": math.NaN(), "inf": math.Inf(1),
		"duration": slog.DurationValue(time.Second), "time": time.Unix(4, 0), "slogtime": slog.TimeValue(time.Unix(5, 0)),
		"slice": make([]int, 40), "map": wide, "wrongmap": map[int]int{1: 2}, "cycle": cycle,
		"struct":  testValue{Password: "privatepass", Public: "ok", Hidden: "hidden", hidden: "hidden"},
		"channel": make(chan int), "pointer": (*int)(nil), "panic": panicError{},
		"group": slog.GroupValue(largeGroups...), "broken": slog.AnyValue(brokenValuer{}),
		strings.Repeat("x", 129): "must-hide",
	}
	s := New()
	s.Append(Record{Message: "values", Time: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), Attrs: values})
	data, err := json.Marshal(page(t, s, Query{}))
	require.NoError(t, err)
	require.NotContains(t, string(data), "privatepass")
	require.NotContains(t, string(data), "must-hide")
	require.Contains(t, string(data), "[redacted]")
	require.Less(t, len(data), MaxRecordBytes)
	// A large group chain cannot build an unbounded handler or expose its value.
	logger := slog.New(s.Handler(nil, "management"))
	for range 20 {
		logger = logger.WithGroup("group")
	}
	logger.Info("bounded", "value", "group-secret")
	groupData, err := json.Marshal(page(t, s, Query{Tail: true, Limit: 1}).Records[0].Attrs)
	require.NoError(t, err)
	require.NotContains(t, string(groupData), "group-secret")
	_, err = s.Writer("desktop").Write([]byte("password=stderr-secret\nsecond line\n"))
	require.NoError(t, err)
	_, err = s.Writer("desktop").Write(nil)
	require.NoError(t, err)
	_, err = s.Writer("desktop").Write(bytes.Repeat([]byte("x"), MaxRecordBytes+1))
	require.NoError(t, err)
	data, err = json.Marshal(page(t, s, Query{Source: "desktop"}))
	require.NoError(t, err)
	require.NotContains(t, string(data), "stderr-secret")
}

type failingHandler struct{}

func (failingHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (failingHandler) Handle(context.Context, slog.Record) error { return errors.New("sink failed") }
func (failingHandler) WithAttrs([]slog.Attr) slog.Handler        { return failingHandler{} }
func (failingHandler) WithGroup(string) slog.Handler             { return failingHandler{} }

func TestLevelReconfigurationInstancesAndSinkFailures(t *testing.T) {
	s := New()
	other := New()
	level := new(slog.LevelVar)
	level.Set(slog.LevelWarn)
	h := s.Handler(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: level}), "management")
	logger := slog.New(h.WithGroup("")).With("before", "saved")
	logger.Info("hidden")
	logger.Warn("visible")
	level.Set(slog.LevelDebug)
	logger.Debug("new level")
	require.Len(t, page(t, s, Query{}).Records, 2)
	require.Empty(t, page(t, other, Query{}).Records)
	attrs := []slog.Attr{}
	for i := range 50 {
		attrs = append(attrs, slog.Int(fmt.Sprint(i), i))
	}
	slog.New(s.Handler(nil, "local").WithAttrs(attrs)).Info("bounded attributes")
	require.LessOrEqual(t, len(page(t, s, Query{Tail: true, Limit: 1}).Records[0].Attrs), 32)
	err := s.Handler(failingHandler{}, "local").Handle(t.Context(), slog.NewRecord(time.Now(), slog.LevelError, "retained despite sink failure", 0))
	require.Error(t, err)
	require.Equal(t, "retained despite sink failure", page(t, s, Query{Tail: true, Limit: 1}).Records[0].Message)
}

func TestConcurrentAppendAndCursorReadsRemainBounded(t *testing.T) {
	s := NewWithOptions(Options{Capacity: 50, MaxBytes: 16 << 10})
	var workers sync.WaitGroup
	for worker := range 8 {
		workers.Go(func() {
			for i := range 120 {
				slog.New(s.Handler(nil, "worker")).Info("parallel", "worker", worker, "i", i)
				v, err := s.Query(Query{Tail: true, Limit: 10})
				if err != nil || len(v.Records) > 10 {
					t.Errorf("invalid snapshot: %v", err)
				}
			}
		})
	}
	workers.Wait()
	v := page(t, s, Query{})
	require.LessOrEqual(t, len(v.Records), 50)
	require.LessOrEqual(t, v.Bytes, 16<<10)
	for i := 1; i < len(v.Records); i++ {
		require.Greater(t, v.Records[i].ID, v.Records[i-1].ID)
	}
}
