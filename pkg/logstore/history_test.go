package logstore

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHistoryBeforeUsesMatchingOlderRecordsAndInclusiveTimeBounds(t *testing.T) {
	s := New()
	start := time.Date(2025, 1, 1, 0, 0, 0, 123456789, time.UTC)
	for i, record := range []Record{
		{Level: "ERROR", Source: "helper"}, {Level: "DEBUG", Source: "helper"},
		{Level: "ERROR", Source: "management"}, {Level: "ERROR", Source: "helper"},
		{Level: "INFO", Source: "helper"}, {Level: "ERROR", Source: "helper"},
		{Level: "ERROR", Source: "helper"}, {Level: "INFO", Source: "management"},
	} {
		record.Time = start.Add(time.Duration(i) * time.Second)
		s.Append(record)
	}
	ids := func(value Page) []uint64 {
		result := []uint64{}
		for _, record := range value.Records {
			result = append(result, record.ID)
		}
		return result
	}
	query := Query{Tail: true, Limit: 2, MinLevel: "error", Source: "helper"}
	latest := page(t, s, query)
	require.Equal(t, []uint64{6, 7}, ids(latest))
	require.True(t, latest.HasMore)
	require.Equal(t, uint64(8), latest.NextCursor)
	require.Equal(t, uint64(1), latest.OldestCursor)
	query.Before = latest.Records[0].ID
	older := page(t, s, query)
	require.Equal(t, []uint64{1, 4}, ids(older))
	require.False(t, older.HasMore, "unmatched retained records are not additional history")
	require.Equal(t, uint64(8), older.NextCursor, "history does not replace the live after cursor")
	query.Before = 7
	query.From, query.To = start.Add(3*time.Second), start.Add(5*time.Second)
	query.Limit = 1
	bounded := page(t, s, query)
	require.Equal(t, []uint64{6}, ids(bounded))
	require.True(t, bounded.HasMore)
	query.Before = 6
	bounded = page(t, s, query)
	require.Equal(t, []uint64{4}, ids(bounded))
	require.False(t, bounded.HasMore)
	query.From, query.To = start.Add(3*time.Second), start.Add(3*time.Second)
	require.Equal(t, []uint64{4}, ids(page(t, s, query)), "time endpoints are inclusive at nanosecond precision")
	query.Before = 1
	require.Empty(t, page(t, s, query).Records)
	s.Append(Record{Level: "ERROR", Source: "helper", Time: start.Add(8 * time.Second)})
	require.Equal(t, []uint64{9}, ids(page(t, s, Query{After: latest.NextCursor})))
	require.Equal(t, []uint64{1, 4}, ids(page(t, s, Query{Before: 6, Limit: 2, MinLevel: "error", Source: "helper"})), "new live records do not move a history boundary")
	for _, invalid := range []Query{{After: 1, Before: 2}, {From: start.Add(time.Second), To: start}} {
		_, err := s.Query(invalid)
		require.Error(t, err)
	}
}

func TestHistoryRetentionAndForwardCursorKeepTheirExistingMeanings(t *testing.T) {
	s := NewWithOptions(Options{Capacity: 3})
	start := time.Now()
	for i := range 5 {
		s.Append(Record{Level: "INFO", Source: "helper", Time: start.Add(time.Duration(i) * time.Second)})
	}
	older := page(t, s, Query{Before: 5, Limit: 1})
	require.Equal(t, uint64(4), older.Records[0].ID)
	require.True(t, older.HasMore)
	require.Equal(t, uint64(3), older.OldestCursor)
	require.Equal(t, uint64(2), older.Dropped)
	require.True(t, older.Gap)
	final := page(t, s, Query{Before: 4, Limit: 1})
	require.Equal(t, uint64(3), final.Records[0].ID)
	require.False(t, final.HasMore)
	require.Empty(t, page(t, s, Query{Before: 3}).Records)
	forward := page(t, s, Query{After: 3, Limit: 1, To: start.Add(3 * time.Second)})
	require.Equal(t, uint64(4), forward.NextCursor)
	require.True(t, forward.HasMore, "after retains the existing unscanned-buffer contract")
	forward = page(t, s, Query{After: forward.NextCursor, To: start.Add(3 * time.Second)})
	require.Empty(t, forward.Records)
	require.Equal(t, uint64(5), forward.NextCursor)
	require.False(t, forward.HasMore)
}
