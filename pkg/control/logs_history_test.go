package control

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/logstore"
)

func TestRuntimeLogHistoryAndTimeFiltersAreReadOnlyAndValidated(t *testing.T) {
	store := logstore.New()
	c := testController(t, Options{LogStore: store})
	token := owner(t, c)
	initial, err := store.Query(logstore.Query{Tail: true})
	require.NoError(t, err)
	base := initial.NextCursor
	start := time.Date(2025, 1, 1, 0, 0, 0, 123456789, time.UTC)
	for i := range 6 {
		level := "ERROR"
		if i%2 == 1 {
			level = "INFO"
		}
		store.Append(logstore.Record{Time: start.Add(time.Duration(i) * time.Second), Level: level, Source: "helper", Message: fmt.Sprint(i)})
	}
	read := func(query string) runtimeLogs {
		response := request(t, c, token, "GET", "/api/v1/logs?"+query, nil)
		require.Equal(t, 200, response.Code, response.Body.String())
		var result runtimeLogs
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
		return result
	}
	filters := "source=helper&min_level=error&from=" + url.QueryEscape(start.Format(time.RFC3339Nano)) + "&to=" + url.QueryEscape(start.Add(4*time.Second).Format(time.RFC3339Nano))
	latest := read(filters + "&limit=1")
	require.Equal(t, base+5, latest.Records[0].ID)
	require.True(t, latest.HasMore)
	older := read(fmt.Sprintf("%s&before=%d&limit=2", filters, latest.Records[0].ID))
	require.Equal(t, []uint64{base + 1, base + 3}, []uint64{older.Records[0].ID, older.Records[1].ID})
	require.False(t, older.HasMore)
	require.Equal(t, base+6, older.NextCursor)
	for _, query := range []string{
		"before=0", "before=-1", "before=bad", "before=18446744073709551616", "before=2&after=0", "before=1&before=2",
		"from=bad", "from=", "to=bad", "from=2025-01-02T00:00:00Z&to=2025-01-01T00:00:00Z", "from=2025-01-01T00:00:00Z&from=2025-01-01T00:00:00Z", "to=2025-01-01T00:00:00Z&to=2025-01-01T00:00:00Z", "from=%zz",
	} {
		require.Equal(t, 400, request(t, c, token, "GET", "/api/v1/logs?"+query, nil).Code, query)
	}
	final, err := store.Query(logstore.Query{Tail: true})
	require.NoError(t, err)
	require.Equal(t, base+6, final.NextCursor, "reads and rejected query parameters never generate logs")
	require.Empty(t, c.Operations())
}

func TestUnchangedManagementPollingNeverAppendsRuntimeLogs(t *testing.T) {
	store := logstore.New()
	c := testController(t, Options{LogStore: store})
	token := owner(t, c)
	before, err := store.Query(logstore.Query{Tail: true})
	require.NoError(t, err)
	for range 3 {
		for _, endpoint := range []string{"state", "config", "traffic", "flows", "dns", "geoip", "outbounds/health", "operations", "logs"} {
			response := request(t, c, token, "GET", "/api/v1/"+endpoint, nil)
			require.Equal(t, 200, response.Code, endpoint+": "+response.Body.String())
		}
	}
	after, err := store.Query(logstore.Query{Tail: true})
	require.NoError(t, err)
	require.Equal(t, before.NextCursor, after.NextCursor)
	require.Equal(t, before.Dropped, after.Dropped)
	require.Empty(t, c.Operations())
}
