package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/logstore"
)

type logStatusSource struct {
	CaptureData
	status logstore.RemoteStatus
}

func (s logStatusSource) LogStatus() logstore.RemoteStatus { return s.status }

func TestRuntimeLogsAuthorizationLatestPageAndIncrementalQueries(t *testing.T) {
	store := logstore.New()
	c := testController(t, Options{LogStore: store})
	for i := range 5 {
		store.Append(logstore.Record{Level: "INFO", Source: "management", Message: fmt.Sprint(i)})
	}
	require.Equal(t, 401, request(t, c, "", "GET", "/api/v1/logs", nil).Code)
	pair, err := c.pair("read")
	require.NoError(t, err)
	token, session, err := c.claim("", pair.Code, true)
	require.NoError(t, err)
	read := func(path string) runtimeLogs {
		response := request(t, c, token, "GET", path, nil)
		require.Equal(t, 200, response.Code, response.Body.String())
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		var logs runtimeLogs
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &logs))
		return logs
	}
	latest := read("/api/v1/logs?limit=2")
	require.Len(t, latest.Records, 2)
	require.Equal(t, uint64(4), latest.Records[0].ID)
	require.Equal(t, uint64(5), latest.NextCursor)
	first := read("/api/v1/logs?after=0&limit=2")
	require.Equal(t, uint64(1), first.Records[0].ID)
	require.True(t, first.HasMore)
	next := read(fmt.Sprintf("/api/v1/logs?after=%d&limit=2", first.NextCursor))
	require.Equal(t, uint64(3), next.Records[0].ID)
	require.Empty(t, read("/api/v1/logs?after=5").Records)
	require.Empty(t, read("/api/v1/logs?min_level=error&source=helper").Records)
	c.mu.Lock()
	c.dataSource = logStatusSource{status: logstore.RemoteStatus{Dropped: 7, Error: "helper disconnected"}}
	c.mu.Unlock()
	require.Equal(t, uint64(7), read("/api/v1/logs").Helper.Dropped)
	require.False(t, read("/api/v1/logs").Helper.Connected)
	require.Equal(t, 403, request(t, c, token, "POST", "/api/v1/logs", nil).Code, "read-only never grants a mutation endpoint")
	require.True(t, c.revoke(session.ID))
	require.Equal(t, 401, request(t, c, token, "GET", "/api/v1/logs", nil).Code)
}

func TestRuntimeLogQueryBoundsAndEarlyCaptureFailureAreExplicit(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	for _, query := range []string{"after=-1", "after=x", "after=18446744073709551616", "limit=0", "limit=-1", "limit=201", "limit=bad", "after=1&after=2", "unknown=true", "min_level=trace", "source=" + strings.Repeat("x", 65), "source=" + strings.Repeat("x", 1025)} {
		response := request(t, c, token, "GET", "/api/v1/logs?"+query, nil)
		require.Equal(t, 400, response.Code, query)
	}
	err := c.Start(context.Background())
	require.ErrorContains(t, err, "enable the TUN inbound")
	require.Contains(t, c.State().LastError, "enable the TUN inbound")
	require.Equal(t, "ready", c.State().ControlState)
	response := request(t, c, token, "GET", "/api/v1/logs", nil)
	require.Equal(t, 200, response.Code)
	var logs runtimeLogs
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &logs))
	require.Equal(t, "Capture startup failed", logs.Records[len(logs.Records)-1].Message)
	require.Equal(t, "ERROR", logs.Records[len(logs.Records)-1].Level)
	require.False(t, c.doc.Inbound.Enabled, "logging must not enable capture")
}
