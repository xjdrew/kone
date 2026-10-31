package control

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestCoreCaptureSnapshotsRemainConsistentThroughHTTPAndClear(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	one, err := kone.FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	c.dataSource = one
	flow := one.TrafficObserver().Begin(kone.FlowRecord{ConfigVersion: 7, Inbound: "tun", Protocol: "tcp", Source: "127.0.0.1:50000", Destination: "192.0.2.1:443", Target: "fixture.example:443"})
	flow.Decision(kone.RoutingDecision{RuleID: "fixture", Outbound: "direct"}, "direct", "192.0.2.1:443", true)
	flow.AddUpload(128, 0)
	flow.AddDownload(64, 0)
	flow.Finish(nil, false)
	response := request(t, c, token, "GET", "/api/v1/traffic?metric=cumulative", nil)
	require.Equal(t, 200, response.Code, response.Body.String())
	var value struct {
		Traffic kone.TrafficSnapshot `json:"traffic"`
		Sankey  kone.SankeySnapshot  `json:"sankey"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &value))
	require.Len(t, value.Traffic.Records, 1)
	require.Equal(t, "fixture.example:443", value.Traffic.Records[0].Target)
	require.Equal(t, value.Traffic.Timestamp, value.Sankey.Timestamp)
	require.Equal(t, 200, request(t, c, token, "GET", "/api/v1/flows/"+flow.ID(), nil).Code)
	require.Equal(t, 200, request(t, c, token, "GET", "/api/v1/flows?protocol=tcp", nil).Code)
	require.Equal(t, 200, request(t, c, token, "GET", "/api/v1/dns", nil).Code)
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/privacy/clear", nil).Code)
	require.Equal(t, 410, request(t, c, token, "GET", "/api/v1/flows/"+flow.ID(), nil).Code)
	response = request(t, c, token, "GET", "/api/v1/flows", nil)
	var cleared kone.TrafficSnapshot
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &cleared))
	require.Empty(t, cleared.Records)
	require.Equal(t, value.Traffic.Totals.Upload, cleared.Totals.Upload, "clearing detail does not reset independently accumulated payload")
	require.Equal(t, value.Traffic.Totals.Download, cleared.Totals.Download)
	require.Equal(t, value.Traffic.Totals.Started, cleared.Totals.Started)
}
