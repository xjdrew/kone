package control

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

// Reproduce the actual helper codec, which does not retain empty slices.
type helperCaptureData struct{ *kone.One }

func (source helperCaptureData) TrafficData(query kone.TrafficQuery, options kone.SankeyOptions) (kone.TrafficSnapshot, kone.SankeySnapshot, error) {
	traffic, graph, err := source.One.TrafficData(query, options)
	if err != nil {
		return traffic, graph, err
	}
	type reply struct {
		Traffic kone.TrafficSnapshot
		Sankey  kone.SankeySnapshot
	}
	var wire bytes.Buffer
	if err = gob.NewEncoder(&wire).Encode(reply{traffic, graph}); err != nil {
		return traffic, graph, err
	}
	var decoded reply
	err = gob.NewDecoder(&wire).Decode(&decoded)
	return decoded.Traffic, decoded.Sankey, err
}

func TestCoreCaptureSnapshotsRemainConsistentThroughHTTPAndClear(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	one, err := kone.FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	c.dataSource = helperCaptureData{one}
	decodedTraffic, decodedGraph, err := c.dataSource.TrafficData(kone.TrafficQuery{}, kone.SankeyOptions{})
	require.NoError(t, err)
	require.Nil(t, decodedTraffic.Records)
	require.Nil(t, decodedGraph.Paths)
	empty := request(t, c, token, "GET", "/api/v1/traffic", nil)
	require.Equal(t, 200, empty.Code)
	var collections map[string]map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(empty.Body.Bytes(), &collections))
	for _, field := range []string{"nodes", "links", "paths"} {
		require.JSONEq(t, "[]", string(collections["sankey"][field]))
	}
	require.JSONEq(t, "[]", string(collections["traffic"]["records"]))
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
	require.NotNil(t, cleared.Records, "empty /flows collections must encode as arrays after helper RPC")
	require.Equal(t, value.Traffic.Totals.Upload, cleared.Totals.Upload, "clearing detail does not reset independently accumulated payload")
	require.Equal(t, value.Traffic.Totals.Download, cleared.Totals.Download)
	require.Equal(t, value.Traffic.Totals.Started, cleared.Totals.Started)
}
