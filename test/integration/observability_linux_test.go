package integration

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xjdrew/kone/pkg/kone"
)

// Only the disposable native TUN jobs run this test. It verifies observations
// against real DNS -> Fake-IP -> TCP -> proxy bytes, never synthetic UI data.
func TestSystemLifecycleTrafficObservability(t *testing.T) {
	cfg := systemConfig(t)
	proxy := localConnectProxy(t, "observed payload")
	cfg.Outbounds = []kone.OutboundConfig{{Name: "monitor", URL: proxy.URL}}
	cfg.Rule = []kone.RuleConfig{{ID: "observed-rule", Schema: "DOMAIN", Pattern: "observed.example", Outbound: "monitor"}, {Schema: "FINAL", Outbound: kone.BuiltinDirect}}
	one, stop, done := systemStart(t, cfg)
	request := new(dns.Msg)
	request.SetQuestion("observed.example.", dns.TypeA)
	answer, _, err := (&dns.Client{Timeout: time.Second}).Exchange(request, fmt.Sprintf("10.203.0.1:%d", cfg.DNS.ListenPort))
	if err != nil || answer == nil || len(answer.Answer) != 1 {
		t.Fatalf("Fake-IP DNS failed: %v %v", answer, err)
	}
	fake := answer.Answer[0].(*dns.A).A.String()
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("http://" + fake + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "observed payload" {
		t.Fatalf("forwarded payload: %q %v", body, err)
	}
	var record kone.FlowRecord
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		snapshot := one.TrafficSnapshot(kone.TrafficQuery{Target: "observed.example"})
		if len(snapshot.Records) > 0 && snapshot.Records[0].EndedAt != nil {
			record = snapshot.Records[0]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if record.ID == "" || record.Upload == 0 || record.Download == 0 || record.RuleID != "observed-rule" || record.ExpectedOutbound != "monitor" || record.EffectiveOutbound != "monitor" || record.DomainSource != "fake-ip" {
		t.Fatalf("incomplete real flow observation: %+v", record)
	}
	if record.RealDestination != "" {
		t.Fatalf("proxy endpoint must not be invented as business destination: %s", record.RealDestination)
	}
	graph := one.TrafficObserver().Sankey(kone.TrafficQuery{}, kone.SankeyOptions{Metric: "cumulative"})
	if graph.Total != float64(record.Upload+record.Download) || len(graph.Paths) != 1 || !strings.Contains(graph.Paths[0].Target, "observed.example") {
		t.Fatalf("Sankey does not match real flow: %+v", graph)
	}
	updated := one.Snapshot().Config
	updated.Rule[0].Outbound = kone.BuiltinReject
	if err := one.Reload(updated); err != nil {
		t.Fatal(err)
	}
	if response, err := client.Get("http://" + fake + "/"); err == nil {
		response.Body.Close()
		t.Fatal("reject rule allowed TCP")
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		snapshot := one.TrafficSnapshot(kone.TrafficQuery{Status: "rejected", Target: "observed.example"})
		if len(snapshot.Records) > 0 {
			if snapshot.Records[0].Upload != 0 || snapshot.Records[0].Download != 0 {
				t.Fatal("zero-byte rejection manufactured traffic")
			}
			stop()
			if err := systemWait(t, done); err != nil {
				t.Fatal(err)
			}
			noSystemInterface(t, cfg)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("zero-byte rejection was not recorded")
}
