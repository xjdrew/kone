package kone

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// DetailOff still includes independent business counters. These benchmarks
// measure observer CPU/allocation overhead, not TUN throughput or proxy RTT.
func BenchmarkObservationIncrement(b *testing.B) {
	for _, protocol := range []string{"tcp", "udp"} {
		for _, recording := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/Detail%v", protocol, recording), func(b *testing.B) {
				observer := NewTrafficObserver(ObservationOptions{Capacity: 512, PathCapacity: 128})
				observer.SetRecording(recording)
				packets := uint64(0)
				if protocol == "udp" {
					packets = 1
				}
				b.SetBytes(2920)
				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					flow := observer.Begin(FlowRecord{Protocol: protocol, Source: "192.0.2.1:1234", Target: "example.com:443"})
					flow.Decision(RoutingDecision{RuleID: "r1", Outbound: BuiltinDirect}, BuiltinDirect, "", true)
					for pb.Next() {
						flow.AddUpload(1460, packets)
						flow.AddDownload(1460, packets)
					}
					flow.Finish(nil, false)
				})
			})
		}
	}
}

func BenchmarkObservationSession(b *testing.B) {
	for _, protocol := range []string{"tcp", "udp"} {
		for _, recording := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/Detail%v", protocol, recording), func(b *testing.B) {
				observer := NewTrafficObserver(ObservationOptions{Capacity: 512, PathCapacity: 128})
				observer.SetRecording(recording)
				packets := uint64(0)
				if protocol == "udp" {
					packets = 1
				}
				b.SetBytes(2920)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					flow := observer.Begin(FlowRecord{Protocol: protocol, Source: "192.0.2.1:1234", Target: "example.com:443"})
					flow.Decision(RoutingDecision{RuleID: "r1", Outbound: BuiltinDirect}, BuiltinDirect, "", true)
					flow.AddUpload(1460, packets)
					flow.AddDownload(1460, packets)
					flow.Finish(nil, false)
				}
			})
		}
	}
}

func benchmarkObservedPopulation() (*TrafficObserver, []*ObservedFlow) {
	var seconds atomic.Int64
	seconds.Store(1000)
	observer := NewTrafficObserver(ObservationOptions{Capacity: 2048, PathCapacity: 512, Now: func() time.Time { return time.Unix(seconds.Load(), 0) }})
	var active []*ObservedFlow
	for index := range 2048 {
		flow := observer.Begin(FlowRecord{Protocol: []string{"tcp", "udp"}[index%2], Source: "192.0.2.1:1234", Target: fmt.Sprintf("target-%d.example:443", index%128)})
		flow.Decision(RoutingDecision{RuleID: fmt.Sprintf("r%d", index%8), Outbound: BuiltinDirect}, BuiltinDirect, "", true)
		flow.AddUpload(1460, 1)
		flow.AddDownload(2920, 1)
		if index < 128 {
			active = append(active, flow)
		} else {
			flow.Finish(nil, false)
		}
	}
	seconds.Store(1001)
	return observer, active
}

func BenchmarkObservationQueries(b *testing.B) {
	for _, kind := range []string{"Snapshot", "Sankey"} {
		for _, updates := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/ActiveUpdates%v", kind, updates), func(b *testing.B) {
				observer, active := benchmarkObservedPopulation()
				var stop atomic.Bool
				var workers sync.WaitGroup
				if updates {
					for worker := range 2 {
						workers.Add(1)
						go func(offset int) {
							defer workers.Done()
							index := offset
							for !stop.Load() {
								flow := active[index%len(active)]
								flow.AddUpload(1460, 1)
								flow.AddDownload(1460, 1)
								index += 2
							}
						}(worker)
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if kind == "Snapshot" {
						value := observer.Snapshot(TrafficQuery{Limit: 100})
						runtime.KeepAlive(value)
					} else {
						value := observer.Sankey(TrafficQuery{}, SankeyOptions{Window: 5 * time.Second, Limit: 20})
						runtime.KeepAlive(value)
					}
				}
				b.StopTimer()
				stop.Store(true)
				workers.Wait()
				for _, flow := range active {
					flow.Finish(nil, false)
				}
			})
		}
	}
}

func BenchmarkObservationBoundedLoad(b *testing.B) {
	observer := NewTrafficObserver(ObservationOptions{Capacity: 512, PathCapacity: 128})
	b.ReportAllocs()
	b.ResetTimer()
	for index := range b.N {
		flow := observer.Begin(FlowRecord{Protocol: "udp", Target: fmt.Sprintf("target-%d.example:443", index%4096)})
		flow.Decision(RoutingDecision{RuleID: "r1", Outbound: BuiltinDirect}, BuiltinDirect, "", true)
		flow.AddUpload(512, 1)
		flow.Finish(nil, false)
		if index%64 == 0 {
			value := observer.Snapshot(TrafficQuery{Limit: 20})
			runtime.KeepAlive(value)
		}
	}
	b.StopTimer()
	if len(observer.records) > 512 || len(observer.paths) > 129 {
		b.Fatal("observer exceeded configured detail/path bounds")
	}
	b.ReportMetric(float64(len(observer.records)), "retained_records")
	b.ReportMetric(float64(len(observer.paths)), "retained_paths")
}
