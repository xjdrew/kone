package kone

// freezeObservation runs only after flow admission, workers and protocol stacks
// have stopped. UI graph pause and recording preferences do not call this hook.
func (one *One) freezeObservation() { one.TrafficObserver().freeze() }

func (observer *TrafficObserver) freeze() {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if observer.frozenAt.IsZero() {
		observer.frozenAt = observer.now()
	}
}

// Data reads table, counters and graph under the same observation lock and clock.
// Their anchor and payload totals therefore describe one coherent point in time.
func (observer *TrafficObserver) Data(query TrafficQuery, options SankeyOptions) (TrafficSnapshot, SankeySnapshot) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	now := observer.now()
	return observer.snapshotLocked(query, now), observer.sankeyLocked(query, options, now)
}

func (one *One) GeoIPData() (GeoIPRuntimeStatus, error) { return one.GeoIPStatus(), nil }

func (one *One) TrafficData(query TrafficQuery, options SankeyOptions) (TrafficSnapshot, SankeySnapshot, error) {
	observer := one.TrafficObserver()
	traffic, graph := observer.Data(query, options)
	return traffic, graph, nil
}
func (one *One) FlowRecord(id string) (FlowRecord, bool, error) {
	record, ok := one.TrafficObserver().Get(id)
	return record, ok, nil
}
func (one *One) DNSData() (DNSRuntimeStatus, []DNSQueryEvent, error) {
	return one.DNSStatus(), one.DNSQueries(), nil
}
func (one *One) ClearObservation() error {
	one.TrafficObserver().Clear()
	one.ClearDNSQueries()
	one.ClearDNSCache()
	return nil
}
