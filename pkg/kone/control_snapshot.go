package kone

func (one *One) GeoIPData() (GeoIPRuntimeStatus, error) { return one.GeoIPStatus(), nil }

func (one *One) TrafficData(query TrafficQuery, options SankeyOptions) (TrafficSnapshot, SankeySnapshot, error) {
	observer := one.TrafficObserver()
	return observer.Snapshot(query), observer.Sankey(query, options), nil
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
