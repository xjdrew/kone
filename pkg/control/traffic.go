package control

// gob-based helper RPC can decode an empty slice as nil. JSON collection fields
// must remain arrays whether capture runs in-process or through a helper.
func jsonArray[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}
