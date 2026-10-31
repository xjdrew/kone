//go:build !linux

package ping

type identFilterState struct{}

func (c *Conn) updateIdentFilter(wireIdentifier uint16) {
}
