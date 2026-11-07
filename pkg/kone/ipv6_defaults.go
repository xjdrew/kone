package kone

import (
	"fmt"
	"net"
	"net/netip"
)

// DefaultIPv6Network enables dual stack only when an active non-loopback
// interface has a usable unicast address. Link-local support alone is not an
// indication that real IPv6 destinations can be reached.
func DefaultIPv6Network() string {
	if !SupportsIPv6Capture() {
		return ""
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var occupied []netip.Prefix
	usable := false
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return ""
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
				continue
			}
			occupied = append(occupied, prefix.Masked())
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 && prefix.Addr().IsGlobalUnicast() {
				usable = true
			}
		}
	}
	return selectIPv6Network(usable, occupied)
}

func selectIPv6Network(usable bool, occupied []netip.Prefix) string {
	if !usable {
		return ""
	}
	for index := 0; index < 256; index++ {
		value := "fd7a:203::1/120"
		if index != 0 {
			value = fmt.Sprintf("fd7a:203:%x::1/120", index)
		}
		candidate := netip.MustParsePrefix(value)
		conflict := false
		for _, prefix := range occupied {
			if prefix.Overlaps(candidate) {
				conflict = true
				break
			}
		}
		if !conflict {
			return value
		}
	}
	return ""
}
