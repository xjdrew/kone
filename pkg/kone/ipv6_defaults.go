package kone

// DefaultIPv6Network is the owned TUN gateway in the default Fake-IP subnet.
// Synthetic AAAA and proxying over an IPv4 transport do not require a native
// IPv6 uplink; physical reachability remains a separate runtime concern.
func DefaultIPv6Network() string {
	if !SupportsIPv6Capture() {
		return ""
	}
	return "fd00:10:192::1/64"
}
