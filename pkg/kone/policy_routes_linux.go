package kone

import (
	"net/netip"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func systemPolicyRoutes() ([]policyRoute, error) {
	entries, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	routes := make([]policyRoute, 0, len(entries))
	for _, entry := range entries {
		if entry.LinkIndex == 0 || entry.Type != unix.RTN_UNICAST {
			continue
		}
		prefix := netip.MustParsePrefix("0.0.0.0/0")
		if entry.Family == netlink.FAMILY_V6 {
			prefix = netip.MustParsePrefix("::/0")
		}
		if entry.Dst != nil {
			address, ok := netip.AddrFromSlice(entry.Dst.IP)
			if !ok {
				continue
			}
			bits, _ := entry.Dst.Mask.Size()
			prefix = netip.PrefixFrom(address.Unmap(), bits).Masked()
		}
		routes = append(routes, policyRoute{Prefix: prefix, Interface: entry.LinkIndex, Metric: uint32(max(entry.Priority, 0)), Gateway: entry.Gw.String()})
	}
	return routes, nil
}
