package kone

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

func systemPolicyRoutes() ([]policyRoute, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	routes := make([]policyRoute, 0, table.NumEntries)
	for _, entry := range table.Rows() {
		var address netip.Addr
		switch entry.DestinationPrefix.Prefix.Family {
		case windows.AF_INET:
			address = netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(&entry.DestinationPrefix.Prefix)).Addr)
		case windows.AF_INET6:
			address = netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(&entry.DestinationPrefix.Prefix)).Addr)
		default:
			continue
		}
		routes = append(routes, policyRoute{Prefix: netip.PrefixFrom(address, int(entry.DestinationPrefix.PrefixLength)).Masked(), Interface: int(entry.InterfaceIndex), Metric: entry.Metric, Gateway: policyGateway(entry.NextHop)})
	}
	return routes, nil
}

func policyGateway(address windows.RawSockaddrInet) string {
	switch address.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(&address)).Addr).String()
	case windows.AF_INET6:
		return netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(&address)).Addr).String()
	}
	return ""
}
