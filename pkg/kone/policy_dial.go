package kone

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"

	"github.com/sagernet/sing/common/control"
)

type policyRoute struct {
	Prefix    netip.Prefix
	Interface int
	Metric    uint32
	Gateway   string
}
type routeNode struct {
	children [2]int
	device   int
}
type routeIndex struct{ nodes []routeNode }

func newRouteIndex(routes []policyRoute) *routeIndex {
	index := &routeIndex{nodes: make([]routeNode, 3)} // zero is absent, 1 IPv4, 2 IPv6
	// The lowest metric wins when several routes have the same prefix.
	slices.SortStableFunc(routes, func(a, b policyRoute) int {
		if a.Metric < b.Metric {
			return 1
		}
		if a.Metric > b.Metric {
			return -1
		}
		return 0
	})
	for _, route := range routes {
		if route.Prefix.Addr().Is4In6() {
			if route.Prefix.Bits() <= 96 {
				continue // Covers all IPv4 addresses; retain the physical default.
			}
			route.Prefix = netip.PrefixFrom(route.Prefix.Addr().Unmap(), route.Prefix.Bits()-96)
		}
		address := route.Prefix.Addr().Unmap()
		if !route.Prefix.IsValid() || route.Prefix.Bits() == 0 {
			continue
		}
		root, offset := 2, 0
		if address.Is4() {
			root, offset = 1, 96
		}
		bytes := address.As16()
		for bit := 0; bit < route.Prefix.Bits(); bit++ {
			direction := int((bytes[(bit+offset)/8] >> (7 - (bit+offset)%8)) & 1)
			next := index.nodes[root].children[direction]
			if next == 0 {
				next = len(index.nodes)
				index.nodes = append(index.nodes, routeNode{})
				index.nodes[root].children[direction] = next
			}
			root = next
		}
		index.nodes[root].device = route.Interface
	}
	return index
}
func (index *routeIndex) device(address netip.Addr) int {
	address = address.Unmap()
	root, offset, bits := 2, 0, 128
	if address.Is4() {
		root, offset, bits = 1, 96, 32
	}
	bytes, selected := address.As16(), 0
	for bit := 0; bit < bits; bit++ {
		root = index.nodes[root].children[(bytes[(bit+offset)/8]>>(7-(bit+offset)%8))&1]
		if root == 0 {
			break
		}
		if index.nodes[root].device != 0 {
			selected = index.nodes[root].device
		}
	}
	return selected
}

// Snapshot native routes before capture. Direct LAN/VPN connections use their
// real route's interface; proxy transports keep the explicit physical uplink.
// Lookups allocate nothing and are bounded by address width, not table size.
func policyDirectDialer(base *net.Dialer, cfg *KoneConfig) (*net.Dialer, error) {
	if cfg.Policy.Mode == "" || cfg.Policy.Mode == "custom" {
		return nil, nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("inspect policy interfaces: %w", err)
	}
	devices := map[int]net.Interface{}
	hosts := map[netip.Addr]bool{}
	for _, device := range interfaces {
		if device.Flags&net.FlagUp == 0 || device.Name == cfg.Core.Tun {
			continue
		}
		devices[device.Index] = device
		addresses, err := device.Addrs()
		if err != nil {
			return nil, fmt.Errorf("inspect policy addresses: %w", err)
		}
		for _, address := range addresses {
			if prefix, err := netip.ParsePrefix(address.String()); err == nil {
				hosts[prefix.Addr().Unmap()] = true
			}
		}
	}
	routes, err := systemPolicyRoutes()
	if err != nil {
		return nil, fmt.Errorf("inspect LAN/VPN routing before capture: %w", err)
	}
	if len(routes) > 16384 {
		return nil, fmt.Errorf("policy route table exceeds 16384 entries")
	}
	routes = slices.DeleteFunc(routes, func(route policyRoute) bool {
		_, exists := devices[route.Interface]
		return !exists || isSyntheticPrefix(route.Prefix, cfg.Core)
	})
	index := newRouteIndex(routes)
	dialer := *base
	dialer.Control = func(network, address string, connection syscall.RawConn) error {
		host, _, _ := net.SplitHostPort(address)
		ip, err := netip.ParseAddr(host)
		if err == nil {
			if ip.IsLoopback() || hosts[ip.Unmap()] {
				return nil
			}
			if device, exists := devices[index.device(ip)]; exists {
				return control.BindToInterface0(nil, connection, network, address, device.Name, device.Index, false)
			}
		}
		if base.Control != nil {
			return base.Control(network, address, connection)
		}
		return nil
	}
	return &dialer, nil
}

// PolicyRouteSnapshot reads both address families, including non-default VPN
// routes. The caller hashes this bounded metadata; no traffic is probed.
func PolicyRouteSnapshot(ownedTunName string) ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	devices := make(map[int]string, len(interfaces))
	for _, device := range interfaces {
		if device.Name != ownedTunName {
			devices[device.Index] = device.Name
		}
	}
	routes, err := systemPolicyRoutes()
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(routes))
	for _, route := range routes {
		if name, ok := devices[route.Interface]; ok {
			result = append(result, fmt.Sprintf("%s %s %d %s", name, route.Prefix, route.Metric, route.Gateway))
		}
	}
	return result, nil
}
