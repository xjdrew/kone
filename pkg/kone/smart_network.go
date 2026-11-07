package kone

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Conservative automatic-probe scope. Manual diagnostics have a separate,
// explicitly user-selected target policy. IsGlobalUnicast alone includes many
// non-public and special-purpose networks.
var smartExcludedNetworks = func() []netip.Prefix {
	values := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.175.48.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	}
	result := make([]netip.Prefix, len(values))
	for i, v := range values {
		result[i] = netip.MustParsePrefix(v)
	}
	return result
}()

func smartPublicTarget(snapshot *runtimeSnapshot, ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range smartExcludedNetworks {
		if prefix.Contains(ip) {
			return false
		}
	}
	if diagnosticVirtualAddress(snapshot, ip) || snapshot.rule.protectedAddress(ip.String()) || snapshot.rule.directDomains[ip.String()] {
		return false
	}
	for _, prefix := range snapshot.rule.retired {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// Runs in the network owner, including CLI and privileged helper. No route or
// resolver mutation. Failure blocks automatic probes until the engine restarts.
func smartNetworkFingerprint(tun string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	values := []string{}
	for _, iface := range interfaces {
		if iface.Name == tun || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		values = append(values, iface.Name+":"+strconv.Itoa(iface.Index)+":"+iface.Flags.String())
		addresses, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, address := range addresses {
			values = append(values, iface.Name+":"+address.String())
		}
	}
	dnsContext, err := readDNSSystemContext()
	if err != nil || dnsContext.RequireManual {
		return "", errors.New("cannot inspect resolver scope context")
	}
	for _, server := range dnsContext.DefaultServers {
		values = append(values, "dns:"+server)
	}
	for _, suffix := range dnsContext.SearchDomains {
		values = append(values, "search:"+suffix)
	}
	for _, scope := range dnsContext.Scopes {
		if scope.Interface == tun {
			continue
		}
		servers := append([]string(nil), scope.Servers...)
		sort.Strings(servers)
		values = append(values, "scope:"+scope.Suffix+":"+scope.Interface+":"+strconv.FormatBool(scope.Exact)+":"+strconv.FormatBool(scope.Unavailable)+":"+strings.Join(servers, ","))
	}
	routes, err := PolicyRouteSnapshot(tun)
	if err != nil {
		return "", err
	}
	for _, route := range routes {
		values = append(values, "route:"+route)
	}
	sort.Strings(values)
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:]), nil
}
