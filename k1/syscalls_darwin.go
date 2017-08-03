//
//   date  : 2017-07-14
//   author: xjdrew
//

package k1

import (
	"fmt"
	"net"
)

func initTun(tun string, ipNet *net.IPNet, mtu int) error {
	ip := ipNet.IP
	maskIP := net.IP(ipNet.Mask)
	sargs := fmt.Sprintf("%s %s %s mtu %d netmask %s up", tun, ip.String(), ip.String(), mtu, maskIP.String())
	if err := execCommand("ifconfig", sargs); err != nil {
		return err
	}
	return addRoute(tun, ipNet)
}

func addRoute(tun string, subnet *net.IPNet) error {
	ip := subnet.IP
	maskIP := net.IP(subnet.Mask)
	sargs := fmt.Sprintf("-n add -net %s -netmask %s -interface %s", ip.String(), maskIP.String(), tun)
	return execCommand("route", sargs)
}

// can't listen on tun's ip in macosx
func fixTunIP(ip net.IP) net.IP {
	return net.IPv4zero
}
