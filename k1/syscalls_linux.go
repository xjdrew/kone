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
	sargs := fmt.Sprintf("addr add %s dev %s", ipNet, tun)
	if err := execCommand("ip", sargs); err != nil {
		return err
	}

	// brings the link up
	sargs = fmt.Sprintf("link set dev %s up mtu %d qlen 1000", tun, mtu)
	return execCommand("ip", sargs)
}

func addRoute(tun string, subnet *net.IPNet) error {
	sargs := fmt.Sprintf("route add %s dev %s", subnet, name)
	return execCommand("ip", sargs)
}
