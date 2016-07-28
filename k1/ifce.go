//
//   date  : 2016-05-13
//   author: xjdrew
//

package k1

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

var MTU = 1500

func execCommand(name, sargs string) error {
	args := strings.Split(sargs, " ")
	cmd := exec.Command(name, args...)
	logger.Infof("exec command: %s %s", name, sargs)
	return cmd.Run()
}

func createTun(name string, ip net.IP, mask net.IPMask) (ifce *water.Interface, err error) {
	ifce, err = water.NewTUN(name)
	if err != nil {
		return
	}

	logger.Infof("create %s", ifce.Name())

	// set ip
	ipNet := &net.IPNet{
		IP:   ip,
		Mask: mask,
	}
	sargs := fmt.Sprintf("addr add %s dev %s", ipNet, ifce.Name())
	err = execCommand("ip", sargs)
	if err != nil {
		return
	}

	// brings the link up
	sargs = fmt.Sprintf("link set dev %s up mtu %d qlen 1000", ifce.Name(), MTU)
	err = execCommand("ip", sargs)
	if err != nil {
		return
	}
	return
}

func addRoute(name string, subnet *net.IPNet) error {
	sargs := fmt.Sprintf("route add %s dev %s", subnet, name)
	return execCommand("ip", sargs)
}
