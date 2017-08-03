//
//   date  : 2017-07-20
//   author: xjdrew
//

package k1

import (
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

func execCommand(name, sargs string) error {
	args := strings.Split(sargs, " ")
	cmd := exec.Command(name, args...)
	logger.Infof("exec command: %s %s", name, sargs)
	return cmd.Run()
}

func addRoute(tun string, subnet *net.IPNet) error {
	return nil
}

func createTun(ip net.IP, mask net.IPMask) (*water.Interface, error) {
	ipNet := &net.IPNet{
		IP:   ip,
		Mask: mask,
	}

	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID: "tap0901",
			Network:     ipNet.String(),
		},
	})

	if err != nil {
		return nil, err
	}

	logger.Infof("create %s", ifce.Name())
	return ifce, nil
}

func fixTunIP(ip net.IP) net.IP {
	return ip
}
