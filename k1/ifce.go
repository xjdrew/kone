//
//   date  : 2017-07-14
//   author: xjdrew
//

package k1

import (
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

func createTun(name string, ip net.IP, mask net.IPMask) (*water.Interface, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, err
	}

	logger.Infof("create %s", ifce.Name())

	ipNet := &net.IPNet{
		IP:   ip,
		Mask: mask,
	}

	if err := initTun(ifce.Name(), ipNet, MTU); err != nil {
		return nil, err
	}
	return ifce, nil
}
