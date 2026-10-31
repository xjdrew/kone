//go:build !with_gvisor

package kone

import (
	"errors"
	singtun "github.com/sagernet/sing-tun"
)

func stackTun(t *supervisedTun, kind string) (singtun.Tun, error) {
	if kind == "mixed" {
		return nil, errors.New("mixed stack requires a build with -tags with_gvisor")
	}
	return t, nil
}
