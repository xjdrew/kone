package proxy

import (
	"net"
	"time"
)

type direct struct{}

// Direct is a direct proxy: one that makes network connections directly.
var Direct = direct{}

func (direct) Dial(network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 30 * time.Second}).Dial(network, addr)
}
