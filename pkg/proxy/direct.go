package proxy

import (
	"context"
	"net"
	"time"
)

type direct struct{}

// Direct is a direct proxy: one that makes network connections directly.
var Direct = direct{}

func (direct) Dial(network, addr string) (net.Conn, error) {
	return Direct.DialContext(context.Background(), network, addr)
}

func (direct) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, addr)
}
