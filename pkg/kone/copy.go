package kone

import (
	"io"
	"net"
)

type copied struct {
	upload bool
	bytes  int64
}

func relayConnections(left, right net.Conn) (upload, download int64) {
	results := make(chan copied, 2)
	copyDirection := func(dst, src net.Conn, up bool) {
		n, err := io.Copy(dst, src)
		if err != nil {
			left.Close()
			right.Close()
		} else if half, ok := dst.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		} else {
			dst.Close()
		}
		results <- copied{up, n}
	}
	go copyDirection(right, left, true)
	go copyDirection(left, right, false)
	for range 2 {
		result := <-results
		if result.upload {
			upload = result.bytes
		} else {
			download = result.bytes
		}
	}
	return
}
