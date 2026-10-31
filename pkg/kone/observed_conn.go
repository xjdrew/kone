package kone

import (
	"io"
	"net"
)

// Count writes, not reads: these are payload bytes actually accepted by the
// opposite leg. The wrapper deliberately exposes neither ReaderFrom nor
// WriterTo, so splice/ReadFrom shortcuts cannot bypass accounting.
type observedConn struct {
	net.Conn
	flow   *ObservedFlow
	upload bool
}

func (c *observedConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if n > 0 {
		if c.upload {
			c.flow.AddUpload(uint64(n), 0)
		} else {
			c.flow.AddDownload(uint64(n), 0)
		}
	}
	if err != nil {
		c.flow.TransferError(err)
	}
	return n, err
}

func (c *observedConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if err != nil && err != io.EOF {
		c.flow.TransferError(err)
	}
	return n, err
}

func (c *observedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}
