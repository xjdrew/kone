package k1

import (
	"net"
)

type tcpForwarder struct {
	ln *net.TCPListener
}

func (f *tcpForwarder) GetAddr() (net.IP, uint16) {
	addr := f.ln.Addr().(*net.TCPAddr)
	return addr.IP, uint16(addr.Port)
}

/*
func (f *tcpForwarder) forward(src *net.TCPConn, dst *net.TCPConn) {
	defer dst.CloseWrite()
	defer src.CloseRead()

	io.Copy(dst, src)
}

func (f *tcpForwarder) handleConn(dialer proxy.Dialer, conn *net.TCPConn) {
	addr, err := realServerAddress(conn)
	if err != nil {
		conn.Close()
		log.Printf("get real target address failed:%s", err)
		return
	}

	tunnel, err := dialer.Dial("tcp", addr)
	if err != nil {
		conn.Close()
		log.Printf("dial tunnel failed:%s", err)
		return
	}
	go forward(tunnel.(*net.TCPConn), conn)
	go forward(conn, tunnel.(*net.TCPConn))
}
*/

func (f *tcpForwarder) Start() {
	for {
		conn, err := f.ln.AcceptTCP()
		if err != nil {
			logger.Critical("accept failed: %v", err)
			return
		}
		logger.Infof("new connection from %s", conn.RemoteAddr())
	}
}

func newTcpForwarder(ip net.IP) (*tcpForwarder, error) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: ip})
	if err != nil {
		return nil, err
	}
	logger.Infof("listen on: %v", ln.Addr())

	f := &tcpForwarder{ln: ln}
	return f, nil
}
