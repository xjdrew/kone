package main

import (
	"bufio"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/net/proxy"
)

var (
	cfgProxy  *url.URL
	cfgListen string = ":12345"
)

const SO_ORIGINAL_DST = 80

func getsockopt(s int, level int, name int, val uintptr, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

// realServerAddress returns an intercepted connection's original destination.
func realServerAddress(conn *net.TCPConn) (string, error) {
	file, err := conn.File()
	if err != nil {
		return "", err
	}

	fd := file.Fd()

	var addr syscall.RawSockaddr
	size := uint32(unsafe.Sizeof(addr))
	err = getsockopt(int(fd), syscall.SOL_IP, SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&addr)), &size)
	if err != nil {
		return "", err
	}

	var ip net.IP = make([]byte, 4)
	switch addr.Family {
	case syscall.AF_INET:
		for i, v := range addr.Data[2:6] {
			ip[i] = uint8(v)
		}
	default:
		return "", errors.New("unrecognized address family")
	}

	port := int(addr.Data[0])<<8 + int(addr.Data[1])

	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func parseToken(line string) (token, value string) {
	line = strings.TrimRight(line, "\r\n")
	tokens := strings.SplitN(line, "=", 2)
	if len(tokens) != 2 {
		return
	}

	value = strings.TrimSpace(tokens[1])
	if value == "" {
		return
	}
	token = strings.TrimSpace(tokens[0])
	return
}

func loadConfigFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}

	defer f.Close()

	rd := bufio.NewReader(f)
	lineno := 0

	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}
		lineno++

		if !strings.HasPrefix(line, "#") {
			token, value := parseToken(line)
			switch token {
			case "proxy":
				var err error
				cfgProxy, err = url.Parse(value)
				if err != nil {
					return err
				}
			case "listen":
				cfgListen = value
			default:
			}
		}
	}
	return nil
}

func forward(src *net.TCPConn, dst *net.TCPConn) {
	defer dst.CloseWrite()
	defer src.CloseRead()

	io.Copy(dst, src)
}

func handleConn(dialer proxy.Dialer, conn *net.TCPConn) {
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

func usage() {
	log.Printf("Usage: %s [options] config\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		return
	}

	if err := loadConfigFile(args[0]); err != nil {
		log.Fatal(err)
	}

	dialer, err := proxy.FromURL(cfgProxy, proxy.Direct)
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", cfgListen)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			break
		}
		log.Printf("new connection:%s -> %s", conn.RemoteAddr(), conn.LocalAddr())
		go handleConn(dialer, conn.(*net.TCPConn))
	}
}
