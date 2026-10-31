package proxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProxyURLValidation(t *testing.T) {
	for _, raw := range []string{"http://localhost", "http://:8080", "http://localhost:0", "socks5://localhost:65536", "ftp://localhost:21", "http://localhost:80/path", "http://localhost:80?secret=password"} {
		if _, err := FromUrl(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"http://localhost:80", "https://user:password@example.com:443", "socks5://[::1]:1080"} {
		if _, err := FromUrl(raw); err != nil {
			t.Errorf("%q: %v", raw, err)
		}
	}
}

func TestHTTPConnectPreservesBufferedPayload(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err == nil && (request.Method != "CONNECT" || request.Host != "example.com:443") {
			err = fmt.Errorf("unexpected request: %s %s", request.Method, request.Host)
		}
		if err == nil {
			_, err = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\nearly-payload")
		}
		done <- err
	}()
	p, err := FromUrl("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := p.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "early-payload" {
		t.Fatalf("lost tunnel bytes: %q", data)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTLSHostname(t *testing.T) {
	if got := hostname("[2001:db8::1]:443"); strings.Contains(got, "[") {
		t.Fatalf("invalid TLS server name %q", got)
	}
}

func TestSOCKS5Connect(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		t.Run(fmt.Sprintf("auth=%t", authenticated), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				done <- serveSOCKS(conn, authenticated)
			}()
			credentials := ""
			if authenticated {
				credentials = "alice:secret@"
			}
			p, err := FromUrl("socks5://" + credentials + ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			conn, err := p.Dial("tcp", "example.com:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			out, err := io.ReadAll(conn)
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != "ready" {
				t.Fatalf("unexpected tunnel data %q", out)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func serveSOCKS(conn net.Conn, authenticated bool) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 5 {
		return fmt.Errorf("invalid SOCKS version")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	method := byte(0)
	if authenticated {
		method = 2
	}
	if _, err := conn.Write([]byte{5, method}); err != nil {
		return err
	}
	if authenticated {
		if _, err := io.ReadFull(conn, header); err != nil {
			return err
		}
		user := make([]byte, int(header[1]))
		if _, err := io.ReadFull(conn, user); err != nil {
			return err
		}
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		password := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, password); err != nil {
			return err
		}
		if string(user) != "alice" || string(password) != "secret" {
			return fmt.Errorf("unexpected proxy credentials")
		}
		if _, err := conn.Write([]byte{1, 0}); err != nil {
			return err
		}
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return err
	}
	if request[0] != 5 || request[1] != 1 || request[3] != 3 {
		return fmt.Errorf("expected SOCKS CONNECT with remote DNS")
	}
	length := make([]byte, 1)
	if _, err := io.ReadFull(conn, length); err != nil {
		return err
	}
	target := make([]byte, int(length[0])+2)
	if _, err := io.ReadFull(conn, target); err != nil {
		return err
	}
	if string(target[:len(target)-2]) != "example.com" || binary.BigEndian.Uint16(target[len(target)-2:]) != 443 {
		return fmt.Errorf("unexpected SOCKS target")
	}
	_, err := conn.Write(append([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}, []byte("ready")...))
	return err
}
