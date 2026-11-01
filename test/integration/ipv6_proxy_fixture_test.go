package integration

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type ipv6SOCKSSeen struct {
	protocol, hostname string
}

func ipv6SOCKSPeer(t *testing.T) (string, <-chan ipv6SOCKSSeen) {
	return ipv6SOCKSPeerOn(t, "127.0.0.1")
}

func ipv6SOCKSPeerOn(t *testing.T, host string, transform ...func([]byte) []byte) (string, <-chan ipv6SOCKSSeen) {
	t.Helper()
	network := "4"
	if net.ParseIP(host).To4() == nil {
		network = "6"
	}
	listener, err := net.Listen("tcp"+network, net.JoinHostPort(host, "0"))
	require.NoError(t, err)
	packet, err := net.ListenPacket("udp"+network, net.JoinHostPort(host, "0"))
	require.NoError(t, err)
	seen := make(chan ipv6SOCKSSeen, 8)
	reply := func(port int) []byte {
		address := net.ParseIP(host)
		kind := byte(4)
		if address.To4() != nil {
			address = address.To4()
			kind = 1
		}
		return append(append([]byte{5, 0, 0, kind}, address...), byte(port>>8), byte(port))
	}
	var workers sync.WaitGroup
	var mu sync.Mutex
	stopping := false
	active := map[net.Conn]bool{}
	readTarget := func(reader io.Reader, kind byte) (string, error) {
		size := 0
		switch kind {
		case 1:
			size = 4
		case 4:
			size = 16
		case 3:
			var length [1]byte
			if _, err := io.ReadFull(reader, length[:]); err != nil {
				return "", err
			}
			size = int(length[0])
		default:
			return "", fmt.Errorf("invalid address kind")
		}
		address := make([]byte, size+2)
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		if kind == 3 {
			return string(address[:size]), nil
		}
		return net.IP(address[:size]).String(), nil
	}
	workers.Add(2)
	go func() {
		defer workers.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if stopping {
				mu.Unlock()
				connection.Close()
				return
			}
			active[connection] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				defer func() { mu.Lock(); delete(active, connection); mu.Unlock() }()
				connection.SetDeadline(time.Now().Add(10 * time.Second))
				var hello [2]byte
				if _, err := io.ReadFull(connection, hello[:]); err != nil || hello[0] != 5 || hello[1] > 8 {
					return
				}
				if _, err := io.ReadFull(connection, make([]byte, int(hello[1]))); err != nil {
					return
				}
				connection.Write([]byte{5, 0})
				var request [4]byte
				if _, err := io.ReadFull(connection, request[:]); err != nil {
					return
				}
				hostname, err := readTarget(connection, request[3])
				if err != nil {
					return
				}
				if request[1] == 1 {
					seen <- ipv6SOCKSSeen{"tcp", hostname}
					connection.Write(reply(0))
					io.Copy(connection, connection)
				} else if request[1] == 3 {
					_, port, _ := net.SplitHostPort(packet.LocalAddr().String())
					var value int
					fmt.Sscan(port, &value)
					connection.Write(reply(value))
					connection.SetDeadline(time.Time{})
					io.Copy(io.Discard, connection)
				}
			}()
		}
	}()
	go func() {
		defer workers.Done()
		buffer := make([]byte, 65535)
		for {
			n, source, err := packet.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
				continue
			}
			hostname, err := readTarget(strings.NewReader(string(buffer[4:n])), buffer[3])
			if err != nil {
				continue
			}
			seen <- ipv6SOCKSSeen{"udp", hostname}
			response := buffer[:n]
			if len(transform) > 0 {
				response = transform[0](response)
			}
			packet.WriteTo(response, source)
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		packet.Close()
		mu.Lock()
		stopping = true
		for connection := range active {
			connection.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return "socks5://" + listener.Addr().String(), seen
}
