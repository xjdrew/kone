package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type udpSOCKSFixture struct {
	listener net.Listener
	udp      *net.UDPConn
	mu       sync.Mutex
	control  net.Conn
	workers  sync.WaitGroup
	received chan []byte
	greeting chan struct{}
}

type udpSOCKSOptions struct {
	auth          bool
	rejectAuth    bool
	rejectCommand bool
	hangHandshake bool
	relayHost     string
	mutate        func([]byte) []byte
}

func startUDPSOCKS(t *testing.T, options udpSOCKSOptions) *udpSOCKSFixture {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	f := &udpSOCKSFixture{listener: listener, udp: udp, received: make(chan []byte, 8), greeting: make(chan struct{})}
	f.workers.Add(2)
	go func() {
		defer f.workers.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.control = conn
		f.mu.Unlock()
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var hello [2]byte
		if _, err := io.ReadFull(conn, hello[:]); err != nil {
			return
		}
		methods := make([]byte, int(hello[1]))
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		close(f.greeting)
		if options.hangHandshake {
			var ignored [1]byte
			conn.Read(ignored[:])
			return
		}
		method := byte(0)
		if options.auth {
			method = 2
		}
		if writeSOCKSMessage(conn, []byte{5, method}) != nil {
			return
		}
		if options.auth {
			var prefix [2]byte
			if _, err := io.ReadFull(conn, prefix[:]); err != nil {
				return
			}
			username := make([]byte, int(prefix[1]))
			if _, err := io.ReadFull(conn, username); err != nil {
				return
			}
			var length [1]byte
			if _, err := io.ReadFull(conn, length[:]); err != nil {
				return
			}
			password := make([]byte, int(length[0]))
			if _, err := io.ReadFull(conn, password); err != nil {
				return
			}
			status := byte(0)
			if options.rejectAuth || string(username) != "alice" || string(password) != "secret" {
				status = 1
			}
			if writeSOCKSMessage(conn, []byte{1, status}) != nil || status != 0 {
				return
			}
		}
		var request [4]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil {
			return
		}
		if request[0] != 5 || request[1] != 3 || request[2] != 0 {
			return
		}
		if _, err := readSOCKSAddress(conn, request[3]); err != nil {
			return
		}
		if options.rejectCommand {
			writeSOCKSMessage(conn, []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		host := options.relayHost
		if host == "" {
			host = "127.0.0.1"
		}
		reply, err := appendSOCKSAddress([]byte{5, 0, 0}, socksAddress{host: host, port: uint16(udp.LocalAddr().(*net.UDPAddr).Port)})
		if err != nil {
			return
		}
		if writeSOCKSMessage(conn, reply) != nil {
			return
		}
		conn.SetDeadline(time.Time{})
		io.Copy(io.Discard, conn)
	}()
	go func() {
		defer f.workers.Done()
		buffer := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			packet := append([]byte(nil), buffer[:n]...)
			select {
			case f.received <- append([]byte(nil), packet...):
			default:
			}
			if options.mutate != nil {
				packet = options.mutate(packet)
			}
			udp.WriteToUDP(packet, peer)
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		udp.Close()
		f.mu.Lock()
		if f.control != nil {
			f.control.Close()
		}
		f.mu.Unlock()
		f.workers.Wait()
	})
	return f
}

func (f *udpSOCKSFixture) proxy(t *testing.T, auth bool) *Proxy {
	t.Helper()
	p, err := FromUrl("socks5://" + f.listener.Addr().String())
	require.NoError(t, err)
	if auth {
		p.Url.User = url.UserPassword("alice", "secret")
	}
	return p
}

func TestSOCKSUDPAssociationRoundTripAndPhysicalDialer(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		t.Run(map[bool]string{false: "no auth", true: "password"}[authenticated], func(t *testing.T) {
			fixture := startUDPSOCKS(t, udpSOCKSOptions{auth: authenticated, relayHost: "0.0.0.0"})
			p := fixture.proxy(t, authenticated)
			var calls []string
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				calls = append(calls, network+" "+address)
				return Direct.DialContext(ctx, network, address)
			}
			conn, err := p.DialUDPContextVia(context.Background(), "unresolved.invalid:443", dial)
			require.NoError(t, err)
			t.Cleanup(func() { conn.Close() })
			require.Len(t, calls, 2)
			require.True(t, strings.HasPrefix(calls[0], "tcp "))
			require.Equal(t, "udp "+fixture.udp.LocalAddr().String(), calls[1])
			require.Equal(t, "unresolved.invalid:443", conn.RemoteAddr().String())
			require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
			count, err := conn.Write([]byte("native UDP"))
			require.NoError(t, err)
			require.Equal(t, 10, count)
			payload := make([]byte, 64)
			count, err = conn.Read(payload)
			require.NoError(t, err)
			require.Equal(t, "native UDP", string(payload[:count]))
			packet := <-fixture.received
			require.Equal(t, byte(3), packet[3])
			require.Contains(t, string(packet), "unresolved.invalid")
			require.NoError(t, conn.Close())
			require.NoError(t, conn.Close())
			select {
			case <-conn.(*socksUDPConn).monitorDone:
			case <-time.After(time.Second):
				t.Fatal("SOCKS control monitor did not drain")
			}
		})
	}
}

func TestSOCKSUDPAssociationCancellationAndServerClose(t *testing.T) {
	fixture := startUDPSOCKS(t, udpSOCKSOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := fixture.proxy(t, false).DialUDPContext(ctx, "192.0.2.9:53")
	require.NoError(t, err)
	cancel()
	select {
	case <-conn.(*socksUDPConn).monitorDone:
	case <-time.After(time.Second):
		t.Fatal("cancelled association did not close TCP")
	}
	_, err = conn.Read(make([]byte, 64))
	require.Error(t, err)
	require.NoError(t, conn.Close())
	other := startUDPSOCKS(t, udpSOCKSOptions{})
	second, err := other.proxy(t, false).DialUDPContext(context.Background(), "192.0.2.9:53")
	require.NoError(t, err)
	defer second.Close()
	other.mu.Lock()
	other.control.Close()
	other.mu.Unlock()
	select {
	case <-second.(*socksUDPConn).monitorDone:
	case <-time.After(time.Second):
		t.Fatal("server closed control but UDP stayed alive")
	}
	_, err = second.Write([]byte("closed"))
	require.Error(t, err)
}

func TestSOCKSUDPHandshakeFailureAndRelayValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options udpSOCKSOptions
		want    string
	}{
		{"auth", udpSOCKSOptions{auth: true, rejectAuth: true}, "authentication rejected"},
		{"command", udpSOCKSOptions{rejectCommand: true}, "association rejected"},
		{"relay hostname", udpSOCKSOptions{relayHost: "unrelated.invalid"}, "hostname must match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := startUDPSOCKS(t, tc.options)
			p := f.proxy(t, tc.options.auth)
			_, err := p.DialUDPContext(context.Background(), "192.0.2.9:443")
			require.ErrorContains(t, err, tc.want)
			require.NotContains(t, err.Error(), "secret")
		})
	}
	fixture := startUDPSOCKS(t, udpSOCKSOptions{hangHandshake: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := fixture.proxy(t, false).DialUDPContext(ctx, "192.0.2.9:443"); done <- err }()
	select {
	case <-fixture.greeting:
	case <-time.After(time.Second):
		t.Fatal("handshake not started")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("handshake ignored cancellation")
	}
	pre, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fixture.proxy(t, false).DialUDPContext(pre, "192.0.2.9:443")
	require.ErrorIs(t, err, context.Canceled)
}

func TestSOCKSUDPRejectsFragmentsAndWrongSource(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
		want   error
	}{
		{"fragment", func(p []byte) []byte { p[2] = 1; return p }, ErrSOCKSUDPFragment},
		{"source", func(p []byte) []byte { p[9]++; return p }, ErrSOCKSUDPSource},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := startUDPSOCKS(t, udpSOCKSOptions{mutate: tc.mutate})
			conn, err := f.proxy(t, false).DialUDPContext(context.Background(), "192.0.2.9:53")
			require.NoError(t, err)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			_, err = conn.Write([]byte("test"))
			require.NoError(t, err)
			_, err = conn.Read(make([]byte, 64))
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestSOCKSAddressBoundaries(t *testing.T) {
	for _, target := range []string{"192.0.2.1:53", "[2001:db8::1]:53", "example.com:443"} {
		address, err := parseSOCKSTarget(target)
		require.NoError(t, err)
		packet, err := appendSOCKSAddress(nil, address)
		require.NoError(t, err)
		got, err := readSOCKSAddress(strings.NewReader(string(packet[1:])), packet[0])
		require.NoError(t, err)
		require.Equal(t, address, got)
	}
	for _, target := range []string{"missing-port", "example.com:0", "bad domain:53", "[fe80::1%eth0]:53"} {
		_, err := parseSOCKSTarget(target)
		require.Error(t, err)
	}
	_, err := readSOCKSAddress(strings.NewReader(""), 9)
	require.Error(t, err)
	_, err = readSOCKSAddress(strings.NewReader("\x00"), 3)
	require.Error(t, err)
	p, _ := FromUrl("http://127.0.0.1:8080")
	require.False(t, p.SupportsUDP())
	_, err = p.DialUDPContext(context.Background(), "192.0.2.1:53")
	require.Error(t, err)
	require.False(t, errors.Is(err, context.Canceled))
}
