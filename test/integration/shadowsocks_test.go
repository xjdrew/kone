package integration

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/proxy"
	"golang.org/x/crypto/chacha20poly1305"
)

// This independent test peer follows Shadowsocks SIP004/SIP007 wire framing;
// it does not use the client's cipher/transport package to validate itself.
func ssPeerCipher(method, password string, salt []byte) (cipher.AEAD, error) {
	length := 32
	if method == "aes-128-gcm" {
		length = 16
	}
	var key, previous []byte
	for len(key) < length {
		hash := md5.New()
		hash.Write(previous)
		hash.Write([]byte(password))
		previous = hash.Sum(nil)
		key = append(key, previous...)
	}
	subkey, err := hkdf.Key(sha1.New, key[:length], salt, "ss-subkey", length)
	if err != nil {
		return nil, err
	}
	if method == "chacha20-ietf-poly1305" {
		return chacha20poly1305.New(subkey)
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func ssPeerNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

func ssPeerReadChunk(reader io.Reader, aead cipher.AEAD, nonce []byte) ([]byte, error) {
	header := make([]byte, 2+aead.Overhead())
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	header, err := aead.Open(nil, nonce, header, nil)
	if err != nil {
		return nil, err
	}
	ssPeerNonce(nonce)
	length := binary.BigEndian.Uint16(header)
	if length > 0x3fff {
		return nil, errors.New("invalid SS chunk size")
	}
	payload := make([]byte, int(length)+aead.Overhead())
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	payload, err = aead.Open(nil, nonce, payload, nil)
	ssPeerNonce(nonce)
	return payload, err
}

func ssPeerWriteChunk(writer io.Writer, aead cipher.AEAD, nonce, payload []byte) error {
	header := []byte{byte(len(payload) >> 8), byte(len(payload))}
	packet := aead.Seal(nil, nonce, header, nil)
	ssPeerNonce(nonce)
	packet = append(packet, aead.Seal(nil, nonce, payload, nil)...)
	ssPeerNonce(nonce)
	_, err := writer.Write(packet)
	return err
}

func ssInteropPeer(t *testing.T, method, network string, tamper bool, transform ...func([]byte) []byte) (string, <-chan []byte) {
	t.Helper()
	length := 32
	if method == "aes-128-gcm" {
		length = 16
	}
	received := make(chan []byte, 1)
	var workers sync.WaitGroup
	workers.Add(1)
	if network == "tcp" {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		var control net.Conn
		var mu sync.Mutex
		go func() {
			defer workers.Done()
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			control = conn
			mu.Unlock()
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			salt := make([]byte, length)
			if _, err := io.ReadFull(conn, salt); err != nil {
				return
			}
			aead, err := ssPeerCipher(method, "interop-password", salt)
			if err != nil {
				return
			}
			nonce := make([]byte, aead.NonceSize())
			target, err := ssPeerReadChunk(conn, aead, nonce)
			if err != nil {
				return
			}
			payload, err := ssPeerReadChunk(conn, aead, nonce)
			if err != nil {
				return
			}
			received <- append(target, payload...)
			rand.Read(salt)
			response, err := ssPeerCipher(method, "interop-password", salt)
			if err != nil {
				return
			}
			conn.Write(salt)
			ssPeerWriteChunk(conn, response, make([]byte, response.NonceSize()), payload)
		}()
		t.Cleanup(func() {
			listener.Close()
			mu.Lock()
			if control != nil {
				control.Close()
			}
			mu.Unlock()
			workers.Wait()
		})
		return listener.Addr().String(), received
	}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		defer workers.Done()
		buffer := make([]byte, 65535)
		n, peer, err := packet.ReadFrom(buffer)
		if err != nil || n < length {
			return
		}
		aead, err := ssPeerCipher(method, "interop-password", buffer[:length])
		if err != nil {
			return
		}
		plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), buffer[length:n], nil)
		if err != nil {
			return
		}
		received <- plain
		if len(transform) > 0 {
			plain = transform[0](plain)
		}
		salt := make([]byte, length)
		rand.Read(salt)
		response, err := ssPeerCipher(method, "interop-password", salt)
		if err != nil {
			return
		}
		result := append(salt, response.Seal(nil, make([]byte, response.NonceSize()), plain, nil)...)
		if tamper {
			result[len(result)-1] ^= 1
		}
		packet.WriteTo(result, peer)
	}()
	t.Cleanup(func() { packet.Close(); workers.Wait() })
	return packet.LocalAddr().String(), received
}

func TestShadowsocksAEAD2017Interop(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(method+"/"+network, func(t *testing.T) {
				server, received := ssInteropPeer(t, method, network, false)
				p, err := proxy.FromUrl("ss://" + url.UserPassword(method, "interop-password").String() + "@" + server)
				require.NoError(t, err)
				var calls []string
				dial := func(ctx context.Context, network, address string) (net.Conn, error) {
					calls = append(calls, network+" "+address)
					return proxy.Direct.DialContext(ctx, network, address)
				}
				var conn net.Conn
				if network == "tcp" {
					conn, err = p.DialContextVia(context.Background(), "tcp", "remote.invalid:443", dial)
				} else {
					conn, err = p.DialUDPContextVia(context.Background(), "remote.invalid:443", dial)
				}
				require.NoError(t, err)
				defer conn.Close()
				require.Equal(t, []string{network + " " + server}, calls, "only proxy transport may be dialed locally")
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, err = conn.Write([]byte("encrypted payload"))
				require.NoError(t, err)
				response := make([]byte, len("encrypted payload"))
				_, err = io.ReadFull(conn, response)
				require.NoError(t, err)
				require.Equal(t, "encrypted payload", string(response))
				select {
				case plain := <-received:
					want := append([]byte{3, byte(len("remote.invalid"))}, []byte("remote.invalid")...)
					want = append(want, 1, 187)
					want = append(want, []byte("encrypted payload")...)
					require.True(t, bytes.Equal(want, plain), "server did not decrypt destination and payload")
				case <-time.After(time.Second):
					t.Fatal("SS peer did not decrypt traffic")
				}
			})
		}
	}
}

func TestShadowsocksUDPTamperingFailsAuthentication(t *testing.T) {
	server, _ := ssInteropPeer(t, "aes-128-gcm", "udp", true)
	p, err := proxy.FromUrl("ss://aes-128-gcm:interop-password@" + server)
	require.NoError(t, err)
	conn, err := p.DialUDPContext(context.Background(), "remote.invalid:443")
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	_, err = conn.Write([]byte("authentic"))
	require.NoError(t, err)
	_, err = conn.Read(make([]byte, 64))
	require.Error(t, err, "tampered ciphertext must never become business payload")
}
