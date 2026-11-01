package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

type lanServer struct {
	address     string
	server      *http.Server
	listener    net.Listener
	fingerprint string
}

func (s *lanServer) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.server.Shutdown(ctx)
	_ = s.listener.Close()
}

func privateLocalAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("LAN address must be a private local IP and port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsPrivate() || ip.IsLoopback() {
		return errors.New("choose a private interface IP; wildcard and public listeners are not allowed")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, value := range addresses {
		prefix, err := netip.ParsePrefix(value.String())
		if err == nil && prefix.Addr().Unmap() == ip.Unmap() {
			return nil
		}
	}
	return errors.New("LAN IP is not assigned to this host")
}

func (c *Controller) SetLAN(enabled bool, address string) (map[string]any, error) {
	c.actions.Lock()
	defer c.actions.Unlock()
	if !enabled {
		c.mu.Lock()
		old := c.lan
		c.lan = nil
		for key, s := range c.sessions {
			if s.Remote {
				delete(c.sessions, key)
			}
		}
		c.pairs = map[string]Pairing{}
		c.mu.Unlock()
		if old != nil {
			old.close()
		}
		return c.LANStatus(), nil
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, errors.New("application is stopping")
	}
	if err := privateLocalAddress(address); err != nil {
		return nil, err
	}
	c.mu.Lock()
	existing := c.lan
	c.mu.Unlock()
	if existing != nil {
		return nil, errors.New("disable the existing LAN listener before changing its address")
	}
	host, _, _ := net.SplitHostPort(address)
	certificate, fingerprint, err := c.lanCertificate(net.ParseIP(host))
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: c.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 32768, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}}
	lan := &lanServer{address: listener.Addr().String(), server: server, listener: listener, fingerprint: fingerprint}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		listener.Close()
		return nil, errors.New("application is stopping")
	}
	c.lan = lan
	c.mu.Unlock()
	go func() {
		_ = server.Serve(tls.NewListener(listener, server.TLSConfig))
		c.mu.Lock()
		if c.lan == lan {
			c.lan = nil
		}
		c.mu.Unlock()
	}()
	return c.LANStatus(), nil
}

func (c *Controller) LANStatus() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lan == nil {
		return map[string]any{"enabled": false, "transport": "https", "trust_required": true}
	}
	return map[string]any{"enabled": true, "address": "https://" + c.lan.address, "fingerprint": c.lan.fingerprint, "transport": "https", "trust_required": true, "instructions": "Install the local KONE CA certificate on your own device, verify its fingerprint, then use a short-lived pairing code. No trust settings are changed automatically."}
}

func (c *Controller) lanCertificate(ip net.IP) (tls.Certificate, string, error) {
	caPath, keyPath := filepath.Join(c.directory, "lan-ca.pem"), filepath.Join(c.directory, "lan-ca-key.pem")
	caPEM, caErr := os.ReadFile(caPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	var ca *x509.Certificate
	var key *ecdsa.PrivateKey
	if caErr == nil && keyErr == nil {
		block, _ := pem.Decode(caPEM)
		keyBlock, _ := pem.Decode(keyPEM)
		if block == nil || keyBlock == nil {
			return tls.Certificate{}, "", errors.New("LAN certificate is damaged; restore it before enabling access")
		}
		var err error
		ca, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return tls.Certificate{}, "", err
		}
	} else if !errors.Is(caErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist) {
		return tls.Certificate{}, "", errors.New("LAN certificate/key must both be present or both be absent")
	} else {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "KONE Local Management CA"}, NotBefore: c.now().Add(-time.Minute), NotAfter: c.now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		ca, _ = x509.ParseCertificate(der)
		caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		rawKey, _ := x509.MarshalECPrivateKey(key)
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: rawKey})
		if err = atomicWrite(keyPath, keyPEM); err != nil {
			return tls.Certificate{}, "", err
		}
		if err = atomicWrite(caPath, caPEM); err != nil {
			return tls.Certificate{}, "", err
		}
	}
	if !ca.IsCA || !key.PublicKey.Equal(ca.PublicKey) {
		return tls.Certificate{}, "", errors.New("LAN certificate authority and private key do not match")
	}
	if c.now().Before(ca.NotBefore) || c.now().After(ca.NotAfter) {
		return tls.Certificate{}, "", errors.New("LAN CA certificate expired; renew and re-pair devices before enabling access")
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "KONE Local Management"}, NotBefore: c.now().Add(-time.Minute), NotAfter: c.now().Add(30 * 24 * time.Hour), IPAddresses: []net.IP{ip}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &serverKey.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	leaf = append(leaf, caPEM...)
	serverRaw, _ := x509.MarshalECPrivateKey(serverKey)
	cert, err := tls.X509KeyPair(leaf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverRaw}))
	sum := sha256.Sum256(ca.Raw)
	return cert, hex.EncodeToString(sum[:]), err
}
