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
	"slices"
	"sort"
	"strconv"
	"time"
)

// remoteListenerKey distinguishes remote HTTP from the trusted loopback console.
// A connection through 0.0.0.0 must never inherit local-owner authorization.
type remoteListenerKey struct{}

type accessError struct {
	code  string
	cause error
}

func (e *accessError) Error() string             { return e.cause.Error() }
func accessFailure(code string, err error) error { return &accessError{code: code, cause: err} }

type accessInterface struct {
	Address   string `json:"address"`
	Interface string `json:"interface"`
}

func localAccessInterfaces() ([]accessInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := []accessInterface{}
	seen := map[string]bool{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			result = append(result, accessInterface{Address: ip.String(), Interface: iface.Name})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Address < result[j].Address })
	return result, nil
}

func privateInterfaces(interfaces []accessInterface) []accessInterface {
	result := []accessInterface{}
	for _, item := range interfaces {
		if ip, err := netip.ParseAddr(item.Address); err == nil && ip.IsPrivate() {
			result = append(result, item)
		}
	}
	return result
}

type lanServer struct {
	address     string
	transport   string
	hosts       []string
	server      *http.Server
	listener    net.Listener
	fingerprint string
	certificate tls.Certificate
}

func (s *lanServer) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.server.Shutdown(ctx)
	_ = s.listener.Close()
}

func accessHosts(address string, interfaces []accessInterface) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	ip, ipErr := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || portErr != nil || number < 0 || number > 65535 {
		return nil, accessFailure("access_address", errors.New("select a local interface or 0.0.0.0 and a valid port"))
	}
	ip = ip.Unmap()
	hosts := []string{}
	for _, item := range interfaces {
		local, err := netip.ParseAddr(item.Address)
		if err != nil {
			continue
		}
		if ip == netip.IPv4Unspecified() && local.Is4() || ip == local && ip.IsPrivate() {
			hosts = append(hosts, item.Address)
		}
	}
	if len(hosts) == 0 {
		return nil, accessFailure("access_address", errors.New("the selected interface is no longer available; refresh the address list"))
	}
	return hosts, nil
}

// SetLAN preserves the existing API's HTTPS default.
func (c *Controller) SetLAN(enabled bool, address string) (map[string]any, error) {
	return c.SetRemoteAccess(enabled, address, true)
}

func (c *Controller) revokeRemoteSessionsLocked() {
	for key, session := range c.sessions {
		if session.Remote {
			delete(c.sessions, key)
		}
	}
}

func (c *Controller) SetRemoteAccess(enabled bool, address string, https bool) (map[string]any, error) {
	c.actions.Lock()
	defer c.actions.Unlock()
	c.mu.Lock()
	old, closed := c.lan, c.closed
	c.mu.Unlock()
	if !enabled {
		c.mu.Lock()
		c.lan = nil
		c.revokeRemoteSessionsLocked()
		c.mu.Unlock()
		if old != nil {
			old.close()
		}
		return c.LANStatus(), nil
	}
	if closed {
		return nil, accessFailure("access_stopping", errors.New("application is stopping"))
	}
	if !c.passwordConfigured() {
		return nil, accessFailure("access_password", errors.New("set a management password before enabling remote access"))
	}
	interfaces, err := localAccessInterfaces()
	if err != nil {
		return nil, accessFailure("access_interfaces", err)
	}
	hosts, err := accessHosts(address, interfaces)
	if err != nil {
		return nil, err
	}
	transport := "http"
	if https {
		transport = "https"
	}
	if old != nil && old.address == address && old.transport == transport && slices.Equal(old.hosts, hosts) {
		return c.LANStatus(), nil
	}
	next := &lanServer{address: address, transport: transport, hosts: hosts}
	if https {
		ips := make([]net.IP, 0, len(hosts))
		for _, host := range hosts {
			ips = append(ips, net.ParseIP(host))
		}
		next.certificate, next.fingerprint, err = c.lanCertificate(ips...)
		if err != nil {
			return nil, accessFailure("access_certificate", err)
		}
	}
	// A different port can be prepared before stopping the current listener.
	// On the same port, restore the original listener if replacement fails.
	_, port, _ := net.SplitHostPort(address)
	stopped := false
	if old != nil {
		_, oldPort, _ := net.SplitHostPort(old.address)
		if port == oldPort && port != "0" {
			old.close()
			stopped = true
		}
	}
	if err = c.bindRemote(next); err != nil {
		if stopped {
			restore := *old
			if restoreErr := c.bindRemote(&restore); restoreErr != nil {
				c.mu.Lock()
				c.lan = nil
				c.revokeRemoteSessionsLocked()
				c.mu.Unlock()
				return nil, accessFailure("access_restore", errors.Join(err, restoreErr))
			}
			if err := c.startRemote(&restore); err != nil {
				return nil, err
			}
		}
		return nil, accessFailure("access_bind", err)
	}
	c.mu.Lock()
	c.revokeRemoteSessionsLocked()
	c.mu.Unlock()
	if err := c.startRemote(next); err != nil {
		return nil, err
	}
	if old != nil && !stopped {
		old.close()
	}
	return c.LANStatus(), nil
}

func (c *Controller) bindRemote(lan *lanServer) error {
	host, _, _ := net.SplitHostPort(lan.address)
	network := "tcp6"
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		network = "tcp4"
	}
	listener, err := net.Listen(network, lan.address)
	if err != nil {
		return err
	}
	lan.address, lan.listener = listener.Addr().String(), listener
	handler := c.Handler()
	lan.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), remoteListenerKey{}, lan)))
		}),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 32768,
	}
	if lan.transport == "https" {
		lan.server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{lan.certificate}}
	}
	return nil
}

func (c *Controller) startRemote(lan *lanServer) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = lan.listener.Close()
		return accessFailure("access_stopping", errors.New("application is stopping"))
	}
	c.lan = lan
	c.mu.Unlock()
	// Capture these before starting: a failed replacement may rebind the old plan.
	server, listener := lan.server, lan.listener
	if lan.transport == "https" {
		listener = tls.NewListener(listener, server.TLSConfig)
	}
	go func() {
		_ = server.Serve(listener)
		c.mu.Lock()
		if c.lan == lan && lan.server == server {
			c.lan = nil
		}
		c.mu.Unlock()
	}()
	return nil
}

func (s *lanServer) permits(r *http.Request) bool {
	host, port, err := net.SplitHostPort(r.Host)
	_, boundPort, _ := net.SplitHostPort(s.address)
	ip, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || port != boundPort || (r.TLS != nil) != (s.transport == "https") {
		return false
	}
	return slices.Contains(s.hosts, ip.Unmap().String())
}

func (s *lanServer) urls() []string {
	_, port, _ := net.SplitHostPort(s.address)
	result := []string{}
	for _, host := range s.hosts {
		ip, _ := netip.ParseAddr(host)
		if ip.IsLoopback() && len(s.hosts) > 1 {
			continue
		}
		result = append(result, s.transport+"://"+net.JoinHostPort(host, port))
	}
	return result
}

func (c *Controller) LANStatus() map[string]any {
	interfaces, err := localAccessInterfaces()
	c.mu.Lock()
	defer c.mu.Unlock()
	value := map[string]any{"enabled": false, "https": true, "transport": "https", "trust_required": false,
		"interfaces": privateInterfaces(interfaces), "interfaces_unavailable": err != nil, "urls": []string{}}
	if c.lan == nil {
		return value
	}
	lan := c.lan
	urls := lan.urls()
	value["enabled"], value["listen_address"], value["https"] = true, lan.address, lan.transport == "https"
	value["transport"], value["trust_required"], value["urls"] = lan.transport, lan.transport == "https", urls
	if len(urls) > 0 {
		value["address"] = urls[0]
	}
	if lan.transport == "https" {
		value["fingerprint"] = lan.fingerprint
	}
	return value
}

func (c *Controller) lanCertificate(ips ...net.IP) (tls.Certificate, string, error) {
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
		return tls.Certificate{}, "", errors.New("LAN CA certificate expired; renew and trust the new CA before enabling HTTPS access")
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "KONE Local Management"}, NotBefore: c.now().Add(-time.Minute), NotAfter: c.now().Add(30 * 24 * time.Hour), IPAddresses: ips, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
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
