package control

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLANCertificateTrustPersistenceAndDamage(t *testing.T) {
	c := testController(t, Options{})
	ip := net.ParseIP("192.168.40.2")
	cert, fingerprint, err := c.lanCertificate(ip)
	require.NoError(t, err)
	require.Len(t, fingerprint, 64)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	caPEM, err := os.ReadFile(filepath.Join(c.directory, "lan-ca.pem"))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))
	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: ip.String()})
	require.NoError(t, err)
	_, again, err := c.lanCertificate(ip)
	require.NoError(t, err)
	require.Equal(t, fingerprint, again)
	require.NoError(t, os.WriteFile(filepath.Join(c.directory, "lan-ca.pem"), []byte("broken"), 0600))
	_, _, err = c.lanCertificate(ip)
	require.ErrorContains(t, err, "damaged")
	require.NoError(t, os.Remove(filepath.Join(c.directory, "lan-ca.pem")))
	_, _, err = c.lanCertificate(ip)
	require.ErrorContains(t, err, "both")
	block, _ := pem.Decode(caPEM)
	require.NotNil(t, block)
}

func TestLANAddressBoundaries(t *testing.T) {
	for _, address := range []string{"bad", "0.0.0.0:9201", "[::]:9201", "127.0.0.1:9201", "8.8.8.8:9201", "192.0.2.1:9201", "192.168.254.254:9201"} {
		require.Error(t, privateLocalAddress(address), address)
	}
}

func TestExplicitLANAccessRequiresTLSAuthorizationAndRevokes(t *testing.T) {
	// This opens only an ephemeral authenticated listener. It never changes an
	// interface, firewall, DNS, route, or operating-system certificate store.
	addresses, err := net.InterfaceAddrs()
	require.NoError(t, err)
	var ip netip.Addr
	for _, value := range addresses {
		p, e := netip.ParsePrefix(value.String())
		if e == nil && p.Addr().Is4() && p.Addr().IsPrivate() && !p.Addr().IsLoopback() {
			ip = p.Addr()
			break
		}
	}
	if !ip.IsValid() {
		t.Skip("runner has no assigned private IPv4 address")
	}
	c := testController(t, Options{})
	token := owner(t, c)
	status, err := c.SetLAN(true, net.JoinHostPort(ip.String(), "0"))
	require.NoError(t, err)
	require.True(t, status["enabled"].(bool))
	_, err = c.SetLAN(true, net.JoinHostPort(ip.String(), "0"))
	require.Error(t, err)
	caPEM, err := os.ReadFile(filepath.Join(c.directory, "lan-ca.pem"))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}
	address := status["address"].(string) + "/api/v1/state"
	response, err := client.Get(address)
	require.NoError(t, err)
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	require.Equal(t, 401, response.StatusCode)
	pair, err := c.pair("read")
	require.NoError(t, err)
	remote, session, err := c.claim("", pair.Code, true)
	require.NoError(t, err)
	req, err := http.NewRequest("GET", address, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+remote)
	response, err = client.Do(req)
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, 200, response.StatusCode)
	require.Equal(t, 200, request(t, c, token, "GET", "/api/v1/access/certificate", nil).Code)
	_, err = c.SetLAN(false, "")
	require.NoError(t, err)
	require.False(t, c.revoke(session.ID))
	require.Equal(t, 401, request(t, c, remote, "GET", "/api/v1/state", nil).Code)
	require.Equal(t, 200, request(t, c, token, "GET", "/api/v1/state", nil).Code)
}
