package control

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	cert, fingerprint, err := c.lanCertificate(ip, net.ParseIP("127.0.0.1"))
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
	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "127.0.0.1"})
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

func TestRemoteAccessAddressChoicesAndHostValidation(t *testing.T) {
	interfaces := []accessInterface{{"127.0.0.1", "lo"}, {"192.168.40.2", "eth0"}, {"203.0.113.2", "eth1"}, {"fd00::2", "eth0"}}
	require.Equal(t, []accessInterface{interfaces[1], interfaces[3]}, privateInterfaces(interfaces))
	hosts, err := accessHosts("0.0.0.0:9443", interfaces)
	require.NoError(t, err)
	require.Equal(t, []string{"127.0.0.1", "192.168.40.2", "203.0.113.2"}, hosts)
	listener := &lanServer{address: "0.0.0.0:9443", transport: "http", hosts: hosts}
	require.Equal(t, []string{"http://192.168.40.2:9443", "http://203.0.113.2:9443"}, listener.urls())
	for _, host := range hosts {
		require.True(t, listener.permits(httptest.NewRequest("GET", "http://"+host+":9443/", nil)))
	}
	for _, address := range []string{"http://evil.example:9443/", "http://0.0.0.0:9443/", "http://192.168.40.2:9444/", "https://192.168.40.2:9443/"} {
		require.False(t, listener.permits(httptest.NewRequest("GET", address, nil)), address)
	}
	hosts, err = accessHosts("[fd00::2]:9443", interfaces)
	require.NoError(t, err)
	require.Equal(t, []string{"fd00::2"}, hosts)
	for _, address := range []string{"bad", "[::]:9443", "192.168.40.3:9443", "192.168.40.2:65536", "192.168.40.2:-1", "192.168.40.2:port"} {
		_, err := accessHosts(address, interfaces)
		require.Error(t, err, address)
	}
}

func TestRemoteAccessRequiresPasswordAndKeepsListenerOnFailure(t *testing.T) {
	c := testController(t, Options{})
	_, err := c.SetRemoteAccess(true, "0.0.0.0:0", false)
	require.ErrorContains(t, err, "password")
	require.False(t, c.LANStatus()["enabled"].(bool))
	owner(t, c)
	status, err := c.SetRemoteAccess(true, "0.0.0.0:0", false)
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(c.directory, "lan-ca.pem"))
	require.ErrorIs(t, err, os.ErrNotExist, "HTTP does not create a CA")
	occupied, err := net.Listen("tcp4", "0.0.0.0:0")
	require.NoError(t, err)
	defer occupied.Close()
	_, err = c.SetRemoteAccess(true, occupied.Addr().String(), false)
	require.Error(t, err)
	require.Equal(t, status, c.LANStatus())
	require.NoError(t, os.WriteFile(filepath.Join(c.directory, "lan-ca.pem"), []byte("damaged"), 0600))
	_, err = c.SetRemoteAccess(true, status["listen_address"].(string), true)
	require.Error(t, err)
	require.Equal(t, status, c.LANStatus(), "certificate failure keeps HTTP working")
	_, err = c.SetRemoteAccess(true, status["listen_address"].(string), false)
	require.NoError(t, err, "HTTP never reads the CA")
	require.NoError(t, c.Close())
	_, err = c.SetRemoteAccess(true, "0.0.0.0:0", false)
	require.ErrorContains(t, err, "stopping")
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
	_, err = c.SetLAN(true, status["listen_address"].(string))
	require.NoError(t, err)
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
	remote, session := roleSession(c, "read")
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
