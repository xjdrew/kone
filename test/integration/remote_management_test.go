package integration

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/control"
)

// Exercises real listeners and browser cookie/CSRF behavior without starting
// capture or changing interfaces, routes, DNS, or the OS certificate store.
func TestRemoteManagementPasswordHTTPAndHTTPS(t *testing.T) {
	directory := t.TempDir()
	c, err := control.New(control.Options{Directory: directory})
	require.NoError(t, err)
	defer c.Close()
	local := httptest.NewServer(c.Handler())
	defer local.Close()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	// Replacing a listener may legitimately spend three seconds draining the
	// old HTTP server. Leave room for that bound and TLS setup on race runners;
	// ordinary requests still finish immediately, without polling or sleeps.
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second, Transport: transport}
	do := func(method, url, body, csrf string, want int) (map[string]any, *http.Response) {
		t.Helper()
		r, err := http.NewRequest(method, url, strings.NewReader(body))
		require.NoError(t, err)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		response, err := client.Do(r)
		require.NoError(t, err)
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, want, response.StatusCode, "%s %s: %s", method, url, data)
		var value map[string]any
		require.NoError(t, json.Unmarshal(data, &value))
		return value, response
	}
	localSession, _ := do("POST", local.URL+"/api/v1/session", `{}`, "", 200)
	localCSRF := localSession["csrf_token"].(string)
	do("POST", local.URL+"/api/v1/access/lan", `{"enabled":true,"address":"0.0.0.0:0","https":false}`, localCSRF, 400)
	localSession, _ = do("POST", local.URL+"/api/v1/auth/password", `{"password":"remote-password","confirm_password":"remote-password"}`, localCSRF, 200)
	localCSRF = localSession["csrf_token"].(string)
	status, _ := do("POST", local.URL+"/api/v1/access/lan", `{"enabled":true,"address":"0.0.0.0:0","https":false}`, localCSRF, 200)
	_, port, err := net.SplitHostPort(status["listen_address"].(string))
	require.NoError(t, err)
	remote := "http://127.0.0.1:" + port
	info, _ := do("GET", remote+"/api/v1/auth", "", "", 200)
	require.Equal(t, false, info["local_access"])
	do("GET", remote+"/api/v1/state", "", "", 401) // The local console cookie is not remote authorization.
	do("POST", remote+"/api/v1/session", `{}`, "", 400)
	do("POST", remote+"/api/v1/session", `{"pairing_code":"123456"}`, "", 400)
	_, err = os.Stat(filepath.Join(directory, "lan-ca.pem"))
	require.ErrorIs(t, err, os.ErrNotExist)

	login, response := do("POST", remote+"/api/v1/session", `{"password":"remote-password"}`, "", 200)
	require.Equal(t, "kone_remote_http_session", response.Cookies()[0].Name)
	require.False(t, response.Cookies()[0].Secure)
	require.True(t, response.Cookies()[0].HttpOnly)
	csrf := login["csrf_token"].(string)
	state, _ := do("GET", remote+"/api/v1/state", "", "", 200)
	require.Equal(t, false, state["local_access"])
	require.Equal(t, true, state["remote_session"])
	do("POST", remote+"/api/v1/privacy/clear", `{}`, "", 401)
	do("POST", remote+"/api/v1/privacy/clear", `{}`, csrf, 200)
	do("POST", remote+"/api/v1/access/lan", `{"enabled":false}`, csrf, 403)
	do("POST", remote+"/api/v1/pairing", `{"role":"read"}`, csrf, 404)
	for _, forged := range []string{"host", "origin"} {
		r, err := http.NewRequest("GET", remote+"/api/v1/state", nil)
		require.NoError(t, err)
		if forged == "host" {
			r.Host = "untrusted.example:" + port
		} else {
			r.Header.Set("Origin", "http://untrusted.example:"+port)
		}
		response, err := client.Do(r)
		require.NoError(t, err)
		response.Body.Close()
		require.Equal(t, 403, response.StatusCode)
	}

	status, _ = do("POST", local.URL+"/api/v1/access/lan", `{"enabled":true,"address":"0.0.0.0:`+port+`","https":true}`, localCSRF, 200)
	require.Equal(t, true, status["trust_required"])
	require.NotEmpty(t, status["fingerprint"])
	certificate, err := os.ReadFile(filepath.Join(directory, "lan-ca.pem"))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certificate))
	tlsTransport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	defer tlsTransport.CloseIdleConnections()
	client.Transport = tlsTransport
	remote = "https://127.0.0.1:" + port
	do("GET", remote+"/api/v1/state", "", "", 401)
	_, response = do("POST", remote+"/api/v1/session", `{"password":"remote-password"}`, "", 200)
	require.Equal(t, "kone_remote_session", response.Cookies()[0].Name)
	require.True(t, response.Cookies()[0].Secure)
	do("GET", remote+"/api/v1/state", "", "", 200)
	status, _ = do("POST", local.URL+"/api/v1/access/lan", `{"enabled":true,"address":"0.0.0.0:`+port+`","https":false}`, localCSRF, 200)
	require.NotContains(t, status, "fingerprint")
	client.Transport = transport
	remote = "http://127.0.0.1:" + port
	do("GET", remote+"/api/v1/state", "", "", 401)
	do("POST", remote+"/api/v1/session", `{"password":"remote-password"}`, "", 200)
	do("GET", remote+"/api/v1/state", "", "", 200)
	do("POST", local.URL+"/api/v1/access/lan", `{"enabled":false}`, localCSRF, 200)
	state, _ = do("GET", local.URL+"/api/v1/state", "", "", 200)
	require.Equal(t, true, state["local_access"])
	require.Equal(t, "paused", state["data_state"])
}
