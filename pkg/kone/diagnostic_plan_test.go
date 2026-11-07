package kone

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiagnosticPlanPinsDialIPAndVerifiesDomainThroughDirectAndHTTPProxy(t *testing.T) {
	cleanProxyEnv(t)
	names := make(chan string, 8)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("probe sent HTTP application traffic") }))
	target.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { names <- hello.ServerName; return nil, nil }}
	target.StartTLS()
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	name := target.Certificate().DNSNames[0]
	endpoint := strings.TrimPrefix(target.URL, "https://")
	pinned := make(chan string, 8)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			http.Error(w, "CONNECT only", 400)
			return
		}
		pinned <- r.Host
		upstream, err := net.Dial("tcp", endpoint)
		if err != nil {
			http.Error(w, "target", 502)
			return
		}
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		defer client.Close()
		defer upstream.Close()
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, client); upstream.Close(); close(done) }()
		_, _ = io.Copy(client, upstream)
		client.Close()
		<-done
	}))
	defer proxy.Close()
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:5353"}
	cfg.Outbounds = []OutboundConfig{{Name: "office", URL: proxy.URL}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	defer one.Close()
	one.policy.Load().outbounds.directDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		pinned <- address
		return (&net.Dialer{}).DialContext(ctx, network, endpoint)
	}
	for _, outbound := range []string{BuiltinDirect, "office"} {
		result, err := one.probeDiagnosticPlan(t.Context(), outbound, "8.8.8.8:443", true, 0, diagnosticProbePlan{serverName: name, tlsConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}})
		require.NoError(t, err)
		require.Equal(t, "reachable", result.Status, result.Message)
		require.True(t, result.Protocols.TLS.Tested)
		require.Equal(t, "healthy", result.Protocols.TLS.Status)
		require.Equal(t, "8.8.8.8:443", <-pinned)
		require.Equal(t, name, <-names)
	}
	result, err := one.probeDiagnosticPlan(t.Context(), BuiltinDirect, "8.8.8.8:443", true, 0, diagnosticProbePlan{serverName: "different.invalid", tlsConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}})
	require.NoError(t, err)
	require.Equal(t, "failed", result.Status)
	require.Equal(t, "tls_verification", result.FailureKind)
	require.Equal(t, "failed", result.Protocols.TLS.Status)
}
