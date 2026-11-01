package control

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNetworkMonitorReadsTheRealPlatformWithoutChangingIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sample, err := sampleNetwork(ctx, "")
	require.NoError(t, err)
	require.Len(t, sample.interfaces, 64)
	require.Len(t, sample.dns, 64)
	require.Len(t, sample.routes, 64)
	stopCtx, stop := context.WithCancel(context.Background())
	stop()
	select {
	case _, ok := <-WatchNetworkChanges(stopCtx, "", time.Millisecond):
		require.False(t, ok)
	case <-time.After(time.Second):
		t.Fatal("canceled network watcher did not stop")
	}
}

func TestLANTrustExpiryMismatchedKeysAndShutdownAreExplicit(t *testing.T) {
	now := time.Now()
	c := testController(t, Options{Now: func() time.Time { return now }})
	_, _, err := c.lanCertificate(net.ParseIP("192.168.40.2"))
	require.NoError(t, err)
	now = now.AddDate(2, 0, 0)
	_, _, err = c.lanCertificate(net.ParseIP("192.168.40.2"))
	require.ErrorContains(t, err, "expired")
	other := testController(t, Options{})
	_, _, err = other.lanCertificate(net.ParseIP("192.168.40.3"))
	require.NoError(t, err)
	otherKey, err := os.ReadFile(filepath.Join(other.directory, "lan-ca-key.pem"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(c.directory, "lan-ca-key.pem"), otherKey, 0600))
	_, _, err = c.lanCertificate(net.ParseIP("192.168.40.2"))
	require.ErrorContains(t, err, "do not match")
	require.NoError(t, other.Close())
	_, err = other.SetLAN(true, "192.168.40.3:9201")
	require.ErrorContains(t, err, "stopping")
}

func TestLoopbackHostCannotAuthorizeRemoteRequests(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	r := httptest.NewRequest("GET", "http://127.0.0.1:9200/api/v1/state", nil)
	r.RemoteAddr = "192.168.40.3:50000"
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	c.Handler().ServeHTTP(w, r)
	require.Equal(t, 403, w.Code)
}
