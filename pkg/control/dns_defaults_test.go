package control

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestManagementDNSDefaultKeepsCapturePausedAndPreservesSavedGateMode(t *testing.T) {
	var starts atomic.Int32
	options := Options{Directory: t.TempDir(), Factory: func(*kone.KoneConfig) (Engine, error) { starts.Add(1); return newMemoryEngine(), nil }}
	c := testController(t, options)
	require.Equal(t, kone.SupportsSystemDNS(), c.doc.Config.DNS.System)
	require.Equal(t, "paused", c.State().State)
	require.True(t, c.doc.Inbound.Enabled)
	require.Zero(t, starts.Load(), "initializing management never starts system DNS or capture")
	request := currentRequest(c)
	config := *c.doc.Config
	config.DNS.System = false
	config.DNS.Mode = "gate"
	config.DNS.ListenAddress = "192.0.2.10"
	request.Config = jsonConfig(&config)
	_, err := c.Save(request)
	require.NoError(t, err)
	require.NoError(t, c.Close())
	again := testController(t, options)
	require.False(t, again.doc.Config.DNS.SystemEnabled(), "saved Gate mode must not be reset to Host")
	require.Equal(t, "gate", again.doc.Config.DNS.Mode)
	require.Equal(t, "paused", again.State().State)
	require.Zero(t, starts.Load())
}
