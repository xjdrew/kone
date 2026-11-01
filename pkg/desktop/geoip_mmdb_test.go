package desktop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/geoip"
	"github.com/xjdrew/kone/pkg/kone"
)

func desktopMMDBFixture(t *testing.T) *geoip.Database {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{IPVersion: 6, IncludeReservedNetworks: true, DatabaseType: "Synthetic-Country", Description: map[string]string{"en": "Synthetic test data"}, Languages: []string{"en"}, BuildEpoch: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix()})
	require.NoError(t, err)
	_, network, err := net.ParseCIDR("2001:db8::/32")
	require.NoError(t, err)
	require.NoError(t, tree.Insert(network, mmdbtype.Map{"country_code": mmdbtype.String("CN")}))
	var output bytes.Buffer
	_, err = tree.WriteTo(&output)
	require.NoError(t, err)
	digest := sha256.Sum256(output.Bytes())
	database, err := geoip.LoadMMDB(bytes.NewReader(output.Bytes()), hex.EncodeToString(digest[:]), "ipinfo-lite")
	require.NoError(t, err)
	return database
}

func TestRemoteHelperCarriesMMDBSchemaAcrossStartupAndUpdates(t *testing.T) {
	remote, _, helperDone := helperHarness(t, false)
	database := desktopMMDBFixture(t)
	require.NoError(t, remote.SetTrafficObserver(kone.NewTrafficObserver(kone.ObservationOptions{})))
	require.NoError(t, remote.SetConfigVersion(7))
	require.NoError(t, remote.SetCaptureRecorder(func(string, int) error { return nil }))
	require.NoError(t, remote.SetGeoIPDatabase(database))
	done := make(chan error, 1)
	go func() { done <- remote.Run(context.Background()) }()
	select {
	case <-remote.Ready():
	case err := <-done:
		t.Fatalf("helper MMDB startup failed: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("helper never became ready with MMDB")
	}
	status, err := remote.GeoIPData()
	require.NoError(t, err)
	require.Equal(t, "ipinfo-lite", status.Current.Provider)
	require.True(t, status.Current.IPv6)
	require.Equal(t, database.Metadata().SHA256, status.Current.SHA256)
	require.NoError(t, remote.ApplyGeoIPDatabase(geoip.Builtin(), status.PolicyVersion))
	status, err = remote.GeoIPData()
	require.NoError(t, err)
	require.True(t, status.Current.Builtin)
	require.NoError(t, remote.ApplyGeoIPDatabase(database, status.PolicyVersion))
	status, err = remote.GeoIPData()
	require.NoError(t, err)
	require.Equal(t, "mmdb", status.Current.Format)
	require.Equal(t, database.Metadata().SHA256, status.Current.SHA256)
	require.NoError(t, remote.Close())
	require.NoError(t, <-done)
	require.NoError(t, <-helperDone)
}

func TestHelperRejectsUnrecognizedMMDBSchemaWithoutChangingSnapshot(t *testing.T) {
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:5353"}
	engine := newFakeNetworkEngine(t, cfg)
	t.Cleanup(func() { require.NoError(t, engine.Close()) })
	database := desktopMMDBFixture(t)
	before := engine.GeoIPStatus()
	for _, request := range []GeoIPRequest{
		{Data: database.Bytes(), SHA256: database.Metadata().SHA256, Format: "mmdb", Provider: "unknown"},
		{Data: database.Bytes(), SHA256: database.Metadata().SHA256, Format: "mmdb", Provider: "dbip-lite"},
		{Data: database.Bytes(), SHA256: database.Metadata().SHA256, Format: "unsupported"},
	} {
		require.Error(t, applyHelperGeoIP(engine, request))
		require.Equal(t, before, engine.GeoIPStatus())
	}
}
