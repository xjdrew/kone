package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/geoip"
)

func controlMMDBFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{IPVersion: 6, IncludeReservedNetworks: true, DatabaseType: "Synthetic-Country", Description: map[string]string{"en": "Synthetic test data"}, Languages: []string{"en"}, BuildEpoch: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix()})
	require.NoError(t, err)
	_, network, err := net.ParseCIDR("2001:db8::/32")
	require.NoError(t, err)
	require.NoError(t, tree.Insert(network, mmdbtype.Map{"country_code": mmdbtype.String("CN")}))
	var data bytes.Buffer
	_, err = tree.WriteTo(&data)
	require.NoError(t, err)
	digest := sha256.Sum256(data.Bytes())
	return data.Bytes(), hex.EncodeToString(digest[:])
}

func TestGeoIPMMDBUploadUsesExplicitSchemaAndPersistentChecksum(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	data, digest := controlMMDBFixture(t)
	old := geoip.Builtin().Metadata().SHA256
	for _, testcase := range []struct {
		format, provider string
		status           int
	}{
		{"mmdb", "unknown", 400}, {"bad", "ipinfo-lite", 400}, {"mmdb", "dbip-lite", 400}, {"mmdb", "ipinfo-lite", 200},
	} {
		r := httptest.NewRequest("PUT", "http://127.0.0.1:9200/api/v1/geoip", bytes.NewReader(data))
		r.RemoteAddr = "127.0.0.1:50000"
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("If-Match", strconv.FormatUint(c.doc.Version, 10))
		r.Header.Set("X-GeoIP-Base-SHA256", old)
		r.Header.Set("X-Content-SHA256", digest)
		r.Header.Set("X-GeoIP-Format", testcase.format)
		r.Header.Set("X-GeoIP-Provider", testcase.provider)
		w := httptest.NewRecorder()
		c.Handler().ServeHTTP(w, r)
		require.Equal(t, testcase.status, w.Code, w.Body.String())
	}
	status, err := c.geoIPStatus()
	require.NoError(t, err)
	require.Len(t, status["providers"], 3)
	metadata := status["saved"].(geoip.Metadata)
	require.Equal(t, "ipinfo-lite", metadata.Provider)
	require.True(t, metadata.IPv6)
	require.False(t, metadata.IPv4)
	require.Equal(t, digest, metadata.SHA256)
	_, err = c.updateGeoIPFormat(c.doc.Version, digest, nil, "", "", "", true)
	require.NoError(t, err)
}
