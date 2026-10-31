package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/geoip"
)

func controlGeoIPFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	data, err := json.Marshal(geoip.File{Format: 1, Version: "fixture-1", Source: "https://example.com/countries", License: "CC0-1.0", LicenseURL: "https://creativecommons.org/publicdomain/zero/1.0/", PublishedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), Ranges: geoip.Ranges{{Start: "192.0.2.0", End: "192.0.2.255", Country: "CN"}}})
	require.NoError(t, err)
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:])
}
func TestGeoIPManagementPersistsAndRequiresExplicitPausedUpdate(t *testing.T) {
	c := testController(t, Options{})
	token := owner(t, c)
	data, digest := controlGeoIPFixture(t)
	old := geoip.Builtin().Metadata().SHA256
	_, err := c.updateGeoIP(99, old, data, digest, false)
	require.ErrorIs(t, err, ErrConflict)
	_, err = c.updateGeoIP(c.doc.Version, "stale", data, digest, false)
	require.ErrorIs(t, err, ErrConflict)
	_, err = c.updateGeoIP(c.doc.Version, old, data, "wrong digest", false)
	require.Error(t, err)
	result, err := c.updateGeoIP(c.doc.Version, old, data, digest, false)
	require.NoError(t, err)
	require.Equal(t, digest, result["saved"].(geoip.Metadata).SHA256)
	require.Equal(t, 200, request(t, c, token, "GET", "/api/v1/geoip", nil).Code)
	_, err = c.updateGeoIP(c.doc.Version, digest, nil, "", true)
	require.NoError(t, err)
	_, err = c.updateGeoIP(c.doc.Version, old, data, digest, false)
	require.NoError(t, err)
	repository, err := geoip.OpenRepository(filepath.Join(c.directory, "geoip"))
	require.NoError(t, err)
	require.Equal(t, digest, repository.Current().Metadata().SHA256)
	enable(t, c)
	require.NoError(t, c.Start(t.Context()))
	_, err = c.updateGeoIP(c.doc.Version, digest, nil, "", true)
	require.ErrorContains(t, err, "pause")
	require.NoError(t, c.Pause(t.Context()))
	r := httptest.NewRequest("PUT", "http://127.0.0.1:9200/api/v1/geoip", strings.NewReader(string(data)))
	r.RemoteAddr = "127.0.0.1:50000"
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("If-Match", "2")
	r.Header.Set("X-Content-SHA256", digest)
	r.Header.Set("X-GeoIP-Base-SHA256", digest)
	w := httptest.NewRecorder()
	c.Handler().ServeHTTP(w, r)
	require.Equal(t, 200, w.Code, w.Body.String())
	require.Equal(t, 200, request(t, c, token, "POST", "/api/v1/geoip/rollback", map[string]any{"base_version": c.doc.Version, "base_sha256": digest}).Code)
	require.Equal(t, 400, request(t, c, token, "PUT", "/api/v1/geoip", "bad").Code)
}

func TestSavedGeoIPDamageKeepsManagementAndBlocksCapture(t *testing.T) {
	c := testController(t, Options{})
	require.NoError(t, os.MkdirAll(filepath.Join(c.directory, "geoip"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(c.directory, "geoip", "manifest.json"), []byte("broken"), 0600))
	_, err := c.geoIPStatus()
	require.Error(t, err)
	token := owner(t, c)
	require.Equal(t, 400, request(t, c, token, "GET", "/api/v1/geoip", nil).Code)
	require.Equal(t, 400, request(t, c, token, "POST", "/api/v1/rules/simulate", map[string]any{"target": "example.com", "port": 443}).Code)
	directory, err := DefaultDirectory()
	require.NoError(t, err)
	require.Equal(t, "kone", filepath.Base(directory))
}
