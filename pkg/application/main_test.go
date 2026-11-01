package application

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })
	for _, key := range []string{"http_proxy", "https_proxy", "socks_proxy", "HTTP_PROXY", "HTTPS_PROXY", "SOCKS_PROXY"} {
		t.Setenv(key, "")
	}
	filename := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(filename, []byte("[dns]\nservers=['1.1.1.1']\n"), 0600))
	missingGeoIP := filepath.Join(t.TempDir(), "geoip.toml")
	require.NoError(t, os.WriteFile(missingGeoIP, []byte("[geoip]\nprovider='ipinfo-lite'\nfile='missing.mmdb'\nsha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n"), 0600))
	for _, tc := range []struct {
		name     string
		args     []string
		code     int
		out, err string
	}{
		{"version", []string{"-version"}, 0, "Version:", ""},
		{"help", []string{"-help"}, 0, "", "TOML"},
		{"unknown", []string{"-unknown"}, 2, "", "flag provided but not defined"},
		{"check", []string{"-check", "-config", filename}, 0, "Configuration valid", ""},
		{"check missing GeoIP", []string{"-check", "-config", missingGeoIP}, 2, "", "GeoIP configuration error"},
		{"debug", []string{"-debug", "-check", filename}, 0, "Configuration valid", ""},
		{"ambiguous", []string{"-config", filename, filename}, 2, "", "either -config"},
		{"extra arguments", []string{"one", "two"}, 2, "", "at most one"},
		{"missing", []string{"-config", filename + ".missing"}, 2, "", "Configuration error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, err bytes.Buffer
			require.Equal(t, tc.code, run(tc.args, &out, &err))
			require.Contains(t, out.String(), tc.out)
			require.Contains(t, err.String(), tc.err)
		})
	}
}
