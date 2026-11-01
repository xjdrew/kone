package geoip

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepositoryFingerprintKeepsManifestPathsBounded(t *testing.T) {
	_, err := FingerprintRepository("")
	require.Error(t, err)
	directory := t.TempDir()
	before, err := FingerprintRepository(directory)
	require.NoError(t, err)
	require.False(t, before.HasManifest())
	repository, err := OpenRepository(directory)
	require.NoError(t, err)
	require.True(t, before.MatchesRepository(repository))
	require.False(t, before.MatchesRepository(nil))
	for _, manifest := range []string{
		`{"format":1,"current":"../../outside"}`,
		`{"format":1,"current":"builtin","previous":"../outside"}`,
		`{"format":2,"current":"builtin","mmdb_providers":{"builtin":"ipinfo-lite"}}`,
	} {
		require.NoError(t, os.WriteFile(filepath.Join(directory, "manifest.json"), []byte(manifest), 0600))
		_, err = FingerprintRepository(directory)
		require.Error(t, err)
	}
	require.NoError(t, ResetBuiltin(directory))
	after, err := FingerprintRepository(directory)
	require.NoError(t, err)
	require.True(t, after.HasManifest())
	require.False(t, before.Equal(after))
	require.True(t, after.MatchesRepository(repository))
}

func TestRepositoryManifestRejectsNonRegularPathsBeforeOpening(t *testing.T) {
	directory := t.TempDir()
	manifest := filepath.Join(directory, "manifest.json")
	require.NoError(t, os.Mkdir(manifest, 0700))
	_, err := FingerprintRepository(directory)
	require.ErrorContains(t, err, "regular file")
	_, err = OpenRepository(directory)
	require.ErrorContains(t, err, "regular file")
	require.NoError(t, os.Remove(manifest))
	require.NoError(t, os.WriteFile(manifest, make([]byte, 4097), 0600))
	_, err = FingerprintRepository(directory)
	require.ErrorContains(t, err, "4096")
}
