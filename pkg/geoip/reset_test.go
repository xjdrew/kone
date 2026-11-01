package geoip

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExplicitResetRestoresBuiltinAndRepairsDamagedManifest(t *testing.T) {
	directory := t.TempDir()
	repository, err := OpenRepository(directory)
	require.NoError(t, err)
	data, digest := fixtureBytes(t, fixtureFile("CN", "v1"))
	_, err = repository.Install(data, digest)
	require.NoError(t, err)
	require.NoError(t, ResetBuiltin(directory))
	reopened, err := OpenRepository(directory)
	require.NoError(t, err)
	require.True(t, reopened.Current().Metadata().Builtin)
	require.Nil(t, reopened.Previous())
	require.FileExists(t, filepath.Join(directory, digest+".json"), "explicit profile backups can retain their uploaded data")
	require.NoError(t, os.WriteFile(filepath.Join(directory, "manifest.json"), []byte("damaged"), 0600))
	require.NoError(t, ResetBuiltin(directory))
	reopened, err = OpenRepository(directory)
	require.NoError(t, err)
	require.True(t, reopened.Current().Metadata().Builtin)
	require.Error(t, ResetBuiltin(""))
	require.Error(t, ResetBuiltin(filepath.Join(directory, "manifest.json", "child")))
}
