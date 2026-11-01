package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func legacyProfile(t *testing.T, path, configuration string) []byte {
	t.Helper()
	confirmed := false
	data, err := json.Marshal(storedDocument{Version: 8, TOML: configuration, Inbound: Inbound{ID: "tun-test", Name: "Office", Enabled: true}, DirectOnlyConfirmed: &confirmed})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
	return data
}

func TestManagedProfileRetiresLegacyManagerWithoutLosingSettings(t *testing.T) {
	for _, address := range []string{"", "127.0.0.1:9200", "0.0.0.0:9200"} {
		t.Run(address, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			original := legacyProfile(t, path, "[general]\nmanager-addr='"+address+"'\nlog-format='json'\n[[outbounds]]\nname='office'\nurl='http://alice:secret@127.0.0.1:8080'\n[[rules]]\ntype='FINAL'\noutbound='office'\n")
			doc, err := readDocument(path)
			require.NoError(t, err)
			require.Equal(t, uint64(8), doc.Version)
			require.Equal(t, Inbound{ID: "tun-test", Name: "Office", Enabled: true}, doc.Inbound)
			require.False(t, doc.DirectOnlyConfirmed)
			require.Equal(t, "json", doc.Config.General.LogFormat)
			require.Equal(t, "http://alice:secret@127.0.0.1:8080", doc.Config.Outbounds[0].URL)
			require.Equal(t, "office", doc.Config.Rule[0].Outbound)
			for _, filename := range []string{path, path + ".legacy-manager"} {
				data, err := os.ReadFile(filename)
				require.NoError(t, err)
				require.Equal(t, original, data)
			}
			info, err := os.Stat(path + ".legacy-manager")
			require.NoError(t, err)
			if runtime.GOOS != "windows" {
				require.Equal(t, os.FileMode(0600), info.Mode().Perm())
			}
			require.NoError(t, writeDocument(path, doc))
			updated, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NotContains(t, string(updated), "manager-addr")
			backup, err := os.ReadFile(path + ".legacy-manager")
			require.NoError(t, err)
			require.Equal(t, original, backup)
		})
	}
}

func TestLegacyProfileMigrationIsStrictAndPreservesFirstBackup(t *testing.T) {
	for _, configuration := range []string{
		"[general]\nmanager-addr=1\n",
		"[general]\nmanager-addr=''\nmisspelled-option=true\n",
		"[general]\nmisspelled-option=true\n",
		"[general\nmanager-addr=''\n",
	} {
		path := filepath.Join(t.TempDir(), "settings.json")
		original := legacyProfile(t, path, configuration)
		_, err := readDocument(path)
		require.Error(t, err)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, original, data)
		_, err = os.Stat(path + ".legacy-manager")
		require.ErrorIs(t, err, os.ErrNotExist)
	}
	path := filepath.Join(t.TempDir(), "settings.json")
	legacyProfile(t, path, "[general]\nmanager-addr=''\n")
	require.NoError(t, os.WriteFile(path+".legacy-manager", []byte("first backup"), 0600))
	_, err := readDocument(path)
	require.NoError(t, err)
	data, err := os.ReadFile(path + ".legacy-manager")
	require.NoError(t, err)
	require.Equal(t, "first backup", string(data))
}

func TestNewManagedWritesRejectLegacyManagerOption(t *testing.T) {
	_, err := decodeManaged(map[string]any{"general": map[string]any{"manager-addr": ""}})
	require.ErrorContains(t, err, "general.manager-addr was removed")
}
