package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

func TestPasswordProfileParametersAndDeterminism(t *testing.T) {
	require.Equal(t, 2, passwordVersion)
	require.Equal(t, 19456, passwordMemory)
	require.Equal(t, 2, passwordIterations)
	require.Equal(t, 1, passwordParallelism)
	salt := []byte("0123456789abcdef")
	key := passwordKey("kone-version-two-password", salt)
	require.Equal(t, []byte{
		0x11, 0x7f, 0x7b, 0xb5, 0x55, 0xa2, 0xce, 0x41,
		0xde, 0x33, 0xd0, 0x34, 0xbf, 0xbc, 0xb3, 0x6b,
		0x2f, 0xa5, 0x25, 0xf6, 0x6d, 0xef, 0xf6, 0xe1,
		0x77, 0x82, 0x15, 0x29, 0x30, 0xb9, 0x60, 0x2f,
	}, key)
	require.Equal(t, key, passwordKey("kone-version-two-password", salt))
	require.NotEqual(t, key, passwordKey("different-owner-password", salt))
	require.NotEqual(t, key, passwordKey("kone-version-two-password", []byte("fedcba9876543210")))
}

func TestUnsupportedPasswordVersionsFailClosedWithoutChangingTheFile(t *testing.T) {
	for _, version := range []int{1, 3} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "auth.json")
			data, err := json.Marshal(passwordCredentials{Version: version, Salt: []byte("0123456789abcdef"), Hash: make([]byte, 32)})
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, data, 0600))
			_, err = New(Options{Directory: directory})
			require.ErrorContains(t, err, "password format is unsupported")
			require.ErrorIs(t, err, ErrPasswordFormatUnsupported)
			require.ErrorContains(t, err, "auth.json")
			preserved, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, data, preserved)
		})
	}
}

func BenchmarkPasswordKey(b *testing.B) {
	salt := []byte("0123456789abcdef")
	b.Run("v2_19MiB_t2_p1", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			passwordKey("benchmark-owner-password", salt)
		}
	})
	// This reference measures the previous cost without supporting its format.
	b.Run("reference_64MiB_t3_p1", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			argon2.IDKey([]byte("benchmark-owner-password"), salt, 3, 64*1024, 1, 32)
		}
	})
}
