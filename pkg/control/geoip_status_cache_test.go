package control

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/geoip"
)

func TestGeoIPStatusCacheAvoidsMMDBReloadAndDetectsReplacement(t *testing.T) {
	directory := t.TempDir()
	repository, err := geoip.OpenRepository(directory)
	require.NoError(t, err)
	data, digest := controlMMDBFixture(t)
	_, err = repository.InstallMMDB(data, digest, "ipinfo-lite")
	require.NoError(t, err)
	var cache geoIPStatusCache
	loads := 0
	loader := func(path string) (*geoip.Repository, error) { loads++; return geoip.OpenRepository(path) }
	first, err := cache.load(directory, loader)
	require.NoError(t, err)
	require.Equal(t, digest, first.current.SHA256)
	for range 10 {
		next, err := cache.load(directory, loader)
		require.NoError(t, err)
		require.Equal(t, first, next)
	}
	require.Equal(t, 1, loads, "a status poll must not reverify the MMDB")
	path := filepath.Join(directory, digest+".mmdb")
	info, err := os.Stat(path)
	require.NoError(t, err)
	replacement := filepath.Join(directory, "replacement")
	require.NoError(t, os.WriteFile(replacement, data, 0600))
	require.NoError(t, os.Chtimes(replacement, info.ModTime(), info.ModTime()))
	require.NoError(t, os.Rename(replacement, path))
	_, err = cache.load(directory, loader)
	require.NoError(t, err)
	require.Equal(t, 2, loads, "same-size/same-mtime replacement still changes file identity")
	broken := append([]byte(nil), data...)
	broken[0] ^= 0xff
	require.NoError(t, os.WriteFile(path, broken, 0600))
	require.NoError(t, os.Chtimes(path, time.Now(), info.ModTime().Add(time.Minute)))
	value, err := cache.load(directory, loader)
	require.ErrorContains(t, err, "SHA256")
	require.Empty(t, value.current.SHA256, "damage must not return the previous cached metadata")
	require.Equal(t, 3, loads)
	require.NoError(t, os.WriteFile(path, data, 0600))
	_, err = cache.load(directory, loader)
	require.NoError(t, err)
	require.Equal(t, 4, loads)
}

func TestGeoIPStatusCacheTracksManifestAndPreviousDatabaseDamage(t *testing.T) {
	directory := t.TempDir()
	repository, err := geoip.OpenRepository(directory)
	require.NoError(t, err)
	previous, previousDigest := controlGeoIPFixture(t)
	_, err = repository.Install(previous, previousDigest)
	require.NoError(t, err)
	data, digest := controlMMDBFixture(t)
	_, err = repository.InstallMMDB(data, digest, "ipinfo-lite")
	require.NoError(t, err)
	var cache geoIPStatusCache
	loads := 0
	loader := func(path string) (*geoip.Repository, error) { loads++; return geoip.OpenRepository(path) }
	value, err := cache.load(directory, loader)
	require.NoError(t, err)
	require.True(t, value.hasPrevious)
	require.Equal(t, previousDigest, value.previous.SHA256)
	manifestPath := filepath.Join(directory, "manifest.json")
	manifest, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, append(manifest, '\n'), 0600))
	_, err = cache.load(directory, loader)
	require.NoError(t, err)
	require.Equal(t, 2, loads, "manifest bytes are part of the cache key")
	path := filepath.Join(directory, previousDigest+".json")
	require.NoError(t, os.WriteFile(path, []byte("broken rollback data"), 0600))
	_, err = cache.load(directory, loader)
	require.ErrorContains(t, err, "rollback")
	require.NoError(t, os.WriteFile(path, previous, 0600))
	require.NoError(t, os.Remove(manifestPath))
	for range 2 {
		_, err = cache.load(directory, loader)
		require.ErrorContains(t, err, "manifest disappeared")
	}
	require.NoError(t, geoip.ResetBuiltin(directory))
	value, err = cache.load(directory, loader)
	require.NoError(t, err)
	require.True(t, value.current.Builtin)
	require.NoError(t, os.WriteFile(manifestPath, []byte("invalid"), 0600))
	_, err = cache.load(directory, loader)
	require.ErrorContains(t, err, "manifest")
}

func TestGeoIPStatusCacheConcurrentReadersValidateOnce(t *testing.T) {
	directory := t.TempDir()
	var cache geoIPStatusCache
	var loads atomic.Int32
	loader := func(path string) (*geoip.Repository, error) { loads.Add(1); return geoip.OpenRepository(path) }
	errorsSeen := make(chan error, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 10 {
				metadata, err := cache.load(directory, loader)
				if err != nil {
					errorsSeen <- err
					return
				}
				if !metadata.current.Builtin {
					errorsSeen <- errors.New("fresh profile lost builtin metadata")
					return
				}
			}
		})
	}
	workers.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, loads.Load())
}

func TestGeoIPStatusCacheRejectsConcurrentPublication(t *testing.T) {
	directory := t.TempDir()
	var cache geoIPStatusCache
	data, digest := controlGeoIPFixture(t)
	loader := func(path string) (*geoip.Repository, error) {
		repository, err := geoip.OpenRepository(path)
		if err == nil {
			_, err = repository.Install(data, digest)
		}
		return repository, err
	}
	_, err := cache.load(directory, loader)
	require.ErrorContains(t, err, "changed during")
	_, err = cache.load(directory, geoip.OpenRepository)
	require.NoError(t, err)
	// An A -> B -> A manifest change can leave matching before/after fingerprints
	// while the loader returned B. Verify the loaded snapshot's identity too.
	cache.valid = false
	manifestPath := filepath.Join(directory, "manifest.json")
	manifest, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	_, err = cache.load(directory, func(path string) (*geoip.Repository, error) {
		if err := geoip.ResetBuiltin(path); err != nil {
			return nil, err
		}
		repository, err := geoip.OpenRepository(path)
		if err == nil {
			err = os.WriteFile(manifestPath, manifest, 0600)
		}
		return repository, err
	})
	require.ErrorContains(t, err, "changed during")
}
