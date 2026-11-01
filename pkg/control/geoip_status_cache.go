package control

import (
	"errors"
	"sync"

	"github.com/xjdrew/kone/pkg/geoip"
)

type geoIPStatusMetadata struct {
	current     geoip.Metadata
	previous    geoip.Metadata
	hasPrevious bool
}

// Keep only validated metadata here: a status poll must neither scan millions
// of MMDB networks nor retain another complete pair of database byte buffers.
// This lock is independent from the lifecycle/controller mutex.
type geoIPStatusCache struct {
	mu           sync.Mutex
	fingerprint  geoip.RepositoryFingerprint
	metadata     geoIPStatusMetadata
	valid        bool
	seenManifest bool
}

func (cache *geoIPStatusCache) load(directory string, loader func(string) (*geoip.Repository, error)) (geoIPStatusMetadata, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	before, err := geoip.FingerprintRepository(directory)
	if err != nil {
		cache.valid = false
		return geoIPStatusMetadata{}, err
	}
	if cache.seenManifest && !before.HasManifest() {
		cache.valid = false
		return geoIPStatusMetadata{}, errors.New("saved GeoIP manifest disappeared; repair it or explicitly restore builtin data")
	}
	if cache.valid && cache.fingerprint.Equal(before) {
		return cache.metadata, nil
	}
	cache.valid = false
	repository, err := loader(directory)
	if err != nil {
		return geoIPStatusMetadata{}, err
	}
	after, err := geoip.FingerprintRepository(directory)
	if err != nil {
		return geoIPStatusMetadata{}, err
	}
	if !before.Equal(after) || !after.MatchesRepository(repository) {
		return geoIPStatusMetadata{}, errors.New("GeoIP repository changed during status validation; retry the request")
	}
	metadata := geoIPStatusMetadata{current: repository.Current().Metadata()}
	if previous := repository.Previous(); previous != nil {
		metadata.previous, metadata.hasPrevious = previous.Metadata(), true
	}
	cache.fingerprint, cache.metadata, cache.valid = after, metadata, true
	cache.seenManifest = cache.seenManifest || after.HasManifest()
	return metadata, nil
}
