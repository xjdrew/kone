package geoip

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// RepositoryFingerprint is an opaque change detector for a previously verified
// status snapshot. It is not a substitute for validating data before routing,
// import or recovery. Only manifest-selected, content-addressed files are read.
type RepositoryFingerprint struct {
	manifest                          []byte
	files                             []repositoryFileFingerprint
	current, previous                 string
	currentProvider, previousProvider string
}

type repositoryFileFingerprint struct {
	name string
	info os.FileInfo
}

func (f RepositoryFingerprint) HasManifest() bool { return len(f.manifest) != 0 }

// MatchesRepository also checks what the loader actually validated. A manifest
// can change A -> B -> A during a slow load even when both final stats agree.
func (f RepositoryFingerprint) MatchesRepository(repository *Repository) bool {
	if repository == nil {
		return false
	}
	match := func(database *Database, key, provider string) bool {
		if repositoryKey(database) != key {
			return false
		}
		if provider != "" {
			return database != nil && database.mmdb != nil && database.metadata.Provider == provider
		}
		return database == nil || database.mmdb == nil
	}
	return match(repository.Current(), f.current, f.currentProvider) && match(repository.Previous(), f.previous, f.previousProvider)
}

func (f RepositoryFingerprint) Equal(other RepositoryFingerprint) bool {
	if !bytes.Equal(f.manifest, other.manifest) || len(f.files) != len(other.files) {
		return false
	}
	for index, file := range f.files {
		candidate := other.files[index]
		if file.name != candidate.name || file.info.Size() != candidate.info.Size() || file.info.Mode() != candidate.info.Mode() || !file.info.ModTime().Equal(candidate.info.ModTime()) || !os.SameFile(file.info, candidate.info) {
			return false
		}
	}
	return true
}

func FingerprintRepository(directory string) (RepositoryFingerprint, error) {
	fingerprint := RepositoryFingerprint{current: "builtin"}
	if directory == "" {
		return fingerprint, errors.New("GeoIP repository directory is required")
	}
	manifest, raw, err := readRepositoryManifestSnapshot(directory)
	if errors.Is(err, os.ErrNotExist) {
		return fingerprint, nil
	}
	if err != nil {
		return fingerprint, err
	}
	fingerprint.manifest = raw
	fingerprint.current, fingerprint.previous = manifest.Current, manifest.Previous
	fingerprint.currentProvider, fingerprint.previousProvider = manifest.MMDBProviders[manifest.Current], manifest.MMDBProviders[manifest.Previous]
	for _, key := range []string{manifest.Current, manifest.Previous} {
		if key == "" || key == "builtin" {
			continue
		}
		if !validDigest(key) {
			return RepositoryFingerprint{}, errors.New("invalid GeoIP manifest digest")
		}
		extension := ".json"
		if manifest.MMDBProviders[key] != "" {
			extension = ".mmdb"
		}
		name := key + extension
		path := filepath.Join(directory, name)
		// Reject non-regular paths before Open, which could block on a FIFO.
		before, err := os.Lstat(path)
		if err != nil || !before.Mode().IsRegular() {
			return RepositoryFingerprint{}, fmt.Errorf("GeoIP status dataset is absent or not a regular file: %s", name)
		}
		file, err := os.Open(path)
		if err != nil {
			return RepositoryFingerprint{}, err
		}
		info, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || closeErr != nil {
			return RepositoryFingerprint{}, errors.Join(statErr, closeErr)
		}
		if !info.Mode().IsRegular() || !os.SameFile(before, info) {
			return RepositoryFingerprint{}, errors.New("GeoIP status dataset changed during inspection")
		}
		// Retain the handle stat's identity; os.Stat(path) may defer resolving
		// Windows file IDs until a later replacement is already present.
		fingerprint.files = append(fingerprint.files, repositoryFileFingerprint{name: name, info: info})
	}
	return fingerprint, nil
}
