package geoip

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type repositoryManifest struct {
	Format   int    `json:"format"`
	Current  string `json:"current"`
	Previous string `json:"previous,omitempty"`
}

// Repository retains the active file and one rollback file. No source URL is
// fetched. A corrupt saved manifest/database is an error, never an implicit
// switch to old bundled data that would silently change routing decisions.
type Repository struct {
	mu                sync.Mutex
	directory         string
	current, previous *Database
}

func repositoryKey(database *Database) string {
	if database == nil {
		return ""
	}
	if database.metadata.Builtin {
		return "builtin"
	}
	return database.metadata.SHA256
}

func OpenRepository(directory string) (*Repository, error) {
	if directory == "" {
		return nil, errors.New("GeoIP repository directory is required")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	r := &Repository{directory: directory, current: Builtin()}
	manifest, err := readRepositoryManifest(directory)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	r.current, err = r.read(manifest.Current)
	if err != nil {
		return nil, fmt.Errorf("active GeoIP data is invalid; repair or explicitly restore the previous manifest: %w", err)
	}
	if manifest.Previous != "" {
		r.previous, err = r.read(manifest.Previous)
		if err != nil {
			return nil, fmt.Errorf("rollback GeoIP data is invalid: %w", err)
		}
	}
	return r, nil
}

// ResetBuiltin is an explicit user reset. It also repairs a damaged manifest,
// while leaving uploaded bytes available for existing profile backups.
func ResetBuiltin(directory string) error {
	if directory == "" {
		return errors.New("GeoIP repository directory is required")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(repositoryManifest{Format: 1, Current: "builtin"})
	if err != nil {
		return err
	}
	return writeRepositoryFile(filepath.Join(directory, "manifest.json"), data)
}

func readRepositoryManifest(directory string) (repositoryManifest, error) {
	var manifest repositoryManifest
	file, err := os.Open(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return manifest, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 || rejectDuplicateKeys(data) != nil {
		return manifest, errors.New("invalid GeoIP repository manifest")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || manifest.Format != 1 || manifest.Current == "" {
		return manifest, errors.New("invalid GeoIP repository manifest")
	}
	return manifest, nil
}

// RecoverPrevious is an explicit repair action for a damaged active artifact.
// It uses only the previous digest in the validated manifest and revalidates
// those bytes; it never assumes the builtin data is an acceptable substitute.
func RecoverPrevious(directory string) (*Repository, error) {
	manifest, err := readRepositoryManifest(directory)
	if err != nil {
		return nil, err
	}
	if manifest.Previous == "" {
		return nil, errors.New("no previous GeoIP data is available")
	}
	r := &Repository{directory: directory}
	database, err := r.read(manifest.Previous)
	if err != nil {
		return nil, err
	}
	if err := r.publish(database, nil); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Repository) read(key string) (*Database, error) {
	if key == "builtin" {
		return Builtin(), nil
	}
	if !validDigest(key) {
		return nil, errors.New("invalid GeoIP manifest digest")
	}
	file, err := os.Open(filepath.Join(r.directory, key+".json"))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return Load(file, key)
}

func (r *Repository) Current() *Database {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current
}

func (r *Repository) Previous() *Database {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.previous
}

func writeRepositoryFile(path string, data []byte) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".geoip-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (r *Repository) publish(current, previous *Database) error {
	manifest := repositoryManifest{Format: 1, Current: repositoryKey(current), Previous: repositoryKey(previous)}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := writeRepositoryFile(filepath.Join(r.directory, "manifest.json"), data); err != nil {
		return err
	}
	oldCurrent, oldPrevious := r.current, r.previous
	r.current, r.previous = current, previous
	// Own only content-addressed files named in our previous manifest. Do not
	// sweep arbitrary files from the profile directory or remove staged data.
	for _, old := range []*Database{oldCurrent, oldPrevious} {
		key := repositoryKey(old)
		if key != "" && key != "builtin" && key != manifest.Current && key != manifest.Previous {
			_ = os.Remove(filepath.Join(r.directory, key+".json"))
		}
	}
	return nil
}

func (r *Repository) Install(data []byte, expectedSHA256 string) (*Database, error) {
	database, err := Load(bytes.NewReader(data), expectedSHA256)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if repositoryKey(database) == repositoryKey(r.current) {
		return r.current, nil
	}
	path := filepath.Join(r.directory, database.metadata.SHA256+".json")
	if err := writeRepositoryFile(path, database.data); err != nil {
		return nil, err
	}
	if err := r.publish(database, r.current); err != nil {
		if repositoryKey(database) != repositoryKey(r.previous) {
			_ = os.Remove(path)
		}
		return nil, err
	}
	return database, nil
}

func (r *Repository) Rollback() (*Database, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.previous == nil {
		return nil, errors.New("no previous GeoIP data is available")
	}
	// Revalidate persisted bytes before making them current again.
	database, err := r.read(repositoryKey(r.previous))
	if err != nil {
		return nil, err
	}
	if err := r.publish(database, r.current); err != nil {
		return nil, err
	}
	return database, nil
}
