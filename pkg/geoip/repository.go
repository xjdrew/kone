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
	Format        int               `json:"format"`
	Current       string            `json:"current"`
	Previous      string            `json:"previous,omitempty"`
	MMDBProviders map[string]string `json:"mmdb_providers,omitempty"`
}

// Repository retains the active file and one rollback file. No source URL is
// fetched. A corrupt saved manifest/database is an error, never an implicit
// switch to old bundled data that would silently change routing decisions.
type Repository struct {
	mu                sync.Mutex
	directory         string
	current, previous *Database
	mmdbProviders     map[string]string
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
	r.mmdbProviders = manifest.MMDBProviders
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
	manifest, _, err := readRepositoryManifestSnapshot(directory)
	return manifest, err
}

func readRepositoryManifestSnapshot(directory string) (repositoryManifest, []byte, error) {
	var manifest repositoryManifest
	path := filepath.Join(directory, "manifest.json")
	before, err := os.Lstat(path)
	if err != nil {
		return manifest, nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > 4096 {
		return manifest, nil, errors.New("GeoIP repository manifest must be a regular file within 4096 bytes")
	}
	file, err := os.Open(path)
	if err != nil {
		return manifest, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 || !os.SameFile(before, info) {
		return manifest, nil, errors.New("GeoIP repository manifest changed during inspection")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 || rejectDuplicateKeys(data) != nil {
		return manifest, nil, errors.New("invalid GeoIP repository manifest")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || (manifest.Format != 1 && manifest.Format != 2) || manifest.Current == "" {
		return manifest, nil, errors.New("invalid GeoIP repository manifest")
	}
	if len(manifest.MMDBProviders) > 2 || (manifest.Format == 1 && len(manifest.MMDBProviders) != 0) {
		return manifest, nil, errors.New("invalid GeoIP MMDB manifest entries")
	}
	for digest, provider := range manifest.MMDBProviders {
		_, valid := FindProvider(provider)
		if !validDigest(digest) || !valid || (digest != manifest.Current && digest != manifest.Previous) {
			return manifest, nil, errors.New("invalid GeoIP MMDB manifest entry")
		}
	}
	return manifest, data, nil
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
	r := &Repository{directory: directory, mmdbProviders: manifest.MMDBProviders}
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
	extension := ".json"
	if r.mmdbProviders[key] != "" {
		extension = ".mmdb"
	}
	path := filepath.Join(r.directory, key+extension)
	limit := int64(MaxFileSize)
	if extension == ".mmdb" {
		limit = MaxMMDBFileSize
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > limit {
		return nil, errors.New("GeoIP repository data is absent or not a regular file within the format size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || !os.SameFile(before, info) {
		return nil, errors.New("GeoIP repository file changed during inspection")
	}
	if provider := r.mmdbProviders[key]; provider != "" {
		return LoadMMDB(file, key, provider)
	}
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
	for _, database := range []*Database{current, previous} {
		if database != nil && database.mmdb != nil {
			if manifest.MMDBProviders == nil {
				manifest.MMDBProviders = map[string]string{}
			}
			manifest.MMDBProviders[repositoryKey(database)] = database.metadata.Provider
			manifest.Format = 2
		}
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := writeRepositoryFile(filepath.Join(r.directory, "manifest.json"), data); err != nil {
		return err
	}
	oldCurrent, oldPrevious := r.current, r.previous
	r.current, r.previous = current, previous
	r.mmdbProviders = manifest.MMDBProviders
	// Own only content-addressed files named in our previous manifest. Do not
	// sweep arbitrary files from the profile directory or remove staged data.
	for _, old := range []*Database{oldCurrent, oldPrevious} {
		key := repositoryKey(old)
		if key != "" && key != "builtin" && key != manifest.Current && key != manifest.Previous {
			_ = os.Remove(filepath.Join(r.directory, key+databaseExtension(old)))
		}
	}
	return nil
}

func (r *Repository) Install(data []byte, expectedSHA256 string) (*Database, error) {
	database, err := Load(bytes.NewReader(data), expectedSHA256)
	if err != nil {
		return nil, err
	}
	return r.install(database)
}

func databaseExtension(database *Database) string {
	if database != nil && database.mmdb != nil {
		return ".mmdb"
	}
	return ".json"
}

func (r *Repository) InstallMMDB(data []byte, expectedSHA256, provider string) (*Database, error) {
	database, err := LoadMMDB(bytes.NewReader(data), expectedSHA256, provider)
	if err != nil {
		return nil, err
	}
	return r.install(database)
}

func (r *Repository) install(database *Database) (*Database, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range []*Database{r.current, r.previous} {
		if existing != nil && repositoryKey(database) == repositoryKey(existing) && database.metadata.Provider != existing.metadata.Provider {
			return nil, errors.New("the same GeoIP bytes are already associated with a different provider")
		}
	}
	if repositoryKey(database) == repositoryKey(r.current) {
		return r.current, nil
	}
	path := filepath.Join(r.directory, database.metadata.SHA256+databaseExtension(database))
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
