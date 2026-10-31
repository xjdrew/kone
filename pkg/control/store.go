// Package control keeps local management available independently of TUN capture.
package control

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/xjdrew/kone/pkg/kone"
)

var ErrConflict = errors.New("configuration changed; reload the latest version before saving")

type Inbound struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}
type Document struct {
	Version uint64           `json:"version"`
	Config  *kone.KoneConfig `json:"-"`
	Inbound Inbound          `json:"inbound"`
}
type storedDocument struct {
	Version uint64  `json:"version"`
	TOML    string  `json:"toml"`
	Inbound Inbound `json:"inbound"`
}
type CredentialAction struct {
	Action       string `json:"action"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	OriginalName string `json:"original_name"`
}
type SaveRequest struct {
	BaseVersion       uint64                      `json:"base_version"`
	Config            map[string]any              `json:"config"`
	Inbound           Inbound                     `json:"inbound"`
	CredentialActions map[string]CredentialAction `json:"credential_actions,omitempty"`
}

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func randomID(prefix string) string { return prefix + "-" + randomToken()[:16] }

func jsonConfig(cfg *kone.KoneConfig) map[string]any {
	data, _ := cfg.RedactedTOML()
	var value map[string]any
	_ = toml.Unmarshal(data, &value)
	return value
}

func normalizeJSON(value any) (any, error) {
	switch v := value.(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return nil, errors.New("configuration numbers must be integers")
		}
		return n, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			normalized, err := normalizeJSON(item)
			if err != nil {
				return nil, err
			}
			out[key] = normalized
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			normalized, err := normalizeJSON(item)
			if err != nil {
				return nil, err
			}
			out[i] = normalized
		}
		return out, nil
	case float64:
		if v != float64(int64(v)) {
			return nil, errors.New("configuration numbers must be integers")
		}
		return int64(v), nil
	default:
		return value, nil
	}
}

func decodeManaged(value map[string]any) (*kone.KoneConfig, error) {
	normalized, err := normalizeJSON(value)
	if err != nil {
		return nil, err
	}
	data, err := toml.Marshal(normalized)
	if err != nil {
		return nil, errors.New("invalid configuration values")
	}
	return kone.ParseManagedConfig(data)
}

func cloneDocument(doc Document) Document {
	if doc.Config == nil {
		return doc
	}
	data, _ := toml.Marshal(doc.Config)
	cfg, _ := kone.ParseManagedConfig(data)
	return Document{Version: doc.Version, Config: cfg, Inbound: doc.Inbound}
}

func sameDocument(a, b Document) bool {
	if a.Version != b.Version || a.Inbound != b.Inbound {
		return false
	}
	left, errA := toml.Marshal(a.Config)
	right, errB := toml.Marshal(b.Config)
	return errA == nil && errB == nil && bytes.Equal(left, right)
}

func assignIDs(cfg *kone.KoneConfig) {
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].ID == "" {
			cfg.Outbounds[i].ID = randomID("outbound")
		}
	}
	for i := range cfg.Rule {
		if cfg.Rule[i].ID == "" {
			cfg.Rule[i].ID = randomID("rule")
		}
		if cfg.Rule[i].Source == "" {
			cfg.Rule[i].Source = "user"
		}
	}
}

// Older managed profiles had no outbound/rule IDs. Derive repeatable identities
// while reading, then persist them on the next explicit save. Random IDs here
// would make two reads of the same disk revision look like conflicting edits.
func assignReadIDs(cfg *kone.KoneConfig) {
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].ID == "" {
			digest := sha256.Sum256([]byte("outbound\x00" + cfg.Outbounds[i].Name))
			cfg.Outbounds[i].ID = "outbound-" + hex.EncodeToString(digest[:8])
		}
	}
	for i := range cfg.Rule {
		if cfg.Rule[i].ID == "" {
			rule := cfg.Rule[i]
			digest := sha256.Sum256([]byte(fmt.Sprintf("rule\x00%d\x00%s\x00%s\x00%s\x00%s\x00%v\x00%s", i, rule.Schema, rule.Pattern, rule.Outbound, rule.Protocol, rule.Ports, rule.ExpiresAt)))
			cfg.Rule[i].ID = "rule-" + hex.EncodeToString(digest[:8])
		}
	}
	assignIDs(cfg)
}

func prepareDocument(request SaveRequest, current Document) (Document, error) {
	if current.Version == ^uint64(0) {
		return Document{}, errors.New("configuration revision limit reached; restore the profile explicitly")
	}
	if request.BaseVersion != current.Version {
		return Document{}, ErrConflict
	}
	cfg, err := decodeManaged(request.Config)
	if err != nil {
		return Document{}, err
	}
	for i := range cfg.Outbounds {
		o := &cfg.Outbounds[i]
		action := request.CredentialActions[o.Name]
		oldName := o.Name
		if action.OriginalName != "" {
			oldName = action.OriginalName
		}
		var old *kone.OutboundConfig
		for j := range current.Config.Outbounds {
			if current.Config.Outbounds[j].Name == oldName {
				old = &current.Config.Outbounds[j]
				break
			}
		}
		u, _ := url.Parse(o.URL)
		if o.ID == "" && old != nil {
			o.ID = old.ID
		}
		if action.Action == "clear" {
			u.User = nil
			o.URL = u.String()
			continue
		}
		if action.Action == "replace" {
			u.User = url.UserPassword(action.Username, action.Password)
			o.URL = u.String()
			continue
		}
		if action.Action != "" && action.Action != "preserve" {
			return Document{}, errors.New("credential action must be preserve, replace or clear")
		}
		if u.User != nil && u.User.Username() == "REDACTED" {
			if old == nil {
				return Document{}, errors.New("masked credentials cannot be imported; replace or clear credentials")
			}
			oldURL, _ := url.Parse(old.URL)
			if oldURL.Host != u.Host || oldURL.Scheme != u.Scheme {
				return Document{}, errors.New("replace or clear credentials when changing the proxy endpoint")
			}
			u.User = oldURL.User
			o.URL = u.String()
		} else if action.Action == "preserve" && old != nil {
			oldURL, _ := url.Parse(old.URL)
			if oldURL.Host != u.Host || oldURL.Scheme != u.Scheme {
				return Document{}, errors.New("replace or clear credentials when changing the proxy endpoint")
			}
			u.User = oldURL.User
			o.URL = u.String()
		}
	}
	assignIDs(cfg)
	if err := cfg.Validate(); err != nil {
		return Document{}, err
	}
	inbound := request.Inbound
	if inbound.ID == "" {
		inbound.ID = current.Inbound.ID
	}
	if inbound.ID == "" {
		inbound.ID = "tun-main"
	}
	if inbound.ID != current.Inbound.ID && current.Inbound.ID != "" {
		return Document{}, errors.New("the single TUN inbound ID cannot be changed")
	}
	if inbound.Name == "" {
		inbound.Name = "TUN"
	}
	if len(inbound.Name) > 80 || strings.ContainsAny(inbound.Name, "\x00\r\n") {
		return Document{}, errors.New("invalid inbound name")
	}
	return Document{Version: current.Version + 1, Config: cfg, Inbound: inbound}, nil
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".kone-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func writeDocument(path string, doc Document) error {
	configuration, err := toml.Marshal(doc.Config)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(storedDocument{doc.Version, string(configuration), doc.Inbound}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, data)
}

func readDocument(path string) (Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	if len(data) > 1<<20 {
		return Document{}, errors.New("saved configuration exceeds size limit")
	}
	var stored storedDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&stored) != nil || decoder.Decode(new(any)) != io.EOF || stored.Version == 0 {
		return Document{}, errors.New("saved configuration is damaged; restore a backup or save a corrected configuration")
	}
	cfg, err := kone.ParseManagedConfig([]byte(stored.TOML))
	if err != nil {
		return Document{}, errors.New("saved configuration is invalid; restore a backup or save a corrected configuration")
	}
	assignReadIDs(cfg)
	return Document{stored.Version, cfg, stored.Inbound}, nil
}

func DefaultDirectory() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "kone"), nil
}

func safeMessage(err error, cfg *kone.KoneConfig) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if cfg != nil {
		for _, outbound := range cfg.Outbounds {
			u, e := url.Parse(outbound.URL)
			if e == nil && u.User != nil {
				if raw := u.User.String(); raw != "" {
					message = strings.ReplaceAll(message, raw, "REDACTED")
				}
				if password, ok := u.User.Password(); ok && password != "" {
					message = strings.ReplaceAll(message, password, "REDACTED")
				}
				if user := u.User.Username(); user != "" {
					message = strings.ReplaceAll(message, user, "REDACTED")
				}
			}
		}
	}
	if len(message) > 1024 {
		message = message[:1024]
	}
	return message
}

func brokenBackup(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return atomicWrite(path+".broken-"+fmt.Sprint(time.Now().UnixNano()), data)
}
