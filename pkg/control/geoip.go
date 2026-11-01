package control

import (
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/xjdrew/kone/pkg/geoip"
	"github.com/xjdrew/kone/pkg/kone"
)

func (c *Controller) geoIPStatus() (map[string]any, error) {
	metadata, err := c.geoIPCache.load(filepath.Join(c.directory, "geoip"), geoip.OpenRepository)
	if err != nil {
		return nil, err
	}
	value := map[string]any{"saved": metadata.current, "restart_required": false, "providers": geoip.Providers()}
	if metadata.hasPrevious {
		value["previous"] = metadata.previous
	}
	c.mu.Lock()
	engine := c.engine
	c.mu.Unlock()
	if data, ok := engine.(interface {
		GeoIPData() (kone.GeoIPRuntimeStatus, error)
	}); ok {
		status, err := data.GeoIPData()
		if err != nil {
			return nil, err
		}
		value["running"] = status
		value["restart_required"] = status.Current.SHA256 != metadata.current.SHA256
	}
	return value, nil
}

// Dataset updates are explicit local uploads. They never fetch an arbitrary
// source URL, and require paused capture so persistent/runtime state cannot
// diverge across a crash between two independently owned publications.
func (c *Controller) updateGeoIP(base uint64, expectedCurrent string, data []byte, digest string, rollback bool) (map[string]any, error) {
	return c.updateGeoIPFormat(base, expectedCurrent, data, digest, "kone-json", "", rollback)
}

func (c *Controller) updateGeoIPFormat(base uint64, expectedCurrent string, data []byte, digest, format, provider string, rollback bool) (map[string]any, error) {
	c.actions.Lock()
	defer c.actions.Unlock()
	c.mu.Lock()
	version, active := c.doc.Version, c.engine != nil
	c.mu.Unlock()
	if base != version {
		return nil, ErrConflict
	}
	if active {
		return nil, errors.New("pause capture before updating GeoIP data")
	}
	repository, err := geoip.OpenRepository(filepath.Join(c.directory, "geoip"))
	if err != nil {
		if rollback {
			if _, repairErr := geoip.RecoverPrevious(filepath.Join(c.directory, "geoip")); repairErr != nil {
				return nil, repairErr
			}
			return c.geoIPStatus()
		}
		return nil, err
	}
	if expectedCurrent != repository.Current().Metadata().SHA256 {
		return nil, ErrConflict
	}
	if rollback {
		_, err = repository.Rollback()
	} else if format == "mmdb" {
		_, err = repository.InstallMMDB(data, digest, provider)
	} else {
		if format != "" && format != "kone-json" {
			return nil, errors.New("GeoIP format must be kone-json or mmdb")
		}
		_, err = repository.Install(data, digest)
	}
	if err != nil {
		return nil, err
	}
	return c.geoIPStatus()
}

func (c *Controller) geoIPRoute(w http.ResponseWriter, r *http.Request, rollback bool) {
	var base uint64
	var expectedCurrent string
	var data []byte
	var err error
	format := r.Header.Get("X-GeoIP-Format")
	if rollback {
		var input struct {
			BaseVersion uint64 `json:"base_version"`
			BaseSHA256  string `json:"base_sha256"`
		}
		err = readJSON(w, r, &input)
		base = input.BaseVersion
		expectedCurrent = input.BaseSHA256
	} else {
		base, err = strconv.ParseUint(r.Header.Get("If-Match"), 10, 64)
		expectedCurrent = r.Header.Get("X-GeoIP-Base-SHA256")
		if err == nil {
			limit := int64(geoip.MaxFileSize)
			if format == "mmdb" {
				limit = geoip.MaxMMDBFileSize
			}
			data, err = io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
			r.Body.Close()
		}
	}
	if err != nil {
		apiError(w, 400, "request", "Supply a valid base revision and a JSON dataset up to 32 MiB or MMDB up to 64 MiB")
		return
	}
	value, err := c.updateGeoIPFormat(base, expectedCurrent, data, r.Header.Get("X-Content-SHA256"), format, r.Header.Get("X-GeoIP-Provider"), rollback)
	if err != nil {
		status := 400
		if errors.Is(err, ErrConflict) {
			status = 409
		}
		apiError(w, status, "geoip", err.Error())
		return
	}
	writeJSON(w, 200, value)
}
