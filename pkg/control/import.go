package control

import (
	"errors"
	"net/http"

	"github.com/pelletier/go-toml/v2"
	"github.com/xjdrew/kone/pkg/kone"
)

func (c *Controller) importConfiguration(w http.ResponseWriter, r *http.Request, preview bool) {
	var input struct {
		BaseVersion uint64   `json:"base_version"`
		TOML        string   `json:"toml"`
		Inbound     *Inbound `json:"inbound,omitempty"`
	}
	if err := readJSON(w, r, &input); err != nil {
		apiError(w, 400, "request", err.Error())
		return
	}
	c.mu.Lock()
	doc := cloneDocument(c.doc)
	c.mu.Unlock()
	if input.BaseVersion != doc.Version {
		apiError(w, 409, "version_conflict", ErrConflict.Error())
		return
	}
	cfg, err := kone.ParseManagedConfig([]byte(input.TOML))
	if err != nil {
		apiError(w, 400, "configuration", "Invalid TOML configuration; check field names, types and outbound references")
		return
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		apiError(w, 400, "configuration", "Cannot import configuration")
		return
	}
	var configuration map[string]any
	if toml.Unmarshal(data, &configuration) != nil {
		apiError(w, 400, "configuration", "Cannot import configuration")
		return
	}
	inbound := doc.Inbound
	if input.Inbound != nil {
		inbound = *input.Inbound
	}
	request := SaveRequest{BaseVersion: input.BaseVersion, Config: configuration, Inbound: inbound}
	var value map[string]any
	if preview {
		value, err = c.Validate(request)
		if err == nil {
			candidate, e := prepareDocument(request, doc)
			err = e
			if e == nil {
				value["candidate_document"] = map[string]any{"version": candidate.Version, "config": jsonConfig(candidate.Config), "inbound": candidate.Inbound}
			}
		}
	} else {
		value, err = c.Save(request)
	}
	if err != nil {
		if errors.Is(err, ErrConflict) {
			apiError(w, 409, "version_conflict", ErrConflict.Error())
		} else {
			apiError(w, 400, "configuration", "Import could not be validated; masked credentials require a matching saved endpoint")
		}
		return
	}
	writeJSON(w, 200, value)
}
