package control

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/xjdrew/kone/pkg/logstore"
)

// Operational events belong to this controller even when it has no process-wide
// logger. Keep them available independently of the engine's diagnostic level.
func (c *Controller) logEvent(level slog.Level, message string, attrs ...slog.Attr) {
	slog.New(c.logs.Handler(nil, "management")).With("service", "kone").LogAttrs(context.Background(), level, message, attrs...)
}

type runtimeLogs struct {
	logstore.Page
	Helper logstore.RemoteStatus `json:"helper"`
}

func (c *Controller) logsRoute(w http.ResponseWriter, r *http.Request) {
	invalid := func() { apiError(w, 400, "request", "Invalid runtime log query") }
	if len(r.URL.RawQuery) > 1024 {
		invalid()
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		invalid()
		return
	}
	for key, value := range values {
		if len(value) != 1 || key != "after" && key != "before" && key != "from" && key != "to" && key != "limit" && key != "min_level" && key != "source" {
			invalid()
			return
		}
	}
	query := logstore.Query{Source: values.Get("source"), MinLevel: values.Get("min_level")}
	_, hasAfter := values["after"]
	_, hasBefore := values["before"]
	if hasAfter && hasBefore {
		invalid()
		return
	}
	query.Tail = !hasAfter
	if value, exists := values["after"]; exists {
		query.After, err = strconv.ParseUint(value[0], 10, 64)
		if err != nil {
			invalid()
			return
		}
	}
	if value, exists := values["before"]; exists {
		query.Before, err = strconv.ParseUint(value[0], 10, 64)
		if err != nil || query.Before == 0 {
			invalid()
			return
		}
	}
	for key, target := range map[string]*time.Time{"from": &query.From, "to": &query.To} {
		if value, exists := values[key]; exists {
			*target, err = time.Parse(time.RFC3339Nano, value[0])
			if err != nil {
				invalid()
				return
			}
		}
	}
	if value, exists := values["limit"]; exists {
		query.Limit, err = strconv.Atoi(value[0])
		if err != nil || query.Limit < 1 {
			invalid()
			return
		}
	}
	page, err := c.logs.Query(query)
	if err != nil {
		invalid()
		return
	}
	response := runtimeLogs{Page: page}
	c.mu.Lock()
	source := c.dataSource
	c.mu.Unlock()
	if remote, ok := source.(interface{ LogStatus() logstore.RemoteStatus }); ok {
		response.Helper = remote.LogStatus()
	}
	writeJSON(w, 200, response)
}
