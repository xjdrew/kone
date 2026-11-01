package control

import (
	"net/http"
	"strconv"

	"github.com/xjdrew/kone/pkg/logstore"
)

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
	values := r.URL.Query()
	for key, value := range values {
		if len(value) != 1 || key != "after" && key != "limit" && key != "min_level" && key != "source" {
			invalid()
			return
		}
	}
	query := logstore.Query{Source: values.Get("source"), MinLevel: values.Get("min_level")}
	_, hasAfter := values["after"]
	query.Tail = !hasAfter
	var err error
	if value, exists := values["after"]; exists {
		query.After, err = strconv.ParseUint(value[0], 10, 64)
		if err != nil {
			invalid()
			return
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
