package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/xjdrew/kone/pkg/kone"
	web "github.com/xjdrew/kone/web"
)

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func apiError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "request_id": randomID("request")}})
}
func readJSON(w http.ResponseWriter, r *http.Request, value any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return errors.New("invalid JSON request or unknown fields")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func (c *Controller) Handler() http.Handler {
	assets, err := fs.Sub(web.Files, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		if !c.validOrigin(r) {
			apiError(w, 403, "origin", "Access from this host or origin is not allowed")
			return
		}
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
			writeJSON(w, 200, map[string]any{"control": "ready"})
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				apiError(w, 405, "method", "Method not allowed")
				return
			}
			if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.Path, "\\") {
				http.NotFound(w, r)
				return
			}
			if r.URL.Path == "/" {
				w.Header().Set("Cache-Control", "no-cache")
			}
			files.ServeHTTP(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
		if !c.allowRequest(r, path == "session") {
			apiError(w, 429, "rate_limit", "Request limit reached; retry later")
			return
		}
		if path == "session" && r.Method == http.MethodPost {
			var request struct {
				Token       string `json:"token"`
				PairingCode string `json:"pairing_code"`
			}
			if readJSON(w, r, &request) != nil {
				apiError(w, 400, "request", "Invalid authorization request")
				return
			}
			token, session, err := c.claim(request.Token, request.PairingCode, !localRemote(r))
			if err != nil {
				apiError(w, 401, "unauthorized", err.Error())
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "kone_session", Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: int(time.Until(session.Expires).Seconds())})
			writeJSON(w, 200, map[string]any{"role": session.Role, "session_id": session.ID, "csrf_token": session.csrf, "expires": session.Expires})
			return
		}
		session, ok := c.authorize(r)
		if !ok {
			apiError(w, 401, "unauthorized", "Authorize this browser or pair it from the local KONE window")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && session.Role != "admin" {
			apiError(w, 403, "read_only", "This session is read-only")
			return
		}
		c.route(w, r, path, session)
	})
}

func (c *Controller) route(w http.ResponseWriter, r *http.Request, path string, session *Session) {
	respondError := func(err error) {
		status := 400
		code := "request"
		if errors.Is(err, ErrConflict) {
			status = 409
			code = "version_conflict"
		}
		c.mu.Lock()
		message := safeMessage(err, c.doc.Config)
		c.mu.Unlock()
		apiError(w, status, code, message)
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) > 128 {
		apiError(w, 400, "request", "Idempotency key is too long")
		return
	}
	if key != "" {
		key = session.ID + ":" + key
	}
	switch {
	case path == "state" && r.Method == http.MethodGet:
		state := c.State()
		writeJSON(w, 200, map[string]any{"state": state.State, "control_state": state.ControlState, "data_state": state.DataState, "host": state.Host, "role": session.Role, "capabilities": state.Capabilities, "version": state.Version, "saved_version": state.SavedVersion, "running_version": state.RunningVersion, "confirmed_version": state.ConfirmedVersion, "last_error": state.LastError, "config_error": state.ConfigError, "scope": state.Scope, "time": state.Time, "session_id": session.ID, "csrf_token": session.csrf})
	case path == "config" && r.Method == http.MethodGet:
		writeJSON(w, 200, c.Document())
	case path == "config" && r.Method == http.MethodPut:
		var request SaveRequest
		if err := readJSON(w, r, &request); err != nil {
			respondError(err)
			return
		}
		value, err := c.Save(request)
		if err != nil {
			respondError(err)
			return
		}
		writeJSON(w, 200, value)
	case path == "config/validate" && r.Method == http.MethodPost:
		var request SaveRequest
		if err := readJSON(w, r, &request); err != nil {
			respondError(err)
			return
		}
		value, err := c.Validate(request)
		if err != nil {
			respondError(err)
			return
		}
		writeJSON(w, 200, value)
	case (path == "config/import" || path == "config/import/validate") && r.Method == http.MethodPost:
		c.importConfiguration(w, r, path == "config/import/validate")
	case path == "config/defaults" && r.Method == http.MethodPost:
		var request struct {
			BaseVersion uint64 `json:"base_version"`
		}
		if err := readJSON(w, r, &request); err != nil {
			respondError(err)
			return
		}
		c.mu.Lock()
		inbound := c.doc.Inbound
		c.mu.Unlock()
		inbound.Enabled = false
		value, err := c.Save(SaveRequest{BaseVersion: request.BaseVersion, Config: jsonConfig(kone.DefaultConfig()), Inbound: inbound})
		if err != nil {
			respondError(err)
			return
		}
		writeJSON(w, 200, value)
	case path == "config/undo" && r.Method == http.MethodPost:
		var request struct {
			BaseVersion uint64 `json:"base_version"`
		}
		if err := readJSON(w, r, &request); err != nil {
			respondError(err)
			return
		}
		value, err := c.Undo(request.BaseVersion)
		if err != nil {
			respondError(err)
			return
		}
		writeJSON(w, 200, value)
	case path == "config/apply" && r.Method == http.MethodPost:
		op := c.beginOperation("apply", key, 20*time.Second, func(ctx context.Context) (any, error) { return nil, c.Apply(ctx) })
		writeJSON(w, 202, op)
	case strings.HasPrefix(path, "lifecycle/") && r.Method == http.MethodPost:
		action := strings.TrimPrefix(path, "lifecycle/")
		if action == "preflight" {
			writeJSON(w, 200, c.Preflight(r.Context()))
			return
		}
		var actionFn func(context.Context) error
		switch action {
		case "start", "resume":
			actionFn = c.Start
		case "pause", "stop":
			actionFn = c.Pause
		case "restart":
			actionFn = func(ctx context.Context) error {
				if err := c.Pause(ctx); err != nil {
					return err
				}
				return c.Start(ctx)
			}
		case "recover":
			actionFn = c.Recover
		case "exit":
			actionFn = func(context.Context) error { c.cancel(); return nil }
		default:
			apiError(w, 404, "not_found", "Unknown lifecycle action")
			return
		}
		writeJSON(w, 202, c.beginOperation(action, key, 40*time.Second, func(ctx context.Context) (any, error) { return nil, actionFn(ctx) }))
	case path == "traffic" && r.Method == http.MethodGet:
		query := trafficQuery(r)
		window := time.Second
		if n, err := strconv.Atoi(r.URL.Query().Get("window")); err == nil && n > 0 && n <= 60 {
			window = time.Duration(n) * time.Second
		}
		metric := r.URL.Query().Get("metric")
		if metric == "" {
			metric = "total"
		}
		c.mu.Lock()
		observer := c.observer
		c.mu.Unlock()
		writeJSON(w, 200, map[string]any{"traffic": observer.Snapshot(query), "sankey": observer.Sankey(query, kone.SankeyOptions{Window: window, Metric: metric, Limit: 24})})
	case path == "flows" && r.Method == http.MethodGet:
		c.mu.Lock()
		observer := c.observer
		c.mu.Unlock()
		writeJSON(w, 200, observer.Snapshot(trafficQuery(r)))
	case strings.HasPrefix(path, "flows/") && r.Method == http.MethodGet:
		c.mu.Lock()
		observer := c.observer
		c.mu.Unlock()
		id := strings.TrimPrefix(path, "flows/")
		if record, ok := observer.Get(id); ok {
			writeJSON(w, 200, record)
			return
		}
		apiError(w, 410, "expired", "This flow detail has expired; it was not replaced with a newer sample")
	case path == "dns" && r.Method == http.MethodGet:
		c.mu.Lock()
		engine := c.engine
		c.mu.Unlock()
		if one, ok := engine.(*kone.One); ok {
			writeJSON(w, 200, map[string]any{"status": one.DNSStatus(), "queries": one.DNSQueries()})
		} else {
			writeJSON(w, 200, map[string]any{"status": map[string]any{"active": false}, "queries": []any{}})
		}
	case path == "diagnostics" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"operations": c.Operations()})
	case path == "diagnostics" && r.Method == http.MethodPost:
		var request struct {
			Target    string   `json:"target"`
			Outbounds []string `json:"outbounds"`
			TLS       bool     `json:"tls"`
		}
		if err := readJSON(w, r, &request); err != nil {
			respondError(err)
			return
		}
		op, err := c.Diagnose(request.Target, request.Outbounds, request.TLS, key)
		if err != nil {
			respondError(err)
			return
		}
		writeJSON(w, 202, op)
	case strings.HasPrefix(path, "diagnostics/") && strings.HasSuffix(path, "/cancel") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(strings.TrimPrefix(path, "diagnostics/"), "/cancel")
		if err := c.cancelOperation(id); err != nil {
			respondError(err)
			return
		}
		writeJSON(w, 200, map[string]any{"canceled": true})
	case path == "operations" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"operations": c.Operations()})
	case strings.HasPrefix(path, "operations/") && r.Method == http.MethodGet:
		id := strings.TrimPrefix(path, "operations/")
		for _, op := range c.Operations() {
			if op.ID == id {
				writeJSON(w, 200, op)
				return
			}
		}
		apiError(w, 404, "not_found", "Operation expired or unknown")
	case path == "rules/simulate" && r.Method == http.MethodPost:
		c.simulate(w, r)
	case path == "rules/exact" && r.Method == http.MethodPost:
		c.exactRule(w, r)
	case path == "sessions" && r.Method == http.MethodGet:
		if session.Role != "admin" {
			apiError(w, 403, "read_only", "Owner authorization is required")
			return
		}
		writeJSON(w, 200, map[string]any{"sessions": c.sessionList()})
	case path == "pairing" && r.Method == http.MethodPost:
		if !localRemote(r) {
			apiError(w, 403, "local_owner", "Create pairing codes on the KONE host")
			return
		}
		var request struct {
			Role string `json:"role"`
		}
		if err := readJSON(w, r, &request); err != nil {
			respondError(err)
			return
		}
		if request.Role == "" {
			request.Role = "read"
		}
		pair, err := c.pair(request.Role)
		if err != nil {
			respondError(err)
			return
		}
		writeJSON(w, 200, pair)
	case strings.HasPrefix(path, "sessions/") && strings.HasSuffix(path, "/revoke") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(strings.TrimPrefix(path, "sessions/"), "/revoke")
		writeJSON(w, 200, map[string]any{"revoked": c.revoke(id)})
	case path == "export" && r.Method == http.MethodGet:
		c.mu.Lock()
		data, err := c.doc.Config.RedactedTOML()
		c.mu.Unlock()
		if err != nil {
			respondError(err)
			return
		}
		w.Header().Set("Content-Type", "application/toml")
		w.Header().Set("Content-Disposition", "attachment; filename=kone-redacted.toml")
		_, _ = w.Write(data)
	case path == "privacy/clear" && r.Method == http.MethodPost:
		c.mu.Lock()
		observer := c.observer
		engine := c.engine
		c.mu.Unlock()
		observer.Clear()
		if one, ok := engine.(*kone.One); ok {
			one.ClearDNSQueries()
			one.ClearDNSCache()
		}
		writeJSON(w, 200, map[string]any{"cleared": true, "network_changed": false})
	case path == "access/lan" && r.Method == http.MethodPost:
		if !localRemote(r) {
			apiError(w, 403, "local_owner", "LAN access is controlled on the KONE host")
			return
		}
		var request struct {
			Enabled bool   `json:"enabled"`
			Address string `json:"address"`
		}
		if err := readJSON(w, r, &request); err != nil {
			respondError(err)
			return
		}
		value, err := c.SetLAN(request.Enabled, request.Address)
		if err != nil {
			respondError(err)
			return
		}
		writeJSON(w, 200, value)
	case path == "access/lan" && r.Method == http.MethodGet:
		writeJSON(w, 200, c.LANStatus())
	case path == "access/certificate" && r.Method == http.MethodGet:
		if !localRemote(r) || session.Role != "admin" {
			apiError(w, 403, "local_owner", "Download the certificate on the KONE host")
			return
		}
		data, err := os.ReadFile(filepath.Join(c.directory, "lan-ca.pem"))
		if err != nil {
			respondError(err)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename=kone-local-ca.pem")
		_, _ = w.Write(data)
	default:
		apiError(w, 404, "not_found", "Unknown API route or method")
	}
}

func trafficQuery(r *http.Request) kone.TrafficQuery {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	since, _ := time.Parse(time.RFC3339Nano, q.Get("since"))
	until, _ := time.Parse(time.RFC3339Nano, q.Get("until"))
	return kone.TrafficQuery{Protocol: q.Get("protocol"), Status: q.Get("status"), Outbound: q.Get("outbound"), RuleID: q.Get("rule_id"), Inbound: q.Get("inbound"), Target: q.Get("target"), Source: q.Get("source"), Cursor: q.Get("cursor"), Anchor: q.Get("anchor"), Since: since, Until: until, Limit: limit, PathIDs: strings.FieldsFunc(q.Get("path_ids"), func(r rune) bool { return r == ',' }), FlowIDs: strings.FieldsFunc(q.Get("flow_ids"), func(r rune) bool { return r == ',' })}
}

func (c *Controller) Serve(ctx context.Context, address string, ready func(string)) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errors.New("local control must listen on a loopback IP; enable authenticated TLS LAN access separately")
	}
	lock, err := lockInstance(filepath.Join(c.directory, "instance.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	c.mu.Lock()
	c.address = listener.Addr().String()
	c.mu.Unlock()
	server := &http.Server{Handler: c.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32768}
	stop := context.AfterFunc(ctx, func() { c.cancel() })
	defer stop()
	go func() {
		<-c.ctx.Done()
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(stopCtx)
	}()
	if ready != nil {
		ready("http://" + listener.Addr().String() + "/#token=" + c.BootstrapToken())
	}
	err = server.Serve(listener)
	closeErr := c.Close()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return errors.Join(err, closeErr)
}

func (c *Controller) simulate(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Target   string `json:"target"`
		Protocol string `json:"protocol"`
		Port     uint16 `json:"port"`
	}
	if err := readJSON(w, r, &request); err != nil {
		apiError(w, 400, "request", err.Error())
		return
	}
	c.mu.Lock()
	doc := cloneDocument(c.doc)
	c.mu.Unlock()
	decision, err := kone.ExplainRouting(doc.Config, request.Target, request.Protocol, request.Port)
	if err != nil && decision.Outbound == "" {
		apiError(w, 400, "decision", safeMessage(err, doc.Config))
		return
	}
	decision.ConfigVersion = doc.Version
	writeJSON(w, 200, decision)
}

func (c *Controller) exactRule(w http.ResponseWriter, r *http.Request) {
	var request struct {
		BaseVersion uint64 `json:"base_version"`
		Target      string `json:"target"`
		Outbound    string `json:"outbound"`
		Protocol    string `json:"protocol"`
		Port        uint16 `json:"port"`
	}
	if err := readJSON(w, r, &request); err != nil {
		apiError(w, 400, "request", err.Error())
		return
	}
	if len(request.Target) > 253 || strings.ContainsAny(request.Target, " /\\\x00\r\n\t") {
		apiError(w, 400, "target", "Use an exact hostname or IP")
		return
	}
	c.mu.Lock()
	doc := cloneDocument(c.doc)
	c.mu.Unlock()
	rule := kone.RuleConfig{ID: randomID("rule"), Source: "one-click", Schema: "DOMAIN", Pattern: strings.ToLower(strings.TrimSuffix(request.Target, ".")), Outbound: request.Outbound, Protocol: request.Protocol}
	if address, err := netip.ParseAddr(request.Target); err == nil {
		if !address.Is4() {
			apiError(w, 400, "unsupported", "IPv6 capture is not available")
			return
		}
		rule.Schema = "IP-CIDR"
		rule.Pattern = address.String() + "/32"
	}
	if request.Port != 0 {
		rule.Ports = []uint16{request.Port}
	}
	for _, existing := range doc.Config.Rule {
		if existing.Schema == rule.Schema && existing.Pattern == rule.Pattern && existing.Protocol == rule.Protocol {
			apiError(w, 409, "duplicate_rule", "An exact rule already exists; edit it instead")
			return
		}
	}
	doc.Config.Rule = append([]kone.RuleConfig{rule}, doc.Config.Rule...)
	data, _ := doc.Config.RedactedTOML()
	var config map[string]any
	_ = toml.Unmarshal(data, &config)
	value, err := c.Save(SaveRequest{BaseVersion: request.BaseVersion, Config: config, Inbound: doc.Inbound})
	if err != nil {
		apiError(w, 409, "save", safeMessage(err, doc.Config))
		return
	}
	writeJSON(w, 200, map[string]any{"saved": value, "applied": false, "rule_id": rule.ID, "verification": "Apply explicitly, then verify a new connection"})
}
