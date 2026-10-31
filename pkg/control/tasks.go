package control

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/xjdrew/kone/pkg/kone"
)

type ProbeResult struct {
	Target        string    `json:"target"`
	Outbound      string    `json:"outbound"`
	Protocol      string    `json:"protocol"`
	Stage         string    `json:"stage"`
	Status        string    `json:"status"`
	Message       string    `json:"message,omitempty"`
	RemoteAddress string    `json:"remote_address,omitempty"`
	DurationMS    int64     `json:"duration_ms"`
	Time          time.Time `json:"time"`
	Expires       time.Time `json:"expires"`
	Scope         string    `json:"scope"`
}

func validTarget(target string) error {
	if len(target) > 320 || strings.ContainsAny(target, "/\\?#@\x00\r\n\t ") {
		return errors.New("target must be a hostname or IP with an explicit port")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return errors.New("target must be host:port")
	}
	p, e := strconv.Atoi(port)
	if e != nil || p < 1 || p > 65535 {
		return errors.New("invalid target port")
	}
	if a, e := netip.ParseAddr(host); e == nil {
		if a.IsUnspecified() || a.IsMulticast() {
			return errors.New("target cannot be unspecified or multicast")
		}
	} else {
		for _, r := range host {
			if r > 127 || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
				return errors.New("invalid target hostname")
			}
		}
	}
	return nil
}

func probeTarget(ctx context.Context, cfg *kone.KoneConfig, outbound, target string, withTLS bool) (r ProbeResult) {
	start := time.Now()
	r = ProbeResult{Target: target, Outbound: outbound, Protocol: "tcp", Stage: "connect", Status: "failed", Time: start, Expires: start.Add(5 * time.Minute), Scope: "diagnostic; not application traffic"}
	defer func() { r.DurationMS = time.Since(start).Milliseconds() }()
	if err := validTarget(target); err != nil {
		r.Message = err.Error()
		return r
	}
	one, err := kone.FromConfig(cfg)
	if err != nil {
		r.Stage = "configuration_or_dns"
		r.Message = safeMessage(err, cfg)
		return r
	}
	defer one.Close()
	conn, err := one.DialDiagnostic(ctx, outbound, target)
	r.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		r.Message = safeMessage(err, cfg)
		return r
	}
	defer conn.Close()
	r.RemoteAddress = conn.RemoteAddr().String()
	if withTLS {
		r.Stage = "tls"
		host, _, _ := net.SplitHostPort(target)
		client := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err = client.HandshakeContext(ctx); err != nil {
			r.Message = safeMessage(err, cfg)
			r.DurationMS = time.Since(start).Milliseconds()
			return r
		}
	}
	r.Status = "reachable"
	r.Message = "TCP connection succeeded; application requests were not replayed"
	if withTLS {
		r.Message = "TCP and verified TLS succeeded; no application request was sent"
	}
	r.DurationMS = time.Since(start).Milliseconds()
	return r
}

func (c *Controller) beginOperation(kind, key string, timeout time.Duration, fn func(context.Context) (any, error)) Operation {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return Operation{Kind: kind, Status: "failed", Error: "Application is stopping"}
	}
	if key != "" {
		if id, ok := c.requestKeys[kind+":"+key]; ok {
			if existing := c.operations[id]; existing != nil {
				copy := *existing
				c.mu.Unlock()
				return copy
			}
		}
	}
	running := 0
	for _, operation := range c.operations {
		if operation.Status == "running" {
			running++
		}
	}
	if running >= 8 {
		c.mu.Unlock()
		return Operation{Kind: kind, Status: "failed", Error: "Operation limit reached; retry after current tasks finish"}
	}
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
	op := &Operation{ID: randomID("op"), Kind: kind, Status: "running", Stage: kind, Started: c.now(), cancel: cancel}
	c.operations[op.ID] = op
	c.operationOrder = append(c.operationOrder, op.ID)
	if key != "" {
		c.requestKeys[kind+":"+key] = op.ID
	}
	for len(c.operationOrder) > 64 {
		index := -1
		for i, id := range c.operationOrder {
			if c.operations[id].Status != "running" {
				index = i
				break
			}
		}
		if index < 0 {
			break
		}
		old := c.operationOrder[index]
		delete(c.operations, old)
		c.operationOrder = append(c.operationOrder[:index], c.operationOrder[index+1:]...)
		for key, id := range c.requestKeys {
			if id == old {
				delete(c.requestKeys, key)
			}
		}
	}
	copy := *op
	c.mu.Unlock()
	go func() {
		result, err := fn(ctx)
		cancel()
		c.mu.Lock()
		defer c.mu.Unlock()
		now := c.now()
		op.Finished = &now
		op.Result = result
		op.Status = "succeeded"
		if err != nil {
			op.Status = "failed"
			if errors.Is(err, context.Canceled) {
				op.Status = "canceled"
			}
			op.Error = safeMessage(err, c.doc.Config)
		}
	}()
	return copy
}

func (c *Controller) Operations() []Operation {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Operation, 0, len(c.operations))
	for i := len(c.operationOrder) - 1; i >= 0; i-- {
		if op := c.operations[c.operationOrder[i]]; op != nil {
			out = append(out, *op)
		}
	}
	return out
}
func (c *Controller) cancelOperation(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	op := c.operations[id]
	if op == nil {
		return errors.New("operation not found")
	}
	op.cancel()
	return nil
}

func (c *Controller) Diagnose(target string, outbounds []string, withTLS bool, key string) (Operation, error) {
	if err := validTarget(target); err != nil {
		return Operation{}, err
	}
	if len(outbounds) == 0 {
		outbounds = []string{kone.BuiltinDirect}
	}
	if len(outbounds) > 8 {
		return Operation{}, errors.New("too many comparison outbounds")
	}
	c.mu.Lock()
	doc := cloneDocument(c.doc)
	c.mu.Unlock()
	known := map[string]bool{kone.BuiltinDirect: true}
	for _, outbound := range doc.Config.Outbounds {
		known[outbound.Name] = true
	}
	for _, name := range outbounds {
		if !known[name] {
			return Operation{}, errors.New("unknown or non-dialing outbound")
		}
	}
	return c.beginOperation("diagnostics", key, 20*time.Second, func(ctx context.Context) (any, error) {
		select {
		case c.probeSlots <- struct{}{}:
		default:
			return nil, errors.New("diagnostic concurrency limit reached")
		}
		defer func() { <-c.probeSlots }()
		results := make([]ProbeResult, 0, len(outbounds))
		for _, name := range outbounds {
			if err := ctx.Err(); err != nil {
				return results, err
			}
			probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			result := c.probe(probeCtx, engineConfig(doc), name, target, withTLS)
			cancel()
			results = append(results, result)
		}
		suggested := false
		if len(results) > 1 && results[0].Outbound == kone.BuiltinDirect && results[0].Status == "failed" {
			for _, r := range results[1:] {
				if r.Status == "reachable" {
					suggested = true
				}
			}
		}
		return map[string]any{"target": target, "results": results, "suggest_proxy": suggested, "automatic_rule": false}, nil
	}), nil
}
