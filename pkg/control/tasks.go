package control

import (
	"context"
	"errors"
	"time"

	"github.com/xjdrew/kone/pkg/kone"
)

type ProbeResult = kone.DiagnosticResult

var ErrDiagnosticRateLimit = errors.New("diagnostic rate limit reached; allow one minute before retrying")

func probeUDPTarget(ctx context.Context, cfg *kone.KoneConfig, outbound, target string, options kone.DiagnosticOptions) ProbeResult {
	now := time.Now()
	base := ProbeResult{Target: target, Outbound: outbound, Protocol: "udp", Time: now, Expires: now.Add(5 * time.Minute), Scope: "explicit UDP/DNS response test; not application traffic"}
	one, err := kone.FromConfig(cfg)
	if err != nil {
		base.Stage, base.Status, base.Message = "configuration_or_dns", "failed", safeMessage(err, cfg)
		return base
	}
	defer one.Close()
	result, err := one.ProbeDiagnosticRequestVersion(ctx, outbound, target, options, 0)
	if err != nil {
		if result.Target == "" {
			result = base
		}
		result.Status = "unknown"
		result.Stage = "lifecycle"
		result.Message = safeMessage(err, cfg)
	}
	return result
}

func validTarget(target string) error {
	return kone.ValidateDiagnosticTarget(target)
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
	r, err = one.ProbeDiagnostic(ctx, outbound, target, withTLS)
	if err != nil {
		r.Status = "unknown"
		r.Stage = "lifecycle"
		r.Message = safeMessage(err, cfg)
	}
	return r
}

func (c *Controller) beginOperation(kind, key string, timeout time.Duration, fn func(context.Context) (any, error)) Operation {
	operation, _ := c.beginOperationAdmitted(kind, key, timeout, fn, nil)
	return operation
}

// Admission and idempotent lookup share the operation lock: another kind of
// operation cannot evict a completed request between checking and charging it.
func (c *Controller) beginOperationAdmitted(kind, key string, timeout time.Duration, fn func(context.Context) (any, error), admit func() error) (Operation, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return Operation{Kind: kind, Status: "failed", Error: "Application is stopping"}, nil
	}
	if key != "" {
		if id, ok := c.requestKeys[kind+":"+key]; ok {
			if existing := c.operations[id]; existing != nil {
				copy := *existing
				c.mu.Unlock()
				return copy, nil
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
		return Operation{Kind: kind, Status: "failed", Error: "Operation limit reached; retry after current tasks finish"}, nil
	}
	if admit != nil {
		if err := admit(); err != nil {
			c.mu.Unlock()
			return Operation{}, err
		}
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
	return copy, nil
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
	return c.DiagnoseProtocol(target, outbounds, kone.DiagnosticOptions{TLS: withTLS}, key)
}

func (c *Controller) DiagnoseProtocol(target string, outbounds []string, options kone.DiagnosticOptions, key string) (Operation, error) {
	options, err := options.Normalize()
	if err != nil {
		return Operation{}, err
	}
	if err := validTarget(target); err != nil {
		return Operation{}, err
	}
	if len(outbounds) == 0 {
		outbounds = []string{kone.BuiltinDirect}
	}
	if len(outbounds) > 8 {
		return Operation{}, errors.New("too many comparison outbounds")
	}
	outbounds = append([]string(nil), outbounds...)
	c.mu.Lock()
	doc := cloneDocument(c.doc)
	engine := c.engine
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
	// Called under the operation lock only for an admitted new request.
	admit := func() error {
		now := c.now()
		if now.Sub(c.diagnosticRate.start) >= time.Minute {
			c.diagnosticRate = rateWindow{start: now}
		}
		if c.diagnosticRate.count+len(outbounds) > 32 {
			return ErrDiagnosticRateLimit
		}
		c.diagnosticRate.count += len(outbounds)
		return nil
	}
	return c.beginOperationAdmitted("diagnostics", key, 20*time.Second, func(ctx context.Context) (any, error) {
		select {
		case c.probeSlots <- struct{}{}:
		default:
			return nil, errors.New("diagnostic concurrency limit reached")
		}
		defer func() { <-c.probeSlots }()
		results := make([]ProbeResult, 0, len(outbounds))
		partial := func(cause error) (any, error) {
			if options.Protocol == "udp" {
				return map[string]any{"target": target, "protocol": "udp", "results": results, "automatic_rule": false, "suggest_proxy": false}, cause
			}
			return results, cause
		}
		for _, name := range outbounds {
			if err := ctx.Err(); err != nil {
				return partial(err)
			}
			probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			var result ProbeResult
			var probeErr error
			if options.Protocol == "udp" {
				if active, ok := engine.(interface {
					ProbeDiagnosticRequestVersion(context.Context, string, string, kone.DiagnosticOptions, uint64) (kone.DiagnosticResult, error)
				}); ok {
					result, probeErr = active.ProbeDiagnosticRequestVersion(probeCtx, name, target, options, doc.Version)
				} else if engine != nil {
					result = ProbeResult{Target: target, Outbound: name, Protocol: "udp", Status: "unsupported", Stage: "capability", Message: "The running engine does not support independent UDP diagnostics", ConfigVersion: doc.Version}
				} else {
					result = c.probeUDP(probeCtx, engineConfig(doc), name, target, options)
					result.ConfigVersion = doc.Version
				}
			} else if active, ok := engine.(interface {
				ProbeDiagnosticVersion(context.Context, string, string, bool, uint64) (kone.DiagnosticResult, error)
			}); ok {
				result, probeErr = active.ProbeDiagnosticVersion(probeCtx, name, target, options.TLS, doc.Version)
			} else {
				result = c.probe(probeCtx, engineConfig(doc), name, target, options.TLS)
				result.ConfigVersion = doc.Version
			}
			cancel()
			results = append(results, result)
			if probeErr != nil {
				return partial(probeErr)
			}
			if err := ctx.Err(); err != nil {
				return partial(err)
			}
		}
		suggested := false
		if options.Protocol == "tcp" && len(results) > 1 && results[0].Outbound == kone.BuiltinDirect && results[0].Status == "failed" {
			for _, r := range results[1:] {
				if r.Status == "reachable" {
					suggested = true
				}
			}
		}
		return map[string]any{"target": target, "protocol": options.Protocol, "results": results, "suggest_proxy": suggested, "automatic_rule": false}, nil
	}, admit)
}
