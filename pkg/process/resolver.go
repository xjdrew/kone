// Package process attributes already observed local sockets without delaying
// forwarding. Missing permissions and ambiguous/reused identities stay unknown.
package process

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Query struct {
	Protocol    string
	Source      netip.AddrPort
	Destination netip.AddrPort
	ObservedAt  time.Time
}

type Result struct {
	Status     string    `json:"status"`
	Reason     string    `json:"reason,omitempty"`
	PID        uint32    `json:"pid,omitempty"`
	Name       string    `json:"name,omitempty"`
	Path       string    `json:"path,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	Source     string    `json:"source"`
}

type Options struct {
	Workers        int
	QueueSize      int
	Timeout        time.Duration
	Lookup         func(context.Context, Query) (Result, error)
	LocalAddresses func() ([]netip.Addr, error)
	Now            func() time.Time
}

type request struct {
	ctx     context.Context
	query   Query
	deliver func(Result)
}
type Resolver struct {
	ctx     context.Context
	cancel  context.CancelFunc
	queue   chan request
	options Options
	workers sync.WaitGroup
	once    sync.Once
}

func localAddresses() ([]netip.Addr, error) {
	values, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	for _, value := range values {
		if prefix, err := netip.ParsePrefix(value.String()); err == nil {
			addresses = append(addresses, prefix.Addr().Unmap())
		}
	}
	return addresses, nil
}

func New(options Options) *Resolver {
	if options.Workers <= 0 {
		options.Workers = 2
	}
	if options.Workers > 4 {
		options.Workers = 4
	}
	if options.QueueSize <= 0 {
		options.QueueSize = 64
	}
	if options.QueueSize > 1024 {
		options.QueueSize = 1024
	}
	if options.Timeout <= 0 {
		options.Timeout = 500 * time.Millisecond
	}
	if options.Timeout > 2*time.Second {
		options.Timeout = 2 * time.Second
	}
	if options.Lookup == nil {
		options.Lookup = lookupNative
	}
	if options.LocalAddresses == nil {
		options.LocalAddresses = localAddresses
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Resolver{ctx: ctx, cancel: cancel, queue: make(chan request, options.QueueSize), options: options}
	for range options.Workers {
		r.workers.Add(1)
		go r.work()
	}
	return r
}

// LookupAsync never waits for a worker. A full queue declines the request so
// the caller can keep its explicit unknown attribution and continue forwarding.
func (r *Resolver) LookupAsync(ctx context.Context, query Query, deliver func(Result)) bool {
	if ctx == nil || deliver == nil || ctx.Err() != nil || r.ctx.Err() != nil {
		return false
	}
	select {
	case <-r.ctx.Done():
		return false
	case r.queue <- request{ctx: ctx, query: query, deliver: deliver}:
		return true
	default:
		return false
	}
}

func (r *Resolver) work() {
	defer r.workers.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		case work := <-r.queue:
			if r.ctx.Err() != nil || work.ctx.Err() != nil {
				continue
			}
			ctx, cancel := context.WithTimeout(r.ctx, r.options.Timeout)
			stop := context.AfterFunc(work.ctx, cancel)
			result := r.resolve(ctx, work.query)
			stop()
			cancel()
			if r.ctx.Err() == nil && work.ctx.Err() == nil {
				work.deliver(result)
			}
		}
	}
}

func (r *Resolver) resolve(ctx context.Context, query Query) Result {
	now := r.options.Now()
	unknown := Result{Status: "unknown", Source: "system_socket_snapshot", ObservedAt: now}
	if query.Protocol != "tcp" && query.Protocol != "udp" || !query.Source.IsValid() || !query.Destination.IsValid() || query.Source.Port() == 0 {
		unknown.Reason = "invalid socket identity"
		return unknown
	}
	if query.ObservedAt.IsZero() || now.Sub(query.ObservedAt) > 2*time.Second || query.ObservedAt.After(now.Add(50*time.Millisecond)) {
		unknown.Reason = "socket observation is stale or has an invalid timestamp"
		return unknown
	}
	addresses, err := r.options.LocalAddresses()
	if err != nil {
		unknown.Reason = "local interface inspection is unavailable"
		return unknown
	}
	local := false
	for _, address := range addresses {
		if address.Unmap() == query.Source.Addr().Unmap() {
			local = true
			break
		}
	}
	if !local {
		unknown.Status = "remote"
		unknown.Reason = "source belongs to a remote client, not a host interface"
		unknown.Source = "local_interface_snapshot"
		return unknown
	}
	if ctx.Err() != nil {
		unknown.Reason = "process attribution timed out"
		return unknown
	}
	result, err := r.options.Lookup(ctx, query)
	if err != nil {
		unknown.Reason = "socket owner is unavailable, ambiguous, exited, or access was denied"
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			unknown.Reason = "process attribution timed out"
		}
		return unknown
	}
	if result.Status != "matched" || result.PID == 0 || result.Name == "" || result.StartedAt.IsZero() || result.StartedAt.After(query.ObservedAt) {
		unknown.Reason = "process identity could not be validated at observation time"
		return unknown
	}
	if ctx.Err() != nil {
		unknown.Reason = "process attribution timed out"
		return unknown
	}
	result.ObservedAt = r.options.Now()
	return result
}

func (r *Resolver) Close() { r.once.Do(r.cancel); r.workers.Wait() }
