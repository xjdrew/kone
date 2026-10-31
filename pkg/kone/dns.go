package kone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	DnsDefaultPort         = 53
	DnsDefaultTtl          = 600
	DnsDefaultPacketSize   = 4096
	DnsDefaultReadTimeout  = 5
	DnsDefaultWriteTimeout = 5
)

var ErrResolve = errors.New("DNS resolution failed")

type Dns struct {
	one         *One
	server      *dns.Server
	client      *dns.Client
	nameservers []string
	ctx         context.Context
	started     atomic.Bool
}

func (d *Dns) Resolve(domain string) (*dns.Msg, error) {
	return d.ResolveContext(context.Background(), domain)
}
func (d *Dns) ResolveContext(ctx context.Context, domain string) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	return d.resolve(ctx, r)
}

// Every upstream owns its message and connection. Cancellation closes pending
// reads as well as dials; miekg/dns otherwise only honors context deadlines.
func (d *Dns) resolve(parent context.Context, r *dns.Msg) (*dns.Msg, error) {
	if r == nil || len(r.Question) != 1 {
		return nil, errors.New("DNS query must contain exactly one question")
	}
	ctx, cancel := context.WithCancel(parent)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	type answer struct {
		msg *dns.Msg
		err error
	}
	results := make(chan answer, len(d.nameservers))
	for _, server := range d.nameservers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			conn, err := d.client.DialContext(ctx, server)
			if err != nil {
				results <- answer{err: err}
				return
			}
			defer conn.Close()
			stopped := make(chan struct{})
			stop := context.AfterFunc(ctx, func() { conn.Close(); close(stopped) })
			defer func() {
				if !stop() {
					<-stopped
				}
			}()
			msg, _, err := d.client.ExchangeWithConnContext(ctx, r.Copy(), conn)
			if err == nil && msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
				err = fmt.Errorf("upstream returned rcode %d", msg.Rcode)
			}
			results <- answer{msg: msg, err: err}
		}(server)
	}
	var failures []error
	for range d.nameservers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			if result.err == nil {
				return result.msg, nil
			}
			failures = append(failures, result.err)
		}
	}
	return nil, errors.Join(append([]error{ErrResolve}, failures...)...)
}

func (d *Dns) doIPv4Query(r *dns.Msg) (*dns.Msg, error) {
	return d.query(d.ctx, d.one.policy.Load(), r)
}
func (d *Dns) query(ctx context.Context, s *runtimeSnapshot, r *dns.Msg) (*dns.Msg, error) {
	domain := normalizeDomain(r.Question[0].Name)
	if d.one.dnsTable.IsNonProxyDomain(domain, s.version) {
		return d.resolve(ctx, r)
	}
	record := d.one.dnsTable.Get(domain)
	policy := s.rule.Proxy(domain)
	if record != nil {
		policy = s.rule.ProxyDNS(domain, record.resolved)
	}
	if s.rule.OutboundType(policy) == OutboundReject {
		reply := new(dns.Msg)
		reply.SetRcode(r, dns.RcodeRefused)
		return reply, nil
	}
	if s.rule.OutboundType(policy) != OutboundDirect {
		if record == nil {
			record = d.one.dnsTable.Set(domain, policy)
		}
		if record == nil {
			return nil, errors.New("virtual IP pool exhausted")
		}
		return record.Answer(r), nil
	}
	msg, err := d.resolve(ctx, r)
	if err != nil || len(msg.Answer) == 0 {
		return msg, err
	}
	policy = s.rule.ProxyDNS(domain, msg)
	if s.rule.OutboundType(policy) == OutboundReject {
		reply := new(dns.Msg)
		reply.SetRcode(r, dns.RcodeRefused)
		return reply, nil
	}
	if s.rule.OutboundType(policy) != OutboundDirect {
		record = d.one.dnsTable.Set(domain, policy)
		if record == nil {
			return nil, errors.New("virtual IP pool exhausted")
		}
		d.one.dnsTable.SetRealIP(domain, msg)
		return record.Answer(r), nil
	}
	d.one.dnsTable.SetNonProxyDomain(domain, msg.Answer[0].Header().Ttl, s.version)
	return msg, nil
}

func (d *Dns) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if r == nil {
		return
	}
	if len(r.Question) != 1 {
		reply := new(dns.Msg)
		reply.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(reply)
		return
	}
	s := d.one.policy.Load() // exactly one rule/proxy/config generation per request
	var msg *dns.Msg
	var err error
	if r.Question[0].Qclass == dns.ClassINET && r.Question[0].Qtype == dns.TypeA {
		msg, err = d.query(d.ctx, s, r)
	} else {
		msg, err = d.resolve(d.ctx, r)
	}
	if err != nil {
		dns.HandleFailed(w, r)
	} else {
		w.WriteMsg(msg)
	}
}

func NewDns(one *One, cfg DNSConfig) (*Dns, error) {
	d := &Dns{one: one, ctx: context.Background()}
	addr := net.JoinHostPort(fixTunIP(one.ip).String(), strconv.Itoa(int(cfg.ListenPort)))
	d.server = &dns.Server{Net: "udp", Addr: addr, Handler: d, UDPSize: int(cfg.PacketSize), ReadTimeout: time.Duration(cfg.ReadTimeout) * time.Second, WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second}
	d.client = &dns.Client{Net: "udp", UDPSize: cfg.PacketSize, Timeout: time.Duration(cfg.ReadTimeout+cfg.WriteTimeout) * time.Second, ReadTimeout: time.Duration(cfg.ReadTimeout) * time.Second, WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second}
	for _, server := range cfg.Servers {
		normalized, err := normalizeDNSServer(server)
		if err != nil {
			return nil, err
		}
		d.nameservers = append(d.nameservers, normalized)
	}
	return d, nil
}
