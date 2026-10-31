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
var ErrDNSBusy = errors.New("DNS resolver concurrency limit reached")

type Dns struct {
	one         *One
	server      *dns.Server
	tcpServer   *dns.Server
	client      *dns.Client
	tcpClient   *dns.Client
	nameservers []string
	routes      []DNSRouteConfig
	ctx         context.Context
	started     atomic.Bool
	tcpStarted  atomic.Bool
	history     *dnsHistory
	cache       *dnsResponseCache
	pending     chan struct{}
	ipv6        *ipv6DNSServers
}

func (d *Dns) Resolve(domain string) (*dns.Msg, error) {
	return d.ResolveContext(context.Background(), domain)
}
func (d *Dns) ResolveContext(ctx context.Context, domain string) (*dns.Msg, error) {
	return d.ResolveTypeContext(ctx, domain, dns.TypeA)
}

func (d *Dns) ResolveTypeContext(ctx context.Context, domain string, kind uint16) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetQuestion(dns.Fqdn(domain), kind)
	meta := &dnsQueryMeta{}
	start := time.Now()
	msg, err := d.resolve(context.WithValue(ctx, dnsMetaKey{}, meta), r)
	version := uint64(0)
	if d.one != nil {
		if s := d.one.policy.Load(); s != nil {
			version = s.configurationVersion()
		}
	}
	d.recordQuery(r, msg, err, "control", "", version, start, meta)
	return msg, err
}

func (d *Dns) setDialer(dialer *net.Dialer) { d.client.Dialer = dialer; d.tcpClient.Dialer = dialer }

// Every exchange owns its connection and message. Close on cancellation as
// miekg/dns honors deadlines but otherwise cannot interrupt an active read.
func (d *Dns) exchange(ctx context.Context, client *dns.Client, server string, r *dns.Msg) (*dns.Msg, error) {
	conn, err := client.DialContext(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.Close(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	msg, _, err := client.ExchangeWithConnContext(ctx, r.Copy(), conn)
	return msg, err
}

type dnsLookupResult struct {
	msg               *dns.Msg
	err               error
	server, transport string
}

func (d *Dns) lookup(ctx context.Context, server string, r *dns.Msg) dnsLookupResult {
	result := dnsLookupResult{server: server, transport: "udp"}
	result.msg, result.err = d.exchange(ctx, d.client, server, r)
	if result.err == nil && result.msg != nil && result.msg.Truncated {
		result.transport = "tcp"
		result.msg, result.err = d.exchange(ctx, d.tcpClient, server, r)
	}
	if result.err == nil && (result.msg == nil || result.msg.Truncated) {
		result.err = errors.New("truncated DNS response after TCP retry")
	}
	if result.err == nil && result.msg.Rcode != dns.RcodeSuccess && result.msg.Rcode != dns.RcodeNameError {
		result.err = fmt.Errorf("upstream returned rcode %d", result.msg.Rcode)
	}
	return result
}

func (d *Dns) resolve(parent context.Context, r *dns.Msg) (*dns.Msg, error) {
	if r == nil || len(r.Question) != 1 {
		return nil, errors.New("DNS query must contain exactly one question")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	meta, _ := parent.Value(dnsMetaKey{}).(*dnsQueryMeta)
	servers, route := d.selectResolvers(r.Question[0].Name)
	if meta != nil {
		meta.Route = route
		meta.Cache = "miss"
	}
	key := dnsCacheKey(r, route)
	if msg := d.cache.get(key, r.Id, time.Now()); msg != nil {
		msg.Question = append([]dns.Question(nil), r.Question...)
		if meta != nil {
			meta.Cache = "hit"
			meta.Upstream = "cache"
		}
		return msg, nil
	}
	if len(servers) == 0 {
		return nil, ErrResolve
	}
	if d.pending != nil {
		select {
		case d.pending <- struct{}{}:
			defer func() { <-d.pending }()
		default:
			return nil, ErrDNSBusy
		}
	}
	if meta != nil {
		meta.AttemptedResolvers = append([]string(nil), servers...)
		if len(servers) == 1 {
			meta.Upstream, meta.UpstreamTransport = servers[0], "udp"
		}
	}
	ctx, cancel := context.WithCancel(parent)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	results := make(chan dnsLookupResult, len(servers))
	for _, server := range servers {
		wg.Add(1)
		go func(server string) { defer wg.Done(); results <- d.lookup(ctx, server, r) }(server)
	}
	var negative *dnsLookupResult
	var failures []error
	complete := func(result dnsLookupResult) (*dns.Msg, error) {
		if meta != nil {
			meta.Upstream = result.server
			meta.UpstreamTransport = result.transport
		}
		d.cache.put(key, result.msg, time.Now())
		return result.msg, nil
	}
	// Wait for configured resolvers before accepting NXDOMAIN, so a fast
	// negative response cannot defeat a positive answer from another resolver.
	// Split routes are exclusive: failures never fall back to public servers.
	for range servers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			if result.err == nil {
				if result.msg.Rcode != dns.RcodeNameError && len(result.msg.Answer) > 0 {
					return complete(result)
				}
				copy := result
				negative = &copy
			} else {
				if meta != nil {
					meta.Upstream = result.server
					meta.UpstreamTransport = result.transport
				}
				failures = append(failures, result.err)
			}
		}
	}
	if negative != nil {
		return complete(*negative)
	}
	return nil, errors.Join(append([]error{ErrResolve}, failures...)...)
}

func (d *Dns) doIPv4Query(r *dns.Msg) (*dns.Msg, error) {
	return d.query(d.ctx, d.one.policy.Load(), r)
}
func (d *Dns) query(ctx context.Context, s *runtimeSnapshot, r *dns.Msg) (*dns.Msg, error) {
	domain := normalizeDomain(r.Question[0].Name)
	table := d.one.dnsTable
	if r.Question[0].Qtype == dns.TypeAAAA {
		table = d.one.dnsTable6
	}
	if table == nil {
		return d.resolve(ctx, r)
	}
	if table.IsNonProxyDomain(domain, s.version) {
		return d.resolve(ctx, r)
	}
	record := table.Get(domain)
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
			record = table.Set(domain, policy)
		}
		if record == nil {
			return nil, errors.New("virtual IP pool exhausted")
		}
		if meta, _ := ctx.Value(dnsMetaKey{}).(*dnsQueryMeta); meta != nil {
			meta.Cache = "fake-ip"
			meta.Virtual = []string{record.IP.String()}
			if record.RealIP != nil {
				meta.Real = []string{record.RealIP.String()}
			}
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
		record = table.Set(domain, policy)
		if record == nil {
			return nil, errors.New("virtual IP pool exhausted")
		}
		table.SetRealIP(domain, msg)
		if meta, _ := ctx.Value(dnsMetaKey{}).(*dnsQueryMeta); meta != nil {
			meta.Virtual = []string{record.IP.String()}
			meta.Real = dnsAddresses(msg)
		}
		return record.Answer(r), nil
	}
	table.SetNonProxyDomain(domain, msg.Answer[0].Header().Ttl, s.version)
	return msg, nil
}

// HandleQuery is shared by owned UDP/TCP listeners and sing-tun's DNS callback.
// Every client request reads one policy generation and creates one DNS event.
func (d *Dns) HandleQuery(ctx context.Context, r *dns.Msg, transport, source string) (*dns.Msg, error) {
	if r == nil || len(r.Question) != 1 {
		return nil, errors.New("DNS query must contain exactly one question")
	}
	s := d.one.policy.Load()
	meta := &dnsQueryMeta{}
	start := time.Now()
	ctx = context.WithValue(ctx, dnsMetaKey{}, meta)
	var msg *dns.Msg
	var err error
	if r.Question[0].Qclass == dns.ClassINET && (r.Question[0].Qtype == dns.TypeA || r.Question[0].Qtype == dns.TypeAAAA && d.one.dnsTable6 != nil) {
		msg, err = d.query(ctx, s, r)
	} else {
		msg, err = d.resolve(ctx, r)
	}
	d.recordQuery(r, msg, err, transport, source, s.configurationVersion(), start, meta)
	return msg, err
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
	transport := "udp"
	if w.RemoteAddr().Network() == "tcp" || w.RemoteAddr().Network() == "tcp4" || w.RemoteAddr().Network() == "tcp6" {
		transport = "tcp"
	}
	msg, err := d.HandleQuery(d.ctx, r, transport, w.RemoteAddr().String())
	if err != nil {
		msg = new(dns.Msg)
		msg.SetRcode(r, dns.RcodeServerFailure)
	}
	if transport == "udp" {
		size := uint16(512)
		if opt := r.IsEdns0(); opt != nil {
			size = opt.UDPSize()
			if size < 512 {
				size = 512
			}
		}
		msg.Truncate(int(size))
	}
	w.WriteMsg(msg)
}

func NewDns(one *One, cfg DNSConfig) (*Dns, error) {
	d := &Dns{one: one, ctx: context.Background(), history: newDNSHistory(int(cfg.HistoryLimit), time.Duration(cfg.HistoryRetention)*time.Second), cache: newDNSResponseCache(int(cfg.CacheLimit)), pending: make(chan struct{}, 64)}
	addr := net.JoinHostPort(fixTunIP(one.ip).String(), strconv.Itoa(int(cfg.ListenPort)))
	makeServer := func(network string) *dns.Server {
		return &dns.Server{Net: network, Addr: addr, Handler: d, UDPSize: int(cfg.PacketSize), ReadTimeout: time.Duration(cfg.ReadTimeout) * time.Second, WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second}
	}
	d.server, d.tcpServer = makeServer("udp"), makeServer("tcp")
	d.ipv6 = d.ipv6Servers(cfg)
	client := dns.Client{UDPSize: cfg.PacketSize, Timeout: time.Duration(cfg.ReadTimeout+cfg.WriteTimeout) * time.Second, ReadTimeout: time.Duration(cfg.ReadTimeout) * time.Second, WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second}
	udpClient, tcpClient := client, client
	udpClient.Net, tcpClient.Net = "udp", "tcp"
	d.client, d.tcpClient = &udpClient, &tcpClient
	for _, server := range cfg.Servers {
		normalized, err := normalizeDNSServer(server)
		if err != nil {
			return nil, err
		}
		d.nameservers = append(d.nameservers, normalized)
	}
	for _, route := range cfg.Rules {
		copy := DNSRouteConfig{Suffix: normalizeDNSSuffix(route.Suffix)}
		for _, server := range route.Servers {
			normalized, err := normalizeDNSServer(server)
			if err != nil {
				return nil, err
			}
			copy.Servers = append(copy.Servers, normalized)
		}
		d.routes = append(d.routes, copy)
	}
	return d, nil
}
