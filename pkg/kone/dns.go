//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/miekg/dns/dnsutil"
)

const (
	DnsDefaultPort         = 53
	DnsDefaultTtl          = 600
	DnsDefaultPacketSize   = 4096
	DnsDefaultReadTimeout  = 5
	DnsDefaultWriteTimeout = 5
)

var ErrResolve = errors.New("resolve timeout")

type Dns struct {
	one         *One
	server      *dns.Server
	client      *dns.Client
	nameservers []string
}

// query synchronously
func (d *Dns) Resolve(domain string) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	return d.resolve(r)
}

func (d *Dns) resolve(r *dns.Msg) (*dns.Msg, error) {
	if r == nil || len(r.Question) != 1 {
		return nil, errors.New("DNS query must contain exactly one question")
	}
	var wg sync.WaitGroup
	msgCh := make(chan *dns.Msg, 1)

	qname := r.Question[0].Name

	Q := func(ns string) {
		defer wg.Done()

		r, rtt, err := d.client.Exchange(r, ns)
		if err != nil {
			slog.Debug("DNS query failed", "domain", qname, "server", ns, "error", err)
			return
		}

		// remove this code
		if r.Rcode != dns.RcodeSuccess {
			slog.Debug("DNS upstream returned error", "domain", qname, "server", ns, "rcode", r.Rcode)
			return
		}

		slog.Debug("DNS query completed", "domain", qname, "server", ns, "rcode", r.Rcode, "duration", rtt)

		select {
		case msgCh <- r:
		default:
		}
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for _, ns := range d.nameservers {
		wg.Add(1)
		go Q(ns)

		select {
		case r := <-msgCh:
			return r, nil
		case <-ticker.C:
			continue
		}
	}

	wg.Wait()

	select {
	case r := <-msgCh:
		return r, nil
	default:
		slog.Error("DNS query timed out", "domain", qname)
		return nil, ErrResolve
	}
}

func (d *Dns) doIPv4Query(r *dns.Msg) (*dns.Msg, error) {
	one := d.one

	domain := normalizeDomain(dnsutil.TrimDomainName(r.Question[0].Name, "."))
	// short circuit: non proxy
	if one.dnsTable.IsNonProxyDomain(domain) {
		return d.resolve(r)
	}

	// short circuit: proxy
	record := one.dnsTable.Get(domain)
	if record != nil {
		if record.Proxy == "DIRECT" {
			return d.resolve(r)
		}
		return record.Answer(r), nil
	}

	// match by domain
	proxy := one.rule.Proxy(domain)
	if proxy != "DIRECT" {
		record := one.dnsTable.Set(domain, proxy)
		if record == nil {
			return nil, errors.New("virtual IP pool exhausted")
		}
		return record.Answer(r), nil
	}

	// match by IP & CNAME
	msg, err := d.resolve(r)
	if err != nil || len(msg.Answer) == 0 {
		return msg, err
	}

	proxy = one.rule.ProxyDNS(domain, msg)

	// if IP or CNAME use proxy
	if proxy != "DIRECT" {
		record := one.dnsTable.Set(domain, proxy)
		if record == nil {
			return nil, errors.New("virtual IP pool exhausted")
		}
		one.dnsTable.SetRealIP(domain, msg)
		return record.Answer(r), nil
	} else {
		// set domain as a non-proxy-domain
		one.dnsTable.SetNonProxyDomain(domain, msg.Answer[0].Header().Ttl)
		// final
		return msg, err
	}
}

func isIPv4Query(q dns.Question) bool {
	if q.Qclass == dns.ClassINET && q.Qtype == dns.TypeA {
		return true
	}
	return false
}

func (d *Dns) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if r == nil {
		return
	}
	if len(r.Question) != 1 {
		rsp := new(dns.Msg)
		rsp.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(rsp)
		return
	}
	d.one.policyMu.RLock()
	defer d.one.policyMu.RUnlock()
	isIPv4 := isIPv4Query(r.Question[0])

	var msg *dns.Msg
	var err error

	if isIPv4 {
		msg, err = d.doIPv4Query(r)
	} else {
		msg, err = d.resolve(r)
	}

	if err != nil {
		dns.HandleFailed(w, r)
	} else {
		w.WriteMsg(msg)
	}
}

func (d *Dns) Serve() error {
	slog.Info("DNS listener starting", "address", d.server.Addr)
	return d.server.ListenAndServe()
}

func NewDns(one *One, cfg CoreConfig) (*Dns, error) {
	d := new(Dns)
	d.one = one

	dnsListenAddr := fmt.Sprintf("%s:%d", fixTunIP(one.ip), cfg.DnsListenPort)
	server := &dns.Server{
		Net:          "udp",
		Addr:         dnsListenAddr,
		Handler:      dns.HandlerFunc(d.ServeDNS),
		UDPSize:      int(cfg.DnsPacketSize),
		ReadTimeout:  time.Duration(cfg.DnsReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.DnsWriteTimeout) * time.Second,
	}

	client := &dns.Client{
		Net:          "udp",
		UDPSize:      cfg.DnsPacketSize,
		ReadTimeout:  time.Duration(cfg.DnsReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.DnsWriteTimeout) * time.Second,
	}

	d.server = server
	d.client = client

	for _, addr := range cfg.DnsServer {
		var err error
		addr, err = normalizeDNSServer(addr)
		if err != nil {
			return nil, err
		}

		if addr != dnsListenAddr { // don't add self
			d.nameservers = append(d.nameservers, addr)
		}
	}
	slog.Info("DNS upstreams configured", "servers", d.nameservers)
	return d, nil
}
