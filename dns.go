//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"errors"
	"fmt"
	"strings"
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

var errResolve = errors.New("resolve error")

type Dns struct {
	one         *One
	server      *dns.Server
	client      *dns.Client
	nameservers []string
}

func (d *Dns) resolve(r *dns.Msg) (*dns.Msg, error) {
	var wg sync.WaitGroup
	msgCh := make(chan *dns.Msg, 1)

	qname := r.Question[0].Name

	Q := func(ns string) {
		defer wg.Done()

		r, rtt, err := d.client.Exchange(r, ns)
		if err != nil {
			logger.Debugf("[dns] resolve %s on %s failed: %v", qname, ns, err)
			return
		}

		if r.Rcode == dns.RcodeServerFailure {
			logger.Debugf("[dns] resolve %s on %s failed: code %d", qname, ns, r.Rcode)
			return
		}

		logger.Debugf("[dns] resolve %s on %s, code: %d, rtt: %d", qname, ns, r.Rcode, rtt)

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
		logger.Errorf("[dns] query %s failed", qname)
		return nil, errResolve
	}
}

func (d *Dns) fillRealIP(record *DomainRecord, r *dns.Msg) {
	// resolve
	msg, err := d.resolve(r)
	if err != nil || len(msg.Answer) == 0 {
		return
	}
	record.SetRealIP(msg)
}

func (d *Dns) doIPv4Query(r *dns.Msg) (*dns.Msg, error) {
	one := d.one

	domain := dnsutil.TrimDomainName(r.Question[0].Name, ".")
	// if is a non-proxy-domain
	if one.dnsTable.IsNonProxyDomain(domain) {
		return d.resolve(r)
	}

	// if have already hijacked
	record := one.dnsTable.Get(domain)
	if record != nil {
		return record.Answer(r), nil
	}

	// match by domain
	proxy := one.rule.Proxy(domain)

	// if domain use proxy
	if proxy != "DIRECT" {
		record := one.dnsTable.Set(domain, proxy)
		go d.fillRealIP(record, r) // why?
		return record.Answer(r), nil
	}

	// resolve
	msg, err := d.resolve(r)
	if err != nil || len(msg.Answer) == 0 {
		return msg, err
	}

	// try match by cname and ip
	for _, item := range msg.Answer {
		switch answer := item.(type) {
		case *dns.A:
			// test ip
			proxy = one.rule.Proxy(answer.A)
			if proxy != "DIRECT" {
				break
			}
		case *dns.CNAME:
			// test cname
			proxy = one.rule.Proxy(answer.Target)
			if proxy != "DIRECT" {
				break
			}
		default:
			logger.Noticef("[dns] unexpected response %s -> %v", domain, item)
		}
	}

	// if ip use proxy
	if proxy != "DIRECT" {
		record := one.dnsTable.Set(domain, proxy)
		record.SetRealIP(msg)
		return record.Answer(r), nil
	}

	// set domain as a non-proxy-domain
	one.dnsTable.SetNonProxyDomain(domain, msg.Answer[0].Header().Ttl)

	// final
	return msg, err
}

func isIPv4Query(q dns.Question) bool {
	if q.Qclass == dns.ClassINET && q.Qtype == dns.TypeA {
		return true
	}
	return false
}

func (d *Dns) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
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
	logger.Infof("[dns] listen on %s", d.server.Addr)
	return d.server.ListenAndServe()
}

func NewDns(one *One, cfg CoreConfig) (*Dns, error) {
	d := new(Dns)
	d.one = one

	server := &dns.Server{
		Net:          "udp",
		Addr:         fmt.Sprintf("%s:%d", fixTunIP(one.ip), cfg.DnsListenPort),
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
		if !strings.Contains(addr, ":") {
			d.nameservers = append(d.nameservers, addr+":53")
		}
	}
	return d, nil
}
