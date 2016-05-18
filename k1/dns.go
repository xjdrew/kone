//
//   date  : 2016-05-13
//   author: xjdrew
//

package k1

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/miekg/dns/dnsutil"
)

const (
	dnsDefaultPort         = 53
	dnsDefaultTtl          = 600
	dnsDefaultPacketSize   = 4096
	dnsDefaultReadTimeout  = 5
	dnsDefaultWriteTimeout = 5
)

var resolveErr = errors.New("resolve error")

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
			logger.Errorf("[dns] resolve %s on %s failed: %v", qname, ns, err)
			return
		}

		if r != nil && r.Rcode != dns.RcodeSuccess {
			if r.Rcode == dns.RcodeServerFailure {
				logger.Errorf("[dns] resolve %s on %s failed", qname, ns)
				return
			}
		}

		logger.Debugf("[dns] resolve %s on %s, code: %d, rtt: %d", qname, ns, r.Rcode, rtt)

		select {
		case msgCh <- r:
		default:
		}
	}

	ticker := time.NewTicker(200 * time.Millisecond)
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
		return nil, resolveErr
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
	matched, proxy := one.rule.Proxy(domain)

	// if domain use proxy
	if matched && proxy != "" {
		if record := one.dnsTable.Set(domain, proxy); record != nil {
			go d.fillRealIP(record, r)
			return record.Answer(r), nil
		}
	}

	// resolve
	msg, err := d.resolve(r)
	if err != nil || len(msg.Answer) == 0 {
		return msg, err
	}

	if !matched {
		// try match by cname and ip
		for _, item := range msg.Answer {
			switch answer := item.(type) {
			case *dns.A:
				// test ip
				_, proxy = one.rule.Proxy(answer.A)
				break
			case *dns.CNAME:
				// test cname
				matched, proxy = one.rule.Proxy(answer.Target)
				if matched && proxy != "" {
					break
				}
			default:
				logger.Noticef("[dns] unexpected response %s -> %v", domain, item)
			}
		}
		// if ip use proxy
		if proxy != "" {
			if record := one.dnsTable.Set(domain, proxy); record != nil {
				record.SetRealIP(msg)
				return record.Answer(r), nil
			}
		}
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

func NewDns(one *One, cfg DnsConfig) (*Dns, error) {
	d := new(Dns)
	d.one = one

	server := &dns.Server{
		Net:          "udp",
		Addr:         fmt.Sprintf("%s:%d", one.ip, cfg.DnsPort),
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
	d.nameservers = cfg.Nameserver
	return d, nil
}
