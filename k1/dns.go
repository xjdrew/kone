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
	dnsDefaultPort = 53

	dnsDefaultTtl = 600
)

var resolveErr = errors.New("resolve error")

type Dns struct {
	one         *One
	server      *dns.Server
	nameservers []string
}

func (d *Dns) resolve(r *dns.Msg) (*dns.Msg, error) {
	var wg sync.WaitGroup
	msgCh := make(chan *dns.Msg, 1)

	c := &dns.Client{
		Net: "udp",
	}

	qname := r.Question[0].Name

	Q := func(ns string) {
		defer wg.Done()

		r, rtt, err := c.Exchange(r, ns)
		if err != nil {
			return
		}

		if r != nil && r.Rcode != dns.RcodeSuccess {
			if r.Rcode == dns.RcodeServerFailure {
				logger.Errorf("[dns] resolve %s on %s failedd", qname, ns)
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

func (d *Dns) doIPv4Query(r *dns.Msg) (*dns.Msg, error) {
	one := d.one

	domain := dnsutil.TrimDomainName(r.Question[0].Name, ".")
	// if is a non-proxy-domain
	if one.dnsCache.IsNonProxyDomain(domain) {
		return d.resolve(r)
	}

	// if have already hijacked
	record := one.dnsCache.Get(domain)
	if record != nil {
		return record.Answer(r), nil
	}

	// test domain
	proxy := one.rule.Proxy(domain)

	// if domain use proxy
	if proxy != "" {
		if record := one.dnsCache.Set(domain, proxy); record != nil {
			return record.Answer(r), nil
		}
	}

	// resolve
	msg, err := d.resolve(r)
	if len(msg.Answer) == 0 || err != nil {
		return msg, err
	}

	var answer *dns.A
	var ok bool
	if answer, ok = msg.Answer[0].(*dns.A); !ok {
		logger.Noticef("[dns] unexpected response %s -> %v", domain, msg.Answer[0])
		return msg, err
	}

	// test ip
	proxy = one.rule.Proxy(answer.A)

	// if ip use proxy
	if proxy != "" {
		if record := one.dnsCache.Set(domain, proxy); record != nil {
			return record.Answer(r), nil
		}
	}

	// set domain as a non-proxy-domain
	one.dnsCache.SetNonProxyDomain(domain, answer.Header().Ttl)

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

func NewDns(one *One, general GeneralConfig, dnsConfig DnsConfig) (*Dns, error) {
	d := new(Dns)
	d.one = one

	server := &dns.Server{
		Net:          "udp",
		Addr:         fmt.Sprintf("%s:%d", general.IP, dnsConfig.DnsPort),
		Handler:      dns.HandlerFunc(d.ServeDNS),
		UDPSize:      4096,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	d.server = server
	d.nameservers = dnsConfig.Nameserver
	return d, nil
}
