package k1

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	dnsDefaultPort = 53
)

var resolveErr = errors.New("resolve error")

type Dns struct {
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
			logger.Noticef("[dns] resolve %s on %s failed: %d", qname, ns, r.Rcode)
			if r.Rcode == dns.RcodeServerFailure {
				return
			}
		}

		logger.Debugf("[dns] resolve %s on %s succeed, rtt: %d", qname, ns, rtt)

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

func (d *Dns) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg, err := d.resolve(r)
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

func NewDns(general GeneralConfig, dnsConfig DnsConfig) (*Dns, error) {
	d := new(Dns)

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
