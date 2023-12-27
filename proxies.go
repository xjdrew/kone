//
//   date  : 2016-05-13
//   author: xjdrew
//

package kone

import (
	"fmt"
	"net"
	"strings"

	"github.com/xjdrew/kone/proxy"
)

type Proxies struct {
	proxies map[string]*proxy.Proxy
}

func (p *Proxies) Dial(pname string, addr string) (net.Conn, error) {
	logger.Debugf("[proxy] dail host %s by proxy %s", addr, pname)
	dialer := p.proxies[pname]
	if dialer != nil {
		return dialer.Dial("tcp", addr)
	}
	return nil, fmt.Errorf("no proxy: %s", pname)
}

func NewProxies(one *One, config map[string]string) (*Proxies, error) {
	p := &Proxies{}

	proxies := make(map[string]*proxy.Proxy)
	for pname, url := range config {
		proxy, err := proxy.FromUrl(url)
		if err != nil {
			return nil, err
		}

		logger.Debugf("[proxy] add proxy %s = %s", pname, url)
		proxies[pname] = proxy

		// don't hijack proxy domain
		host := proxy.Url.Host
		index := strings.IndexByte(proxy.Url.Host, ':')
		if index > 0 {
			host = proxy.Url.Host[:index]
		}
		one.rule.DirectDomain(host)
	}
	p.proxies = proxies
	return p, nil
}
