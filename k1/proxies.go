//
//   date  : 2016-05-13
//   author: xjdrew
//

package k1

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/xjdrew/kone/proxy"
)

var errNoProxy = errors.New("no proxy")

type Proxies struct {
	proxies map[string]*proxy.Proxy
	dft     string
}

func (p *Proxies) Dial(proxy string, addr string) (net.Conn, error) {
	if proxy == "" {
		return p.DefaultDial(addr)
	}

	dialer := p.proxies[proxy]
	if dialer != nil {
		return dialer.Dial("tcp", addr)
	}
	return nil, fmt.Errorf("Invalid proxy: %s", proxy)
}

func (p *Proxies) DefaultDial(addr string) (net.Conn, error) {
	dialer := p.proxies[p.dft]
	if dialer == nil {
		return nil, errNoProxy
	}
	return dialer.Dial("tcp", addr)
}

func NewProxies(one *One, config map[string]*ProxyConfig) (*Proxies, error) {
	p := &Proxies{}

	proxies := make(map[string]*proxy.Proxy)
	for name, item := range config {
		proxy, err := proxy.FromUrl(item.Url)
		if err != nil {
			return nil, err
		}

		if item.Default || p.dft == "" {
			p.dft = name
		}
		proxies[name] = proxy

		// don't hijack proxy domain
		host := proxy.Url.Host
		index := strings.IndexByte(proxy.Url.Host, ':')
		if index > 0 {
			host = proxy.Url.Host[:index]
		}
		one.rule.DirectDomain(host)
	}
	p.proxies = proxies
	logger.Infof("[proxies] default proxy: %q", p.dft)
	return p, nil
}
