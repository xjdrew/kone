package k1

import (
	"net"

	"github.com/xjdrew/kone/proxy"
)

type Proxies struct {
	proxies map[string]proxy.Dialer
	dft     proxy.Dialer
}

func (p *Proxies) DefaultDial(addr string) (net.Conn, error) {
	return p.dft.Dial("tcp", addr)
}

func NewProxies(config map[string]*ProxyConfig) (*Proxies, error) {
	p := &Proxies{}

	proxies := make(map[string]proxy.Dialer)
	for name, item := range config {
		dailer, err := proxy.FromUrl(item.Url)
		if err != nil {
			return nil, err
		}

		if item.Default || p.dft == nil {
			p.dft = dailer
		}
		proxies[name] = dailer
	}
	p.proxies = proxies
	return p, nil
}
