package k1

import (
	"net"

	"github.com/xjdrew/kone/proxy"
)

type proxyContainer struct {
	proxies map[string]proxy.Dialer
	dft     proxy.Dialer
}

func (pc *proxyContainer) DefaultDial(addr string) (net.Conn, error) {
	return pc.dft.Dial("tcp", addr)
}

func newProxyContainer(config map[string]*ProxyConfig) (*proxyContainer, error) {
	pc := &proxyContainer{}

	proxies := make(map[string]proxy.Dialer)
	for name, item := range config {
		dailer, err := proxy.FromUrl(item.Url)
		if err != nil {
			return nil, err
		}

		if item.Default || pc.dft == nil {
			pc.dft = dailer
		}
		proxies[name] = dailer
	}
	pc.proxies = proxies
	return pc, nil
}
