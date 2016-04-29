package proxy

import (
	"net/url"

	"golang.org/x/net/proxy"
)

type Dialer proxy.Dialer

func FromUrl(rawurl string) (dailer Dialer, err error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return
	}

	dailer, err = proxy.FromURL(u, proxy.Direct)
	return
}
