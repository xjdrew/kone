package kone

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	"github.com/xjdrew/kone/pkg/proxy"
)

// Apply explicit DNS suffix policy to the proxy's control transport as well as
// business lookups. Unmatched endpoints retain net.Dialer's hosts/default DNS
// behavior; the underlying resolver never recursively calls this wrapper.
func (one *One) endpointDialer(base *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return base.DialContext(ctx, network, address)
		}
		if _, route := one.dns.selectResolvers(host); route == "" {
			conn, err := base.DialContext(ctx, network, address)
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) {
				return nil, &proxy.StageError{Stage: proxy.StageDNS, Err: err}
			}
			return conn, err
		}
		kinds := []uint16{dns.TypeA, dns.TypeAAAA}
		if strings.HasSuffix(network, "4") {
			kinds = []uint16{dns.TypeA}
		} else if strings.HasSuffix(network, "6") {
			kinds = []uint16{dns.TypeAAAA}
		}
		var failures []error
		for _, kind := range kinds {
			message, err := one.dns.ResolveTypeContext(ctx, host, kind)
			if err != nil {
				return nil, &proxy.StageError{Stage: proxy.StageDNS, Err: err}
			}
			if message.Rcode == dns.RcodeNameError {
				return nil, &proxy.StageError{Stage: proxy.StageDNS, Err: errors.New("proxy endpoint does not exist in its exclusive DNS scope")}
			}
			attempted := false
			for i, answer := range message.Answer {
				if i >= 16 {
					break
				}
				var ip net.IP
				switch record := answer.(type) {
				case *dns.A:
					if kind == dns.TypeA {
						ip = record.A
					}
				case *dns.AAAA:
					if kind == dns.TypeAAAA {
						ip = record.AAAA
					}
				}
				if ip == nil {
					continue
				}
				attempted = true
				conn, err := base.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				failures = append(failures, err)
			}
			if attempted || ctx.Err() != nil {
				break
			}
		}
		failure := errors.Join(append([]error{errors.New("proxy endpoint has no reachable address in its exclusive DNS scope")}, failures...)...)
		if len(failures) == 0 {
			failure = &proxy.StageError{Stage: proxy.StageDNS, Err: failure}
		}
		return nil, failure
	}
}
