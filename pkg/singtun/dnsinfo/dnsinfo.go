package dnsinfo

import (
	"net/netip"
	"time"

	"github.com/sagernet/sing/common"
)

type Resolver struct {
	InterfaceIndex int
	Domain         string
	Servers        []netip.AddrPort
	Search         []string
	Timeout        time.Duration
}

type Configuration struct {
	Resolvers       []Resolver
	ScopedResolvers []Resolver
}

func (c *Configuration) Select(interfaceIndex int) Resolver {
	if interfaceIndex != 0 {
		resolver := common.Find(c.ScopedResolvers, func(it Resolver) bool {
			return it.InterfaceIndex == interfaceIndex && len(it.Servers) > 0
		})
		if len(resolver.Servers) > 0 {
			return resolver
		}
	}
	return common.Find(c.Resolvers, func(it Resolver) bool {
		return it.Domain == "" && len(it.Servers) > 0
	})
}
