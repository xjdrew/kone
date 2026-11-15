package kone

import (
	"fmt"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func systemPolicyRoutes() ([]policyRoute, error) {
	entries, err := newDarwinRoutes().read()
	if err != nil {
		return nil, err
	}
	routes := []policyRoute{}
	for _, entry := range entries {
		message, ok := entry.(*route.RouteMessage)
		if !ok || message.Flags&unix.RTF_UP == 0 || message.Flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE|unix.RTF_LLINFO|unix.RTF_WASCLONED) != 0 {
			continue
		}
		if prefix, ok := darwinMessagePrefix(message); ok {
			gateway := ""
			if len(message.Addrs) > unix.RTAX_GATEWAY {
				gateway = fmt.Sprint(message.Addrs[unix.RTAX_GATEWAY])
			}
			routes = append(routes, policyRoute{Prefix: prefix, Interface: message.Index, Gateway: gateway})
		}
	}
	return routes, nil
}
