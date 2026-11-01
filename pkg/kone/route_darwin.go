package kone

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Darwin's route(8) can print a kernel error and still exit successfully. Use
// PF_ROUTE directly; only a matching kernel acknowledgement establishes a new
// route's ownership. Cleanup rechecks the actual prefix, gateway and interface.
type darwinRoutes struct {
	exchange          func(context.Context, *route.RouteMessage) (bool, *route.RouteMessage, error)
	read              func() ([]route.Message, error)
	interfaceByName   func(string) (*net.Interface, error)
	interfacePrefixes func(*net.Interface) ([]netip.Prefix, error)
}

var darwinRouteSequence atomic.Uint32

func newDarwinRoutes() darwinRoutes {
	return darwinRoutes{exchange: exchangeDarwinRoute, interfaceByName: net.InterfaceByName, interfacePrefixes: nativeDarwinAddressOps().prefixes, read: func() ([]route.Message, error) {
		data, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
		if err != nil {
			return nil, err
		}
		return route.ParseRIB(route.RIBTypeRoute, data)
	}}
}

func darwinPrefix(subnet *net.IPNet) (netip.Prefix, error) {
	if subnet == nil {
		return netip.Prefix{}, errors.New("Darwin route requires an IP prefix")
	}
	bits, size := subnet.Mask.Size()
	address, ok := netip.AddrFromSlice(subnet.IP)
	if !ok || bits < 0 || size != address.Unmap().BitLen() {
		return netip.Prefix{}, errors.New("invalid IP route mask")
	}
	return netip.PrefixFrom(address.Unmap(), bits).Masked(), nil
}

func darwinMessagePrefix(message *route.RouteMessage) (netip.Prefix, bool) {
	if len(message.Addrs) <= unix.RTAX_DST {
		return netip.Prefix{}, false
	}
	var destination netip.Addr
	switch addr := message.Addrs[unix.RTAX_DST].(type) {
	case *route.Inet4Addr:
		destination = netip.AddrFrom4(addr.IP)
	case *route.Inet6Addr:
		if addr.ZoneID != 0 {
			return netip.Prefix{}, false // KONE capture prefixes are unscoped ULA
		}
		destination = netip.AddrFrom16(addr.IP)
	default:
		return netip.Prefix{}, false
	}
	bits := 0
	if message.Flags&unix.RTF_HOST != 0 {
		bits = destination.BitLen()
	} else if len(message.Addrs) > unix.RTAX_NETMASK && message.Addrs[unix.RTAX_NETMASK] != nil {
		var mask net.IPMask
		switch addr := message.Addrs[unix.RTAX_NETMASK].(type) {
		case *route.Inet4Addr:
			mask = net.IPMask(addr.IP[:])
		case *route.Inet6Addr:
			mask = net.IPMask(addr.IP[:])
		default:
			return netip.Prefix{}, false
		}
		var size int
		bits, size = mask.Size()
		if size != destination.BitLen() {
			return netip.Prefix{}, false
		}
	}
	return netip.PrefixFrom(destination, bits).Masked(), true
}

func darwinPrefixRoutes(messages []route.Message, prefix netip.Prefix) []*route.RouteMessage {
	var matches []*route.RouteMessage
	for _, value := range messages {
		if message, ok := value.(*route.RouteMessage); ok {
			if actual, ok := darwinMessagePrefix(message); ok && actual == prefix {
				matches = append(matches, message)
			}
		}
	}
	return matches
}

func darwinOwnedRoute(message *route.RouteMessage, prefix netip.Prefix, index int, requireStatic bool) bool {
	actual, ok := darwinMessagePrefix(message)
	if !ok || actual != prefix || message.Index != index || len(message.Addrs) <= unix.RTAX_GATEWAY {
		return false
	}
	gateway, ok := message.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
	if !ok || gateway.Index != index || message.Flags&(unix.RTF_GATEWAY|unix.RTF_REJECT|unix.RTF_BLACKHOLE|unix.RTF_IFSCOPE) != 0 {
		return false
	}
	return !requireStatic || message.Flags&unix.RTF_STATIC != 0
}

// XNU's nd6_prefix_onlink_common uses an IPv6 interface address (preferably its
// link-local one) as the connected prefix route's gateway, rather than AF_LINK.
// Reuse only the kernel-style, unscoped route for an address prefix actually
// assigned to this exclusive device. It is released with that alias/device;
// this does not establish ownership of any explicit static capture route.
func darwinConnectedIPv6Route(message *route.RouteMessage, prefix netip.Prefix, index int, addresses []netip.Prefix) bool {
	actual, ok := darwinMessagePrefix(message)
	if !prefix.Addr().Is6() || !ok || actual != prefix || message.Index != index ||
		message.Flags&unix.RTF_UP == 0 || message.Flags&(unix.RTF_GATEWAY|unix.RTF_REJECT|unix.RTF_BLACKHOLE|unix.RTF_IFSCOPE|unix.RTF_STATIC|unix.RTF_HOST) != 0 || len(message.Addrs) <= unix.RTAX_GATEWAY {
		return false
	}
	gateway, ok := message.Addrs[unix.RTAX_GATEWAY].(*route.Inet6Addr)
	if !ok || gateway.ZoneID != 0 && gateway.ZoneID != index {
		return false
	}
	addressMatch, gatewayMatch := false, false
	for _, address := range addresses {
		addressMatch = addressMatch || address.Masked() == prefix
		gatewayMatch = gatewayMatch || address.Addr() == netip.AddrFrom16(gateway.IP)
	}
	return addressMatch && gatewayMatch
}

func darwinRouteMessage(kind int, prefix netip.Prefix, device *net.Interface) *route.RouteMessage {
	mask := net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())
	flags := unix.RTF_UP | unix.RTF_STATIC
	if prefix.Bits() == prefix.Addr().BitLen() {
		flags |= unix.RTF_HOST
	}
	addresses := make([]route.Addr, unix.RTAX_MAX)
	addresses[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: device.Index, Name: device.Name}
	if prefix.Addr().Is4() {
		addresses[unix.RTAX_DST] = &route.Inet4Addr{IP: prefix.Addr().As4()}
		addresses[unix.RTAX_NETMASK] = &route.Inet4Addr{IP: [4]byte(mask)}
	} else {
		addresses[unix.RTAX_DST] = &route.Inet6Addr{IP: prefix.Addr().As16()}
		addresses[unix.RTAX_NETMASK] = &route.Inet6Addr{IP: [16]byte(mask)}
	}
	return &route.RouteMessage{Version: unix.RTM_VERSION, Type: kind, Flags: flags, ID: uintptr(os.Getpid()), Seq: int(darwinRouteSequence.Add(1) & 0x7fffffff), Addrs: addresses}
}

func (r darwinRoutes) AddRoute(ctx context.Context, device Device, subnet *net.IPNet) (Cleanup, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prefix, err := darwinPrefix(subnet)
	if err != nil {
		return nil, err
	}
	identity, err := r.interfaceByName(device.Name())
	if err != nil {
		return nil, fmt.Errorf("route interface identity: %w", err)
	}
	messages, err := r.read()
	if err != nil {
		return nil, fmt.Errorf("inspect existing route: %w", err)
	}
	if existing := darwinPrefixRoutes(messages, prefix); len(existing) != 0 {
		// A point-to-point address configuration may itself create this route.
		// Its lifecycle belongs to the exclusively created device; do not claim
		// a second explicit route or delete anything outside that interface.
		if len(existing) == 1 && darwinOwnedRoute(existing[0], prefix, identity.Index, false) {
			return nil, nil
		}
		if len(existing) == 1 && prefix.Addr().Is6() && r.interfacePrefixes != nil {
			addresses, err := r.interfacePrefixes(identity)
			if err != nil {
				return nil, fmt.Errorf("verify connected IPv6 route: %w", err)
			}
			if darwinConnectedIPv6Route(existing[0], prefix, identity.Index, addresses) {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("route %s already exists outside the owned interface: %w", prefix, unix.EEXIST)
	}
	request := darwinRouteMessage(unix.RTM_ADD, prefix, identity)
	sent, _, operationErr := r.exchange(ctx, request)
	cleanup := func(ctx context.Context) error { return r.remove(ctx, prefix, identity) }
	if operationErr != nil {
		if !sent {
			return nil, operationErr
		}
		// If the acknowledgement was lost after a successful write, retain a
		// cleanup only when the previously absent route is now verifiably ours.
		current, inspectErr := r.read()
		if inspectErr == nil {
			matches := darwinPrefixRoutes(current, prefix)
			if len(matches) == 1 && darwinOwnedRoute(matches[0], prefix, identity.Index, true) {
				return cleanup, operationErr
			}
		}
		return nil, errors.Join(operationErr, inspectErr)
	}
	current, err := r.read()
	if err != nil {
		return cleanup, fmt.Errorf("verify added route: %w", err)
	}
	matches := darwinPrefixRoutes(current, prefix)
	if len(matches) != 1 || !darwinOwnedRoute(matches[0], prefix, identity.Index, true) {
		return cleanup, errors.New("added route could not be verified on the owned interface")
	}
	return cleanup, ctx.Err()
}

func (r darwinRoutes) remove(ctx context.Context, prefix netip.Prefix, identity *net.Interface) error {
	currentDevice, err := r.interfaceByName(identity.Name)
	if err != nil || currentDevice.Index != identity.Index {
		return errors.New("route cleanup refused: owned interface identity changed or is unavailable")
	}
	messages, err := r.read()
	if err != nil {
		return fmt.Errorf("inspect route before cleanup: %w", err)
	}
	matches := darwinPrefixRoutes(messages, prefix)
	if len(matches) == 0 {
		return nil
	}
	if len(matches) != 1 || !darwinOwnedRoute(matches[0], prefix, identity.Index, true) {
		return errors.New("route cleanup refused: route was replaced outside its recorded ownership")
	}
	_, _, err = r.exchange(ctx, darwinRouteMessage(unix.RTM_DELETE, prefix, identity))
	return err
}

// darwinRoutingSocket is deliberately narrow so acknowledgement, interruption
// and timeout paths can be exercised without modifying any host network.
type darwinRoutingSocket interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	Close() error
}

type darwinNativeRouteSocket struct{ fd int }

func (s darwinNativeRouteSocket) Write(data []byte) (int, error) { return unix.Write(s.fd, data) }
func (s darwinNativeRouteSocket) Read(data []byte) (int, error)  { return unix.Read(s.fd, data) }
func (s darwinNativeRouteSocket) Close() error                   { return unix.Close(s.fd) }

func exchangeDarwinRoute(ctx context.Context, message *route.RouteMessage) (bool, *route.RouteMessage, error) {
	// Darwin does not expose SOCK_CLOEXEC. Synchronize with os/exec until the
	// descriptor is marked, so concurrent desktop launches cannot inherit it.
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return false, nil, os.NewSyscallError("route socket", err)
	}
	socket := darwinNativeRouteSocket{fd: fd}
	defer socket.Close()
	if err := unix.SetNonblock(fd, true); err != nil {
		return false, nil, err
	}
	return transactDarwinRoute(ctx, socket, message, func(ctx context.Context) error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			count, err := unix.Poll(poll, 50)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return err
			}
			if count != 0 {
				if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
					return errors.New("route socket closed before acknowledgement")
				}
				return nil
			}
		}
	})
}

func transactDarwinRoute(parent context.Context, socket darwinRoutingSocket, request *route.RouteMessage, wait func(context.Context) error) (bool, *route.RouteMessage, error) {
	if err := parent.Err(); err != nil {
		return false, nil, err
	}
	data, err := request.Marshal()
	if err != nil {
		return false, nil, err
	}
	n, err := socket.Write(data)
	if err != nil {
		return false, nil, os.NewSyscallError("route write", err)
	}
	if n != len(data) {
		return true, nil, io.ErrShortWrite
	}
	// Once sent, finish the bounded acknowledgement even when the caller is
	// canceled, so rollback knows whether a kernel change actually succeeded.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
	defer cancel()
	buffer := make([]byte, 65536)
	for range 1024 {
		if err := wait(ctx); err != nil {
			return true, nil, fmt.Errorf("route acknowledgement: %w", err)
		}
		n, err := socket.Read(buffer)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return true, nil, os.NewSyscallError("route read", err)
		}
		if n == 0 {
			return true, nil, io.EOF
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, buffer[:n])
		if err != nil {
			return true, nil, fmt.Errorf("parse route acknowledgement: %w", err)
		}
		for _, value := range messages {
			message, ok := value.(*route.RouteMessage)
			if !ok || message.ID != request.ID || message.Seq != request.Seq || message.Type != request.Type {
				continue
			}
			if message.Err != nil {
				return false, message, fmt.Errorf("kernel route acknowledgement: %w", message.Err)
			}
			return true, message, nil
		}
	}
	return true, nil, errors.New("route acknowledgement exceeded bounded unrelated-message limit")
}
