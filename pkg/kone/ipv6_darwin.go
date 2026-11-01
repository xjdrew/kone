package kone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type darwinAddressOps struct {
	identity func(string) (*net.Interface, error)
	prefixes func(*net.Interface) ([]netip.Prefix, error)
	addIPv6  func(context.Context, string, netip.Prefix) error
}

func nativeDarwinAddressOps() darwinAddressOps {
	return darwinAddressOps{identity: net.InterfaceByName, prefixes: func(device *net.Interface) ([]netip.Prefix, error) {
		addresses, err := device.Addrs()
		if err != nil {
			return nil, err
		}
		var prefixes []netip.Prefix
		for _, address := range addresses {
			if prefix, err := netip.ParsePrefix(address.String()); err == nil {
				prefixes = append(prefixes, prefix)
			}
		}
		return prefixes, nil
	}, addIPv6: addDarwinIPv6Alias}
}

// Only the newly created utun is configured. Alias cleanup checks both its
// retained interface index and the exact address/prefix; link-local addresses
// and replacements made by another owner are never deleted.
func (n systemNetwork) configureDarwinDualStack(ctx context.Context, device Device, cfg CoreConfig, ops darwinAddressOps) (Cleanup, error) {
	identity, err := ops.identity(device.Name())
	if err != nil {
		return nil, fmt.Errorf("read owned utun identity: %w", err)
	}
	check := func() (*net.Interface, error) {
		current, err := ops.identity(identity.Name)
		if err != nil || current.Index != identity.Index {
			return nil, errors.New("utun address operation refused: owned interface identity changed")
		}
		return current, nil
	}
	var undo undoStack
	add := func(prefix netip.Prefix, configure func() error) error {
		current, err := check()
		if err != nil {
			return err
		}
		before, err := ops.prefixes(current)
		if err != nil {
			return err
		}
		for _, existing := range before {
			if existing.Addr() == prefix.Addr() {
				return errors.New("configured utun address already exists; refusing to claim it")
			}
		}
		undo.add("utun address "+prefix.String(), func(ctx context.Context) error {
			current, err := check()
			if err != nil {
				return err
			}
			addresses, err := ops.prefixes(current)
			if err != nil {
				return err
			}
			found := false
			for _, address := range addresses {
				if address.Addr() != prefix.Addr() {
					continue
				}
				if address != prefix {
					return errors.New("utun address cleanup refused: prefix was replaced")
				}
				found = true
			}
			if !found {
				return nil
			}
			family := "inet"
			if prefix.Addr().Is6() {
				family = "inet6"
			}
			_, err = n.run(ctx, "/sbin/ifconfig", identity.Name, family, prefix.String(), "-alias")
			return err
		})
		if err := configure(); err != nil {
			return err // rollback still inspects a possibly partially applied alias
		}
		current, err = check()
		if err != nil {
			return err
		}
		after, err := ops.prefixes(current)
		if err != nil {
			return err
		}
		for _, actual := range after {
			if actual == prefix {
				return ctx.Err()
			}
		}
		return errors.New("configured utun address could not be verified")
	}
	prefix4 := netip.MustParsePrefix(cfg.Network)
	if err := add(prefix4, func() error {
		_, err := n.run(ctx, "/sbin/ifconfig", identity.Name, "inet", prefix4.Addr().String(), prefix4.Addr().String(), "mtu", strconv.Itoa(MTU), "netmask", net.IP(net.CIDRMask(prefix4.Bits(), 32)).String(), "up")
		return err
	}); err != nil {
		return undo.restore, err
	}
	_, subnet4, _ := net.ParseCIDR(cfg.Network)
	cleanup, err := n.AddRoute(ctx, device, subnet4)
	undo.add("IPv4 virtual subnet", cleanup)
	if err != nil {
		return undo.restore, err
	}
	prefix6 := netip.MustParsePrefix(cfg.IPv6Network)
	if err := add(prefix6, func() error { return ops.addIPv6(ctx, identity.Name, prefix6) }); err != nil {
		return undo.restore, err
	}
	_, subnet6, _ := net.ParseCIDR(cfg.IPv6Network)
	cleanup, err = n.AddRoute(ctx, device, subnet6)
	undo.add("IPv6 virtual subnet", cleanup)
	return undo.restore, err
}

// Public Darwin in6_aliasreq ABI: 128 bytes on both supported 64-bit targets.
// NODAD is applied only to an address on this exclusively created point-to-point
// utun, without changing system or physical-interface IPv6 policy.
type darwinAlias6 struct {
	Name                       [unix.IFNAMSIZ]byte
	Address, Destination, Mask unix.RawSockaddrInet6
	Flags                      uint32
	Lifetime                   struct {
		Expire, Preferred       int64
		Valid, PreferredSeconds uint32
	}
}

func darwinIPv6AliasRequest(name string, prefix netip.Prefix) darwinAlias6 {
	var request darwinAlias6
	copy(request.Name[:], name)
	request.Address = unix.RawSockaddrInet6{Len: unix.SizeofSockaddrInet6, Family: unix.AF_INET6, Addr: prefix.Addr().As16()}
	request.Mask = unix.RawSockaddrInet6{Len: unix.SizeofSockaddrInet6, Family: unix.AF_INET6, Addr: [16]byte(net.CIDRMask(prefix.Bits(), 128))}
	request.Flags = 0x20 // IN6_IFF_NODAD, netinet6/in6_var.h
	request.Lifetime.Valid, request.Lifetime.PreferredSeconds = ^uint32(0), ^uint32(0)
	return request
}

func addDarwinIPv6Alias(ctx context.Context, name string, prefix netip.Prefix) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return os.NewSyscallError("IPv6 alias socket", err)
	}
	defer unix.Close(fd)
	request := darwinIPv6AliasRequest(name, prefix)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(0x8080691a), uintptr(unsafe.Pointer(&request))) // SIOCAIFADDR_IN6
	if errno != 0 {
		return os.NewSyscallError("SIOCAIFADDR_IN6", errno)
	}
	return ctx.Err()
}
