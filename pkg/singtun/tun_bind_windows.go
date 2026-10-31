package tun

import (
	"net/netip"
	"slices"
	"strconv"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

type interfaceFamily struct {
	luid   winipcfg.LUID
	family winipcfg.AddressFamily
}

func routeFamilies(routeRanges []netip.Prefix) []winipcfg.AddressFamily {
	var families []winipcfg.AddressFamily
	if slices.ContainsFunc(routeRanges, func(it netip.Prefix) bool { return it.Addr().Is4() }) {
		families = append(families, windows.AF_INET)
	}
	if slices.ContainsFunc(routeRanges, func(it netip.Prefix) bool { return it.Addr().Is6() }) {
		families = append(families, windows.AF_INET6)
	}
	return families
}

// tcpip.sys ignores IP_UNICAST_IF and IPV6_UNICAST_IF for unicast destinations when the bound
// interface has forwarding or weak host send enabled for that family. Teredo enables IPv6 weak host
// send on every interface when it qualifies as a host-specific relay. Weak host send changes raise no
// interface change notification, but Teredo enables weak host receive on its own interface right
// after, which does.
func (t *NativeTun) enforceInterfaceBinding(tunInterface winipcfg.LUID) {
	t.bindInterfaceAccess.Lock()
	defer t.bindInterfaceAccess.Unlock()
	if t.close.Load() == 1 {
		return
	}
	defaultInterface := t.options.InterfaceMonitor.DefaultInterface()
	for _, family := range t.routeFamilies {
		rows, err := winipcfg.GetIPInterfaceTable(family)
		if err != nil {
			if t.options.Logger != nil {
				t.options.Logger.Error(E.Cause(err, "list ", addressFamilyName(family), " interfaces"))
			}
			continue
		}
		for _, row := range rows {
			if row.InterfaceLUID == tunInterface {
				continue
			}
			key := interfaceFamily{luid: row.InterfaceLUID, family: family}
			if row.ForwardingEnabled && defaultInterface != nil && row.InterfaceIndex == uint32(defaultInterface.Index) && !slices.Contains(t.forwardingWarned, key) {
				t.forwardingWarned = append(t.forwardingWarned, key)
				if t.options.Logger != nil {
					t.options.Logger.Warn(addressFamilyName(family), " forwarding is enabled on ", defaultInterface.Name,
						", which makes Windows ignore interface binding and route outbound connections back into the TUN; ",
						"if it is enabled by Mobile Hotspot or Internet Connection Sharing, share the TUN interface instead")
				}
			}
			if !row.WeakHostSend {
				continue
			}
			interfaceName := strconv.FormatUint(uint64(row.InterfaceIndex), 10)
			var interfaceRow *winipcfg.MibIfRow2
			interfaceRow, err = row.InterfaceLUID.Interface()
			if err == nil {
				interfaceName = interfaceRow.Alias()
			}
			err = setWeakHostSend(row.InterfaceLUID, family, false)
			if err != nil {
				if t.options.Logger != nil {
					t.options.Logger.Error(E.Cause(err, "disable ", addressFamilyName(family), " weak host send on ", interfaceName))
				}
				continue
			}
			_, loaded := t.weakHostSendDisabled[key]
			if !loaded {
				t.weakHostSendDisabled[key] = interfaceName
				if t.options.Logger != nil {
					t.options.Logger.Info("disabled ", addressFamilyName(family), " weak host send on ", interfaceName,
						" while the TUN is running, as it makes Windows ignore interface binding")
				}
			}
		}
	}
}

func (t *NativeTun) restoreWeakHostSend() {
	t.bindInterfaceAccess.Lock()
	defer t.bindInterfaceAccess.Unlock()
	for disabled, name := range t.weakHostSendDisabled {
		_, err := disabled.luid.IPInterface(disabled.family)
		if err != nil {
			continue
		}
		err = setWeakHostSend(disabled.luid, disabled.family, true)
		if err != nil && t.options.Logger != nil {
			t.options.Logger.Error(E.Cause(err, "restore ", addressFamilyName(disabled.family), " weak host send on ", name))
		}
	}
}

// InitializeIpInterfaceEntry fills exactly the values that SetIpInterfaceEntry skips.
func setWeakHostSend(luid winipcfg.LUID, family winipcfg.AddressFamily, enabled bool) error {
	var row winipcfg.MibIPInterfaceRow
	row.Init()
	row.Family = family
	row.InterfaceLUID = luid
	row.WeakHostSend = enabled
	return row.Set()
}

func addressFamilyName(family winipcfg.AddressFamily) string {
	if family == windows.AF_INET {
		return "IPv4"
	}
	return "IPv6"
}
