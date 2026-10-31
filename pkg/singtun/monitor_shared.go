//go:build linux || windows || darwin

package tun

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

func (m *networkUpdateMonitor) RegisterCallback(callback NetworkUpdateCallback) *list.Element[NetworkUpdateCallback] {
	m.access.Lock()
	defer m.access.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *networkUpdateMonitor) UnregisterCallback(element *list.Element[NetworkUpdateCallback]) {
	m.access.Lock()
	defer m.access.Unlock()
	m.callbacks.Remove(element)
}

func (m *networkUpdateMonitor) emit() {
	m.access.Lock()
	callbacks := m.callbacks.Array()
	m.access.Unlock()
	for _, callback := range callbacks {
		callback()
	}
}

type defaultInterfaceMonitor struct {
	interfaceFinder       control.InterfaceFinder
	overrideAndroidVPN    bool
	underNetworkExtension bool
	defaultInterface      atomic.Pointer[control.Interface]
	defaultDNSServers     []netip.Addr
	androidVPNEnabled     atomic.Bool
	noRoute               atomic.Bool
	networkMonitor        NetworkUpdateMonitor
	logger                logger.Logger
	checkAccess           sync.Mutex
	checkUpdateTimer      *time.Timer
	element               *list.Element[NetworkUpdateCallback]
	access                sync.Mutex
	callbacks             list.List[DefaultInterfaceUpdateCallback]
	myInterfaces          []string
}

func NewDefaultInterfaceMonitor(networkMonitor NetworkUpdateMonitor, logger logger.Logger, options DefaultInterfaceMonitorOptions) (DefaultInterfaceMonitor, error) {
	return &defaultInterfaceMonitor{
		interfaceFinder:       options.InterfaceFinder,
		overrideAndroidVPN:    options.OverrideAndroidVPN,
		underNetworkExtension: options.UnderNetworkExtension,
		networkMonitor:        networkMonitor,
		logger:                logger,
	}, nil
}

func (m *defaultInterfaceMonitor) Start() error {
	m.element = m.networkMonitor.RegisterCallback(m.delayCheckUpdate)
	m.postCheckUpdate()
	return nil
}

func (m *defaultInterfaceMonitor) delayCheckUpdate() {
	m.access.Lock()
	defer m.access.Unlock()
	if m.checkUpdateTimer == nil {
		m.checkUpdateTimer = time.AfterFunc(time.Second, m.postCheckUpdate)
	} else {
		m.checkUpdateTimer.Reset(time.Second)
	}
}

func (m *defaultInterfaceMonitor) postCheckUpdate() {
	m.checkAccess.Lock()
	defer m.checkAccess.Unlock()
	err := m.interfaceFinder.Update()
	if err != nil {
		m.logger.Error("update interface: ", err)
		m.delayCheckUpdate()
		return
	}
	err = m.checkUpdate()
	if errors.Is(err, ErrNoRoute) {
		if !m.noRoute.Load() {
			m.noRoute.Store(true)
			m.defaultInterface.Store(nil)
			m.emit(nil, 0)
		}
	} else if err != nil {
		m.logger.Error("check interface: ", err)
		m.delayCheckUpdate()
	} else {
		m.noRoute.Store(false)
	}
}

func (m *defaultInterfaceMonitor) Close() error {
	if m.element != nil {
		m.networkMonitor.UnregisterCallback(m.element)
	}
	return nil
}

func (m *defaultInterfaceMonitor) DefaultInterface() *control.Interface {
	return m.defaultInterface.Load()
}

func (m *defaultInterfaceMonitor) OverrideAndroidVPN() bool {
	return m.overrideAndroidVPN
}

func (m *defaultInterfaceMonitor) AndroidVPNEnabled() bool {
	return m.androidVPNEnabled.Load()
}

func (m *defaultInterfaceMonitor) RegisterCallback(callback DefaultInterfaceUpdateCallback) *list.Element[DefaultInterfaceUpdateCallback] {
	m.access.Lock()
	defer m.access.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *defaultInterfaceMonitor) UnregisterCallback(element *list.Element[DefaultInterfaceUpdateCallback]) {
	m.access.Lock()
	defer m.access.Unlock()
	m.callbacks.Remove(element)
}

func (m *defaultInterfaceMonitor) emit(defaultInterface *control.Interface, flags int) {
	m.access.Lock()
	callbacks := m.callbacks.Array()
	m.access.Unlock()
	for _, callback := range callbacks {
		callback(defaultInterface, flags)
	}
}

func (m *defaultInterfaceMonitor) RegisterMyInterface(interfaceName string) {
	m.access.Lock()
	defer m.access.Unlock()
	m.myInterfaces = append(m.myInterfaces, interfaceName)
}

func (m *defaultInterfaceMonitor) MyInterfaces() []string {
	m.access.Lock()
	defer m.access.Unlock()
	return m.myInterfaces
}

func defaultInterfaceChanged(oldInterface *control.Interface, newInterface *control.Interface) bool {
	if oldInterface == nil {
		return true
	}
	if oldInterface.Index != newInterface.Index ||
		oldInterface.MTU != newInterface.MTU ||
		oldInterface.Name != newInterface.Name ||
		!slices.Equal(oldInterface.HardwareAddr, newInterface.HardwareAddr) ||
		oldInterface.Flags != newInterface.Flags {
		return true
	}
	oldNetworks := interfaceNetworks(oldInterface.Addresses)
	newNetworks := interfaceNetworks(newInterface.Addresses)
	return len(oldNetworks) != len(newNetworks) || !common.All(oldNetworks, func(it netip.Prefix) bool {
		return slices.Contains(newNetworks, it)
	})
}

func interfaceNetworks(addresses []netip.Prefix) []netip.Prefix {
	networks := make([]netip.Prefix, 0, len(addresses))
	for _, address := range addresses {
		if address.Addr().Is6() {
			address = netip.PrefixFrom(address.Addr(), min(address.Bits(), 64)).Masked()
		}
		if !slices.Contains(networks, address) {
			networks = append(networks, address)
		}
	}
	return networks
}
