package tun

import (
	"slices"
	"sync"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const registryNotifyFilter = windows.REG_NOTIFY_CHANGE_NAME | windows.REG_NOTIFY_CHANGE_LAST_SET

var dnsRegistryPaths = []string{
	`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
	`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`,
}

type networkUpdateMonitor struct {
	routeListener     *winipcfg.RouteChangeCallback
	interfaceListener *winipcfg.InterfaceChangeCallback
	dnsWatcher        *registryWatcher

	access    sync.Mutex
	callbacks list.List[NetworkUpdateCallback]
	logger    logger.Logger
}

func NewNetworkUpdateMonitor(logger logger.Logger) (NetworkUpdateMonitor, error) {
	return &networkUpdateMonitor{
		logger: logger,
	}, nil
}

func (m *networkUpdateMonitor) Start() error {
	routeListener, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		m.emit()
	})
	if err != nil {
		return err
	}
	interfaceListener, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		m.emit()
	})
	if err != nil {
		routeListener.Unregister()
		return err
	}
	dnsWatcher, err := newRegistryWatcher(dnsRegistryPaths, m.emit, m.logger)
	if err != nil {
		routeListener.Unregister()
		interfaceListener.Unregister()
		return err
	}
	m.routeListener = routeListener
	m.interfaceListener = interfaceListener
	m.dnsWatcher = dnsWatcher
	return nil
}

func (m *networkUpdateMonitor) Close() error {
	if m.routeListener != nil {
		m.routeListener.Unregister()
		m.routeListener = nil
	}
	if m.interfaceListener != nil {
		m.interfaceListener.Unregister()
		m.interfaceListener = nil
	}
	if m.dnsWatcher != nil {
		m.dnsWatcher.Close()
		m.dnsWatcher = nil
	}
	return nil
}

type registryWatcher struct {
	keys   []registry.Key
	events []windows.Handle
	done   chan struct{}
}

func newRegistryWatcher(paths []string, callback func(), logger logger.Logger) (*registryWatcher, error) {
	closeEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, E.Cause(err, "create event")
	}
	watcher := &registryWatcher{
		events: []windows.Handle{closeEvent},
		done:   make(chan struct{}),
	}
	for _, path := range paths {
		var key registry.Key
		key, err = registry.OpenKey(registry.LOCAL_MACHINE, path, registry.NOTIFY)
		if err != nil {
			watcher.release()
			return nil, E.Cause(err, "open registry key ", path)
		}
		watcher.keys = append(watcher.keys, key)
		var event windows.Handle
		event, err = windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			watcher.release()
			return nil, E.Cause(err, "create event")
		}
		watcher.events = append(watcher.events, event)
		err = windows.RegNotifyChangeKeyValue(windows.Handle(key), true, registryNotifyFilter, event, true)
		if err != nil {
			watcher.release()
			return nil, E.Cause(err, "watch registry key ", path)
		}
	}
	go watcher.loop(callback, logger)
	return watcher, nil
}

func (w *registryWatcher) loop(callback func(), logger logger.Logger) {
	defer close(w.done)
	for {
		event, err := windows.WaitForMultipleObjects(w.events, false, windows.INFINITE)
		if err != nil {
			logger.Error("wait registry change: ", err)
			return
		}
		index := int(event - windows.WAIT_OBJECT_0)
		if index == 0 {
			return
		}
		err = windows.RegNotifyChangeKeyValue(windows.Handle(w.keys[index-1]), true, registryNotifyFilter, w.events[index], true)
		if err != nil {
			logger.Error("watch registry key: ", err)
			return
		}
		callback()
	}
}

func (w *registryWatcher) Close() {
	windows.SetEvent(w.events[0])
	<-w.done
	w.release()
}

func (w *registryWatcher) release() {
	for _, key := range w.keys {
		key.Close()
	}
	for _, event := range w.events {
		windows.CloseHandle(event)
	}
}

func (m *defaultInterfaceMonitor) checkUpdate() error {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return err
	}

	lowestMetric := ^uint32(0)
	alias := ""
	var (
		index int
		luid  winipcfg.LUID
	)

	for _, row := range rows {
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}

		ifrow, err := row.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		if ifrow.Type == winipcfg.IfTypePropVirtual || ifrow.Type == winipcfg.IfTypeSoftwareLoopback {
			continue
		}

		iface, err := row.InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil {
			continue
		}

		if !iface.Connected {
			continue
		}

		metric := row.Metric + iface.Metric
		if metric < lowestMetric {
			lowestMetric = metric
			alias = ifrow.Alias()
			index = int(ifrow.InterfaceIndex)
			luid = row.InterfaceLUID
		}
	}

	if alias == "" {
		return ErrNoRoute
	}

	newInterface, err := m.interfaceFinder.ByIndex(index)
	if err != nil {
		return E.Cause(err, "find updated interface: ", alias)
	}
	dnsServers, err := luid.DNS()
	if err != nil {
		return E.Cause(err, "read DNS servers: ", alias)
	}
	oldInterface := m.defaultInterface.Swap(newInterface)
	oldDNSServers := m.defaultDNSServers
	m.defaultDNSServers = dnsServers
	if !defaultInterfaceChanged(oldInterface, newInterface) && slices.Equal(oldDNSServers, dnsServers) {
		return nil
	}
	m.emit(newInterface, 0)
	return nil
}
