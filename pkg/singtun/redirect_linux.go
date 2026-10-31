package tun

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/sagernet/nftables"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"

	"go4.org/netipx"
)

type autoRedirect struct {
	tunOptions              *Options
	ctx                     context.Context
	handler                 Handler
	logger                  logger.Logger
	tableName               string
	networkMonitor          NetworkUpdateMonitor
	ownedNetworkMonitor     bool
	networkListener         *list.Element[NetworkUpdateCallback]
	interfaceFinder         control.InterfaceFinder
	localAddresses          []netip.Prefix
	customRedirectPortFunc  func() int
	customRedirectPort      int
	redirectServer          *redirectServer
	enableIPv4              bool
	enableIPv6              bool
	iptablesPath            string
	ip6tablesPath           string
	useNFTables             bool
	androidSu               bool
	suPath                  string
	routeAddressSet         *[]*netipx.IPSet
	routeExcludeAddressSet  *[]*netipx.IPSet
	nfqueueHandler          *nfqueueHandler
	nfqueueEnabled          bool
	redirectRouteTableIndex int
	redirectRouteAccess     sync.Mutex
	redirectRoutesActive    bool
	dockerFirewallMonitor   *nftables.Monitor
	dockerFirewallDone      chan struct{}
}

func NewAutoRedirect(options AutoRedirectOptions) (AutoRedirect, error) {
	if options.TunOptions.AutoRedirectInputMark == 0 {
		options.TunOptions.AutoRedirectInputMark = DefaultAutoRedirectInputMark
	}
	r := &autoRedirect{
		tunOptions:             options.TunOptions,
		ctx:                    options.Context,
		handler:                options.Handler,
		logger:                 options.Logger,
		networkMonitor:         options.NetworkMonitor,
		interfaceFinder:        options.InterfaceFinder,
		tableName:              options.TableName,
		useNFTables:            runtime.GOOS != "android" && !options.DisableNFTables,
		customRedirectPortFunc: options.CustomRedirectPort,
		routeAddressSet:        options.RouteAddressSet,
		routeExcludeAddressSet: options.RouteExcludeAddressSet,
	}
	if options.TunOptions.NetNs != "" {
		r.interfaceFinder = &networkNamespaceInterfaceFinder{control.NewDefaultInterfaceFinder(), options.TunOptions}
	}
	return r, nil
}

func findAndroidSuPath() (string, error) {
	searchPaths := common.Uniq(common.FilterNotDefault(append(
		strings.Split(os.Getenv("PATH"), ":"),
		"/system/bin",
		"/system/xbin",
		"/product/bin",
		"/odm/bin",
		"/vendor/bin",
		"/vendor/xbin",
		"/apex/com.android.runtime/bin",
		"/sbin",
	)))
	for _, searchPath := range searchPaths {
		suPath, err := exec.LookPath(filepath.Join(searchPath, "su"))
		if err == nil {
			return suPath, nil
		}
	}
	return "", E.New("su not found in ", strings.Join(searchPaths, ":"))
}

func (r *autoRedirect) Start() error {
	var err error
	if runtime.GOOS == "android" {
		r.enableIPv4 = true
		r.iptablesPath = "/system/bin/iptables"
		userId := os.Getuid()
		if userId != 0 {
			r.androidSu = true
			r.suPath, err = findAndroidSuPath()
			if err != nil {
				return E.Cause(err, "root permission is required for auto redirect")
			}
		}
	} else {
		if r.tunOptions.NetNs != "" && !r.useNFTables {
			return E.New("auto_redirect in network namespace requires nftables")
		}
		if r.useNFTables {
			err = runInNetworkNamespace(r.tunOptions.NetNs, r.initializeNFTables)
			if err != nil {
				return E.Cause(err, "missing nftables support")
			}
		}
		if len(r.tunOptions.Inet4Address) > 0 {
			r.enableIPv4 = true
			if !r.useNFTables {
				r.iptablesPath, err = exec.LookPath("iptables")
				if err != nil {
					return E.Cause(err, "iptables is required")
				}
			}
		}
		if len(r.tunOptions.Inet6Address) > 0 {
			r.enableIPv6 = true
			if !r.useNFTables {
				r.ip6tablesPath, err = exec.LookPath("ip6tables")
				if err != nil {
					if !r.enableIPv4 {
						return E.Cause(err, "ip6tables is required")
					} else {
						r.enableIPv6 = false
						r.logger.Error("device has no ip6tables nat support: ", err)
					}
				}
			}
		}
	}
	if r.customRedirectPortFunc != nil {
		r.customRedirectPort = r.customRedirectPortFunc()
	}
	if r.customRedirectPort == 0 {
		var listenAddr netip.Addr
		if runtime.GOOS == "android" {
			listenAddr = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		} else if r.enableIPv6 {
			listenAddr = netip.IPv6Unspecified()
		} else {
			listenAddr = netip.IPv4Unspecified()
		}
		server := newRedirectServer(r.ctx, r.handler, r.logger, listenAddr)
		err = runInNetworkNamespace(r.tunOptions.NetNs, server.Start)
		if err != nil {
			return E.Cause(err, "start redirect server")
		}
		r.redirectServer = server
	}
	if r.useNFTables {
		if r.handler != nil {
			var handler *nfqueueHandler
			handler, err = newNFQueueHandler(nfqueueOptions{
				Context:    r.ctx,
				Handler:    r.handler,
				Logger:     r.logger,
				Queue:      r.effectiveNFQueue(),
				InputMark:  r.tunOptions.AutoRedirectInputMark,
				OutputMark: r.effectiveOutputMark(),
				ResetMark:  r.effectiveResetMark(),
			})
			if err != nil {
				r.logger.Warn("nfqueue not available, pre-match disabled (missing nfnetlink_queue and nft_queue kernel module?): ", err)
			} else if err = runInNetworkNamespace(r.tunOptions.NetNs, handler.Start); err != nil {
				r.logger.Warn("nfqueue start failed, pre-match disabled (missing nfnetlink_queue and nft_queue kernel module?): ", err)
			} else {
				r.nfqueueHandler = handler
				r.nfqueueEnabled = true
			}
		}
		if r.tunOptions.NetNs != "" {
			var monitor NetworkUpdateMonitor
			monitor, err = NewNetworkUpdateMonitor(r.logger)
			if err != nil {
				return E.Cause(err, "create netns network monitor")
			}
			err = runInNetworkNamespace(r.tunOptions.NetNs, monitor.Start)
			if err != nil {
				return E.Cause(err, "start netns network monitor")
			}
			r.networkMonitor = monitor
			r.ownedNetworkMonitor = true
		}
		err = runInNetworkNamespace(r.tunOptions.NetNs, func() error {
			r.cleanupNFTables()
			setupErr := r.setupNFTables()
			if setupErr != nil {
				return E.Cause(setupErr, "setup nftables")
			}
			if r.tunOptions.AutoRedirectMarkMode {
				setupErr = r.setupRedirectRoutes()
				if setupErr != nil {
					r.cleanupNFTables()
					return E.Cause(setupErr, "setup redirect routes")
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		r.cleanupIPTables()
		err = r.setupIPTables()
		if err != nil {
			return E.Cause(err, "setup iptables")
		}
	}
	return nil
}

func (r *autoRedirect) Close() error {
	if r.nfqueueHandler != nil {
		r.nfqueueHandler.Close()
	}
	if r.useNFTables {
		_ = runInNetworkNamespace(r.tunOptions.NetNs, func() error {
			r.cleanupNFTables()
			r.cleanupRedirectRoutes()
			return nil
		})
		if r.ownedNetworkMonitor {
			_ = r.networkMonitor.Close()
		}
	} else {
		r.cleanupIPTables()
	}
	return common.Close(
		common.PtrOrNil(r.redirectServer),
	)
}

func (r *autoRedirect) UpdateRouteAddressSet() {
	if r.useNFTables {
		err := runInNetworkNamespace(r.tunOptions.NetNs, r.nftablesUpdateRouteAddressSet)
		if err != nil {
			r.logger.Error("update route address set: ", err)
		}
	}
}

func (r *autoRedirect) initializeNFTables() error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	_, err = nft.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return err
	}
	r.useNFTables = true
	return nil
}

func (r *autoRedirect) redirectPort() uint16 {
	if r.customRedirectPort > 0 {
		return uint16(r.customRedirectPort)
	}
	return M.AddrPortFromNet(r.redirectServer.listener.Addr()).Port()
}

func (r *autoRedirect) effectiveOutputMark() uint32 {
	if r.tunOptions.AutoRedirectOutputMark != 0 {
		return r.tunOptions.AutoRedirectOutputMark
	}
	return DefaultAutoRedirectOutputMark
}

func (r *autoRedirect) effectiveResetMark() uint32 {
	if r.tunOptions.AutoRedirectResetMark != 0 {
		return r.tunOptions.AutoRedirectResetMark
	}
	return DefaultAutoRedirectResetMark
}

func (r *autoRedirect) effectiveNFQueue() uint16 {
	if r.tunOptions.AutoRedirectNFQueue != 0 {
		return r.tunOptions.AutoRedirectNFQueue
	}
	return DefaultAutoRedirectNFQueue
}

func (r *autoRedirect) shouldSkipOutputChain() bool {
	return len(r.tunOptions.IncludeInterface) > 0 && !common.Contains(r.tunOptions.IncludeInterface, "lo") || common.Contains(r.tunOptions.ExcludeInterface, "lo")
}
