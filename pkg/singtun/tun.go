package tun

import (
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ranges"
)

type Handler interface {
	JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) FlowVerdict
	NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter)
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type Tun interface {
	io.ReadWriter
	Name() (string, error)
	Start() error
	Close() error
	UpdateRouteOptions(tunOptions Options) error
}

type WinTun interface {
	Tun
	ReadPacket() ([]byte, func(), error)
}

type LinuxTUN interface {
	Tun
	N.FrontHeadroom
	BatchSize() int
	BatchRead(buffers [][]byte, offset int, readN []int) (n int, err error)
	BatchWrite(buffers [][]byte, offset int) (n int, err error)
	TXChecksumOffload() bool
	FlushDNSCache()
}

type DarwinTUN interface {
	Tun
	BatchRead() ([]*buf.Buffer, error)
	BatchWrite(buffers []*buf.Buffer) error
}

const (
	DefaultIPRoute2TableIndex                    = 2022
	DefaultIPRoute2RuleIndex                     = 9000
	DefaultIPRoute2AutoRedirectFallbackRuleIndex = 32768
)

const (
	DNSModeDisabled = "disabled"
	DNSModeNative   = "native"
	DNSModeHijack   = "hijack"
)

type Options struct {
	Name                                  string
	NetNs                                 string
	Inet4Address                          []netip.Prefix
	Inet6Address                          []netip.Prefix
	MTU                                   uint32
	GSO                                   bool
	AutoRoute                             bool
	InterfaceScope                        bool
	Inet4Gateway                          netip.Addr
	Inet6Gateway                          netip.Addr
	DNSMode                               string
	DNSAddress                            []netip.Addr
	IPRoute2TableIndex                    int
	IPRoute2RuleIndex                     int
	IPRoute2AutoRedirectFallbackRuleIndex int
	AutoRedirectMarkMode                  bool
	AutoRedirectInputMark                 uint32
	AutoRedirectOutputMark                uint32
	AutoRedirectResetMark                 uint32
	AutoRedirectNFQueue                   uint16
	ExcludeMPTCP                          bool
	Inet4LoopbackAddress                  []netip.Addr
	Inet6LoopbackAddress                  []netip.Addr
	StrictRoute                           bool
	Inet4RouteAddress                     []netip.Prefix
	Inet6RouteAddress                     []netip.Prefix
	Inet4RouteExcludeAddress              []netip.Prefix
	Inet6RouteExcludeAddress              []netip.Prefix
	IncludeInterface                      []string
	ExcludeInterface                      []string
	IncludeUID                            []ranges.Range[uint32]
	ExcludeUID                            []ranges.Range[uint32]
	IncludeAndroidUser                    []int
	IncludePackage                        []string
	ExcludePackage                        []string
	IncludeMACAddress                     []net.HardwareAddr
	ExcludeMACAddress                     []net.HardwareAddr
	InterfaceFinder                       control.InterfaceFinder
	InterfaceMonitor                      DefaultInterfaceMonitor
	FileDescriptor                        int
	Logger                                logger.Logger

	// No work for TCP, do not use.
	_TXChecksumOffload bool

	// For library usages.
	EXP_DisableDNSHijack      bool
	EXP_ExternalConfiguration bool
	// KONE extension: never attach to or reopen another run's device.
	EXP_Exclusive bool

	// For gvisor stack, it should be enabled when MTU is less than 32768; otherwise it should be less than or equal to 8192.
	// The above condition is just an estimate and not exact, calculated on M4 pro.
	EXP_MultiPendingPackets bool

	// Will cause the darwin network to die, do not use.
	EXP_SendMsgX bool
}

func (o *Options) DNSModeOrDefault() string {
	if o.DNSMode == "" {
		if o.AutoRoute {
			return DNSModeHijack
		}
		return DNSModeDisabled
	}
	return o.DNSMode
}

func (o *Options) DNSServerAddress() ([]netip.Addr, error) {
	inet4DNS, err := o.Inet4DNSAddress()
	if err != nil {
		return nil, err
	}
	inet6DNS, err := o.Inet6DNSAddress()
	if err != nil {
		return nil, err
	}
	return append(inet4DNS, inet6DNS...), nil
}

func (o *Options) Inet4DNSAddress() ([]netip.Addr, error) {
	if len(o.Inet4Address) == 0 {
		return nil, nil
	}
	if len(o.DNSAddress) > 0 {
		return common.Filter(o.DNSAddress, netip.Addr.Is4), nil
	}
	if HasNextAddress(o.Inet4Address[0], 1) {
		return []netip.Addr{o.Inet4Address[0].Addr().Next()}, nil
	}
	if !(len(o.Inet6Address) > 0 && HasNextAddress(o.Inet6Address[0], 1)) {
		return nil, E.New("no IPv4 server configured and no usable next address in ", o.Inet6Address[0], " for DNS")
	}
	return nil, nil
}

func (o *Options) Inet6DNSAddress() ([]netip.Addr, error) {
	if len(o.Inet6Address) == 0 {
		return nil, nil
	}
	if len(o.DNSAddress) > 0 {
		return common.Filter(o.DNSAddress, netip.Addr.Is6), nil
	}
	if HasNextAddress(o.Inet6Address[0], 1) {
		return []netip.Addr{o.Inet6Address[0].Addr().Next()}, nil
	}
	if !(len(o.Inet4Address) > 0 && HasNextAddress(o.Inet4Address[0], 1)) {
		return nil, E.New("no IPv6 server configured and no usable next address in ", o.Inet6Address[0], " for DNS")
	}
	return nil, nil
}

func (o *Options) Inet4GatewayAddr() netip.Addr {
	if o.Inet4Gateway.IsValid() {
		return o.Inet4Gateway
	}
	if len(o.Inet4Address) > 0 {
		switch runtime.GOOS {
		case "android":
		case "linux":
			if HasNextAddress(o.Inet4Address[0], 1) {
				return o.Inet4Address[0].Addr().Next()
			}
		case "darwin":
			return o.Inet4Address[0].Addr()
		default:
			if !o.InterfaceScope {
				if HasNextAddress(o.Inet4Address[0], 1) {
					return o.Inet4Address[0].Addr().Next()
				} else {
					return o.Inet4Address[0].Addr()
				}
			}
		}
	}
	return netip.IPv4Unspecified()
}

func (o *Options) Inet6GatewayAddr() netip.Addr {
	if o.Inet6Gateway.IsValid() {
		return o.Inet6Gateway
	}
	if len(o.Inet6Address) > 0 {
		switch runtime.GOOS {
		case "android":
		case "linux":
			if HasNextAddress(o.Inet6Address[0], 1) {
				return o.Inet6Address[0].Addr().Next()
			}
		case "darwin":
			return o.Inet6Address[0].Addr()
		default:
			if !o.InterfaceScope {
				if HasNextAddress(o.Inet6Address[0], 1) {
					return o.Inet6Address[0].Addr().Next()
				} else {
					return o.Inet6Address[0].Addr()
				}
			}
		}
	}
	return netip.IPv6Unspecified()
}

func CalculateInterfaceName(name string) (tunName string) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		tunName = "utun"
	} else if name != "" {
		tunName = name
	} else {
		tunName = "tun"
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	var tunIndex int
	for _, netInterface := range interfaces {
		if strings.HasPrefix(netInterface.Name, tunName) {
			index, parseErr := strconv.ParseInt(netInterface.Name[len(tunName):], 10, 16)
			if parseErr == nil && int(index) >= tunIndex {
				tunIndex = int(index) + 1
			}
		}
	}
	tunName = F.ToString(tunName, tunIndex)
	return
}
