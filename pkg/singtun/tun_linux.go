package tun

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/shell"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/unix"
)

var _ LinuxTUN = (*NativeTun)(nil)

type NativeTun struct {
	tunFd               int
	tunFile             *os.File
	iovecsOutputDefault []unix.Iovec
	interfaceCallback   *list.Element[DefaultInterfaceUpdateCallback]
	options             Options
	readAccess          sync.Mutex
	writeAccess         sync.Mutex
	vnetHdr             bool
	writeBuffer         []byte
	readRawConn         syscall.RawConn
	pendingBuffer       []byte
	pendingLength       int
	vnetHdrWriteBuf     []byte
	gsoToWrite          []int
	tcpGROTable         *tcpGROTable
	udpGROTable         *udpGROTable
	gro                 groDisablementFlags
	txChecksumOffload   bool
}

func New(options Options) (Tun, error) {
	if options.FileDescriptor == 0 {
		return execInNetworkNamespace(options.NetNs, func() (Tun, error) {
			tunFd, err := open(options.Name, options.GSO)
			if err != nil {
				return nil, E.Cause(err, "open tun")
			}
			tunLink, err := netlink.LinkByName(options.Name)
			if err != nil {
				return nil, E.Errors(err, unix.Close(tunFd))
			}
			nativeTun := &NativeTun{
				tunFd:   tunFd,
				tunFile: os.NewFile(uintptr(tunFd), "tun"),
				options: options,
			}
			err = nativeTun.configure(tunLink)
			if err != nil {
				return nil, E.Errors(err, unix.Close(tunFd))
			}
			return nativeTun, nil
		})
	}
	nativeTun := &NativeTun{
		tunFd:   options.FileDescriptor,
		tunFile: os.NewFile(uintptr(options.FileDescriptor), "tun"),
		options: options,
	}
	if options.GSO {
		err := nativeTun.enableGSO()
		if err != nil {
			if options.Logger != nil {
				options.Logger.Warn(err)
			}
		}
	}
	return nativeTun, nil
}

var controlPath string

func init() {
	const defaultTunPath = "/dev/net/tun"
	const androidTunPath = "/dev/tun"
	if rw.IsFile(androidTunPath) {
		controlPath = androidTunPath
	} else {
		controlPath = defaultTunPath
	}
}

func open(name string, vnetHdr bool) (int, error) {
	fd, err := unix.Open(controlPath, unix.O_RDWR, 0)
	if err != nil {
		return -1, E.Cause(err, "open ", controlPath)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return 0, E.Cause(err, "create ifreq")
	}
	flags := unix.IFF_TUN | unix.IFF_NO_PI
	if vnetHdr {
		flags |= unix.IFF_VNET_HDR
	}
	ifr.SetUint16(uint16(flags))
	err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	if err != nil {
		unix.Close(fd)
		return 0, E.Cause(err, "TUNSETIFF")
	}
	err = unix.SetNonblock(fd, true)
	if err != nil {
		unix.Close(fd)
		return 0, E.Cause(err, "set nonblock")
	}
	return fd, nil
}

func (t *NativeTun) configure(tunLink netlink.Link) error {
	err := netlink.LinkSetMTU(tunLink, int(t.options.MTU))
	if errors.Is(err, unix.EPERM) {
		return nil
	} else if err != nil {
		return E.Cause(err, "set mtu")
	}
	if !t.options.EXP_ExternalConfiguration {
		if len(t.options.Inet4Address) > 0 {
			for _, address := range t.options.Inet4Address {
				addr4, _ := netlink.ParseAddr(address.String())
				err = netlink.AddrAdd(tunLink, addr4)
				if err != nil && !errors.Is(err, unix.EEXIST) {
					return E.Cause(err, "add address ", address)
				}
			}
		}
		if len(t.options.Inet6Address) > 0 {
			for _, address := range t.options.Inet6Address {
				addr6, _ := netlink.ParseAddr(address.String())
				err = netlink.AddrAdd(tunLink, addr6)
				if err != nil && !errors.Is(err, unix.EEXIST) {
					return E.Cause(err, "add address ", address)
				}
			}
		}
	}

	if t.options.GSO {
		err = t.enableGSO()
		if err != nil {
			if t.options.Logger != nil {
				t.options.Logger.Warn(err)
			}
		}
	}

	var rxChecksumOffload bool
	rxChecksumOffload, err = checkChecksumOffload(t.options.Name, unix.ETHTOOL_GRXCSUM)
	if err == nil && !rxChecksumOffload {
		_ = setChecksumOffload(t.options.Name, unix.ETHTOOL_SRXCSUM)
	}

	if t.options._TXChecksumOffload {
		var txChecksumOffload bool
		txChecksumOffload, err = checkChecksumOffload(t.options.Name, unix.ETHTOOL_GTXCSUM)
		if err != nil {
			return E.Cause(err, "check tx checksum offload")
		}
		if !txChecksumOffload {
			err = setChecksumOffload(t.options.Name, unix.ETHTOOL_STXCSUM)
			if err != nil {
				return E.Cause(err, "set tx checksum offload")
			}
		}
		t.txChecksumOffload = true
	}

	return nil
}

func (t *NativeTun) enableGSO() error {
	vnetHdrEnabled, err := checkVNETHDREnabled(t.tunFd, t.options.Name)
	if err != nil {
		return E.Cause(err, "enable offload: check IFF_VNET_HDR enabled")
	}
	if !vnetHdrEnabled {
		return E.Cause(err, "enable offload: IFF_VNET_HDR not enabled")
	}
	t.vnetHdr = true
	t.writeBuffer = make([]byte, virtioNetHdrLen+gsoMaxSize)
	t.pendingBuffer = make([]byte, virtioNetHdrLen+gsoMaxSize)
	t.tcpGROTable = newTCPGROTable()
	t.udpGROTable = newUDPGROTable()
	err = setTCPOffload(t.tunFd)
	if err != nil {
		if !(errors.Is(err, unix.EPERM) && t.options.FileDescriptor != 0) {
			if t.options.Logger != nil {
				t.options.Logger.Warn(E.Cause(err, "enable offload: set tcp offload"))
			}
			t.gro.disableTCPGRO()
			t.gro.disableUDPGRO()
		}
	} else {
		err = setUDPOffload(t.tunFd)
		if err != nil {
			if t.options.Logger != nil {
				t.options.Logger.Warn(E.Cause(err, "enable offload: set udp offload"))
			}
			t.gro.disableUDPGRO()
		}
	}
	t.readRawConn, err = t.tunFile.SyscallConn()
	if err != nil {
		return E.Cause(err, "enable offload: get raw conn")
	}
	return nil
}

func (t *NativeTun) probeTCPGRO() error {
	probeAddr := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	if len(t.options.Inet4Address) > 0 {
		probeAddr = t.options.Inet4Address[0].Addr()
	}
	ipPort := netip.AddrPortFrom(probeAddr, 0)
	fingerprint := []byte("sing-tun-probe-tun-gro")
	segmentSize := len(fingerprint)
	iphLen := 20
	tcphLen := 20
	totalLen := iphLen + tcphLen + segmentSize
	bufs := make([][]byte, 2)
	for i := range bufs {
		bufs[i] = make([]byte, virtioNetHdrLen+totalLen, virtioNetHdrLen+(totalLen*2))
		ipv4H := header.IPv4(bufs[i][virtioNetHdrLen:])
		ipv4H.Encode(&header.IPv4Fields{
			SrcAddr:  ipPort.Addr(),
			DstAddr:  ipPort.Addr(),
			Protocol: unix.IPPROTO_TCP,
			// Use a zero value TTL as best effort means to reduce chance of
			// probe packet leaking further than it needs to.
			TTL:         0,
			TotalLength: uint16(totalLen),
		})
		tcpH := header.TCP(bufs[i][virtioNetHdrLen+iphLen:])
		tcpH.Encode(&header.TCPFields{
			SrcPort:    ipPort.Port(),
			DstPort:    ipPort.Port(),
			SeqNum:     1 + uint32(i*segmentSize),
			AckNum:     1,
			DataOffset: 20,
			Flags:      header.TCPFlagAck,
			WindowSize: 3000,
		})
		copy(bufs[i][virtioNetHdrLen+iphLen+tcphLen:], fingerprint)
		ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
		pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ipv4H.SourceAddressSlice(), ipv4H.DestinationAddressSlice(), uint16(tcphLen+segmentSize))
		pseudoCsum = checksum.Checksum(bufs[i][virtioNetHdrLen+iphLen+tcphLen:], pseudoCsum)
		tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))
	}
	_, err := t.BatchWrite(bufs, virtioNetHdrLen)
	if err != nil {
		return E.Cause(err, "batch write")
	}
	return nil
}

func (t *NativeTun) Name() (string, error) {
	var ifr [unix.IFNAMSIZ + 64]byte
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(t.tunFd),
		uintptr(unix.TUNGETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return "", os.NewSyscallError("ioctl TUNGETIFF", errno)
	}
	return unix.ByteSliceToString(ifr[:]), nil
}

func (t *NativeTun) Start() error {
	if t.options.FileDescriptor == 0 {
		if !t.options.EXP_ExternalConfiguration && t.options.NetNs == "" {
			t.options.InterfaceMonitor.RegisterMyInterface(t.options.Name)
		}
		err := runInNetworkNamespace(t.options.NetNs, t.start)
		if err != nil {
			return err
		}
	}
	// The kernel rejects writes with EIO while the device is not up (tun_get_user),
	// so the probe must run after LinkSetUp.
	if t.vnetHdr && t.gro.canTCPGRO() {
		err := t.probeTCPGRO()
		if err != nil {
			t.gro.disableTCPGRO()
			t.gro.disableUDPGRO()
			if t.options.Logger != nil {
				t.options.Logger.Warn(E.Cause(err, "disabled TUN TCP & UDP GRO due to GRO probe error"))
			}
		}
	}
	return nil
}

func (t *NativeTun) start() error {
	tunLink, err := netlink.LinkByName(t.options.Name)
	if err != nil {
		return E.Cause(err, "find tun interface")
	}

	err = netlink.LinkSetUp(tunLink)
	if err != nil {
		return E.Cause(err, "set tun up")
	}

	if t.options.EXP_ExternalConfiguration {
		return nil
	}

	_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+t.options.Name+"/rp_filter", []byte("2"), 0o644)

	if t.options.IPRoute2TableIndex == 0 {
		for {
			t.options.IPRoute2TableIndex = int(rand.Uint32() & 0x7fffffff)
			if t.options.IPRoute2TableIndex <= 255 {
				continue
			}
			routeList, fErr := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: t.options.IPRoute2TableIndex}, netlink.RT_FILTER_TABLE)
			if len(routeList) == 0 || fErr != nil {
				break
			}
		}
	}

	err = t.setRoute(tunLink)
	if err != nil {
		_ = t.unsetRoute0(tunLink)
		return E.Cause(err, "set routes")
	}

	err = t.unsetRules()
	if err != nil {
		return E.Cause(err, "cleanup rules")
	}
	err = t.setRules()
	if err != nil {
		_ = t.unsetRules()
		return E.Cause(err, "set rules")
	}

	if t.options.DNSModeOrDefault() != DNSModeDisabled && t.options.NetNs == "" {
		err = t.setSearchDomainForSystemdResolved()
		if err != nil {
			return E.Cause(err, "set search domain")
		}
	}

	if t.options.AutoRoute && runtime.GOOS == "android" {
		t.interfaceCallback = t.options.InterfaceMonitor.RegisterCallback(t.routeUpdate)
	}
	return nil
}

func (t *NativeTun) Close() error {
	if t.interfaceCallback != nil {
		t.options.InterfaceMonitor.UnregisterCallback(t.interfaceCallback)
	}
	if t.options.EXP_ExternalConfiguration {
		return common.Close(common.PtrOrNil(t.tunFile))
	}
	if t.options.DNSModeOrDefault() != DNSModeDisabled && t.options.NetNs == "" {
		t.unsetSearchDomainForSystemdResolved()
	}
	return E.Errors(runInNetworkNamespace(t.options.NetNs, func() error {
		t.unsetAddresses()
		return E.Errors(t.unsetRoute(), t.unsetRules())
	}), common.Close(common.PtrOrNil(t.tunFile)))
}

func (t *NativeTun) Read(p []byte) (n int, err error) {
	if t.vnetHdr {
		n, err = t.tunFile.Read(t.writeBuffer)
		if err != nil {
			if errors.Is(err, syscall.EBADFD) {
				err = os.ErrClosed
			}
			return
		}
		var sizes [1]int
		n, err = handleVirtioRead(t.writeBuffer[:n], [][]byte{p}, sizes[:], 0)
		if err != nil {
			return
		}
		if n == 0 {
			return
		}
		n = sizes[0]
		return
	} else {
		return t.tunFile.Read(p)
	}
}

// handleVirtioRead splits in into bufs, leaving offset bytes at the front of
// each buffer. It mutates sizes to reflect the size of each element of bufs,
// and returns the number of packets read.
func handleVirtioRead(in []byte, bufs [][]byte, sizes []int, offset int) (int, error) {
	payload, options, err := parseVirtioRead(in)
	if err != nil {
		return 0, err
	}
	return GSOSplit(payload, options, bufs, sizes, offset)
}

func parseVirtioRead(in []byte) ([]byte, GSOOptions, error) {
	var hdr virtioNetHdr
	err := hdr.decode(in)
	if err != nil {
		return nil, GSOOptions{}, err
	}
	in = in[virtioNetHdrLen:]

	options, err := hdr.toGSOOptions()
	if err != nil {
		return nil, GSOOptions{}, err
	}

	// Don't trust HdrLen from the kernel as it can be equal to the length
	// of the entire first packet when the kernel is handling it as part of a
	// FORWARD path. Instead, parse the transport header length and add it onto
	// CsumStart, which is synonymous for IP header length.
	if options.GSOType == GSOUDPL4 {
		options.HdrLen = options.CsumStart + 8
	} else if options.GSOType != GSONone {
		if len(in) <= int(options.CsumStart+12) {
			return nil, GSOOptions{}, errors.New("packet is too short")
		}

		tcpHLen := uint16(in[options.CsumStart+12] >> 4 * 4)
		if tcpHLen < 20 || tcpHLen > 60 {
			// A TCP header must be between 20 and 60 bytes in length.
			return nil, GSOOptions{}, fmt.Errorf("tcp header len is invalid: %d", tcpHLen)
		}
		options.HdrLen = options.CsumStart + tcpHLen
	}

	return in, options, nil
}

func gsoSegmentCount(payload []byte, options GSOOptions) int {
	dataLength := len(payload) - int(options.HdrLen)
	if options.GSOType == GSONone || options.GSOSize == 0 || dataLength < int(options.GSOSize) {
		return 1
	}
	return (dataLength + int(options.GSOSize) - 1) / int(options.GSOSize)
}

func (t *NativeTun) Write(p []byte) (n int, err error) {
	if t.vnetHdr {
		_, err = t.BatchWrite([][]byte{p}, virtioNetHdrLen)
		if err != nil {
			return
		}
		n = len(p)
		return
	}
	return t.tunFile.Write(p)
}

func (t *NativeTun) FrontHeadroom() int {
	if t.vnetHdr {
		return virtioNetHdrLen
	}
	return 0
}

func (t *NativeTun) BatchSize() int {
	if !t.vnetHdr {
		return 1
	}
	/* // Not works on some devices: https://github.com/SagerNet/sing-box/issues/1605
	batchSize := int(gsoMaxSize/t.options.MTU) * 2
	if batchSize > idealBatchSize {
		batchSize = idealBatchSize
	}
	return batchSize*/
	return idealBatchSize
}

func (t *NativeTun) BatchRead(buffers [][]byte, offset int, readN []int) (int, error) {
	t.readAccess.Lock()
	defer t.readAccess.Unlock()
	var used int
	if t.pendingLength > 0 {
		pendingLength := t.pendingLength
		t.pendingLength = 0
		count, err := handleVirtioRead(t.pendingBuffer[:pendingLength], buffers, readN, offset)
		if err != nil {
			return count, err
		}
		used = count
	}
	for used < len(buffers) {
		var (
			readLength int
			err        error
		)
		if used == 0 {
			readLength, err = t.tunFile.Read(t.writeBuffer)
			if err != nil {
				return 0, err
			}
		} else {
			readLength, err = t.readNonblocking(t.writeBuffer)
			if err != nil || readLength == 0 {
				break
			}
		}
		payload, options, parseErr := parseVirtioRead(t.writeBuffer[:readLength])
		if parseErr != nil {
			if used > 0 {
				break
			}
			return 0, parseErr
		}
		if used > 0 && gsoSegmentCount(payload, options) > len(buffers)-used {
			t.writeBuffer, t.pendingBuffer = t.pendingBuffer, t.writeBuffer
			t.pendingLength = readLength
			break
		}
		count, splitErr := GSOSplit(payload, options, buffers[used:], readN[used:], offset)
		if splitErr != nil {
			if used > 0 {
				break
			}
			return count, splitErr
		}
		used += count
	}
	return used, nil
}

func (t *NativeTun) readNonblocking(buffer []byte) (int, error) {
	var (
		readLength int
		readErr    error
	)
	controlErr := t.readRawConn.Read(func(fd uintptr) bool {
		readLength, readErr = syscall.Read(int(fd), buffer)
		return true
	})
	if controlErr != nil {
		return 0, controlErr
	}
	if readErr != nil {
		if readErr == syscall.EAGAIN {
			return 0, nil
		}
		return 0, readErr
	}
	return readLength, nil
}

func (t *NativeTun) BatchWrite(buffers [][]byte, offset int) (int, error) {
	t.writeAccess.Lock()
	defer func() {
		if t.vnetHdr {
			t.tcpGROTable.reset()
			t.udpGROTable.reset()
		}
		t.writeAccess.Unlock()
	}()
	var (
		errs  error
		total int
	)
	t.gsoToWrite = t.gsoToWrite[:0]
	if t.vnetHdr {
		err := handleGRO(buffers, offset, t.tcpGROTable, t.udpGROTable, t.gro, &t.gsoToWrite)
		if err != nil {
			return 0, err
		}
		offset -= virtioNetHdrLen
	} else {
		for i := range buffers {
			t.gsoToWrite = append(t.gsoToWrite, i)
		}
	}
	for _, toWrite := range t.gsoToWrite {
		n, err := t.tunFile.Write(buffers[toWrite][offset:])
		if errors.Is(err, syscall.EBADFD) {
			return total, os.ErrClosed
		}
		if err != nil {
			errs = errors.Join(errs, err)
		} else {
			total += n
		}
	}
	return total, errs
}

func (t *NativeTun) TXChecksumOffload() bool {
	return t.txChecksumOffload
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

func (t *NativeTun) UpdateRouteOptions(tunOptions Options) error {
	if t.options.FileDescriptor > 0 {
		return nil
	} else if t.options.EXP_ExternalConfiguration {
		t.options = tunOptions
		return nil
	} else if !t.options.AutoRoute {
		t.options = tunOptions
		return nil
	}
	return runInNetworkNamespace(t.options.NetNs, func() error {
		tunLink, err := netlink.LinkByName(t.options.Name)
		if err != nil {
			return E.Cause(err, "find tun interface")
		}
		err = t.unsetRoute0(tunLink)
		if err != nil {
			return E.Cause(err, "unset old routes")
		}
		t.options = tunOptions
		return t.setRoute(tunLink)
	})
}

func (t *NativeTun) routes(tunLink netlink.Link) ([]netlink.Route, error) {
	routeRanges, err := t.options.BuildAutoRouteRanges(false)
	if err != nil {
		return nil, E.Cause(err, "build auto route ranges")
	}
	if !t.options.AutoRoute && len(t.options.Inet6Address) > 0 && len(t.options.Inet6RouteAddress) == 0 {
		routeRanges = append(routeRanges, netip.PrefixFrom(netip.IPv6Unspecified(), 0))
	}
	// Do not create gateway on linux by default
	gateway4, gateway6 := t.options.Inet4GatewayAddr(), t.options.Inet6GatewayAddr()
	return common.Map(routeRanges, func(it netip.Prefix) netlink.Route {
		var gateway net.IP
		if it.Addr().Is4() && !gateway4.IsUnspecified() {
			gateway = gateway4.AsSlice()
		} else if it.Addr().Is6() && !gateway6.IsUnspecified() {
			gateway = gateway6.AsSlice()
		}
		return netlink.Route{
			Dst:       prefixToIPNet(it),
			Gw:        gateway,
			LinkIndex: tunLink.Attrs().Index,
			Table:     t.options.IPRoute2TableIndex,
		}
	}), nil
}

func (t *NativeTun) nextIndex6() int {
	ruleList, err := netlink.RuleList(netlink.FAMILY_V6)
	if err != nil {
		return -1
	}
	var minIndex int
	for _, rule := range ruleList {
		if rule.Priority > redirectRouteRulePriority && (minIndex == 0 || rule.Priority < minIndex) {
			minIndex = rule.Priority
		}
	}
	return max(minIndex-1, redirectRouteRulePriority+1)
}

func (t *NativeTun) rules() []*netlink.Rule {
	if !t.options.AutoRoute {
		if len(t.options.Inet6Address) > 0 {
			it := netlink.NewRule()
			it.Priority = t.nextIndex6()
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET6
			it.OifName = t.options.Name
			return []*netlink.Rule{it}
		}
		return nil
	}

	var p4, p6 bool
	var pRule int
	if len(t.options.Inet4Address) > 0 {
		p4 = true
		pRule += 1
	}
	if len(t.options.Inet6Address) > 0 {
		p6 = true
		pRule += 1
	}
	if pRule == 0 {
		return []*netlink.Rule{}
	}

	var rules []*netlink.Rule
	var it *netlink.Rule

	excludeRanges := t.options.ExcludedRanges()

	ruleStart := t.options.IPRoute2RuleIndex
	priority := ruleStart
	priority6 := priority

	if t.options.AutoRedirectMarkMode {
		if p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.Mark = t.options.AutoRedirectOutputMark
			it.MarkSet = true
			it.Goto = priority + 2
			it.Family = unix.AF_INET
			rules = append(rules, it)
			priority++

			it = netlink.NewRule()
			it.Priority = priority
			it.Mark = t.options.AutoRedirectInputMark
			it.MarkSet = true
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET
			rules = append(rules, it)
			priority++

			it = netlink.NewRule()
			it.Priority = priority
			it.Family = unix.AF_INET
			rules = append(rules, it)
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Mark = t.options.AutoRedirectOutputMark
			it.MarkSet = true
			it.Goto = priority6 + 2
			it.Family = unix.AF_INET6
			rules = append(rules, it)
			priority6++

			it = netlink.NewRule()
			it.Priority = priority6
			it.Mark = t.options.AutoRedirectInputMark
			it.MarkSet = true
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET6
			rules = append(rules, it)
			priority6++

			it = netlink.NewRule()
			it.Priority = priority6
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}
		// Fallback rules after system default rules (32766: main, 32767: default)
		// Only reached when main and default tables have no route
		if p4 {
			it = netlink.NewRule()
			it.Priority = t.options.IPRoute2AutoRedirectFallbackRuleIndex
			it.Mark = t.options.AutoRedirectOutputMark
			it.MarkSet = true
			it.Invert = true
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET
			rules = append(rules, it)
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = t.options.IPRoute2AutoRedirectFallbackRuleIndex
			it.Mark = t.options.AutoRedirectOutputMark
			it.MarkSet = true
			it.Invert = true
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}
		return rules
	}

	nopPriority := ruleStart + 10
	for _, excludeRange := range excludeRanges {
		if p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.UIDRange = netlink.NewRuleUIDRange(excludeRange.Start, excludeRange.End)
			it.Goto = nopPriority
			it.Family = unix.AF_INET
			rules = append(rules, it)
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.UIDRange = netlink.NewRuleUIDRange(excludeRange.Start, excludeRange.End)
			it.Goto = nopPriority
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}
	}
	if len(excludeRanges) > 0 {
		if p4 {
			priority++
		}
		if p6 {
			priority6++
		}
	}
	if len(t.options.IncludeInterface) > 0 {
		matchPriority := priority + 2
		matchPriority6 := priority6 + 2
		for _, includeInterface := range t.options.IncludeInterface {
			if p4 {
				it = netlink.NewRule()
				it.Priority = priority
				it.IifName = includeInterface
				it.Goto = matchPriority
				it.Family = unix.AF_INET
				rules = append(rules, it)
			}
			if p6 {
				it = netlink.NewRule()
				it.Priority = priority6
				it.IifName = includeInterface
				it.Goto = matchPriority6
				it.Family = unix.AF_INET6
				rules = append(rules, it)
			}
		}
		if p4 {
			priority++
		}
		if p6 {
			priority6++
		}
		if p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.Family = unix.AF_INET
			it.Goto = nopPriority
			rules = append(rules, it)
			priority++

			it = netlink.NewRule()
			it.Priority = matchPriority
			it.Family = unix.AF_INET
			rules = append(rules, it)
			priority++
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Family = unix.AF_INET6
			it.Goto = nopPriority
			rules = append(rules, it)
			priority6++

			it = netlink.NewRule()
			it.Priority = matchPriority6
			it.Family = unix.AF_INET6
			rules = append(rules, it)
			priority6++
		}
	} else if len(t.options.ExcludeInterface) > 0 {
		for _, excludeInterface := range t.options.ExcludeInterface {
			if p4 {
				it = netlink.NewRule()
				it.Priority = priority
				it.IifName = excludeInterface
				it.Goto = nopPriority
				it.Family = unix.AF_INET
				rules = append(rules, it)
			}
			if p6 {
				it = netlink.NewRule()
				it.Priority = priority6
				it.IifName = excludeInterface
				it.Goto = nopPriority
				it.Family = unix.AF_INET6
				rules = append(rules, it)
			}
		}

		if p4 {
			priority++
		}
		if p6 {
			priority6++
		}
	}

	if runtime.GOOS == "android" && t.options.InterfaceMonitor.AndroidVPNEnabled() {
		const protectedFromVPN = 0x20000
		if p4 {
			it = netlink.NewRule()
			if t.options.InterfaceMonitor.OverrideAndroidVPN() {
				it.Mark = protectedFromVPN
				it.MarkSet = true
			}
			it.Mask = protectedFromVPN
			it.Priority = priority
			it.Family = unix.AF_INET
			it.Goto = nopPriority
			rules = append(rules, it)
			priority++
		}
		if p6 {
			it = netlink.NewRule()
			if t.options.InterfaceMonitor.OverrideAndroidVPN() {
				it.Mark = protectedFromVPN
				it.MarkSet = true
			}
			it.Mask = protectedFromVPN
			it.Family = unix.AF_INET6
			it.Priority = priority6
			it.Goto = nopPriority
			rules = append(rules, it)
			priority6++
		}
	}

	if t.options.StrictRoute {
		if !p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.Family = unix.AF_INET
			it.Type = unix.FR_ACT_UNREACHABLE
			rules = append(rules, it)
			priority++
		}
		if !p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Family = unix.AF_INET6
			it.Type = unix.FR_ACT_UNREACHABLE
			rules = append(rules, it)
			priority6++
		}
	}

	if runtime.GOOS != "android" {
		if p4 {
			for _, address := range t.options.Inet4Address {
				it = netlink.NewRule()
				it.Priority = priority
				it.Dst = address.Masked()
				it.Table = t.options.IPRoute2TableIndex
				it.Family = unix.AF_INET
				rules = append(rules, it)
			}
			priority++

			it = netlink.NewRule()
			it.Priority = priority
			it.Table = t.options.IPRoute2TableIndex
			it.SuppressPrefixlen = 0
			it.Family = unix.AF_INET
			rules = append(rules, it)
			priority++
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Table = t.options.IPRoute2TableIndex
			it.SuppressPrefixlen = 0
			it.Family = unix.AF_INET6
			rules = append(rules, it)
			priority6++
		}
		if p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.Invert = true
			it.Dport = netlink.NewRulePortRange(53, 53)
			it.Table = unix.RT_TABLE_MAIN
			it.SuppressPrefixlen = 0
			it.Family = unix.AF_INET
			rules = append(rules, it)
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Invert = true
			it.Dport = netlink.NewRulePortRange(53, 53)
			it.Table = unix.RT_TABLE_MAIN
			it.SuppressPrefixlen = 0
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}
	}
	if p4 {
		it = netlink.NewRule()
		it.Priority = priority
		it.IifName = t.options.Name
		it.Goto = nopPriority
		it.Family = unix.AF_INET
		rules = append(rules, it)
		priority++

		it = netlink.NewRule()
		it.Priority = priority
		it.Invert = true
		it.IifName = "lo"
		it.Table = t.options.IPRoute2TableIndex
		it.Family = unix.AF_INET
		rules = append(rules, it)

		it = netlink.NewRule()
		it.Priority = priority
		it.IifName = "lo"
		it.Src = netip.PrefixFrom(netip.IPv4Unspecified(), 32)
		it.Table = t.options.IPRoute2TableIndex
		it.Family = unix.AF_INET
		rules = append(rules, it)

		for _, address := range t.options.Inet4Address {
			it = netlink.NewRule()
			it.Priority = priority
			it.IifName = "lo"
			it.Src = address.Masked()
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET
			rules = append(rules, it)
		}
		// priority++
	}
	if p6 {
		for _, address := range t.options.Inet6Address {
			it = netlink.NewRule()
			it.Priority = priority6
			it.IifName = "lo"
			it.Src = address.Masked()
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}
		priority6++

		it = netlink.NewRule()
		it.Priority = priority6
		it.IifName = t.options.Name
		it.Goto = nopPriority
		it.Family = unix.AF_INET6
		rules = append(rules, it)

		it = netlink.NewRule()
		it.Priority = priority6
		it.IifName = "lo"
		it.Src = netip.PrefixFrom(netip.IPv6Unspecified(), 1)
		it.Goto = nopPriority
		it.Family = unix.AF_INET6
		rules = append(rules, it)

		it = netlink.NewRule()
		it.Priority = priority6
		it.IifName = "lo"
		it.Src = netip.PrefixFrom(netip.AddrFrom16([16]byte{0: 128}), 1)
		it.Goto = nopPriority
		it.Family = unix.AF_INET6
		rules = append(rules, it)
		priority6++

		it = netlink.NewRule()
		it.Priority = priority6
		it.Table = t.options.IPRoute2TableIndex
		it.Family = unix.AF_INET6
		rules = append(rules, it)
		// priority6++
	}
	if p4 {
		it = netlink.NewRule()
		it.Priority = nopPriority
		it.Family = unix.AF_INET
		rules = append(rules, it)
	}
	if p6 {
		it = netlink.NewRule()
		it.Priority = nopPriority
		it.Family = unix.AF_INET6
		rules = append(rules, it)
	}
	return rules
}

func (t *NativeTun) setRoute(tunLink netlink.Link) error {
	routes, err := t.routes(tunLink)
	if err != nil {
		return E.Cause(err, "build routes")
	}
	for i, route := range routes {
		err := netlink.RouteAdd(&route)
		if err != nil {
			return E.Cause(err, "add route ", i)
		}
	}
	return nil
}

func (t *NativeTun) setRules() error {
	for i, rule := range t.rules() {
		err := netlink.RuleAdd(rule)
		if err != nil {
			return E.Cause(err, "add rule ", i, "/", len(t.rules()))
		}
	}
	return nil
}

func (t *NativeTun) unsetRoute() error {
	if t.options.FileDescriptor > 0 {
		return nil
	}
	tunLink, err := netlink.LinkByName(t.options.Name)
	if err != nil {
		return E.Cause(err, "find tun interface")
	}
	return t.unsetRoute0(tunLink)
}

func (t *NativeTun) unsetRoute0(tunLink netlink.Link) error {
	if routes, err := t.routes(tunLink); err == nil {
		for _, route := range routes {
			_ = netlink.RouteDel(&route)
		}
	}
	return nil
}

func (t *NativeTun) unsetRules() error {
	if t.options.FileDescriptor > 0 {
		return nil
	}
	if !t.options.AutoRoute && len(t.options.Inet6Address) > 0 && t.options.IPRoute2TableIndex != 0 {
		ruleToDel := netlink.NewRule()
		ruleToDel.Family = unix.AF_INET6
		ruleToDel.OifName = t.options.Name
		ruleToDel.Table = t.options.IPRoute2TableIndex
		err := netlink.RuleDel(ruleToDel)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return E.Cause(err, "unset rule6")
		}
	}
	if t.options.AutoRoute {
		ruleList, err := netlink.RuleList(netlink.FAMILY_ALL)
		if err != nil {
			return E.Cause(err, "list rules")
		}
		for _, rule := range ruleList {
			ruleStart := t.options.IPRoute2RuleIndex
			ruleEnd := ruleStart + 10
			if rule.Priority >= ruleStart && rule.Priority <= ruleEnd || (t.options.AutoRedirectMarkMode && rule.Priority == t.options.IPRoute2AutoRedirectFallbackRuleIndex) {
				ruleToDel := netlink.NewRule()
				ruleToDel.Family = rule.Family
				ruleToDel.Priority = rule.Priority
				err = netlink.RuleDel(ruleToDel)
				if err != nil {
					return E.Cause(err, "unset rule ", rule.Priority, " for ", rule.Family)
				}
			}
		}
	}
	return nil
}

func (t *NativeTun) unsetAddresses() {
	if t.options.FileDescriptor > 0 {
		return
	}
	tunLink, err := netlink.LinkByName(t.options.Name)
	if err != nil {
		return
	}
	for _, address := range t.options.Inet4Address {
		addr, _ := netlink.ParseAddr(address.String())
		_ = netlink.AddrDel(tunLink, addr)
	}
	for _, address := range t.options.Inet6Address {
		addr, _ := netlink.ParseAddr(address.String())
		_ = netlink.AddrDel(tunLink, addr)
	}
}

func (t *NativeTun) resetRules() error {
	t.unsetRules()
	return t.setRules()
}

func (t *NativeTun) routeUpdate(_ *control.Interface, flags int) {
	if flags&FlagAndroidVPNUpdate == 0 {
		return
	}
	err := t.resetRules()
	if err != nil {
		if t.options.Logger != nil {
			t.options.Logger.Error(E.Cause(err, "reset route"))
		}
	}
}

func (t *NativeTun) setSearchDomainForSystemdResolved() error {
	ctlPath, err := exec.LookPath("resolvectl")
	if err != nil {
		return nil
	}
	dnsAddress, err := t.options.DNSServerAddress()
	if err != nil {
		return err
	}
	go func() {
		_ = shell.Exec(ctlPath, "domain", t.options.Name, "~.").Run()
		_ = shell.Exec(ctlPath, "default-route", t.options.Name, "true").Run()
		_ = shell.Exec(ctlPath, append([]string{"dns", t.options.Name}, common.Map(dnsAddress, netip.Addr.String)...)...).Run()
	}()
	return nil
}

func (t *NativeTun) FlushDNSCache() {
	if t.options.FileDescriptor != 0 || t.options.EXP_ExternalConfiguration || t.options.DNSModeOrDefault() == DNSModeDisabled || t.options.NetNs != "" {
		return
	}
	ctlPath, err := exec.LookPath("resolvectl")
	if err != nil {
		return
	}
	// systemd-resolved flushes the cache of a link only when the link switches its current DNS server
	// (link_set_dns_server in resolved-link.c), which a network change never causes for the TUN link.
	go shell.Exec(ctlPath, "flush-caches").Run()
}

func (t *NativeTun) unsetSearchDomainForSystemdResolved() {
	ctlPath, err := exec.LookPath("resolvectl")
	if err != nil {
		return
	}
	_ = shell.Exec(ctlPath, "revert", t.options.Name).Run()
}
