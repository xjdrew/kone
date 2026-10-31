package tun

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNetworkUpdateMonitorReceiveOverrun(t *testing.T) {
	if os.Getuid() != 0 {
		t.SkipNow()
	}
	monitor, err := NewNetworkUpdateMonitor(logger.NOP())
	require.NoError(t, err)
	updates := make(chan struct{}, 1)
	monitor.RegisterCallback(func() {
		select {
		case updates <- struct{}{}:
		default:
		}
	})
	require.NoError(t, monitor.Start())
	defer monitor.Close()

	rawConn, err := monitor.(*networkUpdateMonitor).socket.SyscallConn()
	require.NoError(t, err)
	var (
		socketInode uint64
		controlErr  error
	)
	err = rawConn.Control(func(descriptor uintptr) {
		controlErr = unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_RCVBUF, 0)
		if controlErr != nil {
			return
		}
		var stat unix.Stat_t
		controlErr = unix.Fstat(int(descriptor), &stat)
		socketInode = stat.Ino
	})
	require.NoError(t, err)
	require.NoError(t, controlErr)

	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tunmon" + strconv.Itoa(os.Getpid())}}
	require.NoError(t, netlink.LinkAdd(link))
	defer netlink.LinkDel(link)
	require.NoError(t, netlink.LinkSetUp(link))
	for i := range 4096 {
		err = netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &net.IPNet{IP: net.IPv4(10, byte(i>>8), byte(i), 0), Mask: net.CIDRMask(24, 32)},
			Table:     179,
		})
		require.NoError(t, err)
	}
	require.Greater(t, netlinkSocketDrops(t, socketInode), 0)

drain:
	for {
		select {
		case <-updates:
		case <-time.After(1500 * time.Millisecond):
			break drain
		}
	}
	var usageBefore, usageAfter unix.Rusage
	require.NoError(t, unix.Getrusage(unix.RUSAGE_SELF, &usageBefore))
	time.Sleep(2 * time.Second)
	require.NoError(t, unix.Getrusage(unix.RUSAGE_SELF, &usageAfter))
	cpuTime := time.Duration(usageAfter.Utime.Nano()+usageAfter.Stime.Nano()) -
		time.Duration(usageBefore.Utime.Nano()+usageBefore.Stime.Nano())
	require.Less(t, cpuTime, 200*time.Millisecond)

	require.NoError(t, netlink.LinkSetDown(link))
	select {
	case <-updates:
	case <-time.After(3 * time.Second):
		t.Fatal("no update after link change")
	}
}

func netlinkSocketDrops(t *testing.T, inode uint64) int {
	content, err := os.ReadFile("/proc/net/netlink")
	require.NoError(t, err)
	for _, line := range strings.Split(string(content), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[9] != strconv.FormatUint(inode, 10) {
			continue
		}
		var drops int
		drops, err = strconv.Atoi(fields[8])
		require.NoError(t, err)
		return drops
	}
	t.Fatal("netlink socket not found in /proc/net/netlink")
	return 0
}
