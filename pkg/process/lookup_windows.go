package process

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")

func Supported() bool { return true }

func ownerTable(ctx context.Context, protocol string) ([]byte, error) {
	name, class := "GetExtendedTcpTable", uintptr(5) // TCP_TABLE_OWNER_PID_ALL
	if protocol == "udp" {
		name, class = "GetExtendedUdpTable", 1
	} // UDP_TABLE_OWNER_PID
	proc := ipHelper.NewProc(name)
	if err := proc.Find(); err != nil {
		return nil, err
	}
	size := uint32(4096)
	for range 3 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if size < 4 || size > 8*1024*1024 {
			return nil, errors.New("socket owner table exceeds bound")
		}
		data := make([]byte, size)
		status, _, _ := proc.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, class, 0)
		if status == 0 {
			return data[:size], nil
		}
		if status != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, windows.Errno(status)
		}
	}
	return nil, errors.New("socket owner table changed during inspection")
}

func windowsSocketOwner(data []byte, query Query) (uint32, error) {
	if len(data) < 4 {
		return 0, errors.New("short socket table")
	}
	count := int(binary.LittleEndian.Uint32(data))
	stride := 24
	if query.Protocol == "udp" {
		stride = 12
	}
	if count > (len(data)-4)/stride {
		return 0, errors.New("invalid socket table bounds")
	}
	var owner uint32
	for index := 0; index < count; index++ {
		row := data[4+index*stride : 4+(index+1)*stride]
		offset := 4
		if query.Protocol == "udp" {
			offset = 0
		}
		local := netip.AddrPortFrom(netip.AddrFrom4([4]byte(row[offset:offset+4])), binary.BigEndian.Uint16(row[offset+4:offset+6]))
		if local.Port() != query.Source.Port() || local.Addr() != query.Source.Addr().Unmap() && (query.Protocol != "udp" || !local.Addr().IsUnspecified()) {
			continue
		}
		if query.Protocol == "tcp" {
			remote := netip.AddrPortFrom(netip.AddrFrom4([4]byte(row[12:16])), binary.BigEndian.Uint16(row[16:18]))
			if remote != query.Destination {
				continue
			}
		}
		pid := binary.LittleEndian.Uint32(row[stride-4:])
		if pid == 0 {
			continue
		}
		if owner != 0 && owner != pid {
			return 0, errors.New("ambiguous socket owner")
		}
		owner = pid
	}
	if owner == 0 {
		return 0, errors.New("socket owner unavailable")
	}
	return owner, nil
}

func windowsIdentity(pid uint32) (string, time.Time, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", time.Time{}, err
	}
	defer windows.CloseHandle(handle)
	var created, exited, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return "", time.Time{}, err
	}
	if exited.HighDateTime != 0 || exited.LowDateTime != 0 {
		return "", time.Time{}, errors.New("process has exited")
	}
	name := make([]uint16, 32768)
	size := uint32(len(name))
	if err = windows.QueryFullProcessImageName(handle, 0, &name[0], &size); err != nil {
		return "", time.Time{}, err
	}
	return windows.UTF16ToString(name[:size]), time.Unix(0, created.Nanoseconds()), nil
}

func lookupNative(ctx context.Context, query Query) (Result, error) {
	data, err := ownerTable(ctx, query.Protocol)
	if err != nil {
		return Result{}, err
	}
	pid, err := windowsSocketOwner(data, query)
	if err != nil {
		return Result{}, err
	}
	path, started, err := windowsIdentity(pid)
	if err != nil {
		return Result{}, err
	}
	if started.After(query.ObservedAt) {
		return Result{}, errors.New("PID was created after socket observation")
	}
	data, err = ownerTable(ctx, query.Protocol)
	if err != nil {
		return Result{}, err
	}
	confirmed, err := windowsSocketOwner(data, query)
	if err != nil || confirmed != pid {
		return Result{}, errors.New("socket endpoint was reused")
	}
	confirmedPath, confirmedStart, err := windowsIdentity(pid)
	if err != nil || confirmedPath != path || !confirmedStart.Equal(started) {
		return Result{}, errors.New("process exited or PID was reused")
	}
	reason := "socket tuple and process creation time validated twice"
	if query.Protocol == "udp" {
		reason = "unique local UDP endpoint and process creation time validated twice; system table does not expose the remote endpoint"
	}
	return Result{Status: "matched", PID: pid, Name: filepath.Base(path), Path: path, StartedAt: started, Source: "windows_iphelper_creation_time", Reason: reason}, nil
}
