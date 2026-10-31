package process

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

func Supported() bool { return true }

func procEndpoint(value string) (netip.AddrPort, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || len(parts[0]) != 8 {
		return netip.AddrPort{}, errors.New("invalid proc endpoint")
	}
	address, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var data [4]byte
	binary.NativeEndian.PutUint32(data[:], uint32(address))
	return netip.AddrPortFrom(netip.AddrFrom4(data), uint16(port)), nil
}

func procSocket(ctx context.Context, root string, query Query) (string, error) {
	file, err := os.Open(filepath.Join(root, "net", query.Protocol))
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	inode := ""
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		local, err := procEndpoint(fields[1])
		if err != nil {
			continue
		}
		remote, err := procEndpoint(fields[2])
		if err != nil {
			continue
		}
		if local.Port() != query.Source.Port() || (local.Addr() != query.Source.Addr().Unmap() && (query.Protocol != "udp" || !local.Addr().IsUnspecified())) {
			continue
		}
		if remote != query.Destination && !(query.Protocol == "udp" && remote.Port() == 0 && remote.Addr().IsUnspecified()) {
			continue
		}
		if fields[9] == "0" {
			continue
		}
		if inode != "" && inode != fields[9] {
			return "", errors.New("ambiguous local socket")
		}
		inode = fields[9]
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if inode == "" {
		return "", errors.New("socket no longer exists")
	}
	return inode, nil
}

func procStart(data []byte) (uint64, error) {
	// comm can contain spaces and closing parentheses; the final ')' marks
	// field 2, followed by state (3). starttime is field 22, offset 19 here.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0, errors.New("invalid process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return 0, errors.New("short process stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func procBoot(root string) (time.Time, uint64, error) {
	data, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return time.Time{}, 0, err
	}
	var boot int64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "btime" {
			boot, err = strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return time.Time{}, 0, err
			}
			break
		}
	}
	if boot == 0 {
		return time.Time{}, 0, errors.New("boot time unavailable")
	}
	aux, err := os.ReadFile(filepath.Join(root, "self", "auxv"))
	if err != nil {
		return time.Time{}, 0, err
	}
	word := int(unsafe.Sizeof(uintptr(0)))
	read := func(data []byte) uint64 {
		if word == 8 {
			return binary.NativeEndian.Uint64(data)
		}
		return uint64(binary.NativeEndian.Uint32(data))
	}
	for index := 0; index+2*word <= len(aux); index += 2 * word {
		if read(aux[index:]) == 17 {
			ticks := read(aux[index+word:])
			if ticks > 0 && ticks <= 1000000 {
				return time.Unix(boot, 0), ticks, nil
			}
		}
	}
	return time.Time{}, 0, errors.New("kernel clock tick resolution unavailable")
}

func lookupNative(ctx context.Context, query Query) (Result, error) {
	return lookupProc(ctx, "/proc", query)
}

func boundedDir(path string, limit int) ([]os.DirEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.ReadDir(limit + 1)
	if len(entries) > limit {
		return nil, errors.New("process directory scan bound exceeded")
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return entries, err
}

func lookupProc(ctx context.Context, root string, query Query) (Result, error) {
	inode, err := procSocket(ctx, root, query)
	if err != nil {
		return Result{}, err
	}
	processes, err := boundedDir(root, 8192)
	if err != nil {
		return Result{}, err
	}
	var owner uint32
	var ownerFD string
	inspected := 0
	for _, entry := range processes {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil || !entry.IsDir() {
			continue
		}
		fds, err := boundedDir(filepath.Join(root, entry.Name(), "fd"), 8192)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			inspected++
			if inspected > 65536 {
				return Result{}, errors.New("process scan limit reached")
			}
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			path := filepath.Join(root, entry.Name(), "fd", fd.Name())
			link, err := os.Readlink(path)
			if err != nil || link != "socket:["+inode+"]" {
				continue
			}
			if owner != 0 && owner != uint32(pid) {
				return Result{}, errors.New("socket shared by multiple processes")
			}
			owner, ownerFD = uint32(pid), path
		}
	}
	if owner == 0 {
		return Result{}, errors.New("socket owner unavailable or access denied")
	}
	base := filepath.Join(root, strconv.FormatUint(uint64(owner), 10))
	before, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return Result{}, err
	}
	token, err := procStart(before)
	if err != nil {
		return Result{}, err
	}
	executable, err := os.Readlink(filepath.Join(base, "exe"))
	if err != nil {
		return Result{}, err
	}
	boot, ticks, err := procBoot(root)
	if err != nil {
		return Result{}, err
	}
	started := boot.Add(time.Duration(token/ticks)*time.Second + time.Duration(token%ticks)*time.Second/time.Duration(ticks))
	if query.ObservedAt.Sub(started) < time.Second/time.Duration(ticks) {
		return Result{}, errors.New("process identity is newer than the observation resolution")
	}
	after, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return Result{}, err
	}
	confirmed, err := procStart(after)
	if err != nil || confirmed != token {
		return Result{}, errors.New("process exited or PID was reused")
	}
	link, err := os.Readlink(ownerFD)
	if err != nil || link != "socket:["+inode+"]" {
		return Result{}, errors.New("socket descriptor was reused")
	}
	current, err := procSocket(ctx, root, query)
	if err != nil || current != inode {
		return Result{}, errors.New("socket endpoint was reused")
	}
	return Result{Status: "matched", PID: owner, Name: filepath.Base(executable), Path: executable, StartedAt: started, Source: "linux_proc_inode_starttime", Reason: fmt.Sprintf("socket inode and process start time validated twice (%s)", query.Protocol)}, nil
}
