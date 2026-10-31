package ping

import (
	"sync"
	"syscall"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type identFilterState struct {
	access     sync.Mutex
	attached   bool
	disabled   bool
	identifier uint16
}

// The kernel clones every matching-protocol packet into every unconnected raw
// ICMP socket, so without a socket filter each flow receives and discards all
// other flows' traffic.
func (c *Conn) updateIdentFilter(wireIdentifier uint16) {
	if !c.privileged {
		return
	}
	syscallConn, isSyscallConn := common.Cast[syscall.Conn](c.conn)
	if !isSyscallConn {
		return
	}
	state := &c.identFilter
	state.access.Lock()
	defer state.access.Unlock()
	if state.disabled {
		return
	}
	if state.attached {
		if state.identifier == wireIdentifier {
			return
		}
		state.attached = false
		state.disabled = true
		_ = control.Conn(syscallConn, func(fd uintptr) error {
			return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DETACH_FILTER, 0)
		})
		return
	}
	rawInstructions, err := identFilterProgram(c.destination.Is6(), wireIdentifier)
	if err != nil {
		state.disabled = true
		return
	}
	filter := make([]unix.SockFilter, len(rawInstructions))
	for i, instruction := range rawInstructions {
		filter[i] = unix.SockFilter{Code: instruction.Op, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K}
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	err = control.Conn(syscallConn, func(fd uintptr) error {
		return unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &program)
	})
	if err != nil {
		state.disabled = true
		return
	}
	state.attached = true
	state.identifier = wireIdentifier
}

func identFilterProgram(is6 bool, wireIdentifier uint16) ([]bpf.RawInstruction, error) {
	if !is6 {
		// Raw ICMPv4 sockets deliver the full packet including the IP header.
		return bpf.Assemble([]bpf.Instruction{
			bpf.LoadMemShift{Off: 0},
			bpf.LoadIndirect{Off: 0, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(header.ICMPv4EchoReply), SkipTrue: 3},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(header.ICMPv4DstUnreachable), SkipTrue: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(header.ICMPv4TimeExceeded), SkipTrue: 3},
			bpf.RetConstant{Val: 0},
			bpf.LoadIndirect{Off: 4, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(wireIdentifier), SkipFalse: 1},
			bpf.RetConstant{Val: 0xffffffff},
			bpf.RetConstant{Val: 0},
		})
	}
	// Raw ICMPv6 sockets deliver the ICMPv6 message without the IP header.
	return bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(header.ICMPv6EchoReply), SkipTrue: 3},
		bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: uint32(header.ICMPv6ParamProblem), SkipTrue: 1},
		bpf.RetConstant{Val: 0xffffffff},
		bpf.RetConstant{Val: 0},
		bpf.LoadAbsolute{Off: 4, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(wireIdentifier), SkipFalse: 1},
		bpf.RetConstant{Val: 0xffffffff},
		bpf.RetConstant{Val: 0},
	})
}
