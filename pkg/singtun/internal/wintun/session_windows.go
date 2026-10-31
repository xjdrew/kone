/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Session struct {
	handle uintptr
}

const (
	PacketSizeMax   = 0xffff    // Maximum packet size
	RingCapacityMin = 0x20000   // Minimum ring capacity (128 kiB)
	RingCapacityMax = 0x4000000 // Maximum ring capacity (64 MiB)
)

// Packet with data
type Packet struct {
	Next *Packet              // Pointer to next packet in queue
	Size uint32               // Size of packet (max WINTUN_MAX_IP_PACKET_SIZE)
	Data *[PacketSizeMax]byte // Pointer to layer 3 IPv4 or IPv6 packet
}

var (
	procWintunAllocateSendPacket   = modwintun.NewProc("WintunAllocateSendPacket")
	procWintunEndSession           = modwintun.NewProc("WintunEndSession")
	procWintunGetReadWaitEvent     = modwintun.NewProc("WintunGetReadWaitEvent")
	procWintunReceivePacket        = modwintun.NewProc("WintunReceivePacket")
	procWintunReleaseReceivePacket = modwintun.NewProc("WintunReleaseReceivePacket")
	procWintunSendPacket           = modwintun.NewProc("WintunSendPacket")
	procWintunStartSession         = modwintun.NewProc("WintunStartSession")
)

func (wintun *Adapter) StartSession(capacity uint32) (session Session, err error) {
	r0, _, e1 := syscall.SyscallN(procWintunStartSession.Addr(), uintptr(wintun.handle), uintptr(capacity))
	if r0 == 0 {
		err = e1
	} else {
		session = Session{r0}
	}
	return
}

func (session Session) End() {
	syscall.SyscallN(procWintunEndSession.Addr(), session.handle)
}

func (session Session) ReadWaitEvent() (handle windows.Handle) {
	r0, _, _ := syscall.SyscallN(procWintunGetReadWaitEvent.Addr(), session.handle)
	handle = windows.Handle(r0)
	return
}

func (session Session) ReceivePacket() (packet []byte, err error) {
	var packetSize uint32
	r0, _, e1 := syscall.SyscallN(procWintunReceivePacket.Addr(), session.handle, uintptr(unsafe.Pointer(&packetSize)))
	if r0 == 0 {
		err = e1
		return
	}
	packet = unsafe.Slice((*byte)(unsafe.Pointer(r0)), packetSize)
	return
}

func (session Session) ReleaseReceivePacket(packet []byte) {
	syscall.SyscallN(procWintunReleaseReceivePacket.Addr(), session.handle, uintptr(unsafe.Pointer(&packet[0])))
}

func (session Session) AllocateSendPacket(packetSize int) (packet []byte, err error) {
	r0, _, e1 := syscall.SyscallN(procWintunAllocateSendPacket.Addr(), session.handle, uintptr(packetSize))
	if r0 == 0 {
		err = e1
		return
	}
	packet = unsafe.Slice((*byte)(unsafe.Pointer(r0)), packetSize)
	return
}

func (session Session) SendPacket(packet []byte) {
	syscall.SyscallN(procWintunSendPacket.Addr(), session.handle, uintptr(unsafe.Pointer(&packet[0])))
}
