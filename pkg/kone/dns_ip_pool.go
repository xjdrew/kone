package kone

import (
	"encoding/binary"
	"hash/adler32"
	"net/netip"
)

const DnsIPPoolMaxSpace = 0x3ffff

// The pool stores immutable addresses. Only the DNS table, under its record
// lock, allocates or releases them; network/broadcast/owned addresses stay out.
type DnsIPPool struct {
	base  netip.Addr
	flags []bool
}

func (pool *DnsIPPool) index(ip netip.Addr) (uint32, bool) {
	ip = ip.Unmap()
	if !ip.IsValid() || !pool.base.IsValid() || ip.Is4() != pool.base.Is4() || ip.Compare(pool.base) < 0 {
		return 0, false
	}
	var index uint64
	if ip.Is4() {
		raw, base := ip.As4(), pool.base.As4()
		index = uint64(binary.BigEndian.Uint32(raw[:]) - binary.BigEndian.Uint32(base[:]))
	} else {
		raw, base := ip.As16(), pool.base.As16()
		if binary.BigEndian.Uint64(raw[:8]) != binary.BigEndian.Uint64(base[:8]) {
			return 0, false
		}
		index = binary.BigEndian.Uint64(raw[8:]) - binary.BigEndian.Uint64(base[8:])
	}
	return uint32(index), index < uint64(len(pool.flags))
}

func (pool *DnsIPPool) reserve(ip netip.Addr) {
	if index, ok := pool.index(ip); ok {
		pool.flags[index] = true
	}
}
func (pool *DnsIPPool) Capacity() int { return len(pool.flags) }
func (pool *DnsIPPool) Contains(ip netip.Addr) bool {
	_, ok := pool.index(ip)
	return ok
}
func (pool *DnsIPPool) Release(ip netip.Addr) {
	if index, ok := pool.index(ip); ok {
		pool.flags[index] = false
	}
}

func (pool *DnsIPPool) Alloc(hint string) netip.Addr {
	if len(pool.flags) == 0 {
		return netip.Addr{}
	}
	index := int(adler32.Checksum([]byte(hint)) % uint32(len(pool.flags)))
	if pool.flags[index] {
		index = -1
		for i, used := range pool.flags {
			if !used {
				index = i
				break
			}
		}
		if index < 0 {
			return netip.Addr{}
		}
	}
	pool.flags[index] = true
	if pool.base.Is4() {
		raw := pool.base.As4()
		binary.BigEndian.PutUint32(raw[:], binary.BigEndian.Uint32(raw[:])+uint32(index))
		return netip.AddrFrom4(raw)
	}
	raw := pool.base.As16()
	binary.BigEndian.PutUint64(raw[8:], binary.BigEndian.Uint64(raw[8:])+uint64(index))
	return netip.AddrFrom16(raw)
}

func NewDnsIPPool(prefix netip.Prefix) *DnsIPPool {
	pool := new(DnsIPPool)
	if !prefix.IsValid() || prefix.Addr().Is4() && prefix.Bits() > 30 || prefix.Addr().Is6() && (!prefix.Addr().IsPrivate() || prefix.Bits() < 64 || prefix.Bits() > 120) {
		return pool
	}
	pool.base = prefix.Masked().Addr().Next()
	space := uint64(DnsIPPoolMaxSpace)
	if prefix.Addr().Is4() {
		space = (uint64(1) << (32 - prefix.Bits())) - 2
	} else if 128-prefix.Bits() < 18 {
		space = (uint64(1) << (128 - prefix.Bits())) - 1
	}
	if space > DnsIPPoolMaxSpace {
		space = DnsIPPoolMaxSpace
	}
	pool.flags = make([]bool, int(space))
	pool.reserve(prefix.Addr())
	return pool
}
