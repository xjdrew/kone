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
	if !ip.Is4() || !pool.base.IsValid() || ip.Compare(pool.base) < 0 {
		return 0, false
	}
	raw, base := ip.As4(), pool.base.As4()
	index := binary.BigEndian.Uint32(raw[:]) - binary.BigEndian.Uint32(base[:])
	return index, uint64(index) < uint64(len(pool.flags))
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
	raw := pool.base.As4()
	binary.BigEndian.PutUint32(raw[:], binary.BigEndian.Uint32(raw[:])+uint32(index))
	return netip.AddrFrom4(raw)
}

func NewDnsIPPool(prefix netip.Prefix) *DnsIPPool {
	pool := new(DnsIPPool)
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() > 30 {
		return pool
	}
	pool.base = prefix.Masked().Addr().Next()
	space := (uint64(1) << (32 - prefix.Bits())) - 2
	if space > DnsIPPoolMaxSpace {
		space = DnsIPPoolMaxSpace
	}
	pool.flags = make([]bool, int(space))
	pool.reserve(prefix.Addr())
	return pool
}
