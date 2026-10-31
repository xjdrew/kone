package tcpip

import (
	"encoding/binary"
	"testing"
)

func testPacket(protocol IPProtocol, payloadLen int) []byte {
	p := make([]byte, 20+payloadLen)
	p[0] = 0x45
	p[9] = byte(protocol)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	if protocol == TCP && payloadLen >= 20 {
		p[32] = 0x50
	}
	if protocol == UDP && payloadLen >= 8 {
		binary.BigEndian.PutUint16(p[24:26], uint16(payloadLen))
	}
	return p
}

func TestParseIPv4RejectsMalformedPackets(t *testing.T) {
	cases := [][]byte{nil, {}, {0x45}, make([]byte, 19), testPacket(TCP, 19), testPacket(UDP, 7), testPacket(ICMP, 7)}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[0] = 0x44 }, func(p []byte) { p[0] = 0x4f },
		func(p []byte) { p[2] = 0xff }, func(p []byte) { p[3] = 19 },
		func(p []byte) { p[6] = 0x20 }, func(p []byte) { p[7] = 1 },
		func(p []byte) { p[32] = 0x40 }, func(p []byte) { p[32] = 0xf0 },
	} {
		p := testPacket(TCP, 20)
		mutate(p)
		cases = append(cases, p)
	}
	u := testPacket(UDP, 8)
	u[25] = 7
	cases = append(cases, u)
	for i, p := range cases {
		if _, err := ParseIPv4(p); err == nil {
			t.Errorf("case %d accepted malformed packet", i)
		}
	}
	if IsIPv4(nil) || IsIPv6(nil) {
		t.Fatal("empty packet has an IP version")
	}
}

func TestParseIPv4ValidPackets(t *testing.T) {
	for _, tc := range []struct {
		protocol IPProtocol
		size     int
	}{{TCP, 20}, {UDP, 8}, {ICMP, 8}} {
		p := testPacket(tc.protocol, tc.size)
		p[6] = 0x40 // don't-fragment is supported
		got, err := ParseIPv4(append(p, 0, 0))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(p) || len(got.Payload()) != tc.size {
			t.Fatal("incorrect packet bounds")
		}
	}
}

func FuzzParseIPv4(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x45})
	f.Add(testPacket(TCP, 20))
	f.Add(testPacket(UDP, 8))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParseIPv4(data)
		if err != nil {
			return
		}
		p.SourceIP()
		p.DestinationIP()
		p.Protocol()
		p.Payload()
		p.ResetChecksum()
	})
}
