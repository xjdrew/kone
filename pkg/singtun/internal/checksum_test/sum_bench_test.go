package checksum_test

import (
	"crypto/rand"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/internal/tschecksum"
)

func BenchmarkTsChecksum(b *testing.B) {
	packet := make([][]byte, 1000)
	for i := range 1000 {
		packet[i] = make([]byte, 1500)
		rand.Read(packet[i])
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tschecksum.Checksum(packet[i%1000], 0)
	}
}

func BenchmarkGChecksum(b *testing.B) {
	packet := make([][]byte, 1000)
	for i := range 1000 {
		packet[i] = make([]byte, 1500)
		rand.Read(packet[i])
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checksum.ChecksumDefault(packet[i%1000], 0)
	}
}
