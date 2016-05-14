//
//   date  : 2016-05-13
//   author: xjdrew
//

package tcpip

var (
	zeroChecksum = [2]byte{0x00, 0x00}
)

func Sum(b []byte) uint32 {
	var sum uint32

	n := len(b)
	for i := 0; i < n; i = i + 2 {
		sum += (uint32(b[i]) << 8)
		if i+1 < n {
			sum += uint32(b[i+1])
		}
	}
	return sum
}

// checksum for Internet Protocol family headers
func Checksum(sum uint32, b []byte) (answer [2]byte) {
	sum += Sum(b)
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	sum = ^sum
	answer[0] = byte(sum >> 8)
	answer[1] = byte(sum)
	return
}
