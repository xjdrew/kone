package process

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWindowsOwnerTableRequiresExactTupleAndUniquePID(t *testing.T) {
	query := testQuery(time.Now())
	data := make([]byte, 28)
	binary.LittleEndian.PutUint32(data, 1)
	binary.LittleEndian.PutUint32(data[4:], 5)
	local, remote := query.Source.Addr().As4(), query.Destination.Addr().As4()
	copy(data[8:12], local[:])
	binary.BigEndian.PutUint16(data[12:14], query.Source.Port())
	copy(data[16:20], remote[:])
	binary.BigEndian.PutUint16(data[20:22], query.Destination.Port())
	binary.LittleEndian.PutUint32(data[24:], 42)
	pid, err := windowsSocketOwner(data, query)
	require.NoError(t, err)
	require.Equal(t, uint32(42), pid)
	query.Destination = netip.AddrPortFrom(query.Destination.Addr(), 80)
	_, err = windowsSocketOwner(data, query)
	require.Error(t, err)
	query.Protocol = "udp"
	data = make([]byte, 28)
	binary.LittleEndian.PutUint32(data, 2)
	binary.BigEndian.PutUint16(data[8:10], query.Source.Port())
	binary.LittleEndian.PutUint32(data[12:16], 42)
	binary.BigEndian.PutUint16(data[20:22], query.Source.Port())
	binary.LittleEndian.PutUint32(data[24:28], 43)
	_, err = windowsSocketOwner(data, query)
	require.ErrorContains(t, err, "ambiguous")
	_, err = windowsSocketOwner(data[:6], query)
	require.Error(t, err)
	_, err = windowsSocketOwner(nil, query)
	require.Error(t, err)
}
