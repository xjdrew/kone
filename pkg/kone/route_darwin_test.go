package kone

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// RTM_GET and RIB reads only inspect kernel state. This verifies the real
// socket/acknowledgement ABI as an ordinary macOS user without adding routes,
// creating a TUN, contacting a host, or changing DNS.
func TestDarwinNativeRoutingSocketReadOnly(t *testing.T) {
	r := newDarwinRoutes()
	messages, err := r.read()
	require.NoError(t, err)
	require.NotEmpty(t, messages)
	addresses := make([]route.Addr, unix.RTAX_MAX)
	addresses[unix.RTAX_DST] = &route.Inet4Addr{IP: [4]byte{127, 0, 0, 1}}
	addresses[unix.RTAX_IFP] = &route.LinkAddr{}
	request := &route.RouteMessage{Version: unix.RTM_VERSION, Type: unix.RTM_GET, Flags: unix.RTF_UP | unix.RTF_HOST, ID: uintptr(os.Getpid()), Seq: int(darwinRouteSequence.Add(1)), Addrs: addresses}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sent, response, err := exchangeDarwinRoute(ctx, request)
	require.NoError(t, err)
	require.True(t, sent)
	require.Equal(t, request.Seq, response.Seq)
	require.Equal(t, request.ID, response.ID)
	require.Positive(t, response.Index, "loopback route must identify an actual local interface")
}

func testDarwinRouteTable() (darwinRoutes, *[]route.Message, *[]int) {
	var messages []route.Message
	var operations []int
	r := darwinRoutes{
		interfaceByName: func(name string) (*net.Interface, error) { return &net.Interface{Name: name, Index: 7}, nil },
		read:            func() ([]route.Message, error) { return messages, nil },
		exchange: func(_ context.Context, request *route.RouteMessage) (bool, *route.RouteMessage, error) {
			operations = append(operations, request.Type)
			if request.Type == unix.RTM_ADD {
				copy := *request
				copy.Index = 7
				messages = []route.Message{&copy}
			} else {
				messages = nil
			}
			return true, request, nil
		},
	}
	return r, &messages, &operations
}

func TestDarwinKernelRouteOwnershipAndIdempotentCleanup(t *testing.T) {
	r, _, operations := testDarwinRouteTable()
	_, subnet, _ := net.ParseCIDR("198.18.99.0/24")
	cleanup, err := r.AddRoute(context.Background(), newMemoryDevice(), subnet)
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	require.Equal(t, []int{unix.RTM_ADD}, *operations)
	require.NoError(t, cleanup(context.Background()))
	require.NoError(t, cleanup(context.Background()))
	require.Equal(t, []int{unix.RTM_ADD, unix.RTM_DELETE}, *operations)
}

func TestDarwinExistingForeignRouteIsNeverClaimed(t *testing.T) {
	r, messages, operations := testDarwinRouteTable()
	prefix := netip.MustParsePrefix("198.18.99.0/24")
	foreign := darwinRouteMessage(unix.RTM_GET, prefix, &net.Interface{Name: "lo0", Index: 1})
	foreign.Index = 1
	*messages = []route.Message{foreign}
	_, subnet, _ := net.ParseCIDR(prefix.String())
	cleanup, err := r.AddRoute(context.Background(), newMemoryDevice(), subnet)
	require.ErrorIs(t, err, unix.EEXIST)
	require.Nil(t, cleanup)
	require.Empty(t, *operations)
	// A race after the inspection can also report EEXIST in the kernel ACK.
	*messages = nil
	r.exchange = func(context.Context, *route.RouteMessage) (bool, *route.RouteMessage, error) {
		return false, nil, unix.EEXIST
	}
	cleanup, err = r.AddRoute(context.Background(), newMemoryDevice(), subnet)
	require.ErrorIs(t, err, unix.EEXIST)
	require.Nil(t, cleanup)
}

func TestDarwinRouteCleanupRefusesReplacement(t *testing.T) {
	for _, change := range []string{"interface", "gateway", "scope", "nonstatic", "device-reused"} {
		t.Run(change, func(t *testing.T) {
			r, messages, operations := testDarwinRouteTable()
			currentIndex := 7
			r.interfaceByName = func(name string) (*net.Interface, error) { return &net.Interface{Name: name, Index: currentIndex}, nil }
			_, subnet, _ := net.ParseCIDR("198.18.99.0/24")
			cleanup, err := r.AddRoute(context.Background(), newMemoryDevice(), subnet)
			require.NoError(t, err)
			message := (*messages)[0].(*route.RouteMessage)
			switch change {
			case "interface":
				message.Index = 1
			case "gateway":
				message.Addrs[unix.RTAX_GATEWAY] = &route.Inet4Addr{IP: [4]byte{192, 0, 2, 1}}
			case "scope":
				message.Flags |= unix.RTF_IFSCOPE
			case "nonstatic":
				message.Flags &^= unix.RTF_STATIC
			case "device-reused":
				currentIndex = 9
			}
			if change == "device-reused" {
				require.ErrorContains(t, cleanup(context.Background()), "identity")
			} else {
				require.ErrorContains(t, cleanup(context.Background()), "ownership")
			}
			require.Equal(t, []int{unix.RTM_ADD}, *operations)
		})
	}
}

func TestDarwinRouteCancellationAfterCommitKeepsRollback(t *testing.T) {
	r, _, operations := testDarwinRouteTable()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exchange := r.exchange
	r.exchange = func(ctx context.Context, message *route.RouteMessage) (bool, *route.RouteMessage, error) {
		sent, response, err := exchange(ctx, message)
		cancel()
		return sent, response, err
	}
	_, subnet, _ := net.ParseCIDR("198.18.99.0/24")
	cleanup, err := r.AddRoute(ctx, newMemoryDevice(), subnet)
	require.ErrorIs(t, err, context.Canceled)
	require.NotNil(t, cleanup)
	require.NoError(t, cleanup(context.Background()))
	require.Equal(t, []int{unix.RTM_ADD, unix.RTM_DELETE}, *operations)
}

func TestDarwinLostAcknowledgementRetainsOnlyVerifiedCleanup(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(map[bool]string{false: "not-applied", true: "applied"}[applied], func(t *testing.T) {
			r, messages, _ := testDarwinRouteTable()
			r.exchange = func(_ context.Context, message *route.RouteMessage) (bool, *route.RouteMessage, error) {
				if applied {
					copy := *message
					copy.Index = 7
					*messages = []route.Message{&copy}
				}
				return true, nil, context.DeadlineExceeded
			}
			_, subnet, _ := net.ParseCIDR("198.18.99.0/24")
			cleanup, err := r.AddRoute(context.Background(), newMemoryDevice(), subnet)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			if applied {
				require.NotNil(t, cleanup, "a confirmed self-owned change must still be rolled back")
			} else {
				require.Nil(t, cleanup, "a lost acknowledgement cannot authorize deleting a foreign resource")
			}
		})
	}
}

func TestDarwinAddressCreatedRouteUsesDeviceLifecycle(t *testing.T) {
	r, messages, operations := testDarwinRouteTable()
	prefix := netip.MustParsePrefix("198.18.99.0/24")
	message := darwinRouteMessage(unix.RTM_GET, prefix, &net.Interface{Name: "kone-test", Index: 7})
	message.Index = 7
	message.Flags &^= unix.RTF_STATIC
	*messages = []route.Message{message}
	_, subnet, _ := net.ParseCIDR(prefix.String())
	cleanup, err := r.AddRoute(context.Background(), newMemoryDevice(), subnet)
	require.NoError(t, err)
	require.Nil(t, cleanup)
	require.Empty(t, *operations)
}

type testDarwinRouteSocket struct {
	written func([]byte) (int, error)
	read    func([]byte) (int, error)
}

func (s testDarwinRouteSocket) Write(data []byte) (int, error) {
	if s.written != nil {
		return s.written(data)
	}
	return len(data), nil
}
func (s testDarwinRouteSocket) Read(data []byte) (int, error) { return s.read(data) }
func (s testDarwinRouteSocket) Close() error                  { return nil }

func darwinTestACK(t *testing.T, message *route.RouteMessage, errno unix.Errno) []byte {
	t.Helper()
	data, err := message.Marshal()
	require.NoError(t, err)
	// rt_msghdr.rtm_errno at byte 28 is part of Darwin's public routing ABI.
	binary.NativeEndian.PutUint32(data[28:32], uint32(errno))
	return data
}

func TestDarwinRouteAcknowledgementMatchesEpochAndError(t *testing.T) {
	request := darwinRouteMessage(unix.RTM_ADD, netip.MustParsePrefix("198.18.99.0/24"), &net.Interface{Name: "utun7", Index: 7})
	for _, errno := range []unix.Errno{0, unix.EEXIST, unix.EPERM} {
		t.Run(errno.Error(), func(t *testing.T) {
			other := *request
			other.Seq++
			data := append(darwinTestACK(t, &other, 0), darwinTestACK(t, request, errno)...)
			socket := testDarwinRouteSocket{read: func(buffer []byte) (int, error) { return copy(buffer, data), nil }}
			sent, response, err := transactDarwinRoute(context.Background(), socket, request, func(context.Context) error { return nil })
			require.NotNil(t, response)
			if errno == 0 {
				require.True(t, sent)
				require.NoError(t, err)
			} else {
				require.False(t, sent, "a kernel rejection confirms that no change was applied")
				require.ErrorIs(t, err, errno)
			}
		})
	}
}

func TestDarwinRouteAcknowledgementCancellationAndIO(t *testing.T) {
	request := darwinRouteMessage(unix.RTM_ADD, netip.MustParsePrefix("198.18.99.0/24"), &net.Interface{Name: "utun7", Index: 7})
	ack := darwinTestACK(t, request, 0)
	for _, fault := range []string{"write", "short-write", "read", "eof", "malformed", "wait", "cancel-before", "cancel-after", "interrupted"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads := 0
			socket := testDarwinRouteSocket{read: func(buffer []byte) (int, error) {
				reads++
				switch fault {
				case "read":
					return 0, unix.EBADF
				case "eof":
					return 0, nil
				case "malformed":
					return copy(buffer, []byte{255, 255, 5, 1, 0}), nil
				case "interrupted":
					if reads == 1 {
						return 0, unix.EINTR
					}
				}
				return copy(buffer, ack), nil
			}}
			socket.written = func(data []byte) (int, error) {
				if fault == "write" {
					return 0, unix.EEXIST
				}
				if fault == "short-write" {
					return len(data) - 1, nil
				}
				if fault == "cancel-after" {
					cancel()
				}
				return len(data), nil
			}
			if fault == "cancel-before" {
				cancel()
			}
			sent, _, err := transactDarwinRoute(ctx, socket, request, func(ackContext context.Context) error {
				require.NoError(t, ackContext.Err(), "a sent operation must obtain its ACK even after caller cancellation")
				if fault == "wait" {
					return context.DeadlineExceeded
				}
				return nil
			})
			if fault == "cancel-after" || fault == "interrupted" {
				require.NoError(t, err)
				require.True(t, sent)
			} else {
				require.Error(t, err)
				if fault == "write" || fault == "cancel-before" {
					require.False(t, sent)
				} else {
					require.True(t, sent)
				}
				if fault == "short-write" {
					require.ErrorIs(t, err, io.ErrShortWrite)
				}
				if fault == "cancel-before" {
					require.True(t, errors.Is(err, context.Canceled))
				}
			}
		})
	}
}
