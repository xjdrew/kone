package integration

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/desktop"
	"github.com/xjdrew/kone/pkg/kone"
)

func TestUDPDiagnosticEvidenceAndProgressCrossPrivateRPC(t *testing.T) {
	// Exercise actual loopback UDP/DNS and both private RPC channels. Only the
	// capture run loop is replaced, so no TUN, elevation or OS changes occur.
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	responseDone := make(chan struct{})
	go func() {
		defer close(responseDone)
		buffer := make([]byte, 4096)
		n, peer, err := packet.ReadFrom(buffer)
		if err != nil {
			return
		}
		query := new(dns.Msg)
		if query.Unpack(buffer[:n]) != nil {
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Rcode, reply.Truncated = dns.RcodeRefused, true
		data, _ := reply.Pack()
		_, _ = packet.WriteTo(data, peer)
	}()
	t.Cleanup(func() { packet.Close(); <-responseDone })
	cfg := kone.DefaultConfig()
	cfg.DNS.Servers = []string{"127.0.0.1:9"}
	commandsParent, commandsHelper := net.Pipe()
	eventsParent, eventsHelper := net.Pipe()
	helperDone := make(chan error, 1)
	go func() {
		helperDone <- desktop.ServeHelper(t.Context(), commandsHelper, eventsHelper, func(cfg *kone.KoneConfig) (desktop.NetworkEngine, error) {
			one, err := kone.FromConfig(cfg)
			if err != nil {
				return nil, err
			}
			return &probeOnlyHelperEngine{One: one, ready: make(chan struct{}), stop: make(chan struct{})}, nil
		})
	}()
	remote, err := desktop.NewRemote(cfg, func(context.Context) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
		return commandsParent, eventsParent, nil
	})
	require.NoError(t, err)
	t.Cleanup(func() { remote.Close(); commandsParent.Close(); eventsParent.Close() })
	running := make(chan error, 1)
	go func() { running <- remote.Run(t.Context()) }()
	select {
	case <-remote.Ready():
	case err := <-running:
		t.Fatalf("helper startup: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("helper startup timed out")
	}
	var progress []kone.DiagnosticResult
	ctx := kone.WithDiagnosticProgress(t.Context(), func(value kone.DiagnosticResult) { progress = append(progress, value) })
	result, err := remote.ProbeDiagnosticRequestVersion(ctx, kone.BuiltinDirect, packet.LocalAddr().String(), kone.DiagnosticOptions{Protocol: "udp", DNSName: "private-rpc.invalid", DNSType: "AAAA"}, 1)
	require.NoError(t, err)
	require.Equal(t, "udp", result.Protocol)
	require.Equal(t, "reachable", result.Status)
	require.Equal(t, "REFUSED", result.DNSRCode)
	require.True(t, result.DNSTruncated)
	require.Equal(t, "validated_dns_response", result.Protocols.UDP.Evidence)
	require.True(t, result.Protocols.UDP.Tested)
	require.False(t, result.Protocols.TCP.Tested)
	require.False(t, result.Protocols.TLS.Tested)
	require.Nil(t, result.ConnectLatencyMS)
	require.Equal(t, "complete", result.Progress.Stage)
	require.NotEmpty(t, progress)
	require.Equal(t, "udp", progress[0].Protocol)
	require.False(t, progress[0].Protocols.UDP.Tested, "the first progress event cannot contain later response evidence")
	require.NoError(t, remote.Close())
	require.NoError(t, <-running)
	select {
	case err := <-helperDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("helper did not release IPC after the UDP diagnostic")
	}
}
