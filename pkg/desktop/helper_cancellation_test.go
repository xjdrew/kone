package desktop

import (
	"context"
	"net"
	"net/rpc"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
)

type blockedDeviceCallbacks struct {
	entered chan struct{}
	release <-chan struct{}
}

func (c *blockedDeviceCallbacks) Device(DeviceIdentity, *Empty) error {
	close(c.entered)
	<-c.release
	return nil
}
func (*blockedDeviceCallbacks) Finished(FinishedEvent, *Empty) error { return nil }

func TestHelperCancellationDoesNotWaitForDeviceAcknowledgement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, right := net.Pipe()
		defer right.Close()
		release := make(chan struct{})
		defer close(release)
		callbacks := &blockedDeviceCallbacks{entered: make(chan struct{}), release: release}
		server := rpc.NewServer()
		require.NoError(t, server.RegisterName("Callbacks", callbacks))
		go server.ServeConn(right)
		client := rpc.NewClient(left)
		defer client.Close()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		fake := newFakeNetworkEngine(t, kone.DefaultConfig())
		service := &helperService{ctx: ctx, events: client, factory: func(*kone.KoneConfig) (NetworkEngine, error) { return fake, nil }}
		done := make(chan error, 1)
		go func() {
			done <- service.Start(StartRequest{TOML: []byte("[dns]\nservers=['127.0.0.1:5353']\n"), Version: 1}, &Empty{})
		}()
		<-callbacks.entered
		cancel()
		require.ErrorContains(t, <-done, context.Canceled.Error())
		<-fake.done
		synctest.Wait()
		select {
		case <-fake.Ready():
			t.Fatal("helper became ready before durable device acknowledgement")
		default:
		}
		select {
		case <-fake.stop:
		default:
			t.Fatal("canceled startup did not close its engine")
		}
	})
}

type delayedExitEngine struct {
	*fakeNetworkEngine
	returning chan struct{}
	release   <-chan struct{}
}

func (e *delayedExitEngine) Run(ctx context.Context) error {
	err := e.fakeNetworkEngine.Run(ctx)
	close(e.returning)
	<-e.release // Model terminal log emission after device cleanup has finished.
	return err
}

func TestHelperStopWaitsForRunFinalizationBeforeAcknowledgingCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, right := net.Pipe()
		defer right.Close()
		acknowledge := make(chan struct{})
		close(acknowledge)
		server := rpc.NewServer()
		require.NoError(t, server.RegisterName("Callbacks", &blockedDeviceCallbacks{entered: make(chan struct{}), release: acknowledge}))
		go server.ServeConn(right)
		client := rpc.NewClient(left)
		defer client.Close()
		release := make(chan struct{})
		finish := sync.OnceFunc(func() { close(release) })
		defer finish()
		engine := &delayedExitEngine{fakeNetworkEngine: newFakeNetworkEngine(t, kone.DefaultConfig()), returning: make(chan struct{}), release: release}
		service := &helperService{ctx: t.Context(), events: client, factory: func(*kone.KoneConfig) (NetworkEngine, error) { return engine, nil }}
		require.NoError(t, service.Start(StartRequest{TOML: []byte("[dns]\nservers=['127.0.0.1:5353']\n"), Version: 1}, &Empty{}))
		stopped := make(chan error, 1)
		go func() { stopped <- service.Stop(Empty{}, &StopReply{}) }()
		<-engine.returning
		synctest.Wait()
		select {
		case err := <-stopped:
			t.Fatalf("Stop acknowledged cleanup before Run finalized: %v", err)
		default:
		}
		finish()
		require.NoError(t, <-stopped)
		synctest.Wait()
	})
}
