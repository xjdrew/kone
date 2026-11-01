package desktop

import (
	"context"
	"net"
	"net/rpc"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/logstore"
)

type countedLogCallbacks struct{ batches atomic.Int32 }

func (c *countedLogCallbacks) Logs(LogBatch, *Empty) error {
	c.batches.Add(1)
	return nil
}

func TestHelperPeriodicLogPumpDoesNotCreateOrRepeatUnchangedRecords(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	receiver := new(countedLogCallbacks)
	server := rpc.NewServer()
	require.NoError(t, server.RegisterName("Callbacks", receiver))
	go server.ServeConn(right)
	client := rpc.NewClient(left)
	defer client.Close()
	store := logstore.New()
	store.Append(logstore.Record{Level: "ERROR", Source: "helper", Message: "a real failure remains visible"})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	service := &helperService{ctx: ctx, logForwarder: &helperLogForwarder{store: store, client: client}}
	done := make(chan struct{})
	go func() { defer close(done); service.pumpLogs(ctx) }()
	require.Eventually(t, func() bool { return receiver.batches.Load() == 1 }, time.Second, time.Millisecond)
	time.Sleep(450 * time.Millisecond) // More than two periodic pump intervals.
	cancel()
	<-done
	require.Equal(t, int32(1), receiver.batches.Load())
	logs, err := store.Query(logstore.Query{})
	require.NoError(t, err)
	require.Len(t, logs.Records, 1)
	require.Equal(t, uint64(1), logs.NextCursor)
	require.Equal(t, "ERROR", logs.Records[0].Level)
}
