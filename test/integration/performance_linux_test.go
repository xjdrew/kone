package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"runtime"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/xjdrew/kone/pkg/kone"
	"golang.org/x/sys/unix"
)

type nativePerformanceSample struct {
	Stack           string  `json:"stack"`
	Protocol        string  `json:"protocol"`
	Mode            string  `json:"mode"`
	GoVersion       string  `json:"go_version"`
	Architecture    string  `json:"architecture"`
	GOMAXPROCS      int     `json:"gomaxprocs"`
	Iterations      int     `json:"iterations"`
	PayloadBytes    int     `json:"payload_bytes_per_direction_per_round"`
	Transferred     int64   `json:"verified_payload_bytes_both_directions"`
	DurationNS      int64   `json:"duration_ns"`
	BytesPerSecond  float64 `json:"payload_bytes_per_second"`
	P50NS           int64   `json:"round_trip_p50_ns"`
	P95NS           int64   `json:"round_trip_p95_ns"`
	P99NS           int64   `json:"round_trip_p99_ns"`
	ProcessUserNS   int64   `json:"process_user_cpu_ns"`
	ProcessSystemNS int64   `json:"process_system_cpu_ns"`
	Queries         uint64  `json:"concurrent_snapshot_queries"`
}

func nativePerformanceDNS(t *testing.T) string {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	ready, done := make(chan struct{}), make(chan struct{})
	server := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, query *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.IPv4(127, 0, 0, 1)}}
		writer.WriteMsg(response)
	})}
	go func() { defer close(done); server.ActivateAndServe() }()
	t.Cleanup(func() { server.Shutdown(); packet.Close(); <-done })
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("performance DNS fixture did not become ready")
	}
	return packet.LocalAddr().String()
}

func nativePerformanceEcho(t *testing.T, ctx context.Context) (string, string) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	tcpDone, udpDone := make(chan struct{}), make(chan struct{})
	deadline, _ := ctx.Deadline()
	go func() {
		defer close(tcpDone)
		for {
			connection, err := tcp.Accept()
			if err != nil {
				return
			}
			connection.SetDeadline(deadline)
			io.Copy(connection, connection)
			connection.Close()
		}
	}()
	go func() {
		defer close(udpDone)
		buffer := make([]byte, 2048)
		udp.SetDeadline(deadline)
		for {
			n, peer, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			if _, err := udp.WriteTo(buffer[:n], peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { tcp.Close(); udp.Close(); <-tcpDone; <-udpDone })
	return tcp.Addr().String(), udp.LocalAddr().String()
}

func nativePerformancePercentile(sorted []int64, fraction float64) int64 {
	index := int(math.Ceil(float64(len(sorted))*fraction)) - 1
	if index < 0 {
		index = 0
	}
	return sorted[index]
}

// Only the existing disposable Linux network-namespace job runs this bounded
// sample. It is a runner baseline with race instrumentation, not a benchmark
// claim about physical links, proxy servers, Raspberry Pi or production load.
func TestSystemPerformanceBaseline(t *testing.T) {
	cfg := systemConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tcpAddress, udpAddress := nativePerformanceEcho(t, ctx)
	cfg.DNS.Servers = []string{nativePerformanceDNS(t)}
	cfg.Outbounds = []kone.OutboundConfig{{Name: "prepare-mapping", URL: "http://" + tcpAddress}}
	cfg.Rule = []kone.RuleConfig{{Schema: "DOMAIN", Pattern: "native-performance.example", Outbound: "prepare-mapping"}, {Schema: "FINAL", Outbound: kone.BuiltinDirect}}
	one, stop, done := systemStart(t, cfg)
	query := new(dns.Msg)
	query.SetQuestion("native-performance.example.", dns.TypeA)
	response, _, err := (&dns.Client{Timeout: time.Second}).ExchangeContext(ctx, query, fmt.Sprintf("10.203.0.1:%d", cfg.DNS.ListenPort))
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	fake := response.Answer[0].(*dns.A).A.String()
	require.Contains(t, fake, "10.203.0.")
	// Retain the application's cached Fake-IP, then select direct for actual
	// business flows. No traffic is sent through the preparation-only outbound.
	cfg.Rule[0].Outbound = kone.BuiltinDirect
	require.NoError(t, one.Reload(cfg))
	var heldUDP []net.Conn
	defer func() {
		for _, connection := range heldUDP {
			connection.Close()
		}
	}()
	for _, mode := range []string{"detailed_recording", "counter_only", "recording_with_queries"} {
		one.TrafficObserver().SetRecording(mode != "counter_only")
		for _, protocol := range []string{"tcp", "udp"} {
			t.Run(mode+"/"+protocol, func(t *testing.T) {
				var queryCount atomic.Uint64
				queryCtx, stopQueries := context.WithCancel(ctx)
				queriesDone := make(chan struct{})
				if mode == "recording_with_queries" {
					queryReady := make(chan struct{})
					go func() {
						defer close(queriesDone)
						ticker := time.NewTicker(5 * time.Millisecond)
						defer ticker.Stop()
						for first := true; ; first = false {
							one.TrafficData(kone.TrafficQuery{Limit: 128}, kone.SankeyOptions{Window: time.Second, Limit: 20})
							queryCount.Add(1)
							if first {
								close(queryReady)
							}
							select {
							case <-queryCtx.Done():
								return
							case <-ticker.C:
							}
						}
					}()
					<-queryReady
				} else {
					close(queriesDone)
				}
				defer func() { stopQueries(); <-queriesDone }()
				address, payloadSize := tcpAddress, 16*1024
				if protocol == "udp" {
					address, payloadSize = udpAddress, 1200
				}
				_, port, err := net.SplitHostPort(address)
				require.NoError(t, err)
				connection, err := (&net.Dialer{}).DialContext(ctx, protocol+"4", net.JoinHostPort(fake, port))
				require.NoError(t, err)
				if protocol == "udp" {
					// Keep the three client ports distinct until all samples end.
					heldUDP = append(heldUDP, connection)
				} else {
					defer connection.Close()
				}
				deadline, _ := ctx.Deadline()
				require.NoError(t, connection.SetDeadline(deadline))
				payload, reply := bytes.Repeat([]byte{0x5a}, payloadSize), make([]byte, payloadSize)
				const iterations, warmup = 128, 4
				latencies := make([]int64, 0, iterations)
				var userBefore, userAfter unix.Rusage
				var begin time.Time
				for round := -warmup; round < iterations; round++ {
					if round == 0 {
						require.NoError(t, unix.Getrusage(unix.RUSAGE_SELF, &userBefore))
						begin = time.Now()
					}
					started := time.Now()
					n, err := connection.Write(payload)
					require.NoError(t, err)
					require.Equal(t, payloadSize, n)
					if protocol == "tcp" {
						n, err = io.ReadFull(connection, reply)
					} else {
						n, err = connection.Read(reply)
					}
					elapsed := time.Since(started).Nanoseconds()
					require.NoError(t, err)
					require.Equal(t, payloadSize, n)
					require.Equal(t, payload, reply, "payload corruption cannot be reported as throughput")
					if round >= 0 {
						latencies = append(latencies, elapsed)
					}
				}
				duration := time.Since(begin)
				require.NoError(t, unix.Getrusage(unix.RUSAGE_SELF, &userAfter))
				stopQueries()
				<-queriesDone
				sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
				transferred := int64(iterations * payloadSize * 2)
				sample := nativePerformanceSample{Stack: cfg.Core.Stack, Protocol: protocol, Mode: mode, GoVersion: runtime.Version(), Architecture: runtime.GOARCH, GOMAXPROCS: runtime.GOMAXPROCS(0), Iterations: iterations, PayloadBytes: payloadSize, Transferred: transferred, DurationNS: duration.Nanoseconds(), BytesPerSecond: float64(transferred) / duration.Seconds(), P50NS: nativePerformancePercentile(latencies, .5), P95NS: nativePerformancePercentile(latencies, .95), P99NS: nativePerformancePercentile(latencies, .99), ProcessUserNS: userAfter.Utime.Nano() - userBefore.Utime.Nano(), ProcessSystemNS: userAfter.Stime.Nano() - userBefore.Stime.Nano(), Queries: queryCount.Load()}
				encoded, err := json.Marshal(sample)
				require.NoError(t, err)
				t.Log("KONE_NATIVE_PERFORMANCE " + string(encoded))
			})
		}
	}
	stop()
	require.NoError(t, systemWait(t, done))
	noSystemInterface(t, cfg)
}
