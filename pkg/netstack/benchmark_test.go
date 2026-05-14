// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

// Benchmarks for the full data path: openvpn.Client.Tunnel() →
// gVisor netstack (TCP/UDP socket) → socat echo on 10.8.0.1:8080.
//
// What we measure on top of the pure-tunnel path:
//
//	[user] -> gonet write -> gVisor TCP/UDP stack -> link endpoint ->
//	openvpn AEAD seal -> wire -> server tun0 -> socat -> back ->
//	openvpn AEAD open -> link endpoint -> gVisor TCP/UDP -> gonet read -> [user]
//
// Compare BenchmarkNetstackUDPEcho with test/integration/BenchmarkTunnelUDPEchoRoundtrip
// (same socat UDP echo target, same on-wire cipher) — the delta is purely
// what gVisor + gonet cost. TCP benchmarks add ACK/window-scaling overhead.
//
// Run via:
//
//	cd test/integration && make up && make wait
//	cd ../../pkg/netstack && go test -tags=integration -bench=. -benchmem \
//	    -run=^$ -benchtime=3s -timeout=300s ./...
package netstack

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn"
)

// benchPayloadSizes mirrors the pure-tunnel suite so results line up
// size-for-size when comparing.
var benchPayloadSizes = []int{64, 512, 1400}

// benchTCPStreamChunk is the per-Write chunk size for the pipelined stream
// bench. Picked at ~near-MSS so each write fits comfortably in one TCP
// segment (1400 user bytes + TCP/IP headers stays under typical 1500 MTU
// of OpenVPN's tun once the AEAD overhead is added).
const benchTCPStreamChunk = 1400

func dialBenchVPN(b *testing.B) *openvpn.Client {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cli, err := openvpn.Dial(ctx, &openvpn.Config{
		Network:    "udp",
		RemoteAddr: serverAddr,
		TLSConfig:  loadTLSConfig(b),
		TLSCryptV1: loadTLSCrypt(b),
	})
	if err != nil {
		b.Fatalf("openvpn Dial: %v", err)
	}
	return cli
}

func newBenchNetstack(b *testing.B, cli *openvpn.Client) *Net {
	b.Helper()
	ns, err := New(cli)
	if err != nil {
		b.Fatalf("netstack.New: %v", err)
	}
	return ns
}

// BenchmarkNetstackTCPEcho measures synchronous request/response (Ping-Pong)
// throughput through a single TCP connection. Each iteration: Write payload,
// ReadFull(payload-size) back. Reports MB/s based on one-way payload.
func BenchmarkNetstackTCPEcho(b *testing.B) {
	cli := dialBenchVPN(b)
	defer cli.Close()
	ns := newBenchNetstack(b, cli)
	defer ns.Close()

	for _, size := range benchPayloadSizes {
		size := size
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			conn, err := ns.DialContext(ctx, "tcp", echoAddr)
			if err != nil {
				b.Fatalf("DialContext: %v", err)
			}
			defer conn.Close()

			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i)
			}
			rbuf := make([]byte, size)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				if _, err := conn.Write(payload); err != nil {
					b.Fatalf("iter %d: write: %v", i, err)
				}
				if _, err := io.ReadFull(conn, rbuf); err != nil {
					b.Fatalf("iter %d: read: %v", i, err)
				}
			}
		})
	}
}

// BenchmarkNetstackTCPStream measures pipelined unidirectional throughput.
// One goroutine writes a fixed-size chunk b.N times; another drains the
// echo'd bytes. Final synchronisation waits for both halves to complete.
// This is the "iperf-like" number — bandwidth bound, not latency bound.
func BenchmarkNetstackTCPStream(b *testing.B) {
	cli := dialBenchVPN(b)
	defer cli.Close()
	ns := newBenchNetstack(b, cli)
	defer ns.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := ns.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		b.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	chunk := make([]byte, benchTCPStreamChunk)
	for i := range chunk {
		chunk[i] = byte(i)
	}

	b.SetBytes(int64(benchTCPStreamChunk))
	b.ReportAllocs()
	b.ResetTimer()

	total := int64(b.N) * int64(benchTCPStreamChunk)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rbuf := make([]byte, 32*1024)
		var read int64
		for read < total {
			n, err := conn.Read(rbuf)
			if n > 0 {
				read += int64(n)
			}
			if err != nil {
				if read < total {
					b.Errorf("read: %v (got %d of %d)", err, read, total)
				}
				return
			}
		}
	}()

	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(chunk); err != nil {
			b.Fatalf("iter %d: write: %v", i, err)
		}
	}
	wg.Wait()
}

// BenchmarkNetstackUDPEcho measures synchronous UDP echo via gVisor. Sized
// to line up 1:1 with BenchmarkTunnelUDPEchoRoundtrip — the difference is
// the gVisor UDP socket layer on top of the same on-wire crypto.
//
// gVisor's UDP socket has no in-flight backlog of its own (each Read returns
// one datagram), so request/response lockstep is the natural shape.
func BenchmarkNetstackUDPEcho(b *testing.B) {
	cli := dialBenchVPN(b)
	defer cli.Close()
	ns := newBenchNetstack(b, cli)
	defer ns.Close()

	if !ns.HasIPv4() {
		b.Skip("no IPv4 on tunnel — UDP bench needs v4 to reach the in-container echo")
	}

	for _, size := range benchPayloadSizes {
		size := size
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			conn, err := ns.DialContext(ctx, "udp", echoAddr)
			if err != nil {
				b.Fatalf("DialContext udp: %v", err)
			}
			defer conn.Close()

			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i)
			}
			rbuf := make([]byte, size+64)

			// Warmup: pay any one-time route-lookup / endpoint-init cost.
			if _, err := conn.Write(payload); err != nil {
				b.Fatalf("warmup write: %v", err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Read(rbuf); err != nil {
				b.Fatalf("warmup read: %v", err)
			}
			_ = conn.SetReadDeadline(time.Time{})

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				if _, err := conn.Write(payload); err != nil {
					b.Fatalf("iter %d: write: %v", i, err)
				}
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				if _, err := conn.Read(rbuf); err != nil {
					b.Fatalf("iter %d: read: %v", i, err)
				}
			}
		})
	}
}
