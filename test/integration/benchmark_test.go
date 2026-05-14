// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

// Benchmarks for the *pure* go-openvpn data path: raw IPv4+UDP packets are
// fed directly into Client.Tunnel().Write (no gVisor, no userspace stack).
// The target is the in-container socat UDP echo on 10.8.0.1:8080 (see
// entrypoint.sh). What we measure end-to-end:
//
//	[user] -> AEAD seal -> reliable framing -> transport UDP write ->
//	[kernel: route to tun0 of server] -> [socat UDP echo PIPE] ->
//	[kernel: send back via tun0] -> transport UDP read -> AEAD open ->
//	Tunnel().Read -> [user]
//
// Compare against the netstack benchmarks (pkg/netstack/benchmark_test.go)
// to isolate gVisor's TCP/UDP overhead — the UDP echo sub-benchmarks on
// both sides target the same socat, so the delta is purely gVisor.
//
// Run via the integration Makefile (`make bench`) or directly:
//
//	cd test/integration && make up && make wait
//	cd ../.. && go test -tags=integration -bench=. -benchmem \
//	    -run=^$ -benchtime=3s -timeout=300s ./test/integration/...
package integration_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn"
)

// benchPayloadSizes spans the relevant range: small (well below crypto/AEAD
// fixed overhead amortisation), mid (typical), and near-MTU (limits MSS-like
// fragmentation considerations on the inner IP path).
var benchPayloadSizes = []int{64, 512, 1400}

// dialBenchClient brings the OpenVPN session up; on failure the bench is
// fataled — no point in measuring a half-up tunnel.
func dialBenchClient(b *testing.B) *openvpn.Client {
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

// BenchmarkTunnelUDPEchoRoundtrip measures synchronous request/response
// throughput. Each iteration: build (cached), Write one IPv4+UDP datagram,
// Read replies until the matching echo is observed.
//
// b.SetBytes is the *one-way* payload size so the reported MB/s matches the
// classic iperf-style "throughput in one direction". Multiply by 2 mentally
// for true on-wire bytes.
func BenchmarkTunnelUDPEchoRoundtrip(b *testing.B) {
	cli := dialBenchClient(b)
	defer cli.Close()

	pr := cli.PushedOptions()
	if !pr.LocalIP.Is4() || !pr.Gateway.Is4() {
		b.Skipf("non-IPv4 push reply (%s → %s) — skipping UDP echo bench", pr.LocalIP, pr.Gateway)
	}
	conn := cli.Tunnel()

	srcIP := pr.LocalIP.As4()
	dstIP := pr.Gateway.As4() // 10.8.0.1
	const srcPort uint16 = 40000
	const dstPort uint16 = 8080

	// Warm the data channel: a packet or two pays off slot-init and any
	// late-arrival inbound that would otherwise pollute the read loop on
	// the very first iteration.
	warmPkt := buildUDP4(srcIP, dstIP, srcPort, dstPort, []byte("warmup"))
	rbuf := make([]byte, 2048)
	if !sendAndAwaitEcho(b, conn, warmPkt, rbuf, srcIP, dstIP, srcPort, dstPort, 5*time.Second) {
		b.Fatal("warmup echo failed — server UDP echo not reachable")
	}

	for _, size := range benchPayloadSizes {
		size := size
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i)
			}
			pkt := buildUDP4(srcIP, dstIP, srcPort, dstPort, payload)
			rbuf := make([]byte, 2048)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				if !sendAndAwaitEcho(b, conn, pkt, rbuf, srcIP, dstIP, srcPort, dstPort, 2*time.Second) {
					b.Fatalf("iter %d: echo lost", i)
				}
			}
		})
	}
}

// BenchmarkTunnelUDPWriteOnly fires UDP datagrams one-way without waiting for
// replies. Isolates the outbound encrypt+transport path; useful for spotting
// regressions in AEAD seal cost when round-trip noise (jitter, scheduler)
// would dominate.
//
// The echo replies still come back asynchronously; we drain them at the end
// to keep the receive queue from filling.
func BenchmarkTunnelUDPWriteOnly(b *testing.B) {
	cli := dialBenchClient(b)
	defer cli.Close()

	pr := cli.PushedOptions()
	if !pr.LocalIP.Is4() || !pr.Gateway.Is4() {
		b.Skipf("non-IPv4 push reply (%s → %s) — skipping bench", pr.LocalIP, pr.Gateway)
	}
	conn := cli.Tunnel()

	srcIP := pr.LocalIP.As4()
	dstIP := pr.Gateway.As4()
	const srcPort uint16 = 40001
	const dstPort uint16 = 8080

	for _, size := range benchPayloadSizes {
		size := size
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i)
			}
			pkt := buildUDP4(srcIP, dstIP, srcPort, dstPort, payload)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				if _, err := conn.Write(pkt); err != nil {
					b.Fatalf("iter %d: write: %v", i, err)
				}
			}
			b.StopTimer()

			// Drain pending echoes so we don't leak buffered packets into
			// the next sub-bench. Read with a short deadline; ignore errors.
			rbuf := make([]byte, 2048)
			drainDeadline := time.Now().Add(500 * time.Millisecond)
			_ = conn.SetReadDeadline(drainDeadline)
			for time.Now().Before(drainDeadline) {
				if _, err := conn.Read(rbuf); err != nil {
					break
				}
			}
			_ = conn.SetReadDeadline(time.Time{})
		})
	}
}

// sendAndAwaitEcho writes pkt and reads back from conn, filtering for the
// matching UDP echo (src=dstIP:dstPort, dst=srcIP:srcPort). Stray inbound
// (e.g. server-originated keepalive PINGs are already filtered by
// handleDataIn before they reach us, but ICMP from the kernel-level reply
// path or other control traffic could in theory show up) is skipped.
func sendAndAwaitEcho(
	b *testing.B, conn interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		SetReadDeadline(time.Time) error
	},
	pkt, rbuf []byte,
	srcIP, dstIP [4]byte, srcPort, dstPort uint16,
	timeout time.Duration,
) bool {
	b.Helper()
	if _, err := conn.Write(pkt); err != nil {
		b.Logf("write: %v", err)
		return false
	}
	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	for {
		if time.Now().After(deadline) {
			return false
		}
		n, err := conn.Read(rbuf)
		if err != nil {
			return false
		}
		if isExpectedUDPEcho(rbuf[:n], dstIP, srcIP, dstPort, srcPort) {
			return true
		}
		// Otherwise skip and read again — not our packet.
	}
}

// buildUDP4 assembles an IPv4 + UDP datagram with the supplied payload.
// IP header checksum is filled in; UDP checksum is zeroed (legal for IPv4,
// and socat's echo PIPE doesn't validate it).
func buildUDP4(src, dst [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	const ipHdr = 20
	const udpHdr = 8
	total := ipHdr + udpHdr + len(payload)
	pkt := make([]byte, total)

	// IPv4 header.
	pkt[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[6] = 0x40 // DF, frag offset 0
	pkt[8] = 64   // TTL
	pkt[9] = 17   // protocol = UDP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[10:12], inetChecksum(pkt[0:20]))

	// UDP header.
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpHdr+len(payload)))
	// pkt[26:28] = 0 — UDP checksum disabled.

	copy(pkt[28:], payload)
	return pkt
}

// isExpectedUDPEcho checks that pkt is an IPv4+UDP datagram matching the
// expected (src,dst,srcPort,dstPort) tuple. We deliberately don't validate
// payload length / contents — the bench harness only needs to know "did the
// matching reply arrive."
func isExpectedUDPEcho(pkt []byte, srcIP, dstIP [4]byte, srcPort, dstPort uint16) bool {
	if len(pkt) < 28 {
		return false
	}
	if pkt[0]>>4 != 4 || pkt[9] != 17 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+8 {
		return false
	}
	if [4]byte{pkt[12], pkt[13], pkt[14], pkt[15]} != srcIP {
		return false
	}
	if [4]byte{pkt[16], pkt[17], pkt[18], pkt[19]} != dstIP {
		return false
	}
	if binary.BigEndian.Uint16(pkt[ihl:ihl+2]) != srcPort {
		return false
	}
	if binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]) != dstPort {
		return false
	}
	return true
}
