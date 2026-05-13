// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"
)

func TestUDPRoundTrip(t *testing.T) {
	t.Parallel()
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := Dial(ctx, "udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	want := []byte("hello openvpn")
	if err := client.WritePacket(ctx, want); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 4096)
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("server got %q, want %q", buf[:n], want)
	}
}

func TestTCPLengthPrefixFraming(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	srvCh := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		srvCh <- c
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := Dial(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	srvConn := <-srvCh
	defer func() { _ = srvConn.Close() }()
	server := NewTCP(srvConn)
	defer func() { _ = server.Close() }()

	// Send three packets, varying sizes, ensure they arrive as discrete units.
	pkts := [][]byte{
		bytes.Repeat([]byte{0xAA}, 1),
		bytes.Repeat([]byte{0x55}, 1500),
		bytes.Repeat([]byte{0xFF}, 8000),
	}
	for _, p := range pkts {
		if err := client.WritePacket(ctx, p); err != nil {
			t.Fatalf("write %d bytes: %v", len(p), err)
		}
	}
	for i, want := range pkts {
		got, err := server.ReadPacket(ctx)
		if err != nil {
			t.Fatalf("server read packet %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("packet %d: got %d bytes, want %d", i, len(got), len(want))
		}
	}
}

func TestTCPEmptyPacketRejected(t *testing.T) {
	t.Parallel()
	// We use MemoryPair-style for the framing rejection check would be
	// inappropriate; build a tcp.Pipe directly.
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	tc := NewTCP(a)
	if err := tc.WritePacket(context.Background(), nil); err == nil {
		t.Fatal("expected error on empty packet")
	}
}

func TestMemoryRoundTrip(t *testing.T) {
	t.Parallel()
	a, b := MemoryPair()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()

	ctx := context.Background()
	want := []byte("ovpn")
	if err := a.WritePacket(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := b.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMemoryLoss(t *testing.T) {
	t.Parallel()
	src := rand.New(rand.NewPCG(1, 2))
	drop := func() bool { return src.Float64() < 0.5 } // ~50% loss
	a, b := MemoryPair(WithLoss(drop))
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()

	const N = 10000
	var sent, received int
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			rctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
			_, err := b.ReadPacket(rctx)
			cancel()
			if err != nil {
				return
			}
			received++
		}
	})

	for i := range N {
		if err := a.WritePacket(ctx, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		sent++
	}
	// Allow the reader to drain.
	time.Sleep(100 * time.Millisecond)
	_ = a.Close()
	wg.Wait()

	loss := 1 - float64(received)/float64(sent)
	if loss < 0.4 || loss > 0.6 {
		t.Fatalf("loss rate %.2f outside expected [0.4, 0.6]", loss)
	}
}

func TestMemoryReorder(t *testing.T) {
	t.Parallel()
	src := rand.New(rand.NewPCG(42, 43))
	swap := func() bool { return src.Float64() < 0.5 }
	a, b := MemoryPair(WithReorder(swap))
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()

	const N = 100
	ctx := context.Background()
	for i := range N {
		if err := a.WritePacket(ctx, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	// Flush any held-back packet by writing a sentinel without swap.
	// (The pending packet eventually flushes when shouldSwap returns false.)

	var outOfOrder int
	prev := byte(255)
	first := true
	for range N {
		rctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		p, err := b.ReadPacket(rctx)
		cancel()
		if err != nil {
			break
		}
		if !first && p[0] != prev+1 {
			outOfOrder++
		}
		prev = p[0]
		first = false
	}
	if outOfOrder == 0 {
		t.Fatal("expected some out-of-order packets")
	}
}

func TestContextCancelInterruptsRead(t *testing.T) {
	t.Parallel()
	a, b := MemoryPair()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := a.ReadPacket(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestUDPContextCancel(t *testing.T) {
	t.Parallel()
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	client, err := Dial(ctx, "udp", ln.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err = client.ReadPacket(ctx)
	if err == nil {
		t.Fatal("expected error after cancel")
	}
}
