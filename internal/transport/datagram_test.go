// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// connectedUDP returns a connected *net.UDPConn dialed at a raw listening
// peer, plus the peer. The peer is driven manually with ReadFromUDP /
// WriteToUDP so the test exercises NewDatagram's Read and Write end to end.
func connectedUDP(t *testing.T) (client *net.UDPConn, peer *net.UDPConn) {
	t.Helper()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client, err = net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	return client, peer
}

func TestDatagramRoundTrip(t *testing.T) {
	t.Parallel()
	cli, peer := connectedUDP(t)
	defer func() { _ = peer.Close() }()
	dg := NewDatagram(cli)
	defer func() { _ = dg.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// NewDatagram → peer.
	out := []byte("hello datagram")
	if err := dg.WritePacket(ctx, out); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4096)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	n, cliAddr, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if !bytes.Equal(buf[:n], out) {
		t.Fatalf("peer got %q, want %q", buf[:n], out)
	}

	// peer → NewDatagram.
	in := []byte("hello back")
	if _, err := peer.WriteToUDP(in, cliAddr); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	got, err := dg.ReadPacket(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, in) {
		t.Fatalf("got %q, want %q", got, in)
	}
}

func TestDatagramContextCancel(t *testing.T) {
	t.Parallel()
	cli, peer := connectedUDP(t)
	defer func() { _ = peer.Close() }()
	dg := NewDatagram(cli)
	defer func() { _ = dg.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	if _, err := dg.ReadPacket(ctx); err == nil {
		t.Fatal("expected error after cancel")
	}
}

func TestDatagramClosedErr(t *testing.T) {
	t.Parallel()
	cli, peer := connectedUDP(t)
	defer func() { _ = peer.Close() }()
	dg := NewDatagram(cli)

	if err := dg.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	ctx := context.Background()
	if err := dg.WritePacket(ctx, []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("write after close: got %v, want ErrClosed", err)
	}
	if _, err := dg.ReadPacket(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("read after close: got %v, want ErrClosed", err)
	}
}
