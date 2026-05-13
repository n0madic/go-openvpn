// SPDX-License-Identifier: AGPL-3.0-or-later

package netstack

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// fakeDispatcher captures the packets the LinkEndpoint hands upward.
type fakeDispatcher struct {
	mu      sync.Mutex
	packets []capturedPacket
	wake    chan struct{}
}

type capturedPacket struct {
	proto tcpip.NetworkProtocolNumber
	body  []byte
}

func newFakeDispatcher() *fakeDispatcher {
	return &fakeDispatcher{wake: make(chan struct{}, 16)}
}

func (f *fakeDispatcher) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	v := pkt.ToView()
	body := append([]byte(nil), v.AsSlice()...)
	v.Release()
	f.mu.Lock()
	f.packets = append(f.packets, capturedPacket{proto: proto, body: body})
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *fakeDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func (f *fakeDispatcher) waitPacket(t *testing.T, timeout time.Duration) capturedPacket {
	t.Helper()
	select {
	case <-f.wake:
	case <-time.After(timeout):
		t.Fatal("timeout waiting for inbound packet")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.packets) == 0 {
		t.Fatal("woke up but no packet captured")
	}
	pkt := f.packets[len(f.packets)-1]
	return pkt
}

// TestEndpointInbound feeds raw IP bytes into the tunnel side of the pipe
// and verifies that the LinkEndpoint delivers them as a PacketBuffer with
// the correct NetworkProtocolNumber.
func TestEndpointInbound(t *testing.T) {
	t.Parallel()

	cliConn, srvConn := net.Pipe()
	defer func() { _ = srvConn.Close() }()

	ep := newEndpoint(cliConn, 1500)
	disp := newFakeDispatcher()
	ep.Attach(disp)
	defer ep.Close()

	// Build a minimal IPv4 echo request (no inner payload, no real checksum
	// — endpoint doesn't validate, it just reads version + delivers).
	ipv4Pkt := []byte{
		0x45, 0x00, 0x00, 0x14, 0xab, 0xcd, 0x00, 0x00,
		0x40, 0x01, 0x00, 0x00, 10, 8, 0, 100,
		10, 8, 0, 1,
	}
	if _, err := srvConn.Write(ipv4Pkt); err != nil {
		t.Fatalf("write into pipe: %v", err)
	}

	got := disp.waitPacket(t, 2*time.Second)
	if got.proto != header.IPv4ProtocolNumber {
		t.Fatalf("proto = %d, want IPv4 (%d)", got.proto, header.IPv4ProtocolNumber)
	}
	if !bytes.Equal(got.body, ipv4Pkt) {
		t.Fatalf("body mismatch:\n got: %x\nwant: %x", got.body, ipv4Pkt)
	}

	// IPv6 dispatch path.
	ipv6Pkt := []byte{
		0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x40,
		// src ::1
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		// dst ::1
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	}
	if _, err := srvConn.Write(ipv6Pkt); err != nil {
		t.Fatalf("write v6 into pipe: %v", err)
	}
	got = disp.waitPacket(t, 2*time.Second)
	if got.proto != header.IPv6ProtocolNumber {
		t.Fatalf("v6 proto = %d, want IPv6 (%d)", got.proto, header.IPv6ProtocolNumber)
	}
}

// TestEndpointOutbound builds a PacketBuffer, hands it to WritePackets, and
// verifies it appears verbatim on the other side of the pipe.
func TestEndpointOutbound(t *testing.T) {
	t.Parallel()

	cliConn, srvConn := net.Pipe()
	defer func() { _ = cliConn.Close() }()
	defer func() { _ = srvConn.Close() }()

	ep := newEndpoint(cliConn, 1500)
	defer ep.Close()
	// Attach is required by some stack code paths, but WritePackets does not
	// gate on it. We still Attach a dispatcher to keep the lifecycle realistic.
	ep.Attach(newFakeDispatcher())

	payload := []byte("hello-ip-packet")
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(payload),
	})
	defer pkt.DecRef()

	var pbl stack.PacketBufferList
	pbl.PushBack(pkt)

	// WritePackets blocks on net.Pipe Write until the other side reads,
	// so run it in a goroutine and read concurrently.
	wroteCh := make(chan int, 1)
	go func() {
		n, err := ep.WritePackets(pbl)
		if err != nil {
			t.Errorf("WritePackets: %v", err)
		}
		wroteCh <- n
	}()

	buf := make([]byte, 64)
	n, err := srvConn.Read(buf)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	if got := buf[:n]; !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
	if n := <-wroteCh; n != 1 {
		t.Fatalf("WritePackets returned n=%d, want 1", n)
	}
}

// TestEndpointCloseUnblocksReader: closing the endpoint must release the
// blocking Read in the inbound goroutine.
func TestEndpointCloseUnblocksReader(t *testing.T) {
	t.Parallel()

	cliConn, srvConn := net.Pipe()
	defer func() { _ = srvConn.Close() }()

	ep := newEndpoint(cliConn, 1500)
	ep.Attach(newFakeDispatcher())

	done := make(chan struct{})
	go func() {
		ep.Wait()
		close(done)
	}()

	ep.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not exit after Close")
	}
}

func TestMaskPrefixLen(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mask string
		want int
	}{
		{"255.255.255.0", 24},
		{"255.255.0.0", 16},
		{"255.255.255.255", 32},
		{"0.0.0.0", 0},
		{"255.255.255.240", 28},
	} {
		addr, err := netip.ParseAddr(tc.mask)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := maskPrefixLen(addr); got != tc.want {
			t.Errorf("maskPrefixLen(%s) = %d, want %d", tc.mask, got, tc.want)
		}
	}
}

func TestSubnetFromPrefix(t *testing.T) {
	t.Parallel()
	// Pin some IPv4 prefix and verify it survives the round-trip without
	// losing host bits.
	p := netip.MustParsePrefix("10.8.0.0/24")
	subnet, err := tcpipSubnetFromPrefix(p)
	if err != nil {
		t.Fatalf("subnet: %v", err)
	}
	id := subnet.ID()
	addrBytes := id.AsSlice()
	if !bytes.Equal(addrBytes, []byte{10, 8, 0, 0}) {
		t.Fatalf("got id %v, want 10.8.0.0", addrBytes)
	}
	if subnet.Prefix() != 24 {
		t.Fatalf("prefix=%d, want 24", subnet.Prefix())
	}
}
