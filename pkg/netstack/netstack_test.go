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

	ep := newEndpoint(cliConn, 1500, false)
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

	ep := newEndpoint(cliConn, 1500, false)
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

	ep := newEndpoint(cliConn, 1500, false)
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

// TestTrackedConnLifecycle exercises the active-conns tracker without
// going through gVisor: it inserts mock conns, verifies they're
// remembered, force-closes them, and confirms double-close is safe and
// re-deregistration is idempotent.
func TestTrackedConnLifecycle(t *testing.T) {
	t.Parallel()

	n := &Net{}

	closer1 := &fakeCloseCounter{}
	closer2 := &fakeCloseCounter{}

	tc1 := n.trackConn(closer1).(*trackedConn)
	tc2 := n.trackConn(closer2).(*trackedConn)

	// Both registered.
	count := 0
	n.activeConns.Range(func(_, _ any) bool { count++; return true })
	if count != 2 {
		t.Fatalf("after two trackConn, active=%d, want 2", count)
	}

	// closeActiveOnReconnect closes both and clears the map.
	closed := n.closeActiveOnReconnect()
	if closed != 2 {
		t.Fatalf("closeActiveOnReconnect returned %d, want 2", closed)
	}
	if closer1.closes != 1 || closer2.closes != 1 {
		t.Fatalf("expected each underlying conn closed exactly once, got %d / %d",
			closer1.closes, closer2.closes)
	}
	count = 0
	n.activeConns.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Fatalf("after closeActiveOnReconnect, active=%d, want 0", count)
	}

	// Double-close is idempotent on the wrapper too.
	if err := tc1.Close(); err != nil {
		t.Fatalf("second Close() on tc1 returned error: %v", err)
	}
	if closer1.closes != 2 {
		// Note: the wrapper always forwards Close to the underlying conn,
		// even when already deregistered — this keeps the contract of
		// "Close returns the conn's own error" intact. The dedup is only
		// on the map removal, not on the Conn.Close call. That's safe
		// because gVisor's *TCPConn.Close is already idempotent.
		t.Fatalf("after second Close() on tc1, underlying closes=%d, want 2",
			closer1.closes)
	}

	// New conns can be tracked after a reconnect.
	closer3 := &fakeCloseCounter{}
	_ = n.trackConn(closer3)
	count = 0
	n.activeConns.Range(func(_, _ any) bool { count++; return true })
	if count != 1 {
		t.Fatalf("after fresh trackConn, active=%d, want 1", count)
	}
	_ = tc2 // keep ref for clarity
}

// fakeCloseCounter is a minimal net.Conn that counts Close calls.
// Only Close is exercised; the other net.Conn methods are nil-bodied.
type fakeCloseCounter struct {
	closes int
}

func (f *fakeCloseCounter) Read([]byte) (int, error)         { return 0, nil }
func (f *fakeCloseCounter) Write([]byte) (int, error)        { return 0, nil }
func (f *fakeCloseCounter) Close() error                     { f.closes++; return nil }
func (f *fakeCloseCounter) LocalAddr() net.Addr              { return nil }
func (f *fakeCloseCounter) RemoteAddr() net.Addr             { return nil }
func (f *fakeCloseCounter) SetDeadline(time.Time) error      { return nil }
func (f *fakeCloseCounter) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeCloseCounter) SetWriteDeadline(time.Time) error { return nil }

// TestClampInnerMTU verifies the conservative NIC MTU policy: gVisor's
// NIC MTU must never exceed safeInnerMTU, regardless of what the
// server pushes. This is the architectural equivalent of the
// official OpenVPN client's MSS clamping (mssfix=1492) — gVisor TCP
// auto-negotiates MSS based on NIC MTU, so capping the NIC MTU
// caps the MSS apps inside the tunnel will use, which keeps every
// outer wire datagram comfortably under 1500 bytes after
// OpenVPN/UDP/IP encapsulation.
func TestClampInnerMTU(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		pushed uint32
		want   uint32
	}{
		{"server pushes 1500 (typical): clamp to safe", 1500, safeInnerMTU},
		{"server pushes 1492 (PPPoE): clamp to safe", 1492, safeInnerMTU},
		{"server pushes exactly safeInnerMTU: pass through", safeInnerMTU, safeInnerMTU},
		{"server pushes below safe: respect server", 1280, 1280},
		{"server pushes well below safe: respect server", 576, 576},
		{"server pushes 0 (no MTU pushed): default to safe", 0, safeInnerMTU},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := clampInnerMTU(tc.pushed); got != tc.want {
				t.Errorf("clampInnerMTU(%d) = %d, want %d", tc.pushed, got, tc.want)
			}
		})
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
