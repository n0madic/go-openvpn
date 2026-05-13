// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
)

// MemoryPair returns two PacketConns connected back-to-back in memory.
// Packets written on one side are delivered atomically on the other.
// Optional MemoryOptions inject UDP-style faults for testing the reliability
// layer.
func MemoryPair(opts ...MemoryOption) (PacketConn, PacketConn) {
	a := newMemoryConn("memA", "memB")
	b := newMemoryConn("memB", "memA")
	a.peer, b.peer = b, a
	for _, opt := range opts {
		opt(a)
		opt(b)
	}
	return a, b
}

// MemoryOption configures fault injection on both ends of a MemoryPair.
type MemoryOption func(*memoryConn)

// WithLoss drops outbound packets when shouldDrop returns true.
// Provide a closure backed by a seeded *rand.Rand for determinism.
func WithLoss(shouldDrop func() bool) MemoryOption {
	return func(m *memoryConn) { m.shouldDrop = shouldDrop }
}

// WithReorder swaps the order of successive outbound packets when shouldSwap
// returns true. At most one packet is held back at any time.
func WithReorder(shouldSwap func() bool) MemoryOption {
	return func(m *memoryConn) { m.shouldSwap = shouldSwap }
}

// WithDuplicate sends each outbound packet twice when shouldDup returns true.
func WithDuplicate(shouldDup func() bool) MemoryOption {
	return func(m *memoryConn) { m.shouldDup = shouldDup }
}

type memoryConn struct {
	localName, remoteName string
	peer                  *memoryConn
	q                     chan []byte
	closed                atomic.Bool

	shouldDrop func() bool
	shouldSwap func() bool
	shouldDup  func() bool

	mu      sync.Mutex
	pending []byte // for reorder: at most one packet held back
}

func newMemoryConn(local, remote string) *memoryConn {
	return &memoryConn{
		localName:  local,
		remoteName: remote,
		q:          make(chan []byte, 256),
	}
}

func (m *memoryConn) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case p, ok := <-m.q:
		if !ok {
			return nil, ErrClosed
		}
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *memoryConn) WritePacket(ctx context.Context, p []byte) error {
	if m.closed.Load() || m.peer.closed.Load() {
		return ErrClosed
	}
	if m.shouldDrop != nil && m.shouldDrop() {
		return nil
	}

	out := append([]byte(nil), p...)

	var toSend [][]byte
	if m.shouldSwap != nil {
		m.mu.Lock()
		held := m.pending
		switch {
		case m.shouldSwap() && held == nil:
			// Delay this packet; flush on next call.
			m.pending = out
			m.mu.Unlock()
			return nil
		case held != nil:
			// Flush held packet AFTER the new one — actual reordering.
			m.pending = nil
			m.mu.Unlock()
			toSend = [][]byte{out, held}
		default:
			m.mu.Unlock()
			toSend = [][]byte{out}
		}
	} else {
		toSend = [][]byte{out}
	}

	for _, pkt := range toSend {
		if err := m.deliver(ctx, pkt); err != nil {
			return err
		}
		if m.shouldDup != nil && m.shouldDup() {
			if err := m.deliver(ctx, append([]byte(nil), pkt...)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *memoryConn) deliver(ctx context.Context, p []byte) error {
	select {
	case m.peer.q <- p:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *memoryConn) LocalAddr() net.Addr  { return memAddr(m.localName) }
func (m *memoryConn) RemoteAddr() net.Addr { return memAddr(m.remoteName) }

func (m *memoryConn) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	// Flush any held reorder packet so tests draining on close don't lose it.
	m.mu.Lock()
	held := m.pending
	m.pending = nil
	m.mu.Unlock()
	if held != nil && !m.peer.closed.Load() {
		select {
		case m.peer.q <- held:
		default:
		}
	}
	close(m.q)
	return nil
}

type memAddr string

func (a memAddr) Network() string { return "mem" }
func (a memAddr) String() string  { return string(a) }
