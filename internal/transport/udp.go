// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// maxUDPPacket is the maximum size of a single OpenVPN-over-UDP packet we will
// accept on read. OpenVPN's default link-mtu is 1500 plus a small amount of
// encap overhead; 65535 is the absolute UDP datagram limit. We pick the latter
// to avoid silently truncating server packets if MTU is misconfigured.
const maxUDPPacket = 65535

// kernelSockBufBytes is what we try to set SO_SNDBUF/SO_RCVBUF to on the
// underlying UDP socket. The OS-default values are tiny (macOS ships with
// SO_SNDBUF = 9216 bytes — six OpenVPN frames!) and a burst of traffic from
// gVisor (e.g. dozens of TCP handshakes during a speedtest, or HTTP/2
// fan-out from a browser) trivially fills them up. Once full, the kernel
// rejects writes with ENOBUFS ("no buffer space available"); from the
// outside the tunnel looks like it's silently freezing, because keepalive
// PINGs and data packets are dropped before they ever reach the wire.
//
// 4 MiB is generous but bounded by macOS's kern.ipc.maxsockbuf (default
// 6 MiB on recent versions); the SetWriteBuffer call below downgrades
// silently if the kernel clamps it.
const kernelSockBufBytes = 4 * 1024 * 1024

type udpConn struct {
	c      *net.UDPConn
	closed atomic.Bool

	// rbuf is the single receive buffer reused across ReadPacket calls.
	// The PacketConn interface promises that the slice returned from one
	// ReadPacket is "owned by the caller until the next ReadPacket call",
	// so we can simply hand out u.rbuf[:n] every time — the next call
	// invalidates the previous one. Lazy-allocated on first read so an
	// unused conn never pays for the 64 KiB.
	rbuf []byte

	// lifetimeMu guards lifetimeCtx + lifetimeStop. ReadPacket/WritePacket
	// read lifetimeCtx via atomic load (no lock on the hot path) and only
	// take the lock when installing a new watcher (rare — once per session).
	lifetimeMu   sync.Mutex
	lifetimeCtx  atomic.Pointer[context.Context]
	lifetimeStop chan struct{}
}

func dialUDP(ctx context.Context, network, addr string) (PacketConn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		_ = c.Close()
		return nil, errors.New("transport: DialContext did not return *net.UDPConn")
	}
	tuneSockBufs(uc)
	return &udpConn{c: uc}, nil
}

// NewUDP wraps an existing *net.UDPConn. Useful for tests and for callers that
// need to configure the socket themselves (e.g. fwmark).
func NewUDP(c *net.UDPConn) PacketConn {
	tuneSockBufs(c)
	return &udpConn{c: c}
}

// tuneSockBufs requests larger SO_SNDBUF / SO_RCVBUF on the underlying UDP
// socket so a burst of OpenVPN traffic (encrypted gVisor TCP/UDP packets,
// keepalives) doesn't overflow the kernel send queue. Best effort: the
// kernel silently caps to kern.ipc.maxsockbuf on macOS / net.core.wmem_max
// on Linux, but we still get a much larger window than the OS default.
func tuneSockBufs(c *net.UDPConn) {
	_ = c.SetWriteBuffer(kernelSockBufBytes)
	_ = c.SetReadBuffer(kernelSockBufBytes)
}

func (u *udpConn) ReadPacket(ctx context.Context) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = u.c.SetReadDeadline(deadline)
		defer func() { _ = u.c.SetReadDeadline(time.Time{}) }()
	}
	// Skip the per-call watcher goroutine when ctx is the conn's bound
	// lifetime context: a single watcher installed by BindLifetimeCtx
	// already handles SetDeadline on cancellation. This is the read loop's
	// hot path and easily 20% of allocations otherwise.
	if !u.isLifetimeCtx(ctx) {
		cancel := watchContext(ctx, u.c)
		defer cancel()
	}

	if u.rbuf == nil {
		u.rbuf = make([]byte, maxUDPPacket)
	}
	n, err := u.c.Read(u.rbuf)
	if err != nil {
		if u.closed.Load() {
			return nil, ErrClosed
		}
		return nil, err
	}
	return u.rbuf[:n], nil
}

func (u *udpConn) WritePacket(ctx context.Context, p []byte) error {
	if u.closed.Load() {
		return ErrClosed
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = u.c.SetWriteDeadline(deadline)
		defer func() { _ = u.c.SetWriteDeadline(time.Time{}) }()
	}
	_, err := u.c.Write(p)
	return err
}

// BindLifetimeCtx wires a single, long-lived watcher goroutine that calls
// SetDeadline(past) when ctx.Done() fires. Subsequent ReadPacket/WritePacket
// calls that pass the same ctx skip the per-call watcher spawn. Safe to
// call once per connection — replacing the bound ctx tears down the old
// watcher first.
func (u *udpConn) BindLifetimeCtx(ctx context.Context) {
	if ctx == nil || ctx.Done() == nil {
		return
	}
	u.lifetimeMu.Lock()
	defer u.lifetimeMu.Unlock()
	if u.lifetimeStop != nil {
		close(u.lifetimeStop)
	}
	stop := make(chan struct{})
	u.lifetimeStop = stop
	u.lifetimeCtx.Store(&ctx)
	go func(ctx context.Context, stop chan struct{}) {
		select {
		case <-ctx.Done():
			_ = u.c.SetDeadline(time.Unix(1, 0))
		case <-stop:
		}
	}(ctx, stop)
}

// isLifetimeCtx reports whether ctx is the conn's currently-bound lifetime
// context. Pointer comparison via atomic load — no allocation, no lock.
func (u *udpConn) isLifetimeCtx(ctx context.Context) bool {
	p := u.lifetimeCtx.Load()
	return p != nil && *p == ctx
}

func (u *udpConn) LocalAddr() net.Addr  { return u.c.LocalAddr() }
func (u *udpConn) RemoteAddr() net.Addr { return u.c.RemoteAddr() }

func (u *udpConn) Close() error {
	if u.closed.Swap(true) {
		return nil
	}
	return u.c.Close()
}

// watchContext arranges for ctx cancellation to interrupt a blocking I/O on c
// by setting a past deadline. Returns a cancel function the caller must invoke
// once the I/O has returned to release the watcher goroutine.
func watchContext(ctx context.Context, c net.Conn) func() {
	done := make(chan struct{})
	if ctx.Done() == nil {
		return func() { close(done) }
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = c.SetDeadline(time.Unix(1, 0))
		case <-done:
		}
	}()
	return func() {
		select {
		case <-done:
		default:
			close(done)
		}
	}
}
