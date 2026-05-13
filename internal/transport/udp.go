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

// udpReadBufPool re-uses 64 KiB receive buffers across ReadPacket calls so
// high-throughput sessions don't allocate per-packet.
var udpReadBufPool = sync.Pool{
	New: func() any { b := make([]byte, maxUDPPacket); return &b },
}

type udpConn struct {
	c      *net.UDPConn
	closed atomic.Bool
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
	return &udpConn{c: uc}, nil
}

// NewUDP wraps an existing *net.UDPConn. Useful for tests and for callers that
// need to configure the socket themselves (e.g. fwmark).
func NewUDP(c *net.UDPConn) PacketConn {
	return &udpConn{c: c}
}

func (u *udpConn) ReadPacket(ctx context.Context) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = u.c.SetReadDeadline(deadline)
		defer func() { _ = u.c.SetReadDeadline(time.Time{}) }()
	}
	cancel := watchContext(ctx, u.c)
	defer cancel()

	bufPtr := udpReadBufPool.Get().(*[]byte)
	defer udpReadBufPool.Put(bufPtr)
	buf := *bufPtr

	n, err := u.c.Read(buf)
	if err != nil {
		if u.closed.Load() {
			return nil, ErrClosed
		}
		return nil, err
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
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
