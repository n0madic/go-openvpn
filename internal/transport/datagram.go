// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

// datagramConn adapts a datagram-oriented net.Conn (one Read yields one
// datagram, one Write sends one) into a PacketConn. Unlike udpConn it makes
// no assumptions about the concrete socket type, so it cannot tune kernel
// socket buffers or apply ENOBUFS backpressure — it is the wrapper for
// caller-supplied transports (a proxied UDP association, an obfuscation
// layer) where the conn is not a plain *net.UDPConn.
type datagramConn struct {
	c      net.Conn
	closed atomic.Bool

	// rbuf is the single receive buffer reused across ReadPacket calls.
	// Safe because the session has a single reader goroutine and the
	// PacketConn contract only promises the caller the returned slice
	// until the next ReadPacket on this conn (see udpConn.rbuf for the
	// full rationale). Lazy-allocated so unused conns never pay 64 KiB.
	rbuf []byte
}

// NewDatagram wraps a datagram-oriented net.Conn as a PacketConn. Each
// ReadPacket returns exactly one datagram and each WritePacket sends one.
// Use this for caller-supplied transports that preserve message boundaries
// but are not a plain *net.UDPConn — NewUDP covers that case and additionally
// tunes the kernel socket buffers.
//
// Unlike udpConn this type does not implement BindLifetimeCtx, so each
// ReadPacket whose ctx carries no deadline spawns a short-lived watcher
// goroutine for cancellation. Acceptable for an injected transport; the
// built-in UDP path keeps its hot-path optimisation.
func NewDatagram(c net.Conn) PacketConn {
	return &datagramConn{c: c}
}

func (d *datagramConn) ReadPacket(ctx context.Context) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = d.c.SetReadDeadline(deadline)
		defer func() { _ = d.c.SetReadDeadline(time.Time{}) }()
	}
	cancel := watchContext(ctx, d.c)
	defer cancel()

	if d.rbuf == nil {
		d.rbuf = make([]byte, maxUDPPacket)
	}
	n, err := d.c.Read(d.rbuf)
	if err != nil {
		if d.closed.Load() {
			return nil, ErrClosed
		}
		return nil, err
	}
	// Sub-slice of the shared buffer; the caller owns it only until the
	// next ReadPacket, which overwrites it in place.
	return d.rbuf[:n], nil
}

func (d *datagramConn) WritePacket(ctx context.Context, p []byte) error {
	if d.closed.Load() {
		return ErrClosed
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = d.c.SetWriteDeadline(deadline)
		defer func() { _ = d.c.SetWriteDeadline(time.Time{}) }()
	}
	_, err := d.c.Write(p)
	if err != nil && d.closed.Load() {
		return ErrClosed
	}
	return err
}

func (d *datagramConn) LocalAddr() net.Addr  { return d.c.LocalAddr() }
func (d *datagramConn) RemoteAddr() net.Addr { return d.c.RemoteAddr() }

func (d *datagramConn) Close() error {
	if d.closed.Swap(true) {
		return nil
	}
	return d.c.Close()
}
