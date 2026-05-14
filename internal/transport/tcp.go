// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// maxTCPPacket caps a single framed OpenVPN packet on TCP. The 16-bit length
// prefix allows up to 65535; we reject anything larger as malformed.
const maxTCPPacket = 65535

type tcpConn struct {
	c      net.Conn
	br     *bufio.Reader
	readM  sync.Mutex
	writeM sync.Mutex
	closed atomic.Bool
}

func dialTCP(ctx context.Context, network, addr string) (PacketConn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return newTCPConn(c), nil
}

// NewTCP wraps an existing net.Conn (typically *net.TCPConn). Useful for tests
// and proxied transports.
func NewTCP(c net.Conn) PacketConn {
	return newTCPConn(c)
}

func newTCPConn(c net.Conn) *tcpConn {
	// Disable Nagle. Each WritePacket already produces a fully-framed
	// OpenVPN packet (16-bit length prefix + payload, coalesced via
	// net.Buffers); Nagle's algorithm has nothing useful to merge here
	// and only adds ~40 ms of latency waiting for more bytes that will
	// never come on a per-packet protocol like ours.
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return &tcpConn{c: c, br: bufio.NewReaderSize(c, 8192)}
}

func (t *tcpConn) ReadPacket(ctx context.Context) ([]byte, error) {
	t.readM.Lock()
	defer t.readM.Unlock()

	if deadline, ok := ctx.Deadline(); ok {
		_ = t.c.SetReadDeadline(deadline)
		defer func() { _ = t.c.SetReadDeadline(time.Time{}) }()
	}
	cancel := watchContext(ctx, t.c)
	defer cancel()

	var hdr [2]byte
	if _, err := io.ReadFull(t.br, hdr[:]); err != nil {
		if t.closed.Load() {
			return nil, ErrClosed
		}
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		return nil, errors.New("transport/tcp: zero-length frame")
	}
	if int(n) > maxTCPPacket {
		return nil, fmt.Errorf("transport/tcp: frame too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(t.br, buf); err != nil {
		if t.closed.Load() {
			return nil, ErrClosed
		}
		return nil, err
	}
	return buf, nil
}

func (t *tcpConn) WritePacket(ctx context.Context, p []byte) error {
	if t.closed.Load() {
		return ErrClosed
	}
	if len(p) == 0 {
		return errors.New("transport/tcp: empty packet")
	}
	if len(p) > maxTCPPacket {
		return fmt.Errorf("transport/tcp: packet too large: %d", len(p))
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = t.c.SetWriteDeadline(deadline)
		defer func() { _ = t.c.SetWriteDeadline(time.Time{}) }()
	}

	t.writeM.Lock()
	defer t.writeM.Unlock()

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
	// Coalesce header and payload to avoid two TCP segments per packet when
	// Nagle is off. net.Buffers.WriteTo uses writev where available.
	bufs := net.Buffers{hdr[:], p}
	_, err := bufs.WriteTo(t.c)
	return err
}

func (t *tcpConn) LocalAddr() net.Addr  { return t.c.LocalAddr() }
func (t *tcpConn) RemoteAddr() net.Addr { return t.c.RemoteAddr() }

func (t *tcpConn) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	return t.c.Close()
}
