// SPDX-License-Identifier: AGPL-3.0-or-later

package reliable

import (
	"errors"
	"net"
	"time"
)

// Adapter wraps a Layer in a net.Conn interface so it can be passed directly
// to crypto/tls.Client. Read/Write/Close are forwarded to the underlying
// Layer; address methods return preconfigured net.Addrs; deadlines are
// implemented as best-effort: a deadline in the past unblocks Read/Write,
// otherwise they're no-ops.
type Adapter struct {
	layer      *Layer
	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewAdapter constructs the net.Conn shim. localAddr/remoteAddr surface
// through LocalAddr()/RemoteAddr() and are used purely for diagnostics (and
// possibly to satisfy TLS verification paths that read them).
func NewAdapter(l *Layer, localAddr, remoteAddr net.Addr) *Adapter {
	return &Adapter{layer: l, localAddr: localAddr, remoteAddr: remoteAddr}
}

// Read implements net.Conn.
func (a *Adapter) Read(p []byte) (int, error) { return a.layer.Read(p) }

// Write implements net.Conn.
func (a *Adapter) Write(p []byte) (int, error) { return a.layer.Write(p) }

// Close implements net.Conn. Tears down the underlying Layer.
func (a *Adapter) Close() error { return a.layer.Close() }

// LocalAddr implements net.Conn.
func (a *Adapter) LocalAddr() net.Addr { return a.localAddr }

// RemoteAddr implements net.Conn.
func (a *Adapter) RemoteAddr() net.Addr { return a.remoteAddr }

// SetDeadline implements net.Conn. A past or zero deadline forces Read/Write
// to fail immediately by closing the layer; otherwise it's a no-op. crypto/tls
// uses this primarily to abort handshakes, so closing on a past deadline is
// the correct behaviour.
func (a *Adapter) SetDeadline(t time.Time) error {
	if !t.IsZero() && !t.After(time.Now()) {
		a.layer.CloseRead(errDeadlineExceeded)
		return nil
	}
	return nil
}

// SetReadDeadline implements net.Conn.
func (a *Adapter) SetReadDeadline(t time.Time) error { return a.SetDeadline(t) }

// SetWriteDeadline implements net.Conn.
func (a *Adapter) SetWriteDeadline(t time.Time) error { return a.SetDeadline(t) }

// errDeadlineExceeded mimics the standard library's deadline error.
var errDeadlineExceeded = errors.New("reliable: deadline exceeded")

// Compile-time guard.
var _ net.Conn = (*Adapter)(nil)
