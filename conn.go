// SPDX-License-Identifier: AGPL-3.0-or-later

package openvpn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-openvpn/internal/proto"
	"github.com/n0madic/go-openvpn/internal/session"
)

// PushReply is the public-facing view of the server's PUSH_REPLY.
type PushReply struct {
	LocalIP      netip.Addr
	Netmask      netip.Addr
	Gateway      netip.Addr
	LocalIP6     netip.Prefix // from "ifconfig-ipv6": local address + prefix length
	RemoteIP6    netip.Addr   // from "ifconfig-ipv6": peer address, used as v6 default gateway
	Routes       []netip.Prefix
	Routes6      []netip.Prefix
	DNS          []netip.Addr
	MTU          int
	Cipher       string
	PeerID       uint32
	PingInterval time.Duration
	PingRestart  time.Duration
	Topology     string
}

var errInvalidConfig = errors.New("openvpn: nil Config")

// tunnel implements net.Conn over the session's data path. The handle
// survives AutoReconnect-driven session replacements: it always queries
// Client.session() for the current Session.
type tunnel struct {
	c *Client

	// Deadlines for Read/Write. Stored as Unix-nano (int64) atomics so they
	// can be read on the hot path without a mutex. Zero == no deadline.
	readDeadlineNs  atomic.Int64
	writeDeadlineNs atomic.Int64
}

// Compile-time guard.
var _ net.Conn = (*tunnel)(nil)

// Read returns one decrypted IP packet. When Config.AutoReconnect is true,
// a RestartError from the current session triggers a transparent reconnect
// and the read is retried on the new session.
func (t *tunnel) Read(p []byte) (int, error) {
	ctx, cancel := t.readCtx()
	defer cancel()
	for {
		if t.c.closed.Load() {
			return 0, ErrClosed
		}
		s := t.c.session()
		n, err := s.ReadCtx(ctx, p)
		if err == nil {
			return n, nil
		}
		if isDeadlineErr(err, ctx) {
			return 0, os.ErrDeadlineExceeded
		}
		if next, retry := t.maybeReconnect(ctx, s, err); retry {
			continue
		} else if next != nil {
			if isDeadlineErr(next, ctx) {
				return 0, os.ErrDeadlineExceeded
			}
			return 0, next
		}
		return n, err
	}
}

// Write encrypts and sends one IP packet. Same reconnect semantics as Read.
func (t *tunnel) Write(p []byte) (int, error) {
	ctx, cancel := t.writeCtx()
	defer cancel()
	for {
		if t.c.closed.Load() {
			return 0, ErrClosed
		}
		s := t.c.session()
		n, err := s.WriteCtx(ctx, p)
		if err == nil {
			return n, nil
		}
		if isDeadlineErr(err, ctx) {
			return 0, os.ErrDeadlineExceeded
		}
		if next, retry := t.maybeReconnect(ctx, s, err); retry {
			continue
		} else if next != nil {
			if isDeadlineErr(next, ctx) {
				return 0, os.ErrDeadlineExceeded
			}
			return 0, next
		}
		return n, err
	}
}

// readCtx returns a context that fires at readDeadline. Returns a no-op
// cancel when no deadline is set so callers can always defer cancel().
func (t *tunnel) readCtx() (context.Context, context.CancelFunc) {
	ns := t.readDeadlineNs.Load()
	if ns == 0 {
		return context.Background(), func() {}
	}
	return context.WithDeadline(context.Background(), time.Unix(0, ns))
}

func (t *tunnel) writeCtx() (context.Context, context.CancelFunc) {
	ns := t.writeDeadlineNs.Load()
	if ns == 0 {
		return context.Background(), func() {}
	}
	return context.WithDeadline(context.Background(), time.Unix(0, ns))
}

func isDeadlineErr(err error, ctx context.Context) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if ctx.Err() == context.DeadlineExceeded && errors.Is(err, context.Canceled) {
		// Some wrappers convert DeadlineExceeded to Canceled.
		return true
	}
	return false
}

// maybeReconnect inspects an error from Session.Read/Write and decides
// whether to retry (after triggering a reconnect) or to surface the error.
// Returns (replacementErr, retry):
//
//   - retry=true: caller should loop and try again on the new session.
//   - retry=false, replacementErr=nil: return the original error.
//   - retry=false, replacementErr!=nil: return replacementErr instead.
func (t *tunnel) maybeReconnect(ctx context.Context, failed *session.Session, err error) (error, bool) {
	if !t.c.cfg.AutoReconnect {
		return nil, false
	}
	var re *RestartError
	if !errors.As(err, &re) {
		return nil, false
	}
	if rcErr := t.c.reconnect(ctx, failed, re.Delay); rcErr != nil {
		return rcErr, false
	}
	return nil, true
}

// Close terminates only the user side of the tunnel — the underlying VPN
// session keeps running until Client.Close().
func (t *tunnel) Close() error { return nil }

// LocalAddr returns the IP currently assigned by the server. Re-queried on
// each call so reconnect-driven IP changes surface naturally.
func (t *tunnel) LocalAddr() net.Addr {
	pr := t.c.session().PushReply()
	if !pr.LocalIP.IsValid() {
		return nil
	}
	return &ipAddr{ip: pr.LocalIP.AsSlice()}
}

// RemoteAddr returns the gateway (or peer) tunnel IP from PUSH_REPLY.
func (t *tunnel) RemoteAddr() net.Addr {
	pr := t.c.session().PushReply()
	peer := peerForRemote(pr)
	if !peer.IsValid() {
		return nil
	}
	return &ipAddr{ip: peer.AsSlice()}
}

// SetDeadline sets the deadline for both Read and Write. A zero value
// disables the deadline. Read/Write that overrun the deadline return an
// error that satisfies net.Error.Timeout() == true (os.ErrDeadlineExceeded).
func (t *tunnel) SetDeadline(deadline time.Time) error {
	t.storeDeadline(&t.readDeadlineNs, deadline)
	t.storeDeadline(&t.writeDeadlineNs, deadline)
	return nil
}

// SetReadDeadline sets the deadline for future Read calls only.
func (t *tunnel) SetReadDeadline(deadline time.Time) error {
	t.storeDeadline(&t.readDeadlineNs, deadline)
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls only.
func (t *tunnel) SetWriteDeadline(deadline time.Time) error {
	t.storeDeadline(&t.writeDeadlineNs, deadline)
	return nil
}

// storeDeadline normalises a time.Time deadline into a UnixNano int64.
// Zero value disables (stored as 0).
func (t *tunnel) storeDeadline(dst *atomic.Int64, d time.Time) {
	if d.IsZero() {
		dst.Store(0)
		return
	}
	dst.Store(d.UnixNano())
}

// ipAddr wraps an IP address as a net.Addr.
type ipAddr struct {
	ip net.IP
}

func (a *ipAddr) Network() string { return "ovpn-tun" }
func (a *ipAddr) String() string  { return a.ip.String() }

// peerForRemote picks the most useful "remote" tunnel address for the
// net.Conn: prefer the gateway when set, else the second arg of "ifconfig"
// (RemoteIP for net30/p2p topology).
func peerForRemote(pr proto.PushReply) netip.Addr {
	if pr.Gateway.IsValid() {
		return pr.Gateway
	}
	if pr.RemoteIP.IsValid() {
		return pr.RemoteIP
	}
	return pr.LocalIP
}

// Compile-time guard: tunnel and session.RestartError used together.
var _ = (*session.RestartError)(nil)
