// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
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
	// The PacketConn contract promises the caller owns the returned
	// slice only until the next ReadPacket on this conn, and the
	// session has a single reader goroutine, so direct in-place reuse
	// is safe. Verified that downstream consumers don't retain the
	// slice: control path (reliable.Layer.appendReadLocked) copies
	// via append, data path (slot.Open) decrypts into a fresh
	// plaintext buffer. Lazy-allocated so unused conns never pay the
	// 64 KiB.
	rbuf []byte

	// lifetimeMu guards lifetimeStop. lifetimeCtx is loaded via
	// atomic.Pointer on the hot path (no lock); the mutex only
	// serialises installation of the watcher goroutine.
	lifetimeMu   sync.Mutex
	lifetimeCtx  atomic.Pointer[context.Context]
	lifetimeStop chan struct{}

	// statsENOBUFSRetries counts how many times we hit ENOBUFS on the
	// kernel send buffer and successfully retried after backoff. A
	// healthy session has zero of these; a sustained spike means the
	// upper layer (typically gVisor TCP under a speedtest or bulk
	// upload) is producing packets faster than the kernel can flush
	// to the wire and the backoff loop is doing its job.
	statsENOBUFSRetries atomic.Uint64
}

// ENOBUFSRetries returns the count of WritePacket calls that had to
// back off because the kernel UDP send buffer was full. Exposed via
// transport.PacketConn through a type assertion in stats reporting.
func (u *udpConn) ENOBUFSRetries() uint64 { return u.statsENOBUFSRetries.Load() }

// WritePacket retry-loop tunables. Keeping them as constants (not
// configurable) — these are protocol-correctness numbers, not
// per-deployment tuning knobs.
const (
	// enobufInitialBackoff is the first sleep after ENOBUFS. Below
	// macOS/Linux scheduler tick (1ms) on purpose: the buffer
	// typically drains in microseconds, so the first retry usually
	// succeeds immediately.
	enobufInitialBackoff = 500 * time.Microsecond
	// enobufMaxBackoff caps the exponential backoff. 16ms is small
	// enough that gVisor TCP's send window stays unaffected during
	// transient bursts but large enough to give a saturated kernel
	// buffer real time to drain.
	enobufMaxBackoff = 16 * time.Millisecond
	// enobufMaxTotalSleep is the upper bound on how long one
	// WritePacket call may block waiting for the buffer to drain.
	// Past this we return ENOBUFS to the caller — gVisor TCP then
	// queues for retransmit (lossless), or UDP/keepalive drops the
	// packet (cheap to retry at the next interval).
	//
	// 1500ms is generous — a 1 Gbps speedtest fills 4 MiB SO_SNDBUF
	// in ~33ms, so any genuinely-healthy write finishes far inside
	// this window. The headroom matters because the backpressure
	// only blocks the *one* TCP endpoint's goroutine (gVisor calls
	// WritePackets per endpoint, in parallel); other connections
	// keep flowing while one waits. With a shorter window (we tried
	// 200ms) a sustained burst racked up a small but non-zero error
	// count and the operator-visible WARN flood looked alarming
	// even though gVisor TCP was happily retransmitting and the
	// tunnel was healthy. 1500ms cuts those near-misses to zero
	// in the same workload.
	enobufMaxTotalSleep = 1500 * time.Millisecond
)

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
	// lifetime context: the single watcher installed by BindLifetimeCtx
	// already handles SetDeadline on cancellation. This is the read
	// loop's hot path — eliminating one goroutine spawn + channel
	// allocation per packet matters at sustained 1500+ pps.
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
	// Hand out a sub-slice of the shared buffer. Per the PacketConn
	// contract, the caller owns it only until the next ReadPacket on
	// this conn — overwritten in place by the next u.c.Read. Verified
	// safe: control path (reliable.Layer) copies via append, data
	// path (slot.Open) decrypts into a freshly-allocated plaintext.
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

	// Fast path: vast majority of writes succeed first try.
	_, err := u.c.Write(p)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.ENOBUFS) {
		return err
	}

	// ENOBUFS: kernel UDP send buffer is full. Returning the error
	// straight back to gVisor TCP would let it retransmit the same
	// packet immediately, amplifying the buffer pressure into a
	// retransmit storm. Instead, we block the writer goroutine for
	// a brief backoff so gVisor's TCP send rate naturally throttles
	// down to match the rate at which the kernel can flush to the
	// wire — the same way kernel TCP/IP stacks apply backpressure
	// via EAGAIN/ENOBUFS on the application send call.
	//
	// Total block bounded by enobufMaxTotalSleep to keep one stuck
	// write from pinning the whole writer (a wedged wire would
	// otherwise look indistinguishable from saturated wire).
	backoff := enobufInitialBackoff
	var totalSleep time.Duration
	for {
		if totalSleep >= enobufMaxTotalSleep {
			return err
		}
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= backoff {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		totalSleep += backoff
		if backoff < enobufMaxBackoff {
			backoff *= 2
			if backoff > enobufMaxBackoff {
				backoff = enobufMaxBackoff
			}
		}
		_, err = u.c.Write(p)
		if err == nil {
			u.statsENOBUFSRetries.Add(1)
			return nil
		}
		if !errors.Is(err, syscall.ENOBUFS) {
			return err
		}
	}
}

func (u *udpConn) LocalAddr() net.Addr  { return u.c.LocalAddr() }
func (u *udpConn) RemoteAddr() net.Addr { return u.c.RemoteAddr() }

// BindLifetimeCtx wires a single, long-lived watcher goroutine that
// calls SetDeadline(past) when ctx.Done() fires. Subsequent
// ReadPacket/WritePacket calls that pass the same ctx skip the
// per-call watcher spawn — eliminating one goroutine + channel
// allocation per packet on the hot read path. Safe to call once
// per connection; a second call closes the prior watcher first.
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

// isLifetimeCtx reports whether ctx is the conn's currently-bound
// lifetime context. Pointer comparison via atomic load — no
// allocation, no lock on the hot path.
func (u *udpConn) isLifetimeCtx(ctx context.Context) bool {
	p := u.lifetimeCtx.Load()
	return p != nil && *p == ctx
}

func (u *udpConn) Close() error {
	if u.closed.Swap(true) {
		return nil
	}
	u.lifetimeMu.Lock()
	if u.lifetimeStop != nil {
		close(u.lifetimeStop)
		u.lifetimeStop = nil
	}
	u.lifetimeMu.Unlock()
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
