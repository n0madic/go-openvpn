// SPDX-License-Identifier: AGPL-3.0-or-later

// Package session is the OpenVPN client session orchestrator. It owns the
// transport, tls-crypt wrapper, per-key-id reliability layers and AEAD data
// slots, the TLS handshake state, and the goroutines that pump packets
// between them. Public API (openvpn package) calls Dial and consumes
// Tunnel I/O.
package session

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-openvpn/internal/control"
	"github.com/n0madic/go-openvpn/internal/data"
	"github.com/n0madic/go-openvpn/internal/proto"
	"github.com/n0madic/go-openvpn/internal/reliable"
	"github.com/n0madic/go-openvpn/internal/tlscrypt"
	"github.com/n0madic/go-openvpn/internal/trace"
	"github.com/n0madic/go-openvpn/internal/transport"
	"github.com/n0madic/go-openvpn/internal/workers"
)

// Config holds everything needed to bring up a session.
type Config struct {
	Network    string // "udp" | "tcp"
	RemoteAddr string // host:port

	TLSConfig *tls.Config

	Username string
	Password string

	// Either TLSCryptV1 (256 bytes) or TLSCryptV2 (PEM bundle with embedded
	// WKc). Exactly one must be set.
	TLSCryptV1 []byte
	TLSCryptV2 []byte

	Ciphers          []string
	HandshakeTimeout time.Duration
	// Reneg, when >0, triggers an automatic soft-reset rekey after this
	// much wall time (mirrors OpenVPN's --reneg-sec; default 0 = disabled).
	Reneg time.Duration
	// TransitionWindow controls how long the previous-generation slot
	// remains valid for inbound packets after a rekey. Default 60s.
	TransitionWindow time.Duration
	IngressBuffer    int // user-side ingress chan capacity; default 256

	// DataActivityWarmup is the grace period after session-up during
	// which dataActivityWatch never fires. Default 60s. Set to a very
	// small value in tests.
	DataActivityWarmup time.Duration
	// DataActivityStuckThreshold is the max allowed gap between
	// "user actively sending" and "real (non-PING) inbound data
	// arriving" before the data-path is considered stuck and a
	// RestartError is fired. Default 60s.
	DataActivityStuckThreshold time.Duration

	// PeerInfoVersion overrides the IV_VER field advertised in peer-info.
	// Empty defaults to "2.6.0".
	PeerInfoVersion string

	// HandshakeTracer, when non-nil, receives a HandshakeEvent at the
	// start of every control-channel handshake stage. Useful for
	// production timing/observability and integration tests. nil means
	// no tracing (zero overhead beyond an unused interface field).
	HandshakeTracer trace.HandshakeTracer

	Logger *slog.Logger
}

// Session is the live VPN session.
type Session struct {
	cfg Config
	log *slog.Logger

	transport transport.PacketConn
	wrapper   *tlscrypt.Wrapper
	localSID  uint64

	slots  *slotTable
	layers *layerTable

	// State needed for rekey re-handshake.
	cipher    string
	peerID    uint32
	tlsConfig *tls.Config

	pushReply proto.PushReply

	rekeyMgr *rekeyManager

	// tlsConn is the currently-active TLS control-channel conn — used for
	// sending the EXIT notification on Close and for post-handshake server
	// messages (RESTART, INFO). Replaced on rekey.
	tlsMu   sync.Mutex
	tlsConn *tls.Conn

	// closeErr, if set, is returned from Read/Write after the session has
	// been closed for a specific protocol reason (e.g. server RESTART).
	closeErr atomic.Pointer[error]

	// lastInbound is the UnixNano timestamp of the most recent successfully
	// decrypted data packet of ANY kind (real traffic or PING). Drives
	// pingRestartWatch.
	lastInbound atomic.Int64

	// lastDataInbound is the UnixNano timestamp of the most recent
	// successfully decrypted *non-PING* data packet. Drives
	// dataActivityWatch — a watchdog independent of pingRestartWatch that
	// detects the "tunnel-alive-at-protocol-level but data-path-stuck"
	// failure mode (server PINGs keep lastInbound fresh while real traffic
	// is silently dropped). Without this, the stuck tunnel never triggers
	// AutoReconnect and the user must restart the process manually.
	lastDataInbound atomic.Int64

	// lastUserOutbound is the UnixNano timestamp of the most recent
	// successful Session.WriteCtx (i.e. real user traffic, not keepalive
	// PINGs which bypass Write). Paired with lastDataInbound to tell
	// "the user is actively asking for data" apart from "the user is idle".
	lastUserOutbound atomic.Int64

	// Packet-flow counters (lifetime). Sampled by statsLogger.
	statsForwarded      atomic.Uint64 // delivered to ingressCh
	statsDroppedFull    atomic.Uint64 // ingressCh full → dropped
	statsPingIn         atomic.Uint64 // inbound PING filtered before ingressCh
	statsOpenFailed     atomic.Uint64 // slot.Open returned an error
	statsStrayHandshake atomic.Uint64 // tls-crypt unwrap dropped — stray fresh handshake

	ingressCh chan []byte
	// workers owns the cancellation context shared by every long-running
	// session goroutine (read/write/tick/watch loops). Replaces the
	// ad-hoc ctx+cancel+wg trio with a single API surface that adds
	// panic recovery and per-worker logging.
	workers *workers.Manager
	// ctx is a cached copy of workers.Context() so call sites that
	// previously read s.ctx keep working unchanged.
	ctx    context.Context
	closed atomic.Bool
}

// Dial brings up the session.
func Dial(ctx context.Context, cfg Config) (*Session, error) {
	tr, err := transport.Dial(ctx, cfg.Network, cfg.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("session: dial transport: %w", err)
	}
	return DialWithTransport(ctx, cfg, tr)
}

// DialWithTransport bypasses the network dial step. The supplied transport
// is taken over by the session; on error the caller is responsible for
// closing it.
func DialWithTransport(ctx context.Context, cfg Config, tr transport.PacketConn) (*Session, error) {
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if cfg.TransitionWindow <= 0 {
		cfg.TransitionWindow = 60 * time.Second
	}

	var sidBytes [8]byte
	if _, err := rand.Read(sidBytes[:]); err != nil {
		return nil, fmt.Errorf("session: gen sid: %w", err)
	}
	localSID := binary.BigEndian.Uint64(sidBytes[:])

	wrapper, hardResetOp, err := buildWrapper(cfg)
	if err != nil {
		_ = tr.Close()
		return nil, err
	}

	// Initial reliable layer (key-id 0).
	initialLayer := reliable.New(reliable.Config{LocalSessionID: localSID, InitialKeyID: 0})

	// Session lifetime context is rooted at Background — the passed ctx
	// only gates the handshake (see hctx below). Tying sCtx to ctx would
	// surprise callers that pass a per-call/deadline-bearing context: the
	// resulting session would die when that context expired. The owning
	// openvpn.Client links external cancellation to Session.Close() via
	// its own watcher.
	s := &Session{
		cfg:       cfg,
		log:       log,
		transport: tr,
		wrapper:   wrapper,
		localSID:  localSID,
		slots:     newSlotTable(),
		layers:    newLayerTable(),
		tlsConfig: cfg.TLSConfig,
		ingressCh: make(chan []byte, cfgIngressBuffer(cfg)),
	}
	s.workers = workers.NewManager(context.Background(), log,
		workers.WithPanicHandler(func(name string, r any) {
			s.setCloseErr(fmt.Errorf("session: worker %q panicked: %v", name, r))
		}),
	)
	s.ctx = s.workers.Context()
	s.layers.Install(0, initialLayer)

	// Bind the session lifetime ctx to the transport once, so per-call
	// ReadPacket/WritePacket don't spawn a watcher goroutine every packet.
	// Transports that don't implement the optional interface (e.g. memory
	// transport in tests) keep their per-call behaviour.
	if br, ok := tr.(interface{ BindLifetimeCtx(context.Context) }); ok {
		br.BindLifetimeCtx(s.ctx)
	}

	// Start the read loop (demuxes by opcode + key-id across all layers).
	s.workers.Go("readLoop", func(context.Context) { s.readLoop() })
	// Per-layer write+tick loops for key-id 0.
	s.startLayerPumps(initialLayer)

	// Handshake.
	hctx := ctx
	if cfg.HandshakeTimeout > 0 {
		var hcancel context.CancelFunc
		hctx, hcancel = context.WithTimeout(ctx, cfg.HandshakeTimeout)
		defer hcancel()
	}
	result, err := control.Run(hctx, initialLayer, tr.LocalAddr(), tr.RemoteAddr(), control.Config{
		TLSConfig:       cfg.TLSConfig,
		Username:        cfg.Username,
		Password:        cfg.Password,
		Ciphers:         cfg.Ciphers,
		HardResetOpcode: hardResetOp,
		PeerInfoVersion: cfg.PeerInfoVersion,
		Tracer:          cfg.HandshakeTracer,
	})
	if err != nil {
		s.shutdown()
		return nil, err
	}

	slot, err := buildSlot(0, result)
	if err != nil {
		s.shutdown()
		return nil, fmt.Errorf("session: build initial data slot: %w", err)
	}
	s.slots.Install(slot, true)
	s.pushReply = result.PushReply
	s.cipher = result.Cipher
	s.peerID = result.PeerID

	// Stash the TLS conn for exit-notify on Close and start a reader that
	// listens for post-handshake server messages (RESTART, INFO, EXIT).
	s.installTLSConn(result.TLSConn)

	// Rekey manager + watchdog.
	s.rekeyMgr = newRekeyManager(s, cfg.TransitionWindow)
	rstate := newRekeyState(cfg.Reneg, nil)
	s.workers.Go("rekeyWatch", func(ctx context.Context) { s.rekeyWatch(ctx, rstate) })

	// Keepalive: emit OpenVPN PINGs at the negotiated interval so the peer
	// (and any UDP NAT on the path) sees us as alive; close with a
	// RestartError after PingRestart seconds of inbound silence so
	// openvpn.Client.AutoReconnect can resurrect the session.
	//
	// Many real providers (ProtonVPN among them) do NOT push `ping`/
	// `ping-restart`, so honouring the push reply verbatim leaves the tunnel
	// with no keepalive at all and the server happily drops the session after
	// its own ping-restart fires. Fill the gap with sensible defaults so
	// "tunnel just stops carrying traffic" can't happen out of the box.
	s.applyKeepaliveDefaults()
	now := time.Now().UnixNano()
	s.lastInbound.Store(now)
	// Seed data-liveness timestamps so dataActivityWatch sees a healthy
	// session at start and doesn't false-positive during warmup.
	s.lastDataInbound.Store(now)
	s.lastUserOutbound.Store(now)
	if s.pushReply.PingInterval > 0 {
		s.workers.Go("keepaliveLoop", s.keepaliveLoop)
	}
	if s.pushReply.PingRestart > 0 {
		s.workers.Go("pingRestartWatch", s.pingRestartWatch)
	}
	s.workers.Go("dataActivityWatch", s.dataActivityWatch)
	s.workers.Go("statsLogger", s.statsLogger)

	// Surface the full server-pushed option set for diagnostics. PUSH_REPLY
	// carries no credentials (auth precedes it on the control channel), so
	// logging the raw body is safe.
	log.Debug("openvpn pushed options", "raw", result.PushReply.Raw)

	log.Info("openvpn session up",
		"cipher", result.Cipher,
		"peer_id", result.PeerID,
		"local_ip", result.PushReply.LocalIP.String(),
		"local_ip6", result.PushReply.LocalIP6.String(),
		"gateway", result.PushReply.Gateway.String(),
		"remote_ip6", result.PushReply.RemoteIP6.String(),
		"routes", result.PushReply.Routes,
		"routes6", result.PushReply.Routes6,
		"dns", result.PushReply.DNS,
		"mtu", result.PushReply.MTU,
		"ping", s.pushReply.PingInterval,
		"ping_restart", s.pushReply.PingRestart,
	)
	return s, nil
}

// PushReply returns the parsed server PUSH_REPLY.
func (s *Session) PushReply() proto.PushReply { return s.pushReply }

// Stats is a snapshot of one Session's lifetime packet-flow counters
// and liveness timestamps. Counters are cumulative since the session
// was dialled; timestamps reflect the most recent observation (zero
// time means "no observation yet").
type Stats struct {
	Forwarded        uint64
	DroppedFull      uint64
	PingIn           uint64
	OpenFailed       uint64
	StrayHandshake   uint64
	LastInbound      time.Time
	LastDataInbound  time.Time
	LastUserOutbound time.Time
}

// Stats returns a consistent snapshot of the session's counters and
// liveness timestamps. Safe to call concurrently with traffic.
func (s *Session) Stats() Stats {
	nsToTime := func(ns int64) time.Time {
		if ns == 0 {
			return time.Time{}
		}
		return time.Unix(0, ns)
	}
	return Stats{
		Forwarded:        s.statsForwarded.Load(),
		DroppedFull:      s.statsDroppedFull.Load(),
		PingIn:           s.statsPingIn.Load(),
		OpenFailed:       s.statsOpenFailed.Load(),
		StrayHandshake:   s.statsStrayHandshake.Load(),
		LastInbound:      nsToTime(s.lastInbound.Load()),
		LastDataInbound:  nsToTime(s.lastDataInbound.Load()),
		LastUserOutbound: nsToTime(s.lastUserOutbound.Load()),
	}
}

func (s *Session) UnderlayLocalAddr() net.Addr  { return s.transport.LocalAddr() }
func (s *Session) UnderlayRemoteAddr() net.Addr { return s.transport.RemoteAddr() }

// Read returns the next decrypted IP packet.
func (s *Session) Read(p []byte) (int, error) {
	return s.ReadCtx(context.Background(), p)
}

// ReadCtx is Read with an explicit cancellation context. ctx is honoured
// independently of the session's own context — callers use it to apply
// per-call timeouts (e.g. Tunnel.SetReadDeadline). Returns ctx.Err() when
// the caller cancels, or the session's close reason when the session
// shuts down.
func (s *Session) ReadCtx(ctx context.Context, p []byte) (int, error) {
	select {
	case pkt, ok := <-s.ingressCh:
		if !ok {
			return 0, s.closedErr()
		}
		if len(p) < len(pkt) {
			return 0, fmt.Errorf("session: short buffer (have %d, need %d)", len(p), len(pkt))
		}
		return copy(p, pkt), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-s.ctx.Done():
		if err := s.closedErr(); err != nil {
			return 0, err
		}
		return 0, s.ctx.Err()
	}
}

// Write encrypts and sends a single IP packet through the tunnel.
//
// If the active slot's outbound packet-id crosses the rekey threshold mid-send
// (race against the rekey watchdog), Write triggers a synchronous rekey and
// retries on the new slot. This avoids surfacing ErrPacketIDExhausted to user
// code as a transient error.
func (s *Session) Write(p []byte) (int, error) {
	return s.WriteCtx(context.Background(), p)
}

// WriteCtx is Write with an explicit cancellation context. The transport
// write honours both the caller's ctx and the session's own ctx —
// whichever fires first wins.
func (s *Session) WriteCtx(ctx context.Context, p []byte) (int, error) {
	if s.closed.Load() {
		return 0, s.closedErr()
	}
	slot := s.slots.Active()
	if slot == nil {
		return 0, errors.New("session: data slot not ready")
	}
	wire, err := slot.Seal(p)
	if errors.Is(err, data.ErrPacketIDExhausted) {
		newSlot, rkErr := s.rekeyForExhaustedSlot(slot)
		if rkErr != nil {
			return 0, rkErr
		}
		wire, err = newSlot.Seal(p)
	}
	if err != nil {
		return 0, err
	}
	// Merge caller ctx with session ctx: either cancellation aborts the
	// transport write. The merged context is short-lived (lifetime of one
	// WritePacket call), so the goroutine cost is negligible.
	writeCtx := s.ctx
	var cancel context.CancelFunc
	if ctx != nil && ctx != context.Background() && ctx.Done() != nil {
		writeCtx, cancel = mergedContext(s.ctx, ctx)
		defer cancel()
	}
	werr := s.transport.WritePacket(writeCtx, wire)
	// Return the Seal output buffer to the pool regardless of write
	// outcome. The transport's WritePacket synchronously hands wire to
	// either net.Conn.Write (UDP, single syscall) or net.Buffers.WriteTo
	// (TCP, writev — also synchronous wrt the input slice). Once it
	// returns the kernel has copied out the bytes and we own the memory
	// again.
	data.ReleaseSealedBuf(wire)
	if werr != nil {
		return 0, werr
	}
	// Track real-user activity so dataActivityWatch can tell "user
	// actively sending but nothing coming back" apart from "session idle".
	// Keepalive PINGs intentionally bypass this — they use
	// transport.WritePacket directly.
	s.lastUserOutbound.Store(time.Now().UnixNano())
	return len(p), nil
}

// mergedContext returns a context that fires when either a or b fires.
// Inherits Deadline from whichever side has the earlier one.
func mergedContext(a, b context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(a)
	stop := make(chan struct{})
	go func() {
		select {
		case <-b.Done():
			cancel()
		case <-stop:
		}
	}()
	return ctx, func() {
		close(stop)
		cancel()
	}
}

// rekeyForExhaustedSlot is called from Write when Seal returned
// ErrPacketIDExhausted. It triggers a synchronous rekey if one isn't already
// running, then waits briefly for a fresh slot to become active. Returns the
// new active slot.
func (s *Session) rekeyForExhaustedSlot(old *data.Slot) (*data.Slot, error) {
	if s.rekeyMgr == nil {
		return nil, ErrRekeyRequired
	}
	rkCtx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	err := s.rekeyMgr.PerformSoftReset(rkCtx)
	if err != nil && !errors.Is(err, ErrRekeyInProgress) {
		return nil, fmt.Errorf("session: forced rekey: %w", err)
	}
	// PerformSoftReset returns once the active slot has been swapped, OR
	// (ErrRekeyInProgress) immediately if another goroutine is rekeying —
	// in which case we briefly poll for the swap.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cur := s.slots.Active(); cur != nil && cur != old {
			return cur, nil
		}
		select {
		case <-s.ctx.Done():
			return nil, s.closedErr()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return nil, ErrRekeyRequired
}

// closedErr returns the protocol-level reason for closure (if any),
// otherwise a generic "closed" sentinel.
func (s *Session) closedErr() error {
	if p := s.closeErr.Load(); p != nil {
		return *p
	}
	return ErrClosed
}

// CloseErr returns the protocol-level reason for closure if any was set,
// otherwise nil. Useful for callers that want to distinguish a clean
// shutdown from a server-initiated RESTART or EXIT.
func (s *Session) CloseErr() error {
	if p := s.closeErr.Load(); p != nil {
		return *p
	}
	return nil
}

// ErrClosed is the generic error returned by Read/Write when the session has
// been closed without a more specific reason. RestartError is returned when
// the server requested a RESTART.
var ErrClosed = errors.New("session: closed")

// setCloseErr records the protocol-level reason for closure. First setter
// wins (subsequent calls are no-ops).
func (s *Session) setCloseErr(err error) {
	s.closeErr.CompareAndSwap(nil, &err)
}

// installTLSConn replaces the active TLS control-channel conn and starts a
// reader goroutine that watches for server-initiated messages (RESTART,
// INFO, EXIT). The previously-active conn is closed (which kills its reader).
func (s *Session) installTLSConn(c *tls.Conn) {
	s.tlsMu.Lock()
	prev := s.tlsConn
	s.tlsConn = c
	s.tlsMu.Unlock()
	if prev != nil {
		_ = prev.Close()
	}
	if c != nil {
		s.workers.Go("controlChannelReader", func(context.Context) { s.controlChannelReader(c) })
	}
}

// RequestRestart asks the session to terminate with a *RestartError so the
// surrounding openvpn.Client (when AutoReconnect is on) re-dials. Intended
// for application-level health checks that observe data-plane failure the
// session itself can't detect — for example, the SOCKS5 daemon's resolver
// noticing repeated DNS-over-tunnel timeouts.
//
// Idempotent: a second call while shutdown is in flight is a no-op.
func (s *Session) RequestRestart(reason string) {
	if s.closed.Load() {
		return
	}
	if reason == "" {
		reason = "application requested restart"
	}
	s.log.Warn("session restart requested by application", "reason", reason)
	re := &RestartError{Reason: reason}
	s.setCloseErr(re)
	go func() { _ = s.Close() }()
}

// Rekey triggers a soft-reset rekey synchronously. Useful for tests and for
// users who want explicit control. Returns nil on success.
func (s *Session) Rekey(ctx context.Context) error {
	if s.rekeyMgr == nil {
		return errors.New("session: rekey not initialised")
	}
	return s.rekeyMgr.PerformSoftReset(ctx)
}

// Close tears down the session. Sends an EXIT notification over the
// control channel (best-effort) before teardown so the server can clean up
// immediately rather than waiting for ping-restart timeout.
func (s *Session) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.sendExitNotifyBestEffort(500 * time.Millisecond)
	s.shutdown()
	return nil
}

// sendExitNotifyBestEffort writes "EXIT\0" to the active TLS control channel
// and waits up to timeout for the reliability layer's outbound queue to
// drain (i.e. the server has ACKed the message). Drops silently on error.
//
// Verified against OpenVPN ssl.c::send_control_channel_string("EXIT", ...)
// which writes strlen("EXIT")+1 = 5 bytes including the NUL terminator. The
// peer matches with buf_string_match_head_str(buf, "EXIT") then calls
// process_control_msg_exit which immediately tears down the session.
func (s *Session) sendExitNotifyBestEffort(timeout time.Duration) {
	s.tlsMu.Lock()
	c := s.tlsConn
	s.tlsMu.Unlock()
	if c == nil {
		return
	}
	deadline := time.Now().Add(timeout)
	_ = c.SetWriteDeadline(deadline)
	if _, err := c.Write([]byte("EXIT\x00")); err != nil {
		s.log.Debug("explicit-exit-notify write failed", "err", err)
		return
	}
	// Wait for the active reliable layer to drain its outbound queue (i.e.
	// the server ACKed our EXIT). Otherwise the in-flight packet may be
	// cancelled by shutdown() and never reach the wire.
	layer := s.layers.Get(s.slots.ActiveKID())
	if layer == nil {
		return
	}
	for time.Now().Before(deadline) {
		if layer.QueueLen() == 0 {
			s.log.Debug("explicit-exit-notify acknowledged")
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.log.Debug("explicit-exit-notify timeout waiting for ACK")
}

// controlChannelReader runs as long as conn is open, dispatching server-side
// control-channel messages (RESTART, AUTH_FAILED, INFO, EXIT) into session
// state. Exits cleanly when conn is closed (e.g. during rekey or shutdown).
//
// Wraps the TLS conn in a bufio.Reader so each control message costs ~1 TLS
// record read instead of one per byte.
func (s *Session) controlChannelReader(conn *tls.Conn) {
	br := bufio.NewReader(conn)
	for {
		msg, err := control.ReadControlMessage(br)
		if err != nil {
			return
		}
		switch {
		case msg == "EXIT" || strings.HasPrefix(msg, "EXIT,"):
			// Server has cleanly disconnected.
			s.log.Info("server sent EXIT")
			s.setCloseErr(ErrServerExit)
			_ = s.Close()
			return
		case msg == "RESTART" || strings.HasPrefix(msg, "RESTART,"):
			re := parseRestart(msg)
			s.log.Info("server requested RESTART", "delay", re.Delay, "reason", re.Reason)
			s.setCloseErr(re)
			_ = s.Close()
			return
		case strings.HasPrefix(msg, "AUTH_FAILED"):
			s.log.Warn("server AUTH_FAILED post-handshake", "msg", msg)
			body := strings.TrimPrefix(msg, "AUTH_FAILED")
			body = strings.TrimPrefix(body, ",")
			s.setCloseErr(&AuthFailedError{Message: body})
			_ = s.Close()
			return
		case strings.HasPrefix(msg, "INFO"):
			payload := msg
			if len(msg) > 5 && msg[4] == ',' {
				payload = msg[5:]
			}
			s.log.Info("server INFO", "msg", payload)
		default:
			s.log.Debug("ignoring unknown control message", "msg", msg)
		}
	}
}

// ErrServerExit is returned from Read/Write after the server sent us a clean
// EXIT message.
var ErrServerExit = errors.New("openvpn: server sent EXIT")

// AuthFailedError is returned from Read/Write after the server sent
// AUTH_FAILED post-handshake (e.g. session expired).
type AuthFailedError struct {
	// Message is the raw server-side text after the "AUTH_FAILED" token,
	// without the comma separator (empty if the server sent just "AUTH_FAILED").
	Message string
}

// Error implements the error interface.
func (e *AuthFailedError) Error() string {
	if e.Message == "" {
		return "openvpn: server sent AUTH_FAILED"
	}
	return "openvpn: server sent AUTH_FAILED: " + e.Message
}

// RestartError is returned from Read/Write when the server has requested
// the client to disconnect and reconnect. Format mirrors OpenVPN's
// RESTART[,delay-seconds][,reason] control message.
type RestartError struct {
	// Delay is the suggested wait before reconnecting. Zero when unspecified.
	Delay time.Duration
	// Reason is the optional human-readable cause from the server.
	Reason string
}

// Error implements the error interface.
func (e *RestartError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("openvpn: server requested RESTART (delay=%s): %s", e.Delay, e.Reason)
	}
	return fmt.Sprintf("openvpn: server requested RESTART (delay=%s)", e.Delay)
}

// parseRestart decodes a "RESTART", "RESTART,reason" or "RESTART,N,reason"
// message into a structured RestartError. Tolerant of variant formats.
func parseRestart(msg string) *RestartError {
	re := &RestartError{}
	rest, ok := strings.CutPrefix(msg, "RESTART")
	if !ok {
		return re
	}
	rest = strings.TrimPrefix(rest, ",")
	if rest == "" {
		return re
	}
	// Try "delay,reason" first; if first field is non-numeric, treat whole
	// remainder as reason.
	first, second, hasSecond := strings.Cut(rest, ",")
	if d, err := strconv.Atoi(first); err == nil {
		re.Delay = time.Duration(d) * time.Second
		if hasSecond {
			re.Reason = second
		}
	} else {
		re.Reason = rest
	}
	return re
}

func (s *Session) shutdown() {
	s.workers.Shutdown()
	// Close all layers (cascades into their write/tick goroutines via
	// closed Outbound channel). Key-id is 3 bits, so 0..7 covers all slots.
	for kid := range uint8(8) {
		if l := s.layers.Retire(kid); l != nil {
			_ = l.Close()
		}
	}
	if s.transport != nil {
		_ = s.transport.Close()
	}
	s.workers.Wait()
}

// readLoop demuxes inbound packets by opcode + key-id.
func (s *Session) readLoop() {
	for {
		pkt, err := s.transport.ReadPacket(s.ctx)
		if err != nil {
			return
		}
		if len(pkt) < 1 {
			continue
		}
		opcode, kid := proto.UnpackOpcodeKID(pkt[0])
		switch {
		case opcode.IsData():
			s.handleDataIn(pkt, kid)
		case opcode.IsControl():
			s.handleControlIn(pkt, opcode, kid)
		default:
			s.log.Warn("dropping packet with unknown opcode", "opcode", opcode)
		}
	}
}

func (s *Session) handleDataIn(pkt []byte, kid uint8) {
	slot := s.slots.Get(kid)
	if slot == nil {
		return // pre-handshake or post-retire: drop
	}
	ip, err := slot.Open(pkt)
	if err != nil {
		s.statsOpenFailed.Add(1)
		s.log.Debug("data open failed", "kid", kid, "err", err)
		return
	}
	// Any decryptable inbound packet (real traffic or PING) proves the peer
	// is still alive — feed the ping-restart watchdog before deciding what
	// to do with the payload.
	now := time.Now().UnixNano()
	s.lastInbound.Store(now)
	if proto.IsPing(ip) {
		s.statsPingIn.Add(1)
		// Server-side keepalive PINGs are the half of the keepalive
		// loop that's invisible from outbound logs alone. Logging them
		// makes the "tunnel alive but data-path stuck" diagnostic real:
		// if the operator sees inbound PINGs but no inbound data, that's
		// exactly the failure mode dataActivityWatch is built to catch.
		s.log.Debug("keepalive PING received", "kid", kid)
		return
	}
	// Real (non-PING) inbound data — feed the data-liveness watchdog
	// separately. PINGs alone are not enough to call the data path healthy
	// (server PINGs can keep flowing even when the data path is dead).
	s.lastDataInbound.Store(now)
	// Non-blocking send: if the consumer (gVisor link endpoint reader) is
	// slow or stuck, drop rather than block the entire session.readLoop.
	// Blocking here was the second half of the "tunnel freezes but PINGs
	// flow" failure: handleDataIn would stall on a full channel, the OS
	// UDP receive buffer would back up, and the session would deadlock
	// silently. Drop-on-full lets gVisor TCP fill the gaps via the standard
	// retransmit path; lost UDP packets are the caller's problem same as
	// on any real link.
	select {
	case s.ingressCh <- ip:
		s.statsForwarded.Add(1)
	default:
		s.statsDroppedFull.Add(1)
	}
}

// isStrayUnwrap reports whether a failed-to-unwrap control packet looks
// like benign chatter rather than a real anomaly. Two cases qualify:
//
//   - opcode is P_CONTROL_HARD_RESET_SERVER_V2: the server is initiating a
//     brand-new session, so its tls-crypt send-pid restarts from 1 and
//     trips our replay window. Common when the server lost track of us
//     (HA/restart) or another client is competing for the same CN.
//   - the on-wire session-id differs from the layer's known peer session-id:
//     packets meant for a different session (load-balancer / NAT echo)
//     reaching our socket. Only checked when we already know the peer SID;
//     during the initial handshake the layer hasn't latched it yet.
//
// The packet header is parsed inline (cheap: 9 bytes); wrapper.Unwrap
// zeroes its returned sid on error, so we can't reuse it here.
func isStrayUnwrap(pkt []byte, opcode proto.Opcode, layer *reliable.Layer) bool {
	if opcode == proto.PControlHardResetServerV2 {
		return true
	}
	if len(pkt) >= 9 {
		sid := binary.BigEndian.Uint64(pkt[1:9])
		if expected, ok := layer.RemoteSessionID(); ok && sid != expected {
			return true
		}
	}
	return false
}

func (s *Session) handleControlIn(pkt []byte, opcode proto.Opcode, kid uint8) {
	layer := s.layers.Get(kid)
	if layer == nil {
		s.log.Debug("control packet for unknown key-id", "kid", kid, "opcode", opcode)
		return
	}
	opcodeKID, sid, _, plain, err := s.wrapper.Unwrap(pkt)
	if err != nil {
		// Coalesce the noisy benign case: a server periodically retrying a
		// fresh handshake (HARD_RESET_SERVER_V2) while our session is alive
		// produces a wave of replay-rejected packets with pid restarting
		// from 1. Same for packets bearing a session-id we don't recognize
		// (another client's traffic landing here via load-balancer / NAT
		// quirks). Counted but not logged per-packet; statsLogger surfaces
		// the running total. Anything else still hits Debug so genuine
		// decrypt anomalies remain visible.
		if isStrayUnwrap(pkt, opcode, layer) {
			s.statsStrayHandshake.Add(1)
			return
		}
		s.log.Debug("tls-crypt unwrap failed", "err", err)
		return
	}
	_ = opcodeKID
	in := reliable.InPacket{Opcode: opcode, KeyID: kid, SessionID: sid}
	if opcode == proto.PAckV1 {
		ap, err := proto.ParseAckPayload(plain)
		if err != nil {
			s.log.Debug("ack parse failed", "err", err)
			return
		}
		in.Ack = ap
	} else {
		cp, err := proto.ParseControlPayload(plain)
		if err != nil {
			s.log.Debug("control parse failed", "err", err)
			return
		}
		in.Payload = cp
	}
	if err := layer.HandleInbound(in); err != nil && !errors.Is(err, reliable.ErrClosed) {
		s.log.Debug("handle inbound", "err", err)
	}
}

// startLayerPumps spawns the writer and ticker goroutines for one
// reliable.Layer. They exit when the layer's Outbound chan closes (i.e.
// when the layer is Close()d).
func (s *Session) startLayerPumps(layer *reliable.Layer) {
	kid := layer.KeyID()
	s.workers.Go(fmt.Sprintf("writeLoop[kid=%d]", kid), func(context.Context) { s.writeLoop(layer) })
	s.workers.Go(fmt.Sprintf("tickLoop[kid=%d]", kid), func(context.Context) { s.tickLoop(layer) })
}

func (s *Session) writeLoop(layer *reliable.Layer) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case out, ok := <-layer.Outbound():
			if !ok {
				return
			}
			var body []byte
			var err error
			if out.IsAck() {
				body, err = proto.MarshalAckPayload(out.Ack)
			} else {
				body, err = proto.MarshalControlPayload(out.Payload)
			}
			if err != nil {
				s.log.Warn("marshal outbound", "err", err)
				continue
			}
			opcodeKID := proto.PackOpcodeKID(out.Opcode, out.KeyID)
			wrapped := s.wrapper.Wrap(opcodeKID, out.SessionID, body)
			if err := s.transport.WritePacket(s.ctx, wrapped); err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, transport.ErrClosed) {
					s.log.Warn("transport write", "err", err)
				}
				return
			}
		}
	}
}

func (s *Session) tickLoop(layer *reliable.Layer) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := layer.Tick(); err != nil {
				// Layer-fatal — typically max retransmits. Close the
				// session unless it's the previous (about-to-retire)
				// layer, in which case it's harmless.
				if l := s.slots.Active(); l != nil && layer == s.layers.Get(l.KeyID) {
					s.log.Warn("reliable tick fatal on active layer", "err", err)
					_ = s.Close()
				}
				return
			}
		}
	}
}

// --- helpers ---

func validateConfig(cfg *Config) error {
	if cfg.Network == "" {
		return errors.New("session: Network required")
	}
	if cfg.RemoteAddr == "" {
		return errors.New("session: RemoteAddr required")
	}
	if cfg.TLSConfig == nil {
		return errors.New("session: TLSConfig required")
	}
	if len(cfg.TLSCryptV1) == 0 && len(cfg.TLSCryptV2) == 0 {
		return errors.New("session: tls-crypt key required (v1 or v2)")
	}
	return nil
}

func buildWrapper(cfg Config) (*tlscrypt.Wrapper, proto.Opcode, error) {
	if len(cfg.TLSCryptV2) > 0 {
		bundle, err := tlscrypt.ParseClientBundleV2(cfg.TLSCryptV2)
		if err != nil {
			return nil, 0, fmt.Errorf("session: parse tls-crypt-v2 bundle: %w", err)
		}
		w, err := tlscrypt.New(bundle.Kc, tlscrypt.DirectionInverse)
		if err != nil {
			return nil, 0, fmt.Errorf("session: init tls-crypt-v2: %w", err)
		}
		w.SetFirstWrapTrailer(bundle.WKc)
		return w, proto.PControlHardResetClientV3, nil
	}
	rawKey, err := tlscrypt.ParseStaticKey(cfg.TLSCryptV1)
	if err != nil {
		return nil, 0, fmt.Errorf("session: parse tls-crypt key: %w", err)
	}
	w, err := tlscrypt.New(rawKey, tlscrypt.DirectionInverse)
	if err != nil {
		return nil, 0, fmt.Errorf("session: init tls-crypt: %w", err)
	}
	return w, proto.PControlHardResetClientV2, nil
}

func buildSlot(keyID uint8, r *control.Result) (*data.Slot, error) {
	keyLen, err := control.AEADKeyLen(r.Cipher)
	if err != nil {
		return nil, err
	}
	slot, err := data.NewSlot(data.SlotConfig{
		KeyID:   keyID,
		PeerID:  r.PeerID,
		Cipher:  r.Cipher,
		SendKey: r.KeyMaterial.ClientToServerCipherKey(keyLen),
		SendIV:  r.KeyMaterial.ClientToServerImplicitIV(),
		RecvKey: r.KeyMaterial.ServerToClientCipherKey(keyLen),
		RecvIV:  r.KeyMaterial.ServerToClientImplicitIV(),
	})
	if err != nil {
		return nil, err
	}
	// Wipe the EKM exporter copy once it's been consumed by the AEAD ciphers.
	clear(r.KeyMaterial[:])
	return slot, nil
}

func cfgIngressBuffer(cfg Config) int {
	if cfg.IngressBuffer > 0 {
		return cfg.IngressBuffer
	}
	return 256
}
