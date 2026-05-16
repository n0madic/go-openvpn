// SPDX-License-Identifier: AGPL-3.0-or-later

// Package openvpn is a pure-Go OpenVPN 2.6+ client library. It is user-space
// (no TUN), CGo-free, supports tls-crypt v1 / v2, NCP, and rekey, and exposes
// a net.Conn over which IP packets flow.
//
// Typical usage:
//
//	cli, err := openvpn.Dial(ctx, &openvpn.Config{
//	    Network: "udp", RemoteAddr: "vpn.example:1194",
//	    TLSConfig: tlsCfg, TLSCryptV1: tlsCryptKeyBytes,
//	})
//	if err != nil { ... }
//	defer cli.Close()
//	conn := cli.Tunnel()
//	// Read/Write IP packets through conn.
package openvpn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-openvpn/internal/control"
	"github.com/n0madic/go-openvpn/internal/session"
	"github.com/n0madic/go-openvpn/internal/trace"
)

// ErrAuthFailed is returned from Dial (and surfaced to the caller without
// AutoReconnect retry) when the server replies AUTH_FAILED to our PUSH_REQUEST
// — credentials are wrong, the token is expired, or the account is banned.
// Retrying with the same Config would only repeat the failure and risks
// triggering provider-side IP bans, so AutoReconnect bails out immediately on
// this error.
var ErrAuthFailed = control.ErrAuthFailed

// HandshakeStage names a phase of the OpenVPN client handshake. It is
// re-exported from the internal trace package so callers don't have to
// import an internal path. Use Stage*-prefixed constants below.
type HandshakeStage = trace.HandshakeStage

// Handshake stages, in the order they are emitted by Run.
const (
	StageHardReset      = trace.StageHardReset
	StageTLSHandshake   = trace.StageTLSHandshake
	StageKeyMethod2Send = trace.StageKeyMethod2Send
	StageKeyMethod2Recv = trace.StageKeyMethod2Recv
	StagePushRequest    = trace.StagePushRequest
	StagePushReply      = trace.StagePushReply
	StageDataKeys       = trace.StageDataKeys
	StageComplete       = trace.StageComplete
)

// HandshakeEvent describes one handshake-stage notification.
type HandshakeEvent = trace.HandshakeEvent

// HandshakeTracer is the optional observer interface for handshake
// progress. A single OnHandshakeEvent is emitted at the start of each
// stage with a nil Err; if the stage fails, a second event with the
// same Stage and a non-nil Err is delivered and is the last event for
// that handshake. A final StageComplete event with nil Err marks
// success.
type HandshakeTracer = trace.HandshakeTracer

// RestartError is returned from Tunnel().Read/Write when the server sent us
// a RESTART control message. Inspect Delay for the server's suggested wait
// before reconnecting; Reason for any human-readable explanation.
//
// When Config.AutoReconnect is true the library handles RESTART internally
// and Tunnel().Read/Write transparently continue on the new session — callers
// never see RestartError in that mode.
type RestartError = session.RestartError

// IngressHandler is a fast-path callback that receives one decrypted
// inbound IP packet per call. See SetIngressHandler for the contract.
//
// The most important consumer is pkg/netstack, whose Net.New installs a
// handler that wraps each plaintext IP packet in a gVisor PacketBuffer
// and delivers it directly to the userspace TCP/IP stack — skipping the
// channel hop and read-loop goroutine that Tunnel().Read otherwise needs.
type IngressHandler = session.IngressHandler

// ErrServerExit is returned from Tunnel().Read/Write after the server sent
// a clean EXIT message.
var ErrServerExit = session.ErrServerExit

// ErrClosed is returned from Tunnel().Read/Write after the session has been
// closed without a more specific reason.
var ErrClosed = session.ErrClosed

// ErrReconnectGaveUp is returned when AutoReconnect is enabled and all
// reconnect attempts have failed.
var ErrReconnectGaveUp = errors.New("openvpn: reconnect failed (max attempts exceeded)")

// Config holds Dial parameters.
type Config struct {
	// Network is the underlying transport: "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6".
	Network string
	// RemoteAddr is host:port.
	RemoteAddr string

	// TLSConfig is used for the inner TLS 1.2/1.3 session.
	// At minimum: ServerName + RootCAs. For mTLS, also Certificates.
	TLSConfig *tls.Config

	// Username / Password — optional, sent only if either is non-empty.
	Username string
	Password string

	// TLSCryptV1 is a 256-byte (PEM-wrapped or raw) tls-crypt static key.
	// Exactly one of TLSCryptV1 / TLSCryptV2 must be set.
	TLSCryptV1 []byte
	// TLSCryptV2 is a tls-crypt-v2 client bundle (Kc || WKc, PEM-wrapped).
	TLSCryptV2 []byte

	// Ciphers is the IV_CIPHERS list (priority order). Defaults to
	// AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM.
	Ciphers []string

	// HandshakeTimeout caps the handshake duration. 0 = no timeout (rely on
	// context).
	HandshakeTimeout time.Duration

	// Reneg is the automatic soft-reset rekey interval (default 0 = disabled).
	// Mirrors OpenVPN's --reneg-sec; renamed away from "Seconds" because the
	// field is a time.Duration (staticcheck ST1011).
	Reneg time.Duration

	// AutoReconnect, when true, makes Tunnel().Read/Write transparently
	// re-establish the session when the server sends RESTART. Reconnects
	// use the same Config; the user code never sees RestartError. Callers
	// who want fine-grained control (e.g. UI status updates) can keep this
	// false and react to RestartError themselves.
	AutoReconnect bool
	// ReconnectMaxAttempts caps how many times AutoReconnect will retry
	// before surfacing ErrReconnectGaveUp. Zero means unlimited.
	ReconnectMaxAttempts int
	// ReconnectMaxInterval is the cap on exponential backoff between
	// reconnect attempts. Default 60s.
	ReconnectMaxInterval time.Duration

	// PeerInfoVersion overrides the IV_VER value sent in the peer-info
	// payload of KEY_METHOD 2. Empty defaults to "2.6.0". Use this to
	// mimic specific OpenVPN versions when the server enforces a minimum.
	PeerInfoVersion string

	// HandshakeTracer, when non-nil, receives notifications at each
	// handshake stage of every dialled (or reconnected) session.
	// Useful for production timing diagnostics and tests. nil disables
	// tracing entirely with zero overhead beyond an unused field.
	HandshakeTracer HandshakeTracer

	// Logger receives diagnostic events. nil ⇒ no logging.
	Logger *slog.Logger
}

// Stats is a snapshot of a Client's packet-flow counters and liveness
// timestamps. Counter fields aggregate across all sessions ever
// dialled by this Client — they survive AutoReconnect-driven session
// replacements so monitoring tools see a continuous view. Timestamp
// fields reflect the CURRENT session only; they reset on each
// reconnect (zero time means "no such observation yet").
type Stats struct {
	// Forwarded is the number of decrypted IP packets handed to the
	// Tunnel reader.
	Forwarded uint64
	// DroppedFull is the number of packets dropped because the Tunnel
	// reader could not keep up (ingress channel full).
	DroppedFull uint64
	// PingIn is the number of inbound keepalive PINGs filtered before
	// delivery.
	PingIn uint64
	// OpenFailed is the number of inbound AEAD decrypt failures.
	OpenFailed uint64
	// StrayHandshake is the number of tls-crypt unwrap drops that
	// looked like benign load-balancer / server-restart chatter
	// (stray HARD_RESET_SERVER_V2 or mismatched session-id).
	StrayHandshake uint64
	// HardResetIn is the subset of StrayHandshake events that were
	// specifically inbound P_CONTROL_HARD_RESET_SERVER_V2 — the
	// server explicitly asking us to renegotiate. Non-zero values
	// after the initial handshake indicate the server has forgotten
	// our session (typical aftermath of a laptop sleep). Drives the
	// hardResetWatch goroutine that forces AutoReconnect.
	HardResetIn uint64

	// LastInbound is the time of the most recent successfully
	// decrypted inbound packet of ANY kind (real traffic or PING).
	LastInbound time.Time
	// LastDataInbound is the time of the most recent NON-PING inbound
	// packet — the signal dataActivityWatch uses to distinguish a
	// data-path-stuck failure from genuine idle.
	LastDataInbound time.Time
	// LastUserOutbound is the time of the most recent Tunnel.Write —
	// real user traffic, not keepalive PINGs.
	LastUserOutbound time.Time

	// Reconnects is the number of completed AutoReconnect cycles
	// since this Client was dialled. Zero means we're still on the
	// initial session.
	Reconnects uint64
}

// Client is an active VPN session. When AutoReconnect is enabled, the
// Client survives RESTART events by replacing its internal session
// transparently to the Tunnel net.Conn caller.
type Client struct {
	cfg *Config
	log *slog.Logger

	mu sync.RWMutex
	s  *session.Session

	// reconnectMu serialises Tunnel-triggered reconnects so two parallel
	// Read+Write callers don't dial concurrently.
	reconnectMu sync.Mutex

	closed atomic.Bool

	// ctx is cancelled by Close so an in-flight reconnect stops promptly
	// instead of dialling a fresh session that nobody is going to consume.
	ctx    context.Context
	cancel context.CancelFunc

	// The single user-facing tunnel handle survives reconnects.
	tun *tunnel

	// hooksMu protects onReconnect.
	hooksMu     sync.Mutex
	onReconnect []*reconnectHook

	// ingressHandler is the latest handler installed via SetIngressHandler.
	// Stored at the Client level so AutoReconnect can re-apply it to every
	// freshly-dialled session before that session's first packet arrives.
	// atomic.Pointer is fine here: Client never reads it on a hot path —
	// the read happens once per Dial and once per reconnect.
	ingressHandler atomic.Pointer[IngressHandler]

	// statsMu guards cumStats, the running counter total absorbed
	// from every prior session before a reconnect swap. The current
	// session's counters are added on top whenever Stats is called.
	statsMu  sync.Mutex
	cumStats Stats
}

// reconnectHook bundles a registered callback with the slice element
// pointer that the detach func uses to find and remove this specific
// registration. Pointer identity is unique per registration, so the
// detach func's linear scan does not need a separate token field.
type reconnectHook struct {
	fn func(PushReply)
}

// OnReconnect registers fn to be invoked every time AutoReconnect installs a
// fresh session, AFTER the new session is published as the active one and
// the PushReply is queryable. fn receives the new PUSH_REPLY values so it
// can adapt: most importantly, the new `LocalIP`, `Gateway`, `Routes` and
// `MTU` — the server hands out a new tunnel IP per session, so anything
// using the tunnel IP (gVisor NIC address, SOCKS5 listener bind, etc.) must
// re-sync or its packets will be silently dropped by the server.
//
// fn runs synchronously inside the reconnect path; keep it short. Multiple
// hooks are invoked in registration order. Hooks registered after the
// session is closed will never fire.
//
// OnReconnect returns a detach func that removes the registration. Always
// call it when the hook's target lifetime ends earlier than the Client
// (e.g. a `pkg/netstack.Net` that is closed before its Client) — otherwise
// the closure keeps that target alive past its useful life and may
// dereference fields that have already been torn down. Calling the detach
// func twice or after Client.Close is safe and a no-op.
//
// `pkg/netstack` registers a hook here automatically via Net.New so the
// gVisor NIC tracks reconnects — no caller wiring required for that path.
// Net.Close invokes the returned detach.
func (c *Client) OnReconnect(fn func(PushReply)) (detach func()) {
	if fn == nil {
		return func() {}
	}
	hook := &reconnectHook{fn: fn}
	c.hooksMu.Lock()
	c.onReconnect = append(c.onReconnect, hook)
	c.hooksMu.Unlock()
	return func() {
		c.hooksMu.Lock()
		for i, h := range c.onReconnect {
			if h == hook {
				c.onReconnect = append(c.onReconnect[:i], c.onReconnect[i+1:]...)
				break
			}
		}
		c.hooksMu.Unlock()
	}
}

// SetIngressHandler installs h as the fast-path receive callback for
// the current session and every session installed by AutoReconnect
// after. While a non-nil handler is set, every decrypted non-PING
// inbound IP packet is delivered synchronously to h on the session's
// read-loop goroutine — h MUST be fast and non-blocking.
//
// The handler is wholly incompatible with Tunnel().Read: while a
// non-nil handler is installed, Tunnel().Read blocks indefinitely
// because the ingress channel never receives data. The Client owns a
// single ingress slot; SetIngressHandler is **not** a registration —
// each call replaces the current handler. Pick one consumer.
// pkg/netstack.New installs a handler automatically; callers using
// netstack should not also call SetIngressHandler directly.
//
// SetIngressHandler returns a detach function that clears the handler
// iff it is still the active one — useful from cleanup code where
// another consumer may have replaced ours in the meantime, and you'd
// rather leave them running than blindly rip them out. (pkg/netstack
// uses it from Net.Close for exactly this reason.) Passing nil h is
// the explicit force-clear path: it clears unconditionally and returns
// a no-op detach.
func (c *Client) SetIngressHandler(h IngressHandler) (detach func()) {
	if h == nil {
		c.ingressHandler.Store(nil)
		c.mu.RLock()
		s := c.s
		c.mu.RUnlock()
		if s != nil {
			s.SetIngressHandler(nil)
		}
		return func() {}
	}
	token := &h
	c.ingressHandler.Store(token)
	c.mu.RLock()
	s := c.s
	c.mu.RUnlock()
	if s != nil {
		s.SetIngressHandler(h)
	}
	return func() {
		// CompareAndSwap: clear iff our token is still the registered
		// one. If a later SetIngressHandler call replaced us, the CAS
		// fails and we leave the new handler intact — closing one
		// consumer should not knock out an unrelated one.
		if !c.ingressHandler.CompareAndSwap(token, nil) {
			return
		}
		c.mu.RLock()
		s := c.s
		c.mu.RUnlock()
		if s != nil {
			s.SetIngressHandler(nil)
		}
	}
}

// Stats returns a consistent snapshot of the Client's packet-flow
// counters and liveness timestamps. Counter fields are cumulative
// across reconnects; timestamps reflect only the currently active
// session. See the Stats type for field-level documentation.
func (c *Client) Stats() Stats {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	s := c.session()
	out := c.cumStats
	if s != nil {
		cur := s.Stats()
		out.Forwarded += cur.Forwarded
		out.DroppedFull += cur.DroppedFull
		out.PingIn += cur.PingIn
		out.OpenFailed += cur.OpenFailed
		out.StrayHandshake += cur.StrayHandshake
		out.HardResetIn += cur.HardResetIn
		out.LastInbound = cur.LastInbound
		out.LastDataInbound = cur.LastDataInbound
		out.LastUserOutbound = cur.LastUserOutbound
	}
	return out
}

// absorbStatsLocked folds the supplied session's lifetime counters
// into c.cumStats. Called from the reconnect path just before the
// session pointer is replaced so future Stats calls see a continuous
// running total. Caller must hold c.statsMu. A nil session is a no-op
// (initial dial doesn't have a previous session to absorb).
func (c *Client) absorbStatsLocked(s *session.Session) {
	if s == nil {
		return
	}
	c.foldStatsLocked(s.Stats())
}

// foldStatsLocked is the integer-merge half of absorbStatsLocked,
// factored out so unit tests can exercise the accumulation logic
// without standing up a real Session. Caller must hold c.statsMu.
func (c *Client) foldStatsLocked(st session.Stats) {
	c.cumStats.Forwarded += st.Forwarded
	c.cumStats.DroppedFull += st.DroppedFull
	c.cumStats.PingIn += st.PingIn
	c.cumStats.OpenFailed += st.OpenFailed
	c.cumStats.StrayHandshake += st.StrayHandshake
	c.cumStats.HardResetIn += st.HardResetIn
}

// FireOnReconnect invokes every registered OnReconnect hook with the
// supplied PushReply. The library calls this internally after AutoReconnect
// dials a fresh session; it is also exposed so external code can force a
// re-sync after an out-of-band event (e.g. an integration test that wants
// to simulate "the server handed us a new local IP" without spinning up
// another endpoint).
func (c *Client) FireOnReconnect(pr PushReply) {
	c.hooksMu.Lock()
	hooks := make([]func(PushReply), len(c.onReconnect))
	for i, h := range c.onReconnect {
		hooks[i] = h.fn
	}
	c.hooksMu.Unlock()
	for _, h := range hooks {
		h(pr)
	}
}

// Dial brings up the session. ctx scopes the handshake only — once Dial
// returns successfully, the Client outlives the ctx, so callers should use
// the idiomatic `ctx, cancel := context.WithTimeout(...); defer cancel()`
// pattern without fear of tearing the session down.
//
// To terminate the Client, call Close. To make an external signal (SIGINT,
// shutdown channel) also unblock blocked Tunnel I/O, run:
//
//	go func() { <-ctx.Done(); cli.Close() }()
//
// alongside Dial.
func Dial(ctx context.Context, cfg *Config) (*Client, error) {
	if cfg == nil {
		return nil, errInvalidConfig
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	s, err := session.Dial(ctx, sessionCfg(cfg))
	if err != nil {
		return nil, err
	}
	// cCtx is the Client's lifetime context — rooted at Background so a
	// caller's `defer cancel()` of their Dial ctx (idiomatic Go for releasing
	// the handshake context) doesn't tear down the resulting Client. Close()
	// is the supported way to terminate the Client. Callers that want
	// SIGINT to also unblock Tunnel I/O should run their own
	// `go func() { <-ctx.Done(); cli.Close() }()` watcher.
	cCtx, cancel := context.WithCancel(context.Background())
	c := &Client{cfg: cfg, log: log, s: s, ctx: cCtx, cancel: cancel}
	c.tun = &tunnel{c: c}
	// When AutoReconnect is on, spawn a background watcher that drives
	// reconnect from session-internal triggers (wakeDetectorWatch,
	// pingRestartWatch, hardResetWatch, dataActivityWatch). Without it,
	// reconnect only happens when Tunnel.Read or Tunnel.Write observes
	// the error — but consumers that drive the data path via
	// SetIngressHandler (pkg/netstack and downstream gVisor) never sit
	// in Tunnel.Read. With no outbound traffic either (the wake-up
	// scenario where every gVisor TCP connection has long since timed
	// out and apps haven't retried yet) the RestartError stays
	// unconsumed and the tunnel sits in zombie state — exactly the
	// post-suspend bug we hit live.
	if cfg.AutoReconnect {
		go c.sessionWatcher()
	}
	return c, nil
}

// sessionCfg projects the public Config onto the internal session.Config.
func sessionCfg(cfg *Config) session.Config {
	return session.Config{
		Network:          cfg.Network,
		RemoteAddr:       cfg.RemoteAddr,
		TLSConfig:        cfg.TLSConfig,
		Username:         cfg.Username,
		Password:         cfg.Password,
		TLSCryptV1:       cfg.TLSCryptV1,
		TLSCryptV2:       cfg.TLSCryptV2,
		Ciphers:          cfg.Ciphers,
		HandshakeTimeout: cfg.HandshakeTimeout,
		Reneg:            cfg.Reneg,
		PeerInfoVersion:  cfg.PeerInfoVersion,
		HandshakeTracer:  cfg.HandshakeTracer,
		Logger:           cfg.Logger,
	}
}

// session returns the currently-active session (atomic-snapshot).
func (c *Client) session() *session.Session {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.s
}

// reconnect tears down the current session and dials a fresh one. Respects
// the server's suggested delay, then exponential backoff up to
// ReconnectMaxInterval. Returns ErrReconnectGaveUp on exhaustion or
// context.Canceled when the Client is closed mid-reconnect.
//
// callCtx is the caller's per-operation context (e.g. one derived from
// Tunnel.SetReadDeadline). It is honoured during backoff sleeps and the
// reconnect dial so a Read/Write with a tight deadline doesn't get pinned
// inside reconnect waiting on a slow RESTART/redial — it returns to the
// caller as context.DeadlineExceeded and lets it decide whether to retry.
// The new session itself, however, is rooted at c.ctx so it survives the
// per-call deadline expiring.
//
// Serialised via reconnectMu so concurrent Tunnel Read+Write callers don't
// each initiate their own reconnect. The failed parameter is the session
// the caller saw fail — used to detect "another goroutine already
// reconnected" without relying on CloseErr (which is only set for
// protocol-level closures like RESTART, not generic Close).
func (c *Client) reconnect(callCtx context.Context, failed *session.Session, initialDelay time.Duration) error {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	if c.closed.Load() {
		return ErrClosed
	}

	// Did another goroutine already reconnect on this failure? Compare
	// session pointers — a successful reconnect replaces c.s atomically
	// under c.mu.
	if cur := c.session(); cur != nil && cur != failed {
		return nil
	}

	maxInterval := c.cfg.ReconnectMaxInterval
	if maxInterval <= 0 {
		maxInterval = 60 * time.Second
	}
	maxAttempts := c.cfg.ReconnectMaxAttempts // 0 = unlimited

	if failed != nil {
		_ = failed.Close()
	}

	wait := initialDelay
	for attempt := 1; ; attempt++ {
		if c.closed.Load() {
			return ErrClosed
		}
		if err := callCtx.Err(); err != nil {
			return err
		}
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-t.C:
			case <-callCtx.Done():
				t.Stop()
				return callCtx.Err()
			case <-c.ctx.Done():
				t.Stop()
				return c.ctx.Err()
			}
		}
		if c.closed.Load() {
			return ErrClosed
		}

		// Dial under c.ctx (so the resulting session outlives callCtx) but
		// watch callCtx so a per-call deadline can interrupt a slow Dial.
		// defer close(stopWatch) covers the path where session.Dial panics
		// — without it the watcher goroutine would leak until c.ctx fires.
		dialCtx, dialCancel := context.WithCancel(c.ctx)
		stopWatch := make(chan struct{})
		stopWatchClosed := false
		closeStopWatch := func() {
			if !stopWatchClosed {
				close(stopWatch)
				stopWatchClosed = true
			}
		}
		defer closeStopWatch()
		go func() {
			select {
			case <-callCtx.Done():
				dialCancel()
			case <-stopWatch:
			}
		}()
		s, err := session.Dial(dialCtx, sessionCfg(c.cfg))
		closeStopWatch()
		dialCancel()

		if err != nil && errors.Is(err, ErrAuthFailed) {
			// Terminal: re-dial with the same credentials will keep failing
			// the same way. Surfacing this immediately also avoids hammering
			// the server, which on many providers (ProtonVPN, etc.) leads to
			// an IP ban.
			c.log.Warn("auth failed during reconnect; giving up", "attempt", attempt, "err", err)
			return fmt.Errorf("openvpn: authentication failed on reconnect: %w", err)
		}

		if err == nil {
			if c.closed.Load() {
				// User called Close during the dial — discard the freshly
				// created session so its goroutines tear down cleanly.
				_ = s.Close()
				return ErrClosed
			}
			if callCtx.Err() != nil {
				// Caller bailed (deadline) mid-dial. Don't leak the session.
				_ = s.Close()
				return callCtx.Err()
			}
			// Absorb the failed session's lifetime counters into cumStats
			// before we lose visibility of it. Without this, every
			// reconnect would silently zero the running totals.
			c.statsMu.Lock()
			c.absorbStatsLocked(failed)
			c.cumStats.Reconnects++
			c.statsMu.Unlock()
			c.mu.Lock()
			c.s = s
			// Re-apply any persistent ingress handler to the fresh session
			// before unlocking. Doing this in the same critical section as
			// the c.s swap means no observer (including handleDataIn on the
			// new readLoop) ever sees c.s = new without the handler attached,
			// so the very first inbound packet on the new session takes the
			// fast path instead of falling into the consumerless ingressCh.
			if hp := c.ingressHandler.Load(); hp != nil {
				s.SetIngressHandler(*hp)
			}
			c.mu.Unlock()
			c.log.Info("reconnect successful", "attempt", attempt)
			// Notify subscribers (e.g. pkg/netstack updating the gVisor NIC
			// to the new tunnel IP). Fire AFTER publishing the new session
			// so c.PushedOptions() inside a hook sees the fresh values.
			c.FireOnReconnect(c.PushedOptions())
			return nil
		}
		c.log.Warn("reconnect failed", "attempt", attempt, "err", err)
		if err := callCtx.Err(); err != nil {
			return err
		}
		if maxAttempts > 0 && attempt >= maxAttempts {
			return fmt.Errorf("%w: last error: %v", ErrReconnectGaveUp, err)
		}
		wait = backoffDelay(attempt, maxInterval)
	}
}

// sessionWatchPeriod is how often the background watcher polls the
// current session for a RestartError. Short enough that a wake-from-
// suspend is detected within sub-second once wakeDetectorWatch fires,
// long enough that an idle client costs nothing measurable.
const sessionWatchPeriod = 500 * time.Millisecond

// sessionWatcher polls the active session's CloseErr and drives
// reconnect when it sees a *RestartError. Runs only when AutoReconnect
// is enabled. The exit conditions mirror the Tunnel.Read/Write
// reconnect path:
//
//   - Client closed (Close was called): exit immediately.
//   - Reconnect returned ErrAuthFailed: terminal, do not retry.
//   - Reconnect returned ErrReconnectGaveUp: max-attempts exhausted; the
//     library has surrendered, watcher exits.
//   - Session closed for a non-restart reason (caller-initiated Close,
//     fatal protocol error): no reconnect, watcher exits.
//
// The watcher is intentionally race-tolerant with Tunnel.Read/Write
// callers that also enter reconnect: c.reconnectMu serialises both
// paths, and reconnect's "another goroutine already swapped the
// session" early return makes the second caller a no-op.
func (c *Client) sessionWatcher() {
	ticker := time.NewTicker(sessionWatchPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
		if c.closed.Load() {
			return
		}
		s := c.session()
		if s == nil {
			return
		}
		closeErr := s.CloseErr()
		if closeErr == nil {
			continue
		}
		var re *RestartError
		if !errors.As(closeErr, &re) {
			// Non-restart close (manual Close or unrecoverable error).
			// AutoReconnect is not the right answer; let the user notice
			// via Tunnel.Read/Write or Client.Close().
			return
		}
		c.log.Info("session watcher: RestartError observed; initiating reconnect",
			"reason", re.Reason, "delay", re.Delay)
		rcErr := c.reconnect(c.ctx, s, re.Delay)
		if rcErr == nil {
			// Reconnect installed a fresh session; loop continues to
			// monitor the new one.
			continue
		}
		if errors.Is(rcErr, ErrAuthFailed) ||
			errors.Is(rcErr, ErrReconnectGaveUp) ||
			errors.Is(rcErr, ErrClosed) ||
			errors.Is(rcErr, context.Canceled) {
			c.log.Error("session watcher: terminal reconnect failure; stopping watcher",
				"err", rcErr)
			return
		}
		// Transient failure — reconnect itself has internal backoff so
		// hammering would be redundant. Continue to the next tick;
		// since the failed session still has CloseErr() set, the next
		// iteration will retry immediately.
		c.log.Warn("session watcher: reconnect failed; will retry on next tick",
			"err", rcErr)
	}
}

// backoffDelay computes the exponential backoff for reconnect attempt n
// (1-indexed). Starts at 1s and doubles each attempt, capped at maxInterval.
// Conservative cap on the shift (30) prevents overflow on absurd attempt
// counts; in practice we hit maxInterval long before that.
func backoffDelay(attempt int, maxInterval time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	shift := min(attempt-1, 30)
	d := time.Second << uint(shift)
	if d <= 0 {
		return maxInterval
	}
	return min(d, maxInterval)
}

// Tunnel returns a net.Conn through which user IP packets flow. Each Read
// returns exactly one decrypted IP packet; each Write sends exactly one.
//
// The returned handle is stable across AutoReconnect-driven session
// replacements: a Read that was blocked when the server sent RESTART will
// transparently resume on the new session (assuming reconnect succeeds).
func (c *Client) Tunnel() net.Conn { return c.tun }

// PushedOptions returns the parsed PUSH_REPLY from the current session.
// After AutoReconnect, the values reflect the latest session's reply.
func (c *Client) PushedOptions() PushReply {
	pr := c.session().PushReply()
	return PushReply{
		LocalIP:      pr.LocalIP,
		Netmask:      pr.Netmask,
		Gateway:      pr.Gateway,
		LocalIP6:     pr.LocalIP6,
		RemoteIP6:    pr.RemoteIP6,
		Routes:       pr.Routes,
		Routes6:      pr.Routes6,
		DNS:          pr.DNS,
		MTU:          pr.MTU,
		Cipher:       pr.Cipher,
		PeerID:       pr.PeerID,
		PingInterval: pr.PingInterval,
		PingRestart:  pr.PingRestart,
		Topology:     pr.Topology,
	}
}

// TunnelMTU returns the negotiated tunnel MTU.
func (c *Client) TunnelMTU() int {
	mtu := c.session().PushReply().MTU
	if mtu <= 0 {
		mtu = 1500
	}
	return mtu
}

// UnderlayLocalAddr returns the local socket address of the encrypted transport.
func (c *Client) UnderlayLocalAddr() net.Addr { return c.session().UnderlayLocalAddr() }

// UnderlayRemoteAddr returns the remote socket address of the encrypted transport.
func (c *Client) UnderlayRemoteAddr() net.Addr { return c.session().UnderlayRemoteAddr() }

// Rekey performs a synchronous soft-reset on the current session.
func (c *Client) Rekey(ctx context.Context) error { return c.session().Rekey(ctx) }

// Logger returns the slog.Logger configured for this client. Hook consumers
// (e.g. pkg/netstack) can use this to log with the same handler/level as
// the rest of the openvpn stack rather than relying on slog.Default().
func (c *Client) Logger() *slog.Logger { return c.log }

// RequestRestart tells the current session to close with a *RestartError so
// AutoReconnect (when enabled) re-dials with a fresh peer-id, local IP and
// NAT mapping. The Tunnel handle survives, blocked Reads transparently
// resume on the new session.
//
// Useful when an application-level signal indicates the data plane is dead
// (DNS-over-tunnel timing out repeatedly, watchdog probes failing, etc.) —
// the OpenVPN protocol itself can't always distinguish "tunnel healthy" from
// "tunnel zombie with control plane still chatting", so the consumer of the
// tunnel is best placed to declare it broken.
//
// No-op if the client is closed or AutoReconnect is off (in which case the
// session ends and Tunnel.Read/Write surface the RestartError to the caller).
func (c *Client) RequestRestart(reason string) {
	if c.closed.Load() {
		return
	}
	if s := c.session(); s != nil {
		s.RequestRestart(reason)
	}
}

// Close tears down the session. Idempotent. Cancels any in-flight
// AutoReconnect attempt so no orphan session is left behind.
func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	if c.cancel != nil {
		c.cancel()
	}
	// Wait briefly for a reconnect dial in progress to release its lock,
	// so we close whatever session ends up active. Without this we might
	// race a successful reconnect — c.session() returns the old one and
	// we close it, but the new one (just installed) keeps running.
	c.reconnectMu.Lock()
	s := c.session()
	c.reconnectMu.Unlock()
	if s != nil {
		return s.Close()
	}
	return nil
}
