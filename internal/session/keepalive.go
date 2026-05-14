// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"context"
	"log/slog"
	"time"

	"github.com/n0madic/go-openvpn/internal/data"
	"github.com/n0madic/go-openvpn/internal/proto"
)

// Default keepalive timings used when the server's PUSH_REPLY omits
// `ping`/`ping-restart`. Several real providers (ProtonVPN among them)
// don't push these values, so honouring the push reply verbatim would
// leave the tunnel with no keepalive at all and the server would drop
// the session after its own ping-restart fires. Pushed values always
// win when present.
const (
	defaultPingInterval = 15 * time.Second
	defaultPingRestart  = 60 * time.Second

	// dataActivityCheckPeriod is how often dataActivityWatch samples
	// last-inbound/last-outbound timestamps.
	dataActivityCheckPeriod = 5 * time.Second

	// dataActivityWarmup is the grace period after session-up during
	// which dataActivityWatch never fires. Lets the tunnel settle and
	// avoids a false positive from a transient stall during the first
	// burst of post-handshake traffic.
	dataActivityWarmup = 60 * time.Second

	// dataActivityStuckThreshold is the maximum allowed gap between
	// "user sent something" and "got real data back". When the user is
	// actively sending traffic (lastUserOutbound recent) but no non-PING
	// inbound has arrived for at least this long, we conclude the data
	// path is stuck and trigger a reconnect — pingRestartWatch alone
	// misses this because server-side PINGs keep lastInbound fresh.
	dataActivityStuckThreshold = 60 * time.Second

	// hardResetCheckPeriod is how often hardResetWatch samples the
	// statsHardResetIn counter.
	hardResetCheckPeriod = 5 * time.Second

	// hardResetThreshold is the number of inbound
	// P_CONTROL_HARD_RESET_SERVER_V2 events tolerated before we force
	// AutoReconnect. The server only sends HARD_RESET when it has lost
	// state; a single retry is benign (network burble during initial
	// handshake), but 3+ within a short window means the server has
	// definitively forgotten our session and we're now in a useless
	// "we think we're connected, server doesn't" zombie. Typical
	// after-laptop-sleep aftermath.
	hardResetThreshold = 3

	// wakeDetectGapThreshold is the minimum tick gap (relative to the
	// expected sampling period) that we treat as evidence the host slept.
	// macOS App Nap and ordinary scheduler delays produce gaps under a
	// few seconds; anything beyond this is almost certainly suspend.
	wakeDetectPeriod       = 1 * time.Second
	wakeDetectGapThreshold = 10 * time.Second
)

// applyKeepaliveDefaults fills in ping/ping-restart on the parsed PushReply
// when the server didn't push them. Pushed values always win.
func (s *Session) applyKeepaliveDefaults() {
	if s.pushReply.PingInterval <= 0 {
		s.pushReply.PingInterval = defaultPingInterval
	}
	if s.pushReply.PingRestart <= 0 {
		s.pushReply.PingRestart = defaultPingRestart
	}
}

// keepaliveLoop seals the OpenVPN PING magic into a P_DATA_V2 packet on the
// active slot when no outbound traffic has happened for at least
// PushReply.PingInterval. Exits on session shutdown.
//
// Per OpenVPN protocol semantics ("Ping remote ... if no packets have been
// sent for at least n seconds" — link-options.rst), a PING is only emitted
// when no real user-data outbound traffic has happened within the last
// interval — `forward.c::process_outgoing_link` resets `ping_send_interval`
// after every outbound packet, *including PINGs themselves*. We mirror
// that by checking BOTH s.lastUserOutbound (set by Session.WriteCtx;
// PINGs intentionally don't touch it so dataActivityWatch can tell user
// traffic apart from keepalive) AND a loop-local `lastPingSent` (so a
// PING also resets the schedule, otherwise the fine-grained ticker would
// keep firing PINGs back-to-back during idle).
//
// We sample at interval/4 (≥250ms) rather than once per interval — that
// way the next PING fires promptly once the silence threshold is crossed,
// instead of being delayed by up to a full interval.
//
// Transient WritePacket errors (kernel SO_SNDBUF saturation under burst
// load → ENOBUFS) are non-fatal: we log at Debug and wait for the next
// tick. Stopping the loop on the first hiccup would silently mute
// keepalives for the rest of the session.
func (s *Session) keepaliveLoop(ctx context.Context) {
	interval := s.pushReply.PingInterval
	if interval <= 0 {
		return
	}
	period := interval / 4
	if period < 250*time.Millisecond {
		period = 250 * time.Millisecond
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	// Seed lastPingSent to "now" — same effect as the upstream OpenVPN
	// event_timeout that starts armed at session-up. A PING is due only
	// after `interval` of silence relative to this moment.
	lastPingSent := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if s.closed.Load() {
				return
			}
			// "No outbound for at least `interval`" guard, matching
			// upstream OpenVPN where any outbound packet resets the
			// ping schedule. Take the most recent of user data and
			// our own previous PING — whichever is newer pushes the
			// next PING further out.
			lastOut := time.Unix(0, s.lastUserOutbound.Load())
			//nolint:gocritic // time.Time isn't Ordered; max() wouldn't compile.
			if lastPingSent.After(lastOut) {
				lastOut = lastPingSent
			}
			if now.Sub(lastOut) < interval {
				continue
			}
			slot := s.slots.Active()
			if slot == nil {
				continue
			}
			wire, err := slot.Seal(proto.PingMagic[:])
			if err != nil {
				s.log.Debug("keepalive seal failed", "err", err)
				continue
			}
			werr := s.transport.WritePacket(ctx, wire)
			data.ReleaseSealedBuf(wire)
			if werr != nil {
				s.log.Debug("keepalive write failed (will retry next tick)", "err", werr)
				continue
			}
			lastPingSent = now
			s.log.Debug("keepalive PING sent", "kid", slot.KeyID)
		}
	}
}

// statsLogPeriod is how often statsLogger emits a packet-flow summary.
const statsLogPeriod = 30 * time.Second

// statsLogger periodically logs the session's packet-flow counters so an
// operator can see at a glance whether the tunnel is healthy or whether
// inbound packets are being dropped at the ingress channel (which would
// have been the silent failure mode before non-blocking handleDataIn).
// Logs at WARN when drops are non-zero (operator needs to know), DEBUG
// otherwise. The final tick before shutdown is dispatched from Close()
// itself, not from here.
func (s *Session) statsLogger(ctx context.Context) {
	ticker := time.NewTicker(statsLogPeriod)
	defer ticker.Stop()
	var prevForwarded, prevDropped, prevPingIn, prevOpenFailed, prevStray, prevHardReset uint64
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			forwarded := s.statsForwarded.Load()
			dropped := s.statsDroppedFull.Load()
			pingIn := s.statsPingIn.Load()
			openFailed := s.statsOpenFailed.Load()
			stray := s.statsStrayHandshake.Load()
			hardReset := s.statsHardResetIn.Load()
			deltaForwarded := forwarded - prevForwarded
			deltaDropped := dropped - prevDropped
			deltaPingIn := pingIn - prevPingIn
			deltaOpenFailed := openFailed - prevOpenFailed
			deltaStray := stray - prevStray
			deltaHardReset := hardReset - prevHardReset
			prevForwarded = forwarded
			prevDropped = dropped
			prevPingIn = pingIn
			prevOpenFailed = openFailed
			prevStray = stray
			prevHardReset = hardReset
			// Time since last successful inbound — the strongest signal
			// that the tunnel is or isn't carrying real bytes RIGHT NOW.
			sinceLastIn := now.Sub(time.Unix(0, s.lastDataInbound.Load()))
			level := slog.LevelDebug
			// Anything unusual deserves WARN so it surfaces without -v:
			// ingress drops, decrypt failures, server-driven re-handshake
			// attempts, or a stuck data path (no new forwarded packets
			// for at least one interval).
			if deltaDropped > 0 || deltaOpenFailed > 0 || deltaHardReset > 0 ||
				(deltaForwarded == 0 && sinceLastIn > statsLogPeriod) {
				level = slog.LevelWarn
			}
			s.log.Log(ctx, level, "session stats",
				"interval", statsLogPeriod,
				"delta_forwarded", deltaForwarded,
				"delta_dropped", deltaDropped,
				"delta_ping_in", deltaPingIn,
				"delta_open_failed", deltaOpenFailed,
				"delta_stray_handshake", deltaStray,
				"delta_hard_reset_in", deltaHardReset,
				"since_last_data_in", sinceLastIn.Round(time.Millisecond),
				"forwarded_total", forwarded,
				"dropped_total", dropped,
				"ping_in_total", pingIn,
				"open_failed_total", openFailed,
				"stray_handshake_total", stray,
				"hard_reset_in_total", hardReset,
			)
		}
	}
}

// dataActivityWatch is a watchdog that detects the "tunnel alive at
// protocol level but data path stuck" failure mode and forces a reconnect.
//
// The standard pingRestartWatch fires only on *complete* inbound silence,
// but PingMagic packets keep s.lastInbound fresh. Several real failure
// modes (gVisor link endpoint stall, server-side data-path glitch) leave
// PINGs flowing while user traffic is silently dropped — pingRestartWatch
// never fires, AutoReconnect never kicks in, and the user has to restart
// the process manually.
//
// This watch fires when the user is actively sending traffic but no
// real (non-PING) inbound packet has arrived for dataActivityStuckThreshold.
// The "user actively sending" guard prevents spurious restarts during
// idle periods (no outbound → no expectation of inbound).
//
// Closing is dispatched on a fresh goroutine so this watcher (managed
// by s.workers) returns before Close calls s.workers.Wait, avoiding a
// self-wait deadlock — same pattern as pingRestartWatch.
func (s *Session) dataActivityWatch(ctx context.Context) {
	warmup := s.cfg.DataActivityWarmup
	if warmup <= 0 {
		warmup = dataActivityWarmup
	}
	threshold := s.cfg.DataActivityStuckThreshold
	if threshold <= 0 {
		threshold = dataActivityStuckThreshold
	}
	// Sample at no faster than 100ms (avoid CPU burn on tiny test thresholds)
	// and no slower than dataActivityCheckPeriod (default sampling rate).
	period := threshold / 4
	switch {
	case period < 100*time.Millisecond:
		period = 100 * time.Millisecond
	case period > dataActivityCheckPeriod:
		period = dataActivityCheckPeriod
	}
	start := time.Now()
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if now.Sub(start) < warmup {
				continue
			}
			lastOut := time.Unix(0, s.lastUserOutbound.Load())
			lastIn := time.Unix(0, s.lastDataInbound.Load())
			sinceOut := now.Sub(lastOut)
			sinceIn := now.Sub(lastIn)
			// The user is "actively sending" if they wrote something
			// within the stuck-threshold window. If they're idle, we
			// have no business demanding inbound data.
			if sinceOut >= threshold {
				continue
			}
			if sinceIn < threshold {
				continue
			}
			s.log.Warn("data-activity watch: user sending but no inbound data; forcing reconnect",
				"since_outbound", sinceOut,
				"since_inbound", sinceIn,
				"threshold", threshold,
				"forwarded", s.statsForwarded.Load(),
				"dropped_full", s.statsDroppedFull.Load(),
				"ping_in", s.statsPingIn.Load(),
				"open_failed", s.statsOpenFailed.Load(),
			)
			s.setCloseErr(&RestartError{Reason: "data-activity stuck"})
			go func() { _ = s.Close() }()
			return
		}
	}
}

// pingRestartWatch closes the session with a *RestartError when no inbound
// data packet (real traffic or PING) has been observed for at least
// PushReply.PingRestart. Mirrors OpenVPN's ping-restart semantic.
//
// Closing is dispatched on a fresh goroutine so this watcher (which itself
// is managed by s.workers) returns before Close calls s.workers.Wait,
// avoiding a self-wait deadlock.
func (s *Session) pingRestartWatch(ctx context.Context) {
	restart := s.pushReply.PingRestart
	if restart <= 0 {
		return
	}
	// Poll at no slower than every second so a small restart value (used in
	// tests, and in some real configs) reacts promptly, but no faster than
	// 100ms so we don't burn CPU on long-living idle sessions.
	period := restart / 4
	switch {
	case period < 100*time.Millisecond:
		period = 100 * time.Millisecond
	case period > time.Second:
		period = time.Second
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			last := time.Unix(0, s.lastInbound.Load())
			idle := now.Sub(last)
			if idle < restart {
				continue
			}
			s.log.Warn("ping-restart fired, requesting reconnect",
				"idle", idle, "threshold", restart)
			s.setCloseErr(&RestartError{Reason: "ping-restart timeout"})
			// Detach Close from this goroutine so s.workers.Wait inside
			// Close doesn't deadlock waiting on us.
			go func() { _ = s.Close() }()
			return
		}
	}
}

// hardResetWatch closes the session with a *RestartError when the server
// keeps sending P_CONTROL_HARD_RESET_SERVER_V2 packets — that's the server
// telling us "I lost your session, please re-handshake". `handleControlIn`
// counts these in statsHardResetIn but otherwise drops them; without this
// watch the client would stay in a useless "we think we're connected,
// server doesn't" zombie state until the user notices and restarts.
//
// Threshold-based rather than instant so a single retry during a network
// burble doesn't reset the session needlessly. hardResetThreshold (3)
// within a sampling window is conclusive evidence the server has
// forgotten us — typical aftermath of a laptop suspend/resume cycle that
// outran the server's ping-restart.
func (s *Session) hardResetWatch(ctx context.Context) {
	ticker := time.NewTicker(hardResetCheckPeriod)
	defer ticker.Stop()
	var baseline uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := s.statsHardResetIn.Load()
			if current-baseline < hardResetThreshold {
				continue
			}
			s.log.Warn("hard-reset watch fired, server lost our session; forcing reconnect",
				"hard_reset_in_total", current,
				"hard_reset_since_baseline", current-baseline,
				"threshold", hardResetThreshold,
			)
			s.setCloseErr(&RestartError{Reason: "server hard-reset"})
			go func() { _ = s.Close() }()
			return
		}
	}
}

// wakeDetectorWatch detects a wall-clock jump — the textbook symptom of a
// laptop suspending and waking some seconds/minutes later — and forces a
// reconnect. After a suspend the server has almost certainly dropped our
// session (its ping-restart elapsed while our socket was frozen), and
// continuing on the old keys produces the "tunnel looks alive, nothing
// works" state. Detecting suspend lets AutoReconnect re-handshake
// immediately instead of waiting on pingRestartWatch or dataActivityWatch
// to fail.
//
// Implementation: tick every wakeDetectPeriod and check `now.Sub(lastTick)`.
// A normal tick lands within tens of milliseconds; anything larger than
// wakeDetectGapThreshold (10s) means the runtime was paused, which on a
// healthy host only happens during suspend.
func (s *Session) wakeDetectorWatch(ctx context.Context) {
	lastTick := time.Now()
	ticker := time.NewTicker(wakeDetectPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			gap := now.Sub(lastTick)
			lastTick = now
			if gap < wakeDetectGapThreshold {
				continue
			}
			s.log.Warn("wake detected — host appears to have slept; forcing reconnect",
				"gap", gap, "threshold", wakeDetectGapThreshold)
			s.setCloseErr(&RestartError{Reason: "wake from sleep"})
			go func() { _ = s.Close() }()
			return
		}
	}
}
