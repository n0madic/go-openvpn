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

	// dataActivityWarmupFast / dataActivityStuckThresholdFast /
	// dataActivityFastWindow tighten the watchdog during the first
	// FastWindow after session-up. A freshly-installed session is
	// empirically much more likely to be wedged than a steady-state
	// one: post-reconnect failure modes include server-side state
	// loss for the previous peer-id, source-port-keyed rate limits
	// surviving the reconnect, NAT mapping drift, and gVisor TCP
	// zombies retransmitting on the previous tunnel IP. Spending
	// the full 60s steady threshold confirming each of those is the
	// difference between "tunnel jitters for a few seconds" and
	// "tunnel froze for over a minute". Two minutes is generous
	// enough that any genuine handshake/app-discovery latency
	// straddling a reconnect falls inside the window; past that we
	// trust the relationship enough to revert to the more
	// false-positive-resistant steady values.
	dataActivityWarmupFast         = 10 * time.Second
	dataActivityStuckThresholdFast = 20 * time.Second
	dataActivityFastWindow         = 2 * time.Minute

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
	period := max(interval/4, 250*time.Millisecond)
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
				s.statsOutboundErr.Add(1)
				s.lastOutboundErrNs.Store(time.Now().UnixNano())
				// Promote to WARN so the operator sees keepalive write
				// failures without -v=debug. Recurring writes will
				// surface in the next stats tick too.
				s.log.Warn("keepalive WritePacket failed",
					"err", werr,
					"outbound_err_total", s.statsOutboundErr.Load(),
				)
				continue
			}
			s.statsOutboundOK.Add(1)
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
	var prevOutOK, prevOutErr, prevENOBUFS uint64

	// transportENOBUFS is an optional capability some transports expose
	// (UDP does). When the kernel send buffer fills up the transport
	// blocks the writer goroutine for a brief backoff instead of
	// returning the error straight back to gVisor TCP — exposing the
	// retry count lets operators see backpressure activity without
	// the WARN flood we used to get from amplified retransmits.
	type enobufsReporter interface {
		ENOBUFSRetries() uint64
	}
	enobufsLoader := func() uint64 { return 0 }
	if r, ok := s.transport.(enobufsReporter); ok {
		enobufsLoader = r.ENOBUFSRetries
	}
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
			outOK := s.statsOutboundOK.Load()
			outErr := s.statsOutboundErr.Load()
			enobufs := enobufsLoader()
			deltaForwarded := forwarded - prevForwarded
			deltaDropped := dropped - prevDropped
			deltaPingIn := pingIn - prevPingIn
			deltaOpenFailed := openFailed - prevOpenFailed
			deltaStray := stray - prevStray
			deltaHardReset := hardReset - prevHardReset
			deltaOutOK := outOK - prevOutOK
			deltaOutErr := outErr - prevOutErr
			deltaENOBUFS := enobufs - prevENOBUFS
			prevForwarded = forwarded
			prevDropped = dropped
			prevPingIn = pingIn
			prevOpenFailed = openFailed
			prevStray = stray
			prevHardReset = hardReset
			prevOutOK = outOK
			prevOutErr = outErr
			prevENOBUFS = enobufs
			// Time since last successful inbound — the strongest signal
			// that the tunnel is or isn't carrying real bytes RIGHT NOW.
			sinceLastIn := now.Sub(time.Unix(0, s.lastDataInbound.Load()))
			level := slog.LevelDebug
			// Anything unusual deserves WARN so it surfaces without -v:
			// ingress drops, decrypt failures, server-driven re-handshake
			// attempts, outbound write errors, sustained kernel buffer
			// pressure (ENOBUFS backoff happening a lot), or a stuck
			// data path (no new forwarded packets for at least one
			// interval).
			if deltaDropped > 0 || deltaOpenFailed > 0 || deltaHardReset > 0 || deltaOutErr > 0 ||
				deltaENOBUFS > 10 ||
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
				"delta_outbound_ok", deltaOutOK,
				"delta_outbound_err", deltaOutErr,
				"delta_enobufs_retries", deltaENOBUFS,
				"since_last_data_in", sinceLastIn.Round(time.Millisecond),
				"forwarded_total", forwarded,
				"dropped_total", dropped,
				"ping_in_total", pingIn,
				"open_failed_total", openFailed,
				"stray_handshake_total", stray,
				"hard_reset_in_total", hardReset,
				"outbound_ok_total", outOK,
				"outbound_err_total", outErr,
				"enobufs_retries_total", enobufs,
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
// real (non-PING) inbound packet has arrived for the active threshold.
// The "user actively sending" guard prevents spurious restarts during
// idle periods (no outbound → no expectation of inbound).
//
// Adaptive thresholds: for the first DataActivityFastWindow after
// session-up we use the tighter fast warmup / threshold pair; after
// that we relax to the steady values. A freshly-installed session is
// empirically more likely to be wedged than a steady-state one — see
// the constant block above for the failure-mode catalogue. Outside
// the fast window the longer steady threshold keeps the watchdog from
// false-firing on normal app-level slowdowns.
//
// Closing is dispatched on a fresh goroutine so this watcher (managed
// by s.workers) returns before Close calls s.workers.Wait, avoiding a
// self-wait deadlock — same pattern as pingRestartWatch.
func (s *Session) dataActivityWatch(ctx context.Context) {
	warmupSteady := s.cfg.DataActivityWarmup
	if warmupSteady <= 0 {
		warmupSteady = dataActivityWarmup
	}
	thresholdSteady := s.cfg.DataActivityStuckThreshold
	if thresholdSteady <= 0 {
		thresholdSteady = dataActivityStuckThreshold
	}
	warmupFast := s.cfg.DataActivityWarmupFast
	if warmupFast <= 0 {
		warmupFast = dataActivityWarmupFast
	}
	thresholdFast := s.cfg.DataActivityStuckThresholdFast
	if thresholdFast <= 0 {
		thresholdFast = dataActivityStuckThresholdFast
	}
	fastWindow := s.cfg.DataActivityFastWindow
	if fastWindow <= 0 {
		fastWindow = dataActivityFastWindow
	}
	// Clamp fast values so they never EXCEED steady — a "fast" phase
	// that's actually slower than steady is incoherent. Hit when a
	// caller (almost always a test) sets very short steady values and
	// leaves the fast fields at zero, so the package defaults of
	// 10s/20s would otherwise paradoxically stretch the test before
	// the steady values could fire.
	if warmupFast > warmupSteady {
		warmupFast = warmupSteady
	}
	if thresholdFast > thresholdSteady {
		thresholdFast = thresholdSteady
	}
	// Sample at no faster than 100ms (avoid CPU burn on tiny test thresholds)
	// and no slower than dataActivityCheckPeriod (default sampling rate).
	// Drive the sampling rate off the FAST threshold so the fast phase
	// reacts on its own cadence, not at the slower steady cadence.
	period := thresholdFast / 4
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
			age := now.Sub(start)
			warmup, threshold := warmupSteady, thresholdSteady
			phase := "steady"
			if age < fastWindow {
				warmup, threshold = warmupFast, thresholdFast
				phase = "fast"
			}
			if age < warmup {
				continue
			}
			decision := decideActivityStall(now, age, threshold,
				s.lastUserOutbound.Load(), s.lastDataInbound.Load(),
				s.lastUserOutboundTCP.Load(), s.lastDataInboundTCP.Load(),
				s.lastUserOutboundUDP.Load(), s.lastDataInboundUDP.Load(),
			)
			if decision.reason == "" {
				continue
			}
			s.log.Warn("data-activity watch: user sending but no inbound data; forcing reconnect",
				"signal", decision.reason,
				"since_outbound", decision.sinceOut,
				"since_inbound", decision.sinceIn,
				"threshold", threshold,
				"phase", phase,
				"age", age,
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

// L4 protocol numbers used by sniffL4. Mirrors the values from
// pkg/netstack/endpoint.dispatchInbound — kept private to session so
// the watchdog doesn't pull a cross-module dependency on netstack just
// to recognise TCP/UDP.
const (
	l4ProtoTCP uint8 = 6
	l4ProtoUDP uint8 = 17
)

// sniffL4 returns the IPv4/IPv6 L4 protocol number from a plaintext IP
// datagram, or 0 for "unknown / not-bucketable" (ICMP, fragments,
// IPv6 extension chains we don't walk, malformed). Used by
// handleDataIn / WriteCtx to feed the per-L4 liveness timestamps.
// Same parser as pkg/netstack — keeping a single-line implementation
// here is cheaper than threading a helper across module boundaries.
func sniffL4(pkt []byte) uint8 {
	if len(pkt) < 1 {
		return 0
	}
	switch pkt[0] >> 4 {
	case 4:
		// IPv4 protocol field at byte 9; minimum IHL=5 (20 bytes).
		if len(pkt) < 20 {
			return 0
		}
		return pkt[9]
	case 6:
		// IPv6 NextHeader at byte 6. Extension headers (HBH,
		// Routing, Fragment) would chain to the real L4; we
		// don't walk them — mis-bucketing a packet with extension
		// headers as "other" is harmless for the watchdog because
		// it just means we don't update the L4-specific timestamp
		// and the aggregate path still tracks it.
		if len(pkt) < 40 {
			return 0
		}
		return pkt[6]
	}
	return 0
}

// activityStallDecision is the verdict from decideActivityStall. A
// non-empty reason indicates the watchdog should fire; the timestamps
// are surfaced in the log line for diagnostics. Encoded as a struct
// rather than (reason, sinceOut, sinceIn) returns so callers and the
// test table stay readable.
type activityStallDecision struct {
	reason   string // "" = healthy; "aggregate" / "tcp" / "udp" = fire
	sinceOut time.Duration
	sinceIn  time.Duration
}

// decideActivityStall is the pure decision core of dataActivityWatch.
// It returns a non-empty reason when the user is actively sending
// (within `threshold`) but the matching direction of inbound traffic
// has been silent for at least `threshold`. Per-L4 signals (TCP, UDP)
// fire BEFORE the aggregate so the trigger log records the most
// specific cause — that's the difference between "the tunnel is dead"
// (aggregate) and "TCP is dead while UDP DNS still works" (tcp).
//
// `age` is the watch's own elapsed time since session-up; it's used
// as the inbound floor when the per-L4 inbound has never been
// observed (otherwise a session that started with zero TCP would
// never accumulate `sinceIn >= threshold` since both timestamps stay
// at zero). The aggregate channel intentionally does NOT use that
// floor — historically dataActivityWatch required both sides to be
// observed at least once, and we keep that semantic to avoid
// regressing the existing test suite.
func decideActivityStall(now time.Time, age, threshold time.Duration,
	lastOutNs, lastInNs,
	lastTCPOutNs, lastTCPInNs,
	lastUDPOutNs, lastUDPInNs int64,
) activityStallDecision {
	// Per-L4 first — most specific reason wins so the log line
	// tells the operator exactly which family is wedged.
	if d := checkStallWithFloor(now, age, threshold, lastTCPOutNs, lastTCPInNs); d.reason != "" {
		d.reason = "tcp"
		return d
	}
	if d := checkStallWithFloor(now, age, threshold, lastUDPOutNs, lastUDPInNs); d.reason != "" {
		d.reason = "udp"
		return d
	}
	// Aggregate fallback. Both sides must have been observed at
	// least once — preserving the behaviour the existing
	// test suite expects.
	if lastOutNs > 0 && lastInNs > 0 {
		sinceOut := now.Sub(time.Unix(0, lastOutNs))
		sinceIn := now.Sub(time.Unix(0, lastInNs))
		if sinceOut < threshold && sinceIn >= threshold {
			return activityStallDecision{reason: "aggregate", sinceOut: sinceOut, sinceIn: sinceIn}
		}
	}
	return activityStallDecision{}
}

// checkStallWithFloor runs the per-L4 decision: returns a non-empty
// reason ("matched", to be relabelled by the caller) when the user is
// actively sending on this L4 and the matching inbound has been
// silent for at least `threshold`. When lastInNs is 0 (never received
// on this L4), we use `age` as the floor — a session that's been up
// for `threshold` while sending TCP without a single TCP reply IS
// stuck, and pretending otherwise lets the wedge persist forever.
func checkStallWithFloor(now time.Time, age, threshold time.Duration, lastOutNs, lastInNs int64) activityStallDecision {
	if lastOutNs == 0 {
		return activityStallDecision{}
	}
	sinceOut := now.Sub(time.Unix(0, lastOutNs))
	if sinceOut >= threshold {
		return activityStallDecision{}
	}
	var sinceIn time.Duration
	if lastInNs > 0 {
		sinceIn = now.Sub(time.Unix(0, lastInNs))
	} else {
		sinceIn = age
	}
	if sinceIn < threshold {
		return activityStallDecision{}
	}
	return activityStallDecision{reason: "matched", sinceOut: sinceOut, sinceIn: sinceIn}
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
