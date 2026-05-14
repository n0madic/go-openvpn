// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"context"
	"time"

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
// active slot every PushReply.PingInterval. Exits on session shutdown.
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
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.closed.Load() {
				return
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
			if err := s.transport.WritePacket(ctx, wire); err != nil {
				s.log.Debug("keepalive write failed (will retry next tick)", "err", err)
				continue
			}
			s.log.Debug("keepalive PING sent", "kid", slot.KeyID)
		}
	}
}

// pingRestartWatch closes the session with a *RestartError when no inbound
// data packet (real traffic or PING) has been observed for at least
// PushReply.PingRestart. Mirrors OpenVPN's ping-restart semantic.
//
// Closing is dispatched on a fresh goroutine so this watcher (which itself
// lives inside s.wg) returns before Close calls s.wg.Wait, avoiding a
// self-wait deadlock.
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
			// Detach Close from this goroutine so s.wg.Wait inside Close
			// doesn't deadlock waiting on us.
			go func() { _ = s.Close() }()
			return
		}
	}
}
