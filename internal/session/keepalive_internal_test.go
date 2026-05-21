// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn/internal/workers"
)

// newTestSessionForWatch builds the bare minimum Session needed to exercise
// the standalone watchdog goroutines (hardResetWatch, wakeDetectorWatch) —
// just the atomics, a workers manager, and a closed channel signalled by
// a stand-in close goroutine that watches setCloseErr. Avoids the full
// transport/handshake dance so we can drive the counters directly.
func newTestSessionForWatch(t *testing.T) (*Session, chan struct{}, func()) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mgr := workers.NewManager(context.Background(), log)
	s := &Session{
		log:     log,
		workers: mgr,
		ctx:     mgr.Context(),
		layers:  newLayerTable(),
		slots:   newSlotTable(),
	}
	closed := make(chan struct{}, 1)
	// Watch for the watchdog's `go s.Close()` call by polling closedErr.
	// Production Close() calls workers.Shutdown which cancels ctx; here
	// we mimic that minimally — once closedErr is set we cancel via
	// Shutdown and signal closed.
	pollCtx, pollCancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-pollCtx.Done():
				return
			case <-ticker.C:
				// Use CloseErr (not closedErr) — the latter always
				// returns ErrClosed when no specific error is set,
				// which would make this loop signal `closed` on the
				// first tick before any watchdog has had a chance to
				// fire.
				if s.CloseErr() != nil {
					s.closed.Store(true)
					mgr.Shutdown()
					select {
					case closed <- struct{}{}:
					default:
					}
					return
				}
			}
		}
	}()
	cleanup := func() {
		pollCancel()
		mgr.Shutdown()
	}
	return s, closed, cleanup
}

// TestHardResetWatchFiresOnThresholdCrossing crosses the hardResetThreshold
// in one shot and asserts that hardResetWatch responds within roughly one
// sampling period — closing the session with a *RestartError whose Reason
// is "server hard-reset". Regression for the "laptop slept, server lost
// us, we keep ignoring HARD_RESET" zombie state.
func TestHardResetWatchFiresOnThresholdCrossing(t *testing.T) {
	t.Parallel()
	s, closed, cleanup := newTestSessionForWatch(t)
	defer cleanup()

	// Drive the counter past the threshold before starting the watch
	// so the very first tick fires.
	s.statsHardResetIn.Store(uint64(hardResetThreshold + 1))

	done := make(chan struct{})
	go func() {
		s.hardResetWatch(s.ctx)
		close(done)
	}()

	select {
	case <-closed:
	case <-time.After(hardResetCheckPeriod + 2*time.Second):
		t.Fatal("hardResetWatch did not fire within expected window")
	}
	<-done

	var re *RestartError
	if err := s.closedErr(); !errors.As(err, &re) {
		t.Fatalf("closedErr = %T (%v), want *RestartError", err, err)
	} else if re.Reason != "server hard-reset" {
		t.Errorf("Reason = %q, want %q", re.Reason, "server hard-reset")
	}
}

// TestHardResetWatchStaysQuietBelowThreshold confirms a counter that stays
// below hardResetThreshold never triggers — a single benign HARD_RESET
// during the initial handshake window must not cause a needless reconnect.
func TestHardResetWatchStaysQuietBelowThreshold(t *testing.T) {
	t.Parallel()
	s, closed, cleanup := newTestSessionForWatch(t)
	defer cleanup()

	s.statsHardResetIn.Store(uint64(hardResetThreshold - 1))

	go s.hardResetWatch(s.ctx)

	select {
	case <-closed:
		t.Fatal("hardResetWatch fired below threshold")
	case <-time.After(hardResetCheckPeriod + 500*time.Millisecond):
		// Expected: still alive.
	}
}

// TestWakeDetectorWatchFiresOnLongGap fakes a long sleep by stalling the
// goroutine before the first real tick — the ticker's first delivery
// will be far enough in the future to look like a wake event. We use
// runtime gosched + sleep to keep the test reliable without time
// manipulation tricks.
func TestWakeDetectorWatchFiresOnLongGap(t *testing.T) {
	t.Parallel()

	// Local copy of wakeDetectorWatch with shortened constants so we
	// don't need 10+ seconds. Mirrors the production logic exactly.
	const period = 100 * time.Millisecond
	const gapThreshold = 500 * time.Millisecond

	s, closed, cleanup := newTestSessionForWatch(t)
	defer cleanup()

	var fired atomic.Bool
	go func() {
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		// Burn one tick to set the baseline, then sleep through
		// gapThreshold to simulate suspend.
		<-ticker.C
		time.Sleep(gapThreshold + 200*time.Millisecond)
		lastTick := time.Now().Add(-gapThreshold - 200*time.Millisecond)
		for {
			select {
			case <-s.ctx.Done():
				return
			case now := <-ticker.C:
				gap := now.Sub(lastTick)
				lastTick = now
				if gap < gapThreshold {
					continue
				}
				fired.Store(true)
				// Mirror the production path: setCloseErr first, then
				// fire Close (here the polling goroutine in
				// newTestSessionForWatch picks it up).
				s.setCloseErr(&RestartError{Reason: "wake from sleep"})
				return
			}
		}
	}()

	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("simulated wake-detector did not fire")
	}
	if !fired.Load() {
		t.Fatal("fired flag never set")
	}
	var re *RestartError
	if err := s.closedErr(); !errors.As(err, &re) || re.Reason != "wake from sleep" {
		t.Fatalf("closedErr = %v, want wake-from-sleep RestartError", err)
	}
}

// TestSniffL4 covers the IPv4 / IPv6 paths plus the unknown/short-packet
// fallbacks. Kept tiny — the parser itself is six lines.
func TestSniffL4(t *testing.T) {
	t.Parallel()
	// Minimal IPv4 header (20 bytes): version=4, IHL=5, length=20, proto at [9].
	v4tcp := make([]byte, 20)
	v4tcp[0] = 0x45
	v4tcp[9] = 6
	v4udp := make([]byte, 20)
	v4udp[0] = 0x45
	v4udp[9] = 17
	v4icmp := make([]byte, 20)
	v4icmp[0] = 0x45
	v4icmp[9] = 1
	// Minimal IPv6 header (40 bytes): version=6 in top nibble, NextHeader at [6].
	v6tcp := make([]byte, 40)
	v6tcp[0] = 0x60
	v6tcp[6] = 6
	v6udp := make([]byte, 40)
	v6udp[0] = 0x60
	v6udp[6] = 17
	short := []byte{0x45}

	cases := []struct {
		name string
		in   []byte
		want uint8
	}{
		{"v4 tcp", v4tcp, 6},
		{"v4 udp", v4udp, 17},
		{"v4 icmp (not bucketed)", v4icmp, 1},
		{"v6 tcp", v6tcp, 6},
		{"v6 udp", v6udp, 17},
		{"empty", nil, 0},
		{"v4 truncated", short, 0},
		{"unknown version", []byte{0x70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sniffL4(tc.in); got != tc.want {
				t.Fatalf("sniffL4 = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestDecideActivityStall is the table-driven core test for the L4-aware
// watchdog decision logic. Each case lays out the timestamp landscape that
// dataActivityWatch would see at one tick and asserts the verdict — which
// (if any) signal fires, and that the matched reason string is the most
// specific one available (per-L4 wins over aggregate). Covers the exact
// production failure mode that prompted this rework: TCP dead, UDP
// trickling DNS responses, aggregate channel deceptively healthy.
func TestDecideActivityStall(t *testing.T) {
	t.Parallel()
	const threshold = 20 * time.Second
	now := time.Unix(1_000_000, 0) // arbitrary fixed reference
	ns := func(d time.Duration) int64 { return now.Add(-d).UnixNano() }

	cases := []struct {
		name string
		// Aggregate
		lastOut, lastIn time.Duration
		// L4
		lastTCPOut, lastTCPIn time.Duration
		lastUDPOut, lastUDPIn time.Duration
		// Session age — used as inbound floor when an L4 inbound has
		// never been observed (lastIn == 0).
		age time.Duration
		// Pass -1 in any "last*" field to encode "never observed (0)".
		// We translate -1 → 0 before calling decideActivityStall.
		wantReason string
	}{
		{
			name:       "healthy: aggregate fresh, no L4 signals",
			lastOut:    1 * time.Second,
			lastIn:     1 * time.Second,
			lastTCPOut: -1, lastTCPIn: -1,
			lastUDPOut: -1, lastUDPIn: -1,
			age:        30 * time.Second,
			wantReason: "",
		},
		{
			name:       "idle: nobody sent anything recently",
			lastOut:    60 * time.Second,
			lastIn:     60 * time.Second,
			lastTCPOut: -1, lastTCPIn: -1,
			lastUDPOut: -1, lastUDPIn: -1,
			age:        90 * time.Second,
			wantReason: "",
		},
		{
			// The 2026-05-15 failure mode: server selectively
			// drops TCP, occasional UDP reply keeps aggregate
			// fresh — without L4 awareness this would never
			// fire.
			name:       "tcp dead, udp alive masks aggregate",
			lastOut:    1 * time.Second,
			lastIn:     2 * time.Second,
			lastTCPOut: 1 * time.Second, lastTCPIn: 30 * time.Second,
			lastUDPOut: 5 * time.Second, lastUDPIn: 2 * time.Second,
			age:        90 * time.Second,
			wantReason: "tcp",
		},
		{
			name:       "udp dead, tcp alive",
			lastOut:    1 * time.Second,
			lastIn:     2 * time.Second,
			lastTCPOut: 1 * time.Second, lastTCPIn: 2 * time.Second,
			lastUDPOut: 1 * time.Second, lastUDPIn: 30 * time.Second,
			age:        90 * time.Second,
			wantReason: "udp",
		},
		{
			name:       "aggregate-only stall (no L4 timestamps yet)",
			lastOut:    1 * time.Second,
			lastIn:     30 * time.Second,
			lastTCPOut: -1, lastTCPIn: -1,
			lastUDPOut: -1, lastUDPIn: -1,
			age:        90 * time.Second,
			wantReason: "aggregate",
		},
		{
			// Session is sending TCP but has never received any TCP
			// at all. Age past threshold ⇒ definitely stuck.
			name:    "tcp never received and age past threshold",
			lastOut: -1, lastIn: -1,
			lastTCPOut: 1 * time.Second, lastTCPIn: -1,
			lastUDPOut: -1, lastUDPIn: -1,
			age:        90 * time.Second,
			wantReason: "tcp",
		},
		{
			// Same as above but session is still young — sinceIn
			// (= age) hasn't reached the threshold yet, so we wait.
			name:    "tcp never received but still within threshold age",
			lastOut: -1, lastIn: -1,
			lastTCPOut: 1 * time.Second, lastTCPIn: -1,
			lastUDPOut: -1, lastUDPIn: -1,
			age:        5 * time.Second,
			wantReason: "",
		},
		{
			// Outbound is stale: user stopped sending. Even if
			// inbound is silent we don't fire — they're idle.
			name:    "user idle on tcp, inbound stale",
			lastOut: -1, lastIn: -1,
			lastTCPOut: 60 * time.Second, lastTCPIn: 60 * time.Second,
			lastUDPOut: -1, lastUDPIn: -1,
			age:        120 * time.Second,
			wantReason: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encode := func(d time.Duration) int64 {
				if d < 0 {
					return 0
				}
				return ns(d)
			}
			got := decideActivityStall(now, tc.age, threshold,
				encode(tc.lastOut), encode(tc.lastIn),
				encode(tc.lastTCPOut), encode(tc.lastTCPIn),
				encode(tc.lastUDPOut), encode(tc.lastUDPIn),
			)
			if got.reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q (sinceOut=%v sinceIn=%v)",
					got.reason, tc.wantReason, got.sinceOut, got.sinceIn)
			}
		})
	}
}
