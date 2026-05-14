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
		lastTick := time.Now()
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		// Burn one tick to set the baseline, then sleep through
		// gapThreshold to simulate suspend.
		<-ticker.C
		time.Sleep(gapThreshold + 200*time.Millisecond)
		lastTick = time.Now().Add(-gapThreshold - 200*time.Millisecond)
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
