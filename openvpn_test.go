// SPDX-License-Identifier: AGPL-3.0-or-later

package openvpn

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn/internal/session"
)

// TestOnReconnectDispatch verifies that all registered callbacks fire, in
// order, with the supplied PushReply when fireOnReconnect runs.
func TestOnReconnectDispatch(t *testing.T) {
	t.Parallel()

	c := &Client{}
	var (
		mu      sync.Mutex
		gotIPs  []netip.Addr
		order   []int
		hookIdx int
	)
	for i := range 3 {
		idx := i
		c.OnReconnect(func(pr PushReply) {
			mu.Lock()
			gotIPs = append(gotIPs, pr.LocalIP)
			order = append(order, idx)
			mu.Unlock()
		})
		hookIdx++
	}

	want := netip.MustParseAddr("10.0.0.7")
	c.FireOnReconnect(PushReply{LocalIP: want})

	mu.Lock()
	defer mu.Unlock()
	if len(gotIPs) != 3 {
		t.Fatalf("got %d invocations, want 3", len(gotIPs))
	}
	for i, ip := range gotIPs {
		if ip != want {
			t.Errorf("hook %d: got %v, want %v", i, ip, want)
		}
		if order[i] != i {
			t.Errorf("hook %d fired at position %d, want %d", i, order[i], i)
		}
	}
}

// TestClientStatsAccumulate verifies that Client.Stats() reports the
// running cumulative total across simulated reconnects. Drives the
// internal foldStatsLocked accumulator directly so we don't need a
// real handshake to exercise the math.
func TestClientStatsAccumulate(t *testing.T) {
	t.Parallel()
	c := &Client{}

	// Initial state: everything zero, including Reconnects.
	if got := c.Stats(); got.Forwarded != 0 || got.Reconnects != 0 {
		t.Fatalf("initial Stats = %+v, want zero", got)
	}

	c.statsMu.Lock()
	c.foldStatsLocked(session.Stats{Forwarded: 100, DroppedFull: 5, PingIn: 20})
	c.cumStats.Reconnects++
	c.foldStatsLocked(session.Stats{Forwarded: 200, DroppedFull: 3, OpenFailed: 2})
	c.cumStats.Reconnects++
	c.statsMu.Unlock()

	got := c.Stats()
	if got.Forwarded != 300 {
		t.Errorf("Forwarded = %d, want 300", got.Forwarded)
	}
	if got.DroppedFull != 8 {
		t.Errorf("DroppedFull = %d, want 8", got.DroppedFull)
	}
	if got.PingIn != 20 {
		t.Errorf("PingIn = %d, want 20", got.PingIn)
	}
	if got.OpenFailed != 2 {
		t.Errorf("OpenFailed = %d, want 2", got.OpenFailed)
	}
	if got.Reconnects != 2 {
		t.Errorf("Reconnects = %d, want 2", got.Reconnects)
	}
	// No active session, so timestamps stay zero.
	if !got.LastInbound.IsZero() || !got.LastDataInbound.IsZero() || !got.LastUserOutbound.IsZero() {
		t.Errorf("timestamps should be zero when no session is active: %+v", got)
	}
}

// TestAbsorbStatsLockedNilNoOp confirms that the initial-dial case
// (no previous session to absorb) doesn't trip over a nil pointer.
func TestAbsorbStatsLockedNilNoOp(t *testing.T) {
	t.Parallel()
	c := &Client{}
	c.statsMu.Lock()
	c.absorbStatsLocked(nil)
	c.statsMu.Unlock()
	if got := c.Stats(); got.Forwarded != 0 {
		t.Errorf("absorbStatsLocked(nil) modified counters: %+v", got)
	}
}

// TestOnReconnectNilSkip verifies that registering nil is silently dropped
// (we don't want fireOnReconnect to panic dereferencing a nil entry).
func TestOnReconnectNilSkip(t *testing.T) {
	t.Parallel()

	c := &Client{}
	c.OnReconnect(nil) // must not be added
	c.OnReconnect(nil)

	// fireOnReconnect must not panic with no real hooks installed.
	c.FireOnReconnect(PushReply{})
}

// TestDecideStallSurrender pins down the pure surrender-policy logic so
// every edge case is covered without a live session. The columns line up
// with the conditions documented on decideStallSurrender.
func TestDecideStallSurrender(t *testing.T) {
	t.Parallel()

	stall := &session.RestartError{Reason: stallRestartReason}
	otherRestart := &session.RestartError{Reason: "ping-restart timeout"}
	plainErr := errors.New("plain non-RestartError")

	tests := []struct {
		name          string
		lifetime      time.Duration
		closeErr      error
		counter       int32
		maxStalls     int
		threshold     time.Duration
		wantCounter   int32
		wantSurrender bool
	}{
		{
			name:        "feature disabled (maxStalls=0) never surrenders",
			lifetime:    5 * time.Second,
			closeErr:    stall,
			counter:     99,
			maxStalls:   0,
			threshold:   60 * time.Second,
			wantCounter: 0,
		},
		{
			name:        "non-RestartError resets counter",
			lifetime:    5 * time.Second,
			closeErr:    plainErr,
			counter:     2,
			maxStalls:   3,
			threshold:   60 * time.Second,
			wantCounter: 0,
		},
		{
			name:        "different RestartError reason resets counter",
			lifetime:    5 * time.Second,
			closeErr:    otherRestart,
			counter:     2,
			maxStalls:   3,
			threshold:   60 * time.Second,
			wantCounter: 0,
		},
		{
			name:        "long-lived session resets counter even on stall",
			lifetime:    5 * time.Minute,
			closeErr:    stall,
			counter:     2,
			maxStalls:   3,
			threshold:   60 * time.Second,
			wantCounter: 0,
		},
		{
			name:        "lifetime exactly threshold counts as long-lived",
			lifetime:    60 * time.Second,
			closeErr:    stall,
			counter:     2,
			maxStalls:   3,
			threshold:   60 * time.Second,
			wantCounter: 0,
		},
		{
			name:        "short stall below limit increments without surrender",
			lifetime:    20 * time.Second,
			closeErr:    stall,
			counter:     1,
			maxStalls:   3,
			threshold:   60 * time.Second,
			wantCounter: 2,
		},
		{
			name:          "short stall reaching limit surrenders",
			lifetime:      20 * time.Second,
			closeErr:      stall,
			counter:       2,
			maxStalls:     3,
			threshold:     60 * time.Second,
			wantCounter:   3,
			wantSurrender: true,
		},
		{
			name:          "maxStalls=1 surrenders on the first short stall",
			lifetime:      1 * time.Second,
			closeErr:      stall,
			counter:       0,
			maxStalls:     1,
			threshold:     60 * time.Second,
			wantCounter:   1,
			wantSurrender: true,
		},
		{
			name:        "zero threshold uses the package default (60s)",
			lifetime:    30 * time.Second,
			closeErr:    stall,
			counter:     0,
			maxStalls:   3,
			threshold:   0,
			wantCounter: 1,
		},
		{
			name:        "zero threshold + lifetime ≥ default resets",
			lifetime:    65 * time.Second,
			closeErr:    stall,
			counter:     2,
			maxStalls:   3,
			threshold:   0,
			wantCounter: 0,
		},
		{
			name:        "nil closeErr resets counter (clean close)",
			lifetime:    5 * time.Second,
			closeErr:    nil,
			counter:     2,
			maxStalls:   3,
			threshold:   60 * time.Second,
			wantCounter: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, surrender := decideStallSurrender(
				tc.lifetime, tc.closeErr, tc.counter, tc.maxStalls, tc.threshold,
			)
			if got != tc.wantCounter || surrender != tc.wantSurrender {
				t.Errorf("decideStallSurrender(life=%v, counter=%d, max=%d, thresh=%v) = (%d, %v), want (%d, %v)",
					tc.lifetime, tc.counter, tc.maxStalls, tc.threshold,
					got, surrender, tc.wantCounter, tc.wantSurrender)
			}
		})
	}
}
