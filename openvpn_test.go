// SPDX-License-Identifier: AGPL-3.0-or-later

package openvpn

import (
	"net/netip"
	"sync"
	"testing"

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
