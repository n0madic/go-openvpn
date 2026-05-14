// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"testing"
	"time"
)

// TestStatsSnapshot writes known values into the session's private
// atomic counters and verifies Stats() reflects them exactly. Uses
// the internal _test.go variant so the atomics are reachable.
func TestStatsSnapshot(t *testing.T) {
	t.Parallel()
	s := &Session{}

	s.statsForwarded.Store(100)
	s.statsDroppedFull.Store(5)
	s.statsPingIn.Store(20)
	s.statsOpenFailed.Store(3)
	s.statsStrayHandshake.Store(7)

	tIn := time.Now().Add(-2 * time.Second)
	tData := time.Now().Add(-1 * time.Second)
	tOut := time.Now()
	s.lastInbound.Store(tIn.UnixNano())
	s.lastDataInbound.Store(tData.UnixNano())
	s.lastUserOutbound.Store(tOut.UnixNano())

	got := s.Stats()
	if got.Forwarded != 100 || got.DroppedFull != 5 || got.PingIn != 20 ||
		got.OpenFailed != 3 || got.StrayHandshake != 7 {
		t.Errorf("counter mismatch: %+v", got)
	}
	if !got.LastInbound.Equal(tIn) {
		t.Errorf("LastInbound = %v, want %v", got.LastInbound, tIn)
	}
	if !got.LastDataInbound.Equal(tData) {
		t.Errorf("LastDataInbound = %v, want %v", got.LastDataInbound, tData)
	}
	if !got.LastUserOutbound.Equal(tOut) {
		t.Errorf("LastUserOutbound = %v, want %v", got.LastUserOutbound, tOut)
	}
}

// TestStatsSnapshotZeroTimes confirms a freshly-constructed Session
// (no atomic stores yet) returns zero Time values rather than the
// Unix epoch — important because consumers will use IsZero() to
// distinguish "no observation yet" from "observed long ago".
func TestStatsSnapshotZeroTimes(t *testing.T) {
	t.Parallel()
	s := &Session{}
	got := s.Stats()
	if !got.LastInbound.IsZero() {
		t.Errorf("LastInbound = %v, want zero", got.LastInbound)
	}
	if !got.LastDataInbound.IsZero() {
		t.Errorf("LastDataInbound = %v, want zero", got.LastDataInbound)
	}
	if !got.LastUserOutbound.IsZero() {
		t.Errorf("LastUserOutbound = %v, want zero", got.LastUserOutbound)
	}
}
