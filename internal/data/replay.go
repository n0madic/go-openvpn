// SPDX-License-Identifier: AGPL-3.0-or-later

// Package data implements the OpenVPN 2.6+ data-channel: AEAD seal/open over
// P_DATA_V2 framing, per-key-slot replay protection, and atomic key-slot
// swapping for rekey.
package data

import "sync"

// ReplayWindow is a sliding bitmap-based deduplication window for
// monotonically-incrementing packet-ids. Window size matches OpenVPN's
// default for AEAD data channels (--replay-window 64).
type ReplayWindow struct {
	mu      sync.Mutex
	highest uint32
	bitmap  uint64 // bit i ⇒ pid (highest - i) has been seen
	size    uint
}

// NewReplayWindow constructs a window. size must be ≤64 (uint64 bitmap
// limit); 64 is OpenVPN's default.
func NewReplayWindow(size uint) *ReplayWindow {
	if size == 0 || size > 64 {
		size = 64
	}
	return &ReplayWindow{size: size}
}

// Accept reports whether the given pid is fresh (not yet seen and within the
// window). On true, it is recorded as seen. pid=0 is rejected per OpenVPN
// convention (counters start at 1).
func (w *ReplayWindow) Accept(pid uint32) bool {
	if pid == 0 {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case pid > w.highest:
		shift := pid - w.highest
		if shift >= uint32(w.size) {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.highest = pid
		return true
	case w.highest-pid >= uint32(w.size):
		return false
	default:
		offset := w.highest - pid
		mask := uint64(1) << offset
		if w.bitmap&mask != 0 {
			return false
		}
		w.bitmap |= mask
		return true
	}
}

// Test reports whether pid would be Accept-ed *without* recording it.
// Used to drop obvious replays before AEAD decryption; the actual mark
// happens via Accept after authenticity is verified, so the window can
// only advance for authenticated packets.
func (w *ReplayWindow) Test(pid uint32) bool {
	if pid == 0 {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case pid > w.highest:
		return true
	case w.highest-pid >= uint32(w.size):
		return false
	default:
		return w.bitmap&(uint64(1)<<(w.highest-pid)) == 0
	}
}

// Highest returns the highest pid this window has accepted (for diagnostics).
func (w *ReplayWindow) Highest() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highest
}
