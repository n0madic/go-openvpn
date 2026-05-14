// SPDX-License-Identifier: AGPL-3.0-or-later

// Package data implements the OpenVPN 2.6+ data-channel: AEAD seal/open over
// P_DATA_V2 framing, per-key-slot replay protection, and atomic key-slot
// swapping for rekey.
package data

import "sync"

// DefaultReplayWindow is the default sliding-window size in packets. OpenVPN's
// own default is 64, which is fine for well-behaved low-latency paths but
// folds catastrophically on a Wi-Fi or LTE link where the egress device may
// burst-deliver 100+ packets at once, producing packet-id reorders well over
// the 64-slot window. Once that happens the legitimate older packets get
// silently dropped as "out-of-window" and gVisor TCP sees a giant hole → a
// retransmit storm → a self-reinforcing collapse that we've watched live on
// ProtonVPN with raw `data open failed pid=1507959..1508004` (46 consecutive
// drops) in the operator log. 1024 packets is a generous size — at the
// observed sustained 1500 pps it covers ~700 ms of reorder slack — and costs
// only 128 B of memory per slot.
const DefaultReplayWindow = 1024

// ReplayWindow is a sliding bitmap-based deduplication window for
// monotonically-incrementing packet-ids. The bitmap is a multi-word slice
// so the window can be much larger than the 64-bit limit a single uint64
// would impose.
//
// Bit layout: bitmap[0] bit 0 tracks `highest`, bit 1 tracks `highest-1`,
// ..., bitmap[1] bit 0 tracks `highest-64`, and so on. "Offset" below
// always means `highest - pid` — the distance from the current high
// watermark.
type ReplayWindow struct {
	mu      sync.Mutex
	highest uint32
	bitmap  []uint64
	size    uint // total bits == size; len(bitmap) == ceil(size/64)
}

// NewReplayWindow constructs a window of the requested size (in packets).
// size == 0 ⇒ DefaultReplayWindow. There is no hard upper bound; values in
// the low thousands are typical and cheap.
func NewReplayWindow(size uint) *ReplayWindow {
	if size == 0 {
		size = DefaultReplayWindow
	}
	nWords := (size + 63) / 64
	return &ReplayWindow{size: size, bitmap: make([]uint64, nWords)}
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
		shift := uint(pid - w.highest)
		w.shiftLeftLocked(shift)
		w.bitmap[0] |= 1
		w.highest = pid
		return true
	case w.highest-pid >= uint32(w.size):
		return false
	default:
		offset := uint(w.highest - pid)
		mask := uint64(1) << (offset % 64)
		idx := offset / 64
		if w.bitmap[idx]&mask != 0 {
			return false
		}
		w.bitmap[idx] |= mask
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
		offset := uint(w.highest - pid)
		return w.bitmap[offset/64]&(uint64(1)<<(offset%64)) == 0
	}
}

// Highest returns the highest pid this window has accepted (for diagnostics).
func (w *ReplayWindow) Highest() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highest
}

// shiftLeftLocked shifts the entire bitmap left by `shift` bits (each bit
// moves to a higher offset, mirroring the conceptual aging of every prior
// "seen" marker as the highest watermark moves forward). Words drop off
// the high end when they shift past `size`. Caller holds w.mu.
//
// The slice is updated from the highest index downward so a source word
// is read before its destination overwrite, the same pattern as an
// in-place memmove with overlapping forward direction.
func (w *ReplayWindow) shiftLeftLocked(shift uint) {
	nWords := len(w.bitmap)
	if shift >= w.size {
		// Everything older than the new highest falls off — zero it.
		for i := range w.bitmap {
			w.bitmap[i] = 0
		}
		return
	}
	wordShift := int(shift / 64)
	bitShift := uint(shift % 64)
	for i := nWords - 1; i >= 0; i-- {
		src := i - wordShift
		var v uint64
		if src >= 0 {
			v = w.bitmap[src] << bitShift
		}
		if bitShift > 0 && src-1 >= 0 {
			v |= w.bitmap[src-1] >> (64 - bitShift)
		}
		w.bitmap[i] = v
	}
}
