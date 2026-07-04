// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"sync"
	"sync/atomic"

	"github.com/n0madic/go-openvpn/internal/data"
	"github.com/n0madic/go-openvpn/internal/reliable"
)

// slotTable owns up to two AEAD data Slots indexed by key-id. Only one slot
// is "active" for outbound at a time; the previous slot is kept for inbound
// during the transition window after a rekey.
type slotTable struct {
	mu     sync.RWMutex
	byKID  map[uint8]*data.Slot
	active atomic.Uint32 // current outbound key-id (0..7)
}

func newSlotTable() *slotTable {
	return &slotTable{byKID: make(map[uint8]*data.Slot)}
}

// Install registers a slot under its key-id. If makeActive is true, the slot
// becomes the outbound target.
func (t *slotTable) Install(s *data.Slot, makeActive bool) {
	t.mu.Lock()
	t.byKID[s.KeyID] = s
	t.mu.Unlock()
	if makeActive {
		t.active.Store(uint32(s.KeyID))
	}
}

// RetireIf removes the slot for kid only if it is still the exact object the
// caller installed. Guards the fast-rekey wrap-around case: after 7 rekeys
// key-id values recycle, so a transition-window timer scheduled for an old
// slot must not evict a freshly-installed slot that happens to share the kid.
func (t *slotTable) RetireIf(kid uint8, want *data.Slot) {
	t.mu.Lock()
	if t.byKID[kid] == want {
		delete(t.byKID, kid)
	}
	t.mu.Unlock()
}

// Get returns the slot for the given key-id (nil if absent).
func (t *slotTable) Get(kid uint8) *data.Slot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byKID[kid]
}

// Active returns the slot to use for outbound packets.
func (t *slotTable) Active() *data.Slot { return t.Get(uint8(t.active.Load())) }

// ActiveKID returns the key-id of the active outbound slot.
func (t *slotTable) ActiveKID() uint8 { return uint8(t.active.Load()) }

// Retire removes the slot for the given key-id. No-op if absent.
func (t *slotTable) Retire(kid uint8) {
	t.mu.Lock()
	delete(t.byKID, kid)
	t.mu.Unlock()
}

// layerTable owns up to two reliable.Layers indexed by key-id. Each layer
// has its own writeLoop+tickLoop spawned at Install; both end when the layer
// is closed (which Retire does).
type layerTable struct {
	mu    sync.RWMutex
	byKID map[uint8]*reliable.Layer
}

func newLayerTable() *layerTable {
	return &layerTable{byKID: make(map[uint8]*reliable.Layer)}
}

// Install registers a layer, returning any different layer it displaced under
// the same key-id (nil if none) so the caller can Close it. A displacement
// only happens in the fast-rekey wrap-around case (key-id recycled before the
// previous holder's transition window elapsed); leaving the old layer in place
// would leak its write/tick goroutines.
func (t *layerTable) Install(kid uint8, l *reliable.Layer) (displaced *reliable.Layer) {
	t.mu.Lock()
	if prev, ok := t.byKID[kid]; ok && prev != l {
		displaced = prev
	}
	t.byKID[kid] = l
	t.mu.Unlock()
	return displaced
}

// RetireIf removes and returns the layer for kid only if it is still the exact
// object the caller installed (nil otherwise). See slotTable.RetireIf.
func (t *layerTable) RetireIf(kid uint8, want *reliable.Layer) *reliable.Layer {
	t.mu.Lock()
	defer t.mu.Unlock()
	if l, ok := t.byKID[kid]; ok && l == want {
		delete(t.byKID, kid)
		return l
	}
	return nil
}

// Get returns the layer for the given key-id (nil if absent).
func (t *layerTable) Get(kid uint8) *reliable.Layer {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byKID[kid]
}

// Retire removes the layer for the given key-id and returns it (or nil).
func (t *layerTable) Retire(kid uint8) *reliable.Layer {
	t.mu.Lock()
	l := t.byKID[kid]
	delete(t.byKID, kid)
	t.mu.Unlock()
	return l
}

// nextKeyID computes the next key-id per OpenVPN convention: increment mod 8,
// skipping 0 on wrap-around (key-id 0 is reserved for the initial hard
// reset).
func nextKeyID(cur uint8) uint8 {
	next := (cur + 1) & 0x07
	if next == 0 {
		next = 1
	}
	return next
}
