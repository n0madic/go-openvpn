// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"testing"

	"github.com/n0madic/go-openvpn/internal/data"
	"github.com/n0madic/go-openvpn/internal/reliable"
)

func testSlot(t *testing.T, kid uint8) *data.Slot {
	t.Helper()
	key := make([]byte, 32) // AES-256-GCM key length
	s, err := data.NewSlot(data.SlotConfig{
		KeyID:   kid,
		Cipher:  "AES-256-GCM",
		SendKey: key,
		RecvKey: key,
	})
	if err != nil {
		t.Fatalf("NewSlot: %v", err)
	}
	return s
}

// TestSlotTableRetireIfIdentity verifies RetireIf only removes the exact slot
// object it was given. This guards the fast-rekey key-id wrap-around: after 7
// rekeys key-ids recycle, so a stale transition-window timer scheduled for an
// old slot must not evict a freshly-installed slot sharing that key-id.
func TestSlotTableRetireIfIdentity(t *testing.T) {
	t.Parallel()
	tbl := newSlotTable()
	old := testSlot(t, 1)
	tbl.Install(old, true)

	// A later rekey reuses key-id 1 with a brand-new slot.
	fresh := testSlot(t, 1)
	tbl.Install(fresh, true)

	// The old slot's transition-window timer fires — it must NOT evict the
	// fresh slot now living under the same key-id.
	tbl.RetireIf(1, old)
	if got := tbl.Get(1); got != fresh {
		t.Fatalf("RetireIf(old) evicted the fresh slot; got %p want %p", got, fresh)
	}

	// RetireIf with the current object does remove it.
	tbl.RetireIf(1, fresh)
	if got := tbl.Get(1); got != nil {
		t.Fatalf("RetireIf(fresh) did not remove; got %p", got)
	}
}

// TestLayerTableInstallDisplaced verifies Install returns the layer it evicts
// (so the caller can Close it, avoiding a write/tick goroutine leak on
// fast-rekey wrap-around) and that RetireIf is identity-checked.
func TestLayerTableInstallDisplaced(t *testing.T) {
	t.Parallel()
	tbl := newLayerTable()
	first := reliable.New(reliable.Config{InitialKeyID: 1})
	if displaced := tbl.Install(1, first); displaced != nil {
		t.Fatalf("first Install displaced %p, want nil", displaced)
	}
	second := reliable.New(reliable.Config{InitialKeyID: 1})
	if displaced := tbl.Install(1, second); displaced != first {
		t.Fatalf("Install displaced %p, want the first layer %p", displaced, first)
	}
	// A stale timer for `first` must not evict `second`.
	if got := tbl.RetireIf(1, first); got != nil {
		t.Fatalf("RetireIf(first) removed something after displacement: %p", got)
	}
	if got := tbl.Get(1); got != second {
		t.Fatalf("second layer gone after RetireIf(first); got %p", got)
	}
	if got := tbl.RetireIf(1, second); got != second {
		t.Fatalf("RetireIf(second) returned %p, want %p", got, second)
	}
	if got := tbl.Get(1); got != nil {
		t.Fatalf("layer still present after RetireIf(second); got %p", got)
	}
}
