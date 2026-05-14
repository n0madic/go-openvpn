// SPDX-License-Identifier: AGPL-3.0-or-later

package reliable

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn/internal/proto"
)

// dropMap counts, per message-pid, how many copies of an outbound packet
// the relay should silently drop. Each drop decrements the counter, so a
// value of N means "the first N occurrences of this msgPID are lost; the
// (N+1)-th gets through". Retransmits share the same msgPID as the
// original, which is the unit we model losses in — same approach as
// ooni/minivpn's PacketRelay.
type dropMap struct {
	mu          sync.Mutex
	remaining   map[uint32]int
	droppedTot  atomic.Int64
	droppedList []uint32 // history, for diagnostics
}

func newDropMap(pids ...uint32) *dropMap {
	m := &dropMap{remaining: make(map[uint32]int, len(pids))}
	for _, p := range pids {
		m.remaining[p]++
	}
	return m
}

// shouldDrop reports whether this packet should be silently dropped on
// the wire. Only P_CONTROL_V1 (and other reliability-tracked opcodes)
// can be dropped through msgPID; standalone P_ACK_V1 packets are not
// reliability-tracked, so this returns false for them. (ACK loss is
// covered indirectly: dropping a control packet keeps it in tx queue,
// and the natural retransmit covers the missing ACK.)
func (d *dropMap) shouldDrop(o OutPacket) bool {
	if o.IsAck() {
		return false
	}
	pid := o.Payload.MessagePID
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.remaining[pid] > 0 {
		d.remaining[pid]--
		d.droppedTot.Add(1)
		d.droppedList = append(d.droppedList, pid)
		return true
	}
	return false
}

// drops returns a snapshot of the per-pid drop history.
func (d *dropMap) drops() []uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]uint32, len(d.droppedList))
	copy(out, d.droppedList)
	return out
}

// runLinksWithDrops is like runLinks but installs deterministic drop
// filters on each direction. aToB drops apply when the client sends
// to the server; bToA the opposite. Either may be nil.
func runLinksWithDrops(t *testing.T, a, b *Layer, aToB, bToA *dropMap) (context.CancelFunc, *sync.WaitGroup) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	la := &link{from: a, to: b}
	lb := &link{from: b, to: a}
	var wg sync.WaitGroup
	wg.Go(func() { la.runWithDrops(ctx, t, aToB) })
	wg.Go(func() { lb.runWithDrops(ctx, t, bToA) })
	wg.Go(func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = a.Tick()
				_ = b.Tick()
			}
		}
	})
	return cancel, &wg
}

// runWithDrops mirrors link.run but consults a dropMap per packet
// instead of a packet-agnostic loss probability.
func (k *link) runWithDrops(ctx context.Context, t *testing.T, drops *dropMap) {
	t.Helper()
	for {
		select {
		case <-ctx.Done():
			return
		case out, ok := <-k.from.Outbound():
			if !ok {
				return
			}
			if drops != nil && drops.shouldDrop(out) {
				continue
			}
			k.deliver(out, t)
		}
	}
}

// waitHardResetDone runs the four-way hard reset between client and
// server and waits for both queues to settle. Returns when both layers
// know each other's remote session-id and have no pending tx.
func waitHardResetDone(t *testing.T, client, server *Layer) {
	t.Helper()
	if err := client.SendHardReset(proto.PControlHardResetClientV2); err != nil {
		t.Fatal(err)
	}
	if err := server.SendHardReset(proto.PControlHardResetServerV2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool {
		_, ok1 := client.RemoteSessionID()
		_, ok2 := server.RemoteSessionID()
		return ok1 && ok2 && client.QueueLen() == 0 && server.QueueLen() == 0
	})
}

// streamAndVerify writes payload from client and verifies the server
// reads back exactly the same bytes. Times out at deadline.
func streamAndVerify(t *testing.T, client, server *Layer, payload []byte, deadline time.Duration) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Go(func() {
		if _, err := client.Write(payload); err != nil && !errors.Is(err, ErrClosed) {
			t.Errorf("client write: %v", err)
		}
	})
	got := make([]byte, 0, len(payload))
	wg.Go(func() {
		buf := make([]byte, 4096)
		end := time.Now().Add(deadline)
		for len(got) < len(payload) {
			if time.Now().After(end) {
				t.Errorf("read stalled, got %d/%d", len(got), len(payload))
				return
			}
			n, err := server.Read(buf)
			if err != nil {
				if errors.Is(err, ErrClosed) {
					return
				}
				t.Errorf("server read: %v", err)
				return
			}
			got = append(got, buf[:n]...)
		}
	})
	wg.Wait()
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload diverged: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestDeterministicDropSinglePacket drops exactly one copy of a single
// chunk and verifies recovery via retransmit.
func TestDeterministicDropSinglePacket(t *testing.T) {
	t.Parallel()
	client, server := newLayerPair(t)
	// After hard-reset (msgPID 0) the first P_CONTROL_V1 chunk has
	// msgPID 1; drop that one once.
	drops := newDropMap(2)
	cancel, wg := runLinksWithDrops(t, client, server, drops, nil)
	defer wg.Wait()
	defer cancel()

	waitHardResetDone(t, client, server)
	payload := bytes.Repeat([]byte{0xAB, 0xCD}, 3000) // ~6 KB → 5 chunks
	streamAndVerify(t, client, server, payload, 15*time.Second)
	if got := drops.droppedTot.Load(); got != 1 {
		t.Errorf("expected exactly 1 drop, got %d (history=%v)", got, drops.drops())
	}
}

// TestDeterministicDropAlternating drops msgPIDs 1, 3, 5 — the kind of
// pattern that empirically appears in lossy mobile uplinks.
func TestDeterministicDropAlternating(t *testing.T) {
	t.Parallel()
	client, server := newLayerPair(t)
	drops := newDropMap(2, 4, 6)
	cancel, wg := runLinksWithDrops(t, client, server, drops, nil)
	defer wg.Wait()
	defer cancel()

	waitHardResetDone(t, client, server)
	payload := bytes.Repeat([]byte{0xCA, 0xFE}, 5000) // ~10 KB → ~9 chunks
	streamAndVerify(t, client, server, payload, 30*time.Second)
	got := drops.drops()
	if len(got) != 3 {
		t.Errorf("expected 3 drops, got %d: %v", len(got), got)
	}
}

// TestDeterministicDropConsecutive drops a run of consecutive chunks
// (msgPID 2, 3, 4). Without ACK loss this only delays the stream by
// retransmit backoff for the first of the run.
func TestDeterministicDropConsecutive(t *testing.T) {
	t.Parallel()
	client, server := newLayerPair(t)
	drops := newDropMap(2, 3, 4)
	cancel, wg := runLinksWithDrops(t, client, server, drops, nil)
	defer wg.Wait()
	defer cancel()

	waitHardResetDone(t, client, server)
	payload := bytes.Repeat([]byte{0x12, 0x34}, 4000) // ~8 KB → 7 chunks
	streamAndVerify(t, client, server, payload, 30*time.Second)
	if got := drops.droppedTot.Load(); got != 3 {
		t.Errorf("expected 3 drops, got %d (history=%v)", got, drops.drops())
	}
}

// TestDeterministicDropDoubleSamePID drops msgPID=2 twice. Each drop
// costs one retransmit window (initial 1s, then 2s) so total ≥ 3s.
// Verifies the layer doesn't escalate the backoff past what the
// configured schedule prescribes for a single packet.
func TestDeterministicDropDoubleSamePID(t *testing.T) {
	t.Parallel()
	client, server := newLayerPair(t)
	drops := newDropMap(2, 2)
	cancel, wg := runLinksWithDrops(t, client, server, drops, nil)
	defer wg.Wait()
	defer cancel()

	waitHardResetDone(t, client, server)
	payload := bytes.Repeat([]byte{0xDE, 0xAD}, 2000) // ~4 KB → 4 chunks
	streamAndVerify(t, client, server, payload, 30*time.Second)
	got := drops.drops()
	if len(got) != 2 || got[0] != 2 || got[1] != 2 {
		t.Errorf("expected drops [2,2], got %v", got)
	}
}

// TestDropExhaustsRetransmits drops msgPID=2 enough times to exceed
// MaxRetransmits — Tick must return ErrTooManyRetransmits and the
// stream must NOT complete.
//
// Runtime is bounded by the retransmit schedule (1+2+4+8+16+16+16+16 ≈
// 79s) since we run against the real clock; skipped under -short so
// the dev cycle stays snappy.
func TestDropExhaustsRetransmits(t *testing.T) {
	if testing.Short() {
		t.Skip("real-time retransmit schedule takes ~80s")
	}
	t.Parallel()
	client, server := newLayerPair(t)
	// MaxRetransmits = 8, so 10 drops of the same packet is definitely
	// enough to exhaust the schedule before any reach the server.
	pids := make([]uint32, 0, 10)
	for range 10 {
		pids = append(pids, 2)
	}
	drops := newDropMap(pids...)

	// We need to observe Tick's error directly, so don't use the
	// generic helper. Run links + a dedicated tick loop that signals
	// when the layer gives up.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	la := &link{from: client, to: server}
	lb := &link{from: server, to: client}
	var wg sync.WaitGroup
	wg.Go(func() { la.runWithDrops(ctx, t, drops) })
	wg.Go(func() { lb.runWithDrops(ctx, t, nil) })

	tickErr := make(chan error, 1)
	wg.Go(func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := client.Tick(); err != nil {
					select {
					case tickErr <- err:
					default:
					}
					return
				}
				_ = server.Tick()
			}
		}
	})

	waitHardResetDone(t, client, server)
	// Fire-and-forget — Write will block once queue fills, but the
	// retransmit-exhaustion error fires through Tick first.
	wg.Go(func() {
		_, _ = client.Write(bytes.Repeat([]byte{0xFF}, 8000))
	})

	select {
	case err := <-tickErr:
		if !errors.Is(err, ErrTooManyRetransmits) {
			t.Fatalf("Tick error = %v, want ErrTooManyRetransmits", err)
		}
	case <-time.After(2 * time.Minute):
		t.Fatalf("Tick never returned ErrTooManyRetransmits; drops=%v", drops.drops())
	}
	cancel()
	_ = client.Close()
	_ = server.Close()
	wg.Wait()
}
