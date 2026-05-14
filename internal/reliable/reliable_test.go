// SPDX-License-Identifier: AGPL-3.0-or-later

package reliable

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn/internal/proto"
)

// link plumbs OutPackets from one Layer to InPackets on the other, optionally
// with fault injection. It runs until ctx is cancelled.
type link struct {
	from, to *Layer

	loss    func() bool // drop
	reorder func() bool // hold-then-reverse
}

func (k *link) run(ctx context.Context, t *testing.T) {
	t.Helper()
	var pending *OutPacket
	for {
		select {
		case <-ctx.Done():
			return
		case out, ok := <-k.from.Outbound():
			if !ok {
				return
			}
			if k.loss != nil && k.loss() {
				continue
			}
			if k.reorder != nil {
				if pending == nil && k.reorder() {
					p := out
					pending = &p
					continue
				}
				if pending != nil {
					k.deliver(out, t)
					k.deliver(*pending, t)
					pending = nil
					continue
				}
			}
			k.deliver(out, t)
		}
	}
}

func (k *link) deliver(o OutPacket, t *testing.T) {
	t.Helper()
	in := InPacket{
		Opcode:    o.Opcode,
		KeyID:     o.KeyID,
		SessionID: o.SessionID,
	}
	if o.IsAck() {
		in.Ack = o.Ack
	} else {
		in.Payload = o.Payload
	}
	if err := k.to.HandleInbound(in); err != nil && !errors.Is(err, ErrClosed) {
		t.Errorf("HandleInbound: %v", err)
	}
}

func newLayerPair(t *testing.T) (*Layer, *Layer) {
	t.Helper()
	a := New(Config{LocalSessionID: 0xA1A1A1A1A1A1A1A1})
	b := New(Config{LocalSessionID: 0xB2B2B2B2B2B2B2B2})
	return a, b
}

func runLinks(t *testing.T, a, b *Layer, opts ...func(*link)) (context.CancelFunc, *sync.WaitGroup) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	la := &link{from: a, to: b}
	lb := &link{from: b, to: a}
	for _, opt := range opts {
		opt(la)
		opt(lb)
	}
	var wg sync.WaitGroup
	wg.Go(func() { la.run(ctx, t) })
	wg.Go(func() { lb.run(ctx, t) })
	// Tick loop.
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

// withLoss returns a link option that drops packets with probability p.
// Each link gets its own *rand.Rand to avoid cross-direction data races.
func withLoss(seed1, seed2 uint64, p float64) func(*link) {
	rng := rand.New(rand.NewPCG(seed1, seed2))
	return func(l *link) {
		r := rng
		// Per call returns a fresh rng for each direction.
		rng = rand.New(rand.NewPCG(seed1+1, seed2+1))
		l.loss = func() bool { return r.Float64() < p }
	}
}

// withReorder returns a link option that pairwise-reorders packets with
// probability p. Two distinct rngs are minted across the two directions.
func withReorder(seed1, seed2 uint64, p float64) func(*link) {
	rng := rand.New(rand.NewPCG(seed1, seed2))
	return func(l *link) {
		r := rng
		rng = rand.New(rand.NewPCG(seed1+1, seed2+1))
		l.reorder = func() bool { return r.Float64() < p }
	}
}

func TestHardResetExchange(t *testing.T) {
	t.Parallel()
	client, server := newLayerPair(t)
	cancel, wg := runLinks(t, client, server)
	defer wg.Wait()
	defer cancel()

	if err := client.SendHardReset(proto.PControlHardResetClientV2); err != nil {
		t.Fatal(err)
	}
	if err := server.SendHardReset(proto.PControlHardResetServerV2); err != nil {
		t.Fatal(err)
	}

	// Allow exchanges to settle.
	waitFor(t, time.Second, func() bool {
		return client.QueueLen() == 0 && server.QueueLen() == 0
	})

	// Both sides should know each other's sid.
	if sid, ok := client.RemoteSessionID(); !ok || sid != 0xB2B2B2B2B2B2B2B2 {
		t.Errorf("client remote sid = %x ok=%v", sid, ok)
	}
	if sid, ok := server.RemoteSessionID(); !ok || sid != 0xA1A1A1A1A1A1A1A1 {
		t.Errorf("server remote sid = %x ok=%v", sid, ok)
	}
}

func TestBidirectionalStream(t *testing.T) {
	t.Parallel()
	client, server := newLayerPair(t)
	cancel, wg := runLinks(t, client, server)
	defer wg.Wait()
	defer cancel()

	// Need to do hard reset first so both sides know each other's sid;
	// otherwise our P_CONTROL_V1 packets cannot carry remote_sid (well, they
	// can — with zero — but the test feels more realistic this way).
	if err := client.SendHardReset(proto.PControlHardResetClientV2); err != nil {
		t.Fatal(err)
	}
	if err := server.SendHardReset(proto.PControlHardResetServerV2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		_, ok1 := client.RemoteSessionID()
		_, ok2 := server.RemoteSessionID()
		return ok1 && ok2
	})

	const N = 5000
	payload := make([]byte, N)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range payload {
		payload[i] = byte(rng.IntN(256))
	}

	var wgIO sync.WaitGroup

	// Client writes payload in chunks; server reads it all.
	wgIO.Go(func() {
		if _, err := client.Write(payload); err != nil {
			t.Errorf("client write: %v", err)
		}
	})

	got := make([]byte, 0, N)
	wgIO.Go(func() {
		buf := make([]byte, 4096)
		for len(got) < N {
			n, err := server.Read(buf)
			if err != nil {
				t.Errorf("server read: %v", err)
				return
			}
			got = append(got, buf[:n]...)
		}
	})

	wgIO.Wait()
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload diverged: %d vs %d bytes", len(got), len(payload))
	}
}

func TestRecoveryUnderLoss(t *testing.T) {
	t.Parallel()
	client, server := newLayerPair(t)
	cancel, wg := runLinks(t, client, server, withLoss(42, 43, 0.2))
	defer wg.Wait()
	defer cancel()

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

	// Now stream 20 KB through; under 20% loss every retransmit should win.
	payload := bytes.Repeat([]byte{0xCA, 0xFE}, 10_000)
	var wgIO sync.WaitGroup
	wgIO.Go(func() {
		if _, err := client.Write(payload); err != nil {
			t.Errorf("client write: %v", err)
		}
	})
	got := make([]byte, 0, len(payload))
	wgIO.Go(func() {
		buf := make([]byte, 4096)
		deadline := time.Now().Add(30 * time.Second)
		for len(got) < len(payload) {
			if time.Now().After(deadline) {
				t.Errorf("read stalled, got %d/%d", len(got), len(payload))
				return
			}
			n, err := server.Read(buf)
			if err != nil {
				t.Errorf("server read: %v", err)
				return
			}
			got = append(got, buf[:n]...)
		}
	})
	wgIO.Wait()
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload diverged under loss")
	}
}

func TestRecoveryUnderReorder(t *testing.T) {
	t.Parallel()
	client, server := newLayerPair(t)
	cancel, wg := runLinks(t, client, server, withReorder(7, 11, 0.5))
	defer wg.Wait()
	defer cancel()

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

	payload := bytes.Repeat([]byte{0x12, 0x34, 0x56, 0x78}, 1000)
	var wgIO sync.WaitGroup
	wgIO.Go(func() {
		_, _ = client.Write(payload)
	})
	got := make([]byte, 0, len(payload))
	wgIO.Go(func() {
		buf := make([]byte, 4096)
		deadline := time.Now().Add(10 * time.Second)
		for len(got) < len(payload) {
			if time.Now().After(deadline) {
				t.Errorf("read stalled under reorder, got %d/%d", len(got), len(payload))
				return
			}
			n, err := server.Read(buf)
			if err != nil {
				t.Errorf("read: %v", err)
				return
			}
			got = append(got, buf[:n]...)
		}
	})
	wgIO.Wait()
	if !bytes.Equal(got, payload) {
		t.Fatal("payload diverged under reorder")
	}
}

func TestStandaloneAckEmittedWhenNoOutbound(t *testing.T) {
	t.Parallel()
	client, server := newLayerPair(t)
	cancel, wg := runLinks(t, client, server)
	defer wg.Wait()
	defer cancel()

	if err := client.SendHardReset(proto.PControlHardResetClientV2); err != nil {
		t.Fatal(err)
	}
	if err := server.SendHardReset(proto.PControlHardResetServerV2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return client.QueueLen() == 0 && server.QueueLen() == 0
	})
	// Both sides should drain pending acks via standalone P_ACK_V1 since
	// neither side has outbound payload after hard reset.
	waitFor(t, time.Second, func() bool {
		return client.PendingAcks() == 0 && server.PendingAcks() == 0
	})
}

// TestAckFlushCountBased proves that once MaxAcksPerPacket pending acks
// accumulate, Tick emits a standalone P_ACK_V1 immediately, without
// waiting for AckFlushDelay. Counterpart to the time-based path.
func TestAckFlushCountBased(t *testing.T) {
	t.Parallel()
	var clockMu sync.Mutex
	now := time.Now()
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}

	l := New(Config{LocalSessionID: 1, Clock: clock})
	defer func() { _ = l.Close() }()

	// Inject MaxAcksPerPacket-1 packets — Tick should NOT flush yet
	// because the grace period hasn't elapsed and the count is below
	// the threshold.
	for i := range MaxAcksPerPacket - 1 {
		err := l.HandleInbound(InPacket{
			Opcode:    proto.PControlV1,
			SessionID: 0xAABB,
			Payload:   proto.ControlPayload{MessagePID: uint32(i)},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Tick(); err != nil {
		t.Fatal(err)
	}
	select {
	case out := <-l.Outbound():
		t.Fatalf("standalone ack emitted prematurely: %+v", out)
	case <-time.After(20 * time.Millisecond):
	}

	// One more push crosses MaxAcksPerPacket — Tick must drain now.
	err := l.HandleInbound(InPacket{
		Opcode:    proto.PControlV1,
		SessionID: 0xAABB,
		Payload:   proto.ControlPayload{MessagePID: uint32(MaxAcksPerPacket - 1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Tick(); err != nil {
		t.Fatal(err)
	}
	select {
	case out := <-l.Outbound():
		if !out.IsAck() {
			t.Fatalf("expected standalone P_ACK_V1, got opcode %d", out.Opcode)
		}
		if len(out.Ack.Acks) != MaxAcksPerPacket {
			t.Errorf("ack batch carried %d acks, want %d", len(out.Ack.Acks), MaxAcksPerPacket)
		}
	case <-time.After(time.Second):
		t.Fatal("count-based flush did not emit standalone ack")
	}
}

// TestAckFlushTimeBased confirms a lone pending ack still goes out
// through the grace-period path. Companion to TestAckFlushCountBased.
func TestAckFlushTimeBased(t *testing.T) {
	t.Parallel()
	var clockMu sync.Mutex
	now := time.Now()
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	l := New(Config{LocalSessionID: 1, Clock: clock})
	defer func() { _ = l.Close() }()

	err := l.HandleInbound(InPacket{
		Opcode:    proto.PControlV1,
		SessionID: 0xAABB,
		Payload:   proto.ControlPayload{MessagePID: 0},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Tick before the grace period: nothing should leave.
	advance(AckFlushDelay / 2)
	if err := l.Tick(); err != nil {
		t.Fatal(err)
	}
	select {
	case out := <-l.Outbound():
		t.Fatalf("ack flushed before grace period: %+v", out)
	default:
	}

	// Tick after the grace period: standalone ack must emit.
	advance(AckFlushDelay)
	if err := l.Tick(); err != nil {
		t.Fatal(err)
	}
	select {
	case out := <-l.Outbound():
		if !out.IsAck() || len(out.Ack.Acks) != 1 {
			t.Errorf("unexpected outbound: %+v", out)
		}
	case <-time.After(time.Second):
		t.Fatal("time-based flush did not emit standalone ack")
	}
}

func TestReadAfterCloseReturnsEOF(t *testing.T) {
	t.Parallel()
	l := New(Config{LocalSessionID: 1})
	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = l.Close()
	}()
	buf := make([]byte, 1)
	if _, err := l.Read(buf); err != io.EOF {
		t.Fatalf("got %v, want EOF", err)
	}
}

func TestWriteAfterCloseReturnsErr(t *testing.T) {
	t.Parallel()
	l := New(Config{LocalSessionID: 1})
	_ = l.Close()
	if _, err := l.Write([]byte("hello")); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v, want ErrClosed", err)
	}
}

func TestSessionIDMismatch(t *testing.T) {
	t.Parallel()
	l := New(Config{LocalSessionID: 1})
	defer func() { _ = l.Close() }()
	if err := l.HandleInbound(InPacket{Opcode: proto.PControlV1, SessionID: 100, Payload: proto.ControlPayload{MessagePID: 0}}); err != nil {
		t.Fatal(err)
	}
	if err := l.HandleInbound(InPacket{Opcode: proto.PControlV1, SessionID: 200, Payload: proto.ControlPayload{MessagePID: 1}}); !errors.Is(err, ErrSessionIDMismatch) {
		t.Fatalf("got %v, want ErrSessionIDMismatch", err)
	}
}

func TestRetransmitGiveUpAfterMaxAttempts(t *testing.T) {
	t.Parallel()
	// Use a synthetic clock so backoffs jump forward quickly.
	var clockMu sync.Mutex
	now := time.Now()
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	l := New(Config{LocalSessionID: 1, Clock: clock})
	defer func() { _ = l.Close() }()

	if err := l.SendHardReset(proto.PControlHardResetClientV2); err != nil {
		t.Fatal(err)
	}
	// Drain one packet from outbound (the first send).
	<-l.Outbound()

	// Advance + Tick repeatedly. Each tick should retransmit once until max.
	for i := range MaxRetransmits {
		_ = i
		advance(MaxRetransmit + time.Second)
		err := l.Tick()
		if err != nil {
			if errors.Is(err, ErrTooManyRetransmits) {
				return
			}
			t.Fatalf("Tick: %v", err)
		}
		select {
		case <-l.Outbound():
		case <-time.After(50 * time.Millisecond):
			t.Fatalf("expected retransmit at attempt %d", i+1)
		}
	}
	// One more tick should fail with ErrTooManyRetransmits.
	advance(MaxRetransmit + time.Second)
	if err := l.Tick(); !errors.Is(err, ErrTooManyRetransmits) {
		t.Fatalf("got %v, want ErrTooManyRetransmits", err)
	}
}

// waitFor polls predicate until it returns true or timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waitFor: condition not met within %v", timeout)
}
