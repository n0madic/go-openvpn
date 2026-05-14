// SPDX-License-Identifier: AGPL-3.0-or-later

package workers

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Workers see the manager's context cancelled when Shutdown is called and
// then Wait returns once all of them have exited.
func TestManagerShutdownAndWait(t *testing.T) {
	t.Parallel()
	m := NewManager(context.Background(), discardLogger())

	var ran atomic.Int32
	for i := range 5 {
		name := "w" + string(rune('a'+i))
		m.Go(name, func(ctx context.Context) {
			ran.Add(1)
			<-ctx.Done()
		})
	}
	// Give them a moment to start so Active reflects all 5.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && m.Active() != 5 {
		time.Sleep(time.Millisecond)
	}
	if got := m.Active(); got != 5 {
		t.Fatalf("Active = %d, want 5", got)
	}

	m.Shutdown()

	done := make(chan struct{})
	go func() {
		m.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Wait did not return within 2s; Active=%d", m.Active())
	}
	if got := ran.Load(); got != 5 {
		t.Errorf("ran = %d, want 5", got)
	}
	if got := m.Active(); got != 0 {
		t.Errorf("Active after Wait = %d, want 0", got)
	}
}

// Shutdown is idempotent — multiple calls are safe and do not double-cancel.
func TestManagerShutdownIdempotent(t *testing.T) {
	t.Parallel()
	m := NewManager(context.Background(), discardLogger())
	m.Go("noop", func(ctx context.Context) { <-ctx.Done() })

	for range 10 {
		m.Shutdown()
	}
	m.Wait()
}

// A panicking worker is recovered, logged, the optional handler is invoked,
// and Shutdown is triggered so the rest of the manager comes down cleanly.
func TestManagerPanicTriggersShutdown(t *testing.T) {
	t.Parallel()
	var captured atomic.Value
	var captures atomic.Int32
	m := NewManager(context.Background(), discardLogger(),
		WithPanicHandler(func(worker string, recovered any) {
			captured.Store(worker)
			captures.Add(1)
		}),
	)

	// A peer worker that just waits for shutdown — proves cascade works.
	peerExited := make(chan struct{})
	m.Go("peer", func(ctx context.Context) {
		<-ctx.Done()
		close(peerExited)
	})

	m.Go("boom", func(ctx context.Context) {
		panic("kaboom")
	})

	select {
	case <-peerExited:
	case <-time.After(2 * time.Second):
		t.Fatalf("peer worker not cancelled after panic; Active=%d", m.Active())
	}
	m.Wait()

	if got := captured.Load(); got != "boom" {
		t.Errorf("captured worker = %v, want %q", got, "boom")
	}
	if got := captures.Load(); got != 1 {
		t.Errorf("panic handler invoked %d times, want 1", got)
	}
}

// The manager's context cancels when the parent context fires, even
// without an explicit Shutdown call.
func TestManagerCancelsWithParent(t *testing.T) {
	t.Parallel()
	parent, cancel := context.WithCancel(context.Background())
	m := NewManager(parent, discardLogger())

	stopped := make(chan struct{})
	m.Go("child", func(ctx context.Context) {
		<-ctx.Done()
		close(stopped)
	})

	cancel()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatalf("worker did not observe parent cancellation")
	}
	m.Wait()
}

// ShouldShutdown returns the same Done channel as Context, so callers can
// plug it into existing select loops.
func TestManagerShouldShutdownChannel(t *testing.T) {
	t.Parallel()
	m := NewManager(context.Background(), discardLogger())
	ch := m.ShouldShutdown()
	select {
	case <-ch:
		t.Fatal("ShouldShutdown closed before Shutdown")
	default:
	}
	m.Shutdown()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("ShouldShutdown did not close after Shutdown")
	}
}
