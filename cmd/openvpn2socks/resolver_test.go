// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
)

// TestResolverRestartHookFires verifies that the resolver invokes the
// restart hook exactly once it observes `threshold` consecutive
// DNS-over-tunnel failures.
func TestResolverRestartHookFires(t *testing.T) {
	t.Parallel()

	var (
		hookCalls atomic.Int32
		gotReason string
		mu        sync.Mutex
	)
	r := &resolver{
		log: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	r.SetRestartHook(func(reason string) {
		hookCalls.Add(1)
		mu.Lock()
		gotReason = reason
		mu.Unlock()
	}, 3)

	// Two failures: hook MUST NOT have fired yet.
	r.handleTunnelFailure()
	r.handleTunnelFailure()
	if got := hookCalls.Load(); got != 0 {
		t.Fatalf("hook fired prematurely after 2 failures: calls=%d", got)
	}

	// Third failure: hook fires and counter resets.
	r.handleTunnelFailure()
	if got := hookCalls.Load(); got != 1 {
		t.Fatalf("hook calls = %d after threshold, want 1", got)
	}
	mu.Lock()
	if gotReason == "" {
		t.Error("hook called with empty reason")
	}
	mu.Unlock()

	// After reset, next two failures must not re-trigger.
	r.handleTunnelFailure()
	r.handleTunnelFailure()
	if got := hookCalls.Load(); got != 1 {
		t.Fatalf("hook re-fired after reset: calls=%d", got)
	}

	// Another failure (3rd in this new cycle) crosses threshold again.
	r.handleTunnelFailure()
	if got := hookCalls.Load(); got != 2 {
		t.Fatalf("hook calls = %d after 2nd cycle, want 2", got)
	}
}

// TestResolverRestartHookDisabled verifies that with threshold≤0 or nil
// hook, no calls happen regardless of failure count.
func TestResolverRestartHookDisabled(t *testing.T) {
	t.Parallel()
	var hookCalls atomic.Int32

	r := &resolver{
		log: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	// nil hook — default state.
	for range 10 {
		r.handleTunnelFailure()
	}
	if got := hookCalls.Load(); got != 0 {
		t.Fatalf("hook fired with nil hook: calls=%d", got)
	}

	// threshold 0 explicitly disables.
	r.SetRestartHook(func(string) { hookCalls.Add(1) }, 0)
	for range 10 {
		r.handleTunnelFailure()
	}
	if got := hookCalls.Load(); got != 0 {
		t.Fatalf("hook fired with threshold=0: calls=%d", got)
	}
}

// TestResolverCounterResetsOnSuccess verifies that a successful tunnel
// query clears the consecutive-failures counter. We can't easily drive a
// real DNS query from a unit test, so we test the counter manipulation
// directly through the public-ish path: increment failures, then store 0
// like LookupIP does, then verify subsequent failures start over.
func TestResolverCounterResetsOnSuccess(t *testing.T) {
	t.Parallel()
	var hookCalls atomic.Int32

	r := &resolver{
		log: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	r.SetRestartHook(func(string) { hookCalls.Add(1) }, 3)

	r.handleTunnelFailure()
	r.handleTunnelFailure()
	// Simulate a successful query (matches the `r.consecutiveFails.Store(0)`
	// calls inside LookupIP).
	r.consecutiveFails.Store(0)
	r.handleTunnelFailure()
	r.handleTunnelFailure()
	if got := hookCalls.Load(); got != 0 {
		t.Fatalf("hook fired before threshold after counter reset: calls=%d", got)
	}
	r.handleTunnelFailure() // 3rd in this new streak.
	if got := hookCalls.Load(); got != 1 {
		t.Fatalf("hook calls = %d, want 1", got)
	}
}
