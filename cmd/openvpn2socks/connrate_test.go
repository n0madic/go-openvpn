// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/netip"
	"testing"
	"time"
)

// TestConnRateLimiterBurst verifies the bucket starts full so a
// legitimate fan-out (browser opening connRateBurst parallel conns to
// the same host) is not throttled.
func TestConnRateLimiterBurst(t *testing.T) {
	t.Parallel()
	l := newConnRateLimiter()
	tgt := netip.MustParseAddr("1.2.3.4")

	for i := range connRateBurst {
		if !l.allow(tgt) {
			t.Fatalf("expected first %d connects to be allowed, %d denied", connRateBurst, i)
		}
	}
	// Immediately exceed burst: the very next connect must be refused.
	if l.allow(tgt) {
		t.Fatalf("connect #%d should be refused (burst exhausted)", connRateBurst+1)
	}
}

// TestConnRateLimiterResetClearsAllBuckets covers the AutoReconnect
// path: after Reset every previously-drained bucket starts at full
// capacity again so the post-reconnect burst from a browser
// reopening dozens of conns to the same target is not refused.
func TestConnRateLimiterResetClearsAllBuckets(t *testing.T) {
	t.Parallel()
	l := newConnRateLimiter()
	tgt1 := netip.MustParseAddr("1.2.3.4")
	tgt2 := netip.MustParseAddr("5.6.7.8")
	for range connRateBurst {
		_ = l.allow(tgt1)
		_ = l.allow(tgt2)
	}
	if l.allow(tgt1) || l.allow(tgt2) {
		t.Fatalf("buckets should be drained before Reset")
	}
	l.Reset()
	if !l.allow(tgt1) {
		t.Fatalf("after Reset, tgt1 should be allowed at full capacity")
	}
	if !l.allow(tgt2) {
		t.Fatalf("after Reset, tgt2 should be allowed at full capacity")
	}
}

// TestConnRateLimiterRefillRecovers waits long enough for the bucket
// to refill some tokens and confirms allow() starts returning true
// again. The slept duration is generous to keep the test stable on
// loaded CI runners.
func TestConnRateLimiterRefillRecovers(t *testing.T) {
	t.Parallel()
	l := newConnRateLimiter()
	tgt := netip.MustParseAddr("1.2.3.4")

	// Drain the bucket.
	for range connRateBurst {
		_ = l.allow(tgt)
	}
	if l.allow(tgt) {
		t.Fatalf("expected drained bucket to refuse")
	}
	// At connRateRefillSec=2 tokens/sec, 1 token refills after 500ms.
	// Wait a bit more than that to be robust to scheduler jitter.
	time.Sleep(700 * time.Millisecond)
	if !l.allow(tgt) {
		t.Fatalf("expected at least one refilled token after sleep")
	}
}

// TestConnRateLimiterIndependentTargets confirms a misbehaving target
// doesn't starve well-behaved targets — each destination IP has its
// own bucket.
func TestConnRateLimiterIndependentTargets(t *testing.T) {
	t.Parallel()
	l := newConnRateLimiter()
	noisy := netip.MustParseAddr("1.2.3.4")
	quiet := netip.MustParseAddr("5.6.7.8")

	// Drain noisy target.
	for range connRateBurst {
		_ = l.allow(noisy)
	}
	if l.allow(noisy) {
		t.Fatal("noisy target should be drained")
	}
	// Quiet target must still pass.
	if !l.allow(quiet) {
		t.Fatal("quiet target should not be affected by noisy bucket")
	}
}

// TestConnRateLimiterPortAggregation is the regression test for the
// Telegram Desktop pattern: bursting 20 CONNECTs to one host split
// across :80 and :443 in ~2 seconds. A per-(IP, port) limiter let
// half of those through and triggered upstream rate-limit cascades.
// The current per-IP limiter MUST treat both ports as one bucket so
// the aggregate burst gets shaped down to safe levels.
func TestConnRateLimiterPortAggregation(t *testing.T) {
	t.Parallel()
	l := newConnRateLimiter()
	host := netip.MustParseAddr("1.2.3.4")

	// 20 alternating "ports" worth of bursts. Caller passes the same
	// IP regardless of dest port, so all 20 share one bucket — the
	// excess MUST be refused.
	allowed := 0
	for range 20 {
		if l.allow(host) {
			allowed++
		}
	}
	if allowed > connRateBurst {
		t.Fatalf("instantaneous-burst allowance was %d, want <= %d (bucket should be capped at burst)",
			allowed, connRateBurst)
	}
}
