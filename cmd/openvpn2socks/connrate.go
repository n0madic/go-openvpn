// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/netip"
	"sync"
	"time"
)

// Per-IP connect-burst limiter constants. Tuned to allow legitimate
// browser fan-out (typically 6-8 parallel connections per page load)
// while rejecting the aggressive 20+ connect-per-2-seconds same-host
// bursts observed from misbehaving native clients (Telegram Desktop,
// iCloud sync). Those bursts trigger rate-limiting somewhere upstream
// (the destination server, the VPN edge, or both), which can cascade
// into tunnel-wide degradation because one client decided to open ~20
// connections in 2 seconds.
//
// Refusing the excess locally with REP=0x05 (connection refused) is
// strictly better than letting the burst hit the wire: well-behaved
// clients back off and retry, the misbehaving one keeps thrashing
// at our SOCKS5 layer (which is cheap) instead of the tunnel (which
// is fragile).
//
// The bucket key is the destination IP, NOT (IP, port): observed
// bursts hit both :80 and :443 of one host simultaneously, and a
// per-port limiter let half the burst through. Keying on IP catches
// the aggregate — which is what actually overloads the server.
const (
	// connRateBurst is the bucket capacity per destination IP. A new
	// target starts full so an initial fan-out (one HTTPS page load
	// fanning out to ~6-8 sockets) isn't throttled at all.
	connRateBurst = 8
	// connRateRefillSec is sustained tokens/sec per bucket. With
	// burst=8 this means a healthy browser can open 8 immediately,
	// then 2/sec; well above any real page-load pattern but well
	// below the 10/sec sustained rate that triggered the upstream
	// rate-limit.
	connRateRefillSec = 2.0
	// connRateGCEvery is how often allow() walks the bucket map to
	// drop entries that haven't been touched in connRateMaxIdle.
	// Walks happen under the lock, so the cadence is a balance
	// between memory growth and tail-latency in allow().
	connRateGCEvery = 30 * time.Second
	// connRateMaxIdle is the threshold for GC eligibility. Targets
	// idle longer than this lose their bucket; a fresh one is
	// allocated on the next CONNECT to the same address.
	connRateMaxIdle = 5 * time.Minute
)

// connRateLimiter is a per-destination-IP token bucket. allow()
// returns false when too many CONNECTs to the same destination IP
// have arrived in too short a window — across ALL ports (HTTP and
// HTTPS to one host share the bucket). All operations are safe for
// concurrent use.
type connRateLimiter struct {
	mu      sync.Mutex
	buckets map[netip.Addr]*rateBucket
	lastGC  time.Time
}

type rateBucket struct {
	tokens  float64
	last    time.Time // last token-refill time
	touched time.Time // last allow() observation; used for GC
}

// newConnRateLimiter returns a fresh limiter with an empty bucket map.
func newConnRateLimiter() *connRateLimiter {
	return &connRateLimiter{
		buckets: make(map[netip.Addr]*rateBucket),
		lastGC:  time.Now(),
	}
}

// allow consumes one token from target's bucket. Returns true when
// the CONNECT should proceed, false when it should be refused.
func (l *connRateLimiter) allow(target netip.Addr) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastGC) > connRateGCEvery {
		l.gcLocked(now)
		l.lastGC = now
	}

	b, ok := l.buckets[target]
	if !ok {
		// New target starts at full capacity, then immediately spends
		// one token below.
		b = &rateBucket{tokens: connRateBurst, last: now, touched: now}
		l.buckets[target] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * connRateRefillSec
			if b.tokens > connRateBurst {
				b.tokens = connRateBurst
			}
			b.last = now
		}
	}
	b.touched = now

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

// gcLocked discards buckets idle for longer than connRateMaxIdle.
// Caller must hold l.mu.
func (l *connRateLimiter) gcLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.touched) > connRateMaxIdle {
			delete(l.buckets, k)
		}
	}
}

// Reset drops every bucket. Called from the AutoReconnect hook so a
// client that legitimately needs to re-open many conns to the same
// destination immediately after reconnect (browser tab fan-out after
// every old conn turned zombie) is not refused by stale bucket state.
// Without this the visible symptom is a flood of REP=0x05 replies in
// the first second after reconnect, even though the new tunnel is
// otherwise healthy.
func (l *connRateLimiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets = make(map[netip.Addr]*rateBucket)
	l.lastGC = time.Now()
}
