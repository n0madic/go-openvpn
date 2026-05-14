// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func newTestResolver(t *testing.T) *resolver {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// ns intentionally nil — tests that exercise queryOverTunnel would
	// need a real netstack, but cache logic is testable standalone.
	return newResolver(nil, nil, netip.AddrPort{}, log)
}

// TestCacheStoresAndReturnsHits confirms the basic positive path: write
// once, read many — every subsequent call returns the cached entry until
// dnsCacheTTL elapses.
func TestCacheStoresAndReturnsHits(t *testing.T) {
	t.Parallel()
	r := newTestResolver(t)
	want := []netip.Addr{mustAddr(t, "1.2.3.4"), mustAddr(t, "5.6.7.8")}

	r.cacheSet("example.com", want)

	for i := range 3 {
		got, ok := r.cacheGet("example.com")
		if !ok {
			t.Fatalf("iter %d: cacheGet returned !ok, want hit", i)
		}
		if len(got) != len(want) {
			t.Fatalf("iter %d: len(got)=%d, want %d", i, len(got), len(want))
		}
		for j, ip := range got {
			if ip != want[j] {
				t.Errorf("iter %d: got[%d]=%v, want %v", i, j, ip, want[j])
			}
		}
	}
}

// TestCacheReturnsDefensiveCopy verifies that callers can mutate the
// returned slice without corrupting the cache — a footgun avoided in
// cacheGet by copying before return.
func TestCacheReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()
	r := newTestResolver(t)
	r.cacheSet("host", []netip.Addr{mustAddr(t, "1.1.1.1")})

	first, _ := r.cacheGet("host")
	first[0] = mustAddr(t, "9.9.9.9")

	second, _ := r.cacheGet("host")
	if second[0].String() != "1.1.1.1" {
		t.Errorf("cache poisoned by caller mutation: %v", second[0])
	}
}

// TestCacheExpires verifies that an entry inserted with an artificially
// expired timestamp is treated as a miss and removed.
func TestCacheExpires(t *testing.T) {
	t.Parallel()
	r := newTestResolver(t)
	r.cache["host"] = dnsCacheEntry{
		ips:     []netip.Addr{mustAddr(t, "1.1.1.1")},
		expires: time.Now().Add(-1 * time.Second),
	}

	if _, ok := r.cacheGet("host"); ok {
		t.Fatal("expired entry returned as hit")
	}
	// Subsequent get must still be a miss (no resurrection bug).
	if _, ok := r.cacheGet("host"); ok {
		t.Fatal("expired entry returned as hit on second call")
	}
}

// TestCacheSetEmptyNoop verifies that setting an empty IP slice is a
// no-op — otherwise the cache could record a misleading "no results"
// entry that masks recovery on the next lookup.
func TestCacheSetEmptyNoop(t *testing.T) {
	t.Parallel()
	r := newTestResolver(t)
	r.cacheSet("host", nil)
	if _, ok := r.cacheGet("host"); ok {
		t.Fatal("cacheSet of nil produced a hit")
	}
	r.cacheSet("host", []netip.Addr{})
	if _, ok := r.cacheGet("host"); ok {
		t.Fatal("cacheSet of empty slice produced a hit")
	}
}

// TestPublicDNSFallbackConstant catches an accidental rewrite that
// would change the fallback target without operator awareness. 1.1.1.1
// is intentional and exercised in the LookupIP fallback path.
func TestPublicDNSFallbackConstant(t *testing.T) {
	t.Parallel()
	if publicDNSFallback.Addr().String() != "1.1.1.1" {
		t.Errorf("publicDNSFallback.Addr() = %v, want 1.1.1.1", publicDNSFallback.Addr())
	}
	if publicDNSFallback.Port() != 53 {
		t.Errorf("publicDNSFallback.Port() = %v, want 53", publicDNSFallback.Port())
	}
}
