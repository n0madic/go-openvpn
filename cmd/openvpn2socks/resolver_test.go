// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"
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

// TestPickQueryTypes verifies the address-family-aware qtype filter
// that cuts the DNS wire load in half on v4-only tunnels (the common
// ProtonVPN case observed in the field). AAAA on a v4-only NIC was a
// pure waste: the response IPs would be filtered out by
// filterUsableIPs before any dial anyway.
func TestPickQueryTypes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		hasV4, hasV6 bool
		want         []uint16
	}{
		{"v4-only NIC: only A", true, false, []uint16{dnsTypeA}},
		{"v6-only NIC: only AAAA", false, true, []uint16{dnsTypeAAAA}},
		{"dual-stack NIC: both", true, true, []uint16{dnsTypeA, dnsTypeAAAA}},
		{"no addrs: none", false, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := pickQueryTypes(tc.hasV4, tc.hasV6)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
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

// TestIsProxiableLiteral verifies the address classes refused by
// LookupIP for literal IP hosts. The filter prevents a SOCKS5 client
// from using the proxy to probe the gVisor stack's internal addresses
// (127.0.0.1, ::1) or to ship traffic to ranges that have no meaning
// over the tunnel (multicast, link-local, unspecified).
func TestIsProxiableLiteral(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ip   string
		want bool
	}{
		{"1.2.3.4", true},
		{"127.0.0.1", false},      // loopback
		{"0.0.0.0", false},        // unspecified
		{"224.0.0.1", false},      // multicast
		{"169.254.1.1", false},    // link-local v4
		{"2606:4700:4700::1111", true},
		{"::1", false},            // loopback v6
		{"::", false},             // unspecified v6
		{"fe80::1", false},        // link-local v6
		{"ff02::1", false},        // link-local multicast v6
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			t.Parallel()
			ip := mustAddr(t, tc.ip)
			if got := isProxiableLiteral(ip); got != tc.want {
				t.Errorf("isProxiableLiteral(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

// TestLookupIPLiteralFilter confirms that LookupIP refuses to proxy
// literal IPs of the restricted classes. The error is wrapped so callers
// can errors.Is(err, errDNSDisallowedLiteral) to distinguish from
// resolution failures.
func TestLookupIPLiteralFilter(t *testing.T) {
	t.Parallel()
	r := newTestResolver(t)
	for _, literal := range []string{"127.0.0.1", "::1", "0.0.0.0", "ff02::1"} {
		t.Run(literal, func(t *testing.T) {
			ips, err := r.LookupIP(t.Context(), literal)
			if err == nil {
				t.Fatalf("LookupIP(%s) returned %v, expected error", literal, ips)
			}
			if !errors.Is(err, errDNSDisallowedLiteral) {
				t.Fatalf("LookupIP(%s) err=%v, want errDNSDisallowedLiteral wrap", literal, err)
			}
		})
	}
}

// TestLookupIPAuthoritativeNoDataSuppressesSystemFallback is the
// regression test for the negative-cache leak guard: if any tunneled
// resolver reports authoritative-negative (NXDOMAIN or NOERROR/0), the
// system resolver MUST NOT be queried — that fallback would leak the
// host name to the ISP DNS for no benefit, since the tunneled resolver
// already gave a definitive answer for the usable address families.
func TestLookupIPAuthoritativeNoDataSuppressesSystemFallback(t *testing.T) {
	t.Parallel()
	r := newTestResolver(t)
	// Two pushed resolvers; the first reports authoritative-negative,
	// the second (and any later attempts via publicDNSFallback) MUST
	// still be reached for completeness — but the final fallback to
	// the system resolver MUST stay cold.
	r.pushed = []netip.Addr{mustAddr(t, "10.0.0.1"), mustAddr(t, "10.0.0.2")}
	r.queryOverTunnelFn = func(_ context.Context, server netip.AddrPort, host string) ([]netip.Addr, error) {
		return nil, fmt.Errorf("%w: NXDOMAIN via %s for %s", errDNSAuthoritativeNoData, server, host)
	}
	var systemCalls atomic.Int32
	r.systemLookupFn = func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		systemCalls.Add(1)
		return []netip.Addr{mustAddr(t, "9.9.9.9")}, nil
	}

	ips, err := r.LookupIP(t.Context(), "no-such-host.example.")
	if err == nil {
		t.Fatalf("LookupIP returned %v, expected authoritative-negative error", ips)
	}
	if systemCalls.Load() != 0 {
		t.Fatalf("system resolver was called %d times despite authoritative-negative — DNS leak regressed", systemCalls.Load())
	}
}

// TestLookupIPTransportFailFallsBackToSystem complements the
// authoritative-negative test: when the tunneled resolvers return only
// transport-class failures (timeout, SERVFAIL), the system resolver IS
// the documented last-resort. Without this case the suppression logic
// could over-fire and break tunnels with a flaky pushed DNS.
func TestLookupIPTransportFailFallsBackToSystem(t *testing.T) {
	t.Parallel()
	r := newTestResolver(t)
	r.pushed = []netip.Addr{mustAddr(t, "10.0.0.1")}
	r.queryOverTunnelFn = func(_ context.Context, server netip.AddrPort, host string) ([]netip.Addr, error) {
		return nil, fmt.Errorf("dial timeout via %s for %s", server, host)
	}
	want := mustAddr(t, "9.9.9.9")
	var systemCalls atomic.Int32
	r.systemLookupFn = func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		systemCalls.Add(1)
		return []netip.Addr{want}, nil
	}

	ips, err := r.LookupIP(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("LookupIP returned err=%v, want success via system fallback", err)
	}
	if systemCalls.Load() == 0 {
		t.Fatal("system resolver was not called despite transport-class failures from tunneled resolver")
	}
	if len(ips) != 1 || ips[0] != want {
		t.Fatalf("system fallback returned %v, want [%v]", ips, want)
	}
}

// TestParseDNSAnswersNXDomain confirms RCODE=3 surfaces as
// errDNSAuthoritativeNoData — the sentinel that prevents LookupIP from
// falling back to the system resolver (which would leak the name).
func TestParseDNSAnswersNXDomain(t *testing.T) {
	t.Parallel()
	// 12-byte header: id=0x1234, flags=0x8003 (QR=1, RCODE=3 NXDOMAIN),
	// QDCOUNT=ANCOUNT=NSCOUNT=ARCOUNT=0.
	resp := []byte{
		0x12, 0x34,
		0x80, 0x03,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	_, err := parseDNSAnswers(resp, 0x1234, dnsTypeA)
	if err == nil {
		t.Fatal("expected error for NXDOMAIN response")
	}
	if !errorsIsAuthoritativeNoData(err) {
		t.Fatalf("expected errDNSAuthoritativeNoData, got %v", err)
	}
}

// TestParseDNSAnswersNoData confirms NOERROR with zero matching answers
// is treated as authoritative — the host exists but has no record of
// the requested type (e.g. AAAA-only host queried with A).
func TestParseDNSAnswersNoData(t *testing.T) {
	t.Parallel()
	// Minimal NOERROR / 0 answers reply matching a "host." A query.
	resp := []byte{
		0x12, 0x34, // ID
		0x81, 0x80, // flags: QR=1, RD=1, RA=1, RCODE=0
		0, 1, 0, 0, 0, 0, 0, 0, // QDCOUNT=1, others=0
		// question: "host.", QTYPE=A, QCLASS=IN
		4, 'h', 'o', 's', 't', 0,
		0, 1, // QTYPE=A
		0, 1, // QCLASS=IN
	}
	_, err := parseDNSAnswers(resp, 0x1234, dnsTypeA)
	if err == nil {
		t.Fatal("expected error for NOERROR/0-answers response")
	}
	if !errorsIsAuthoritativeNoData(err) {
		t.Fatalf("expected errDNSAuthoritativeNoData, got %v", err)
	}
}

// TestParseDNSAnswersServfail confirms that non-NXDOMAIN error rcodes
// (e.g. SERVFAIL=2) are NOT classified as authoritative — they signal
// "resolver couldn't answer", which is exactly the condition that
// SHOULD trigger fallback to a different resolver.
func TestParseDNSAnswersServfail(t *testing.T) {
	t.Parallel()
	resp := []byte{
		0x12, 0x34,
		0x80, 0x02, // QR=1, RCODE=2 SERVFAIL
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	_, err := parseDNSAnswers(resp, 0x1234, dnsTypeA)
	if err == nil {
		t.Fatal("expected error for SERVFAIL response")
	}
	if errorsIsAuthoritativeNoData(err) {
		t.Fatalf("SERVFAIL classified as authoritative; got %v", err)
	}
}

// TestDNSCacheHitRate covers the pure rate formula including the
// empty-window guard (would otherwise be a 0/0 NaN that hits the log).
func TestDNSCacheHitRate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		hits, misses uint64
		want         float64
	}{
		{"empty window returns 0 not NaN", 0, 0, 0},
		{"all hits", 10, 0, 100},
		{"all misses", 0, 10, 0},
		{"half and half", 5, 5, 50},
		{"three quarter", 30, 10, 75},
		// Rounding to two decimals: 7/27 = 25.9259...% → 25.93%.
		// Catches a regression where the helper would log float64
		// noise like "25.925925925925927".
		{"two-decimal rounding 7/27", 7, 20, 25.93},
		// 1/3 → 33.3333...% → 33.33% (rounds DOWN).
		{"two-decimal rounding 1/3", 1, 2, 33.33},
		// 2/3 → 66.6666...% → 66.67% (rounds UP).
		{"two-decimal rounding 2/3", 2, 1, 66.67},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := dnsCacheHitRate(tc.hits, tc.misses); got != tc.want {
				t.Errorf("dnsCacheHitRate(%d,%d)=%v, want %v",
					tc.hits, tc.misses, got, tc.want)
			}
		})
	}
}

// TestResolverStats checks that hit/miss counters move in lock-step
// with cache lookups — the contract Stats exposes to operators via
// the periodic stats logger.
func TestResolverStats(t *testing.T) {
	t.Parallel()
	r := newTestResolver(t)
	want := []netip.Addr{mustAddr(t, "1.2.3.4")}
	r.cacheSet("example.com", want)

	if _, _ = r.cacheGet("example.com"); true {
	}
	if _, _ = r.cacheGet("example.com"); true {
	}
	if _, _ = r.cacheGet("nope"); true {
	}

	hits, misses := r.Stats()
	// cacheGet does not bump the counters itself — LookupIP does.
	// So at this point both should still be zero.
	if hits != 0 || misses != 0 {
		t.Fatalf("raw cacheGet should not move resolver.Stats; hits=%d misses=%d", hits, misses)
	}

	// Drive Stats via the LookupIP path: first lookup is a miss
	// (cache wasn't populated for "miss-host"), then the override
	// path fails, no records — but the cacheMiss counter increments.
	r.queryOverTunnelFn = func(_ context.Context, _ netip.AddrPort, _ string) ([]netip.Addr, error) {
		return nil, errors.New("simulated transport failure")
	}
	r.systemLookupFn = func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		return nil, errors.New("no system lookup in test")
	}
	_, _ = r.LookupIP(t.Context(), "miss-host.example.")
	if h, m := r.Stats(); m == 0 {
		t.Fatalf("expected miss after first LookupIP, got hits=%d misses=%d", h, m)
	}

	// Now populate the cache directly and confirm the next lookup
	// counts as a hit.
	r.cacheSet("hit-host.example.", want)
	if _, err := r.LookupIP(t.Context(), "hit-host.example."); err != nil {
		t.Fatalf("LookupIP returned err=%v on cached host", err)
	}
	hits, misses = r.Stats()
	if hits != 1 {
		t.Fatalf("expected hits=1 after cached lookup, got %d (misses=%d)", hits, misses)
	}
}

// errorsIsAuthoritativeNoData is a tiny helper to avoid importing
// "errors" purely for one call site in each test.
func errorsIsAuthoritativeNoData(err error) bool {
	for cur := err; cur != nil; {
		if cur == errDNSAuthoritativeNoData {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := cur.(unwrapper)
		if !ok {
			return false
		}
		cur = u.Unwrap()
	}
	return false
}
