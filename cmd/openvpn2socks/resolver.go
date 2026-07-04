// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-openvpn/pkg/netstack"
	"golang.org/x/sync/singleflight"
)

// dnsCacheTTL is how long a successful resolution is kept. Chosen to be
// short enough that geo-DNS and load-balanced records rotate within a
// reasonable user-visible window, but long enough to mask a flaky
// upstream DNS server through a typical browsing session.
const dnsCacheTTL = 60 * time.Second

// errDNSAuthoritativeNoData is returned by queryOverTunnel when the tunneled
// resolver gave a definitive negative answer for every queried qtype —
// NXDOMAIN (RCODE=3) or NOERROR with zero answers. The host either does
// not exist or does not have records of the requested family. Distinguishing
// this from "resolver unreachable" (network error, timeout, SERVFAIL) is
// critical: a definitive negative MUST NOT trigger a system-resolver
// fallback, because that fallback would leak the query name to the ISP DNS.
var errDNSAuthoritativeNoData = errors.New("dns: authoritative no data")

// errDNSDisallowedLiteral is returned by LookupIP when host is an IP literal
// of a class we never proxy through SOCKS5 — loopback, unspecified,
// multicast, link-local. These would either let a SOCKS5 client probe the
// gVisor stack's internal addresses or send traffic to ranges that have no
// useful meaning over the tunnel.
var errDNSDisallowedLiteral = errors.New("dns: refusing literal IP of restricted class")

// publicDNSFallback is the well-known public resolver we query over the
// tunnel when the pushed/override resolver doesn't respond. Picked over
// 8.8.8.8 specifically because Cloudflare is the most aggressive about
// SLA on DNS uptime and is reachable from virtually every VPN egress.
// The query still goes through the tunnel — no DNS leak.
var publicDNSFallback = netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 53)

// dnsCacheEntry is one cached resolution.
type dnsCacheEntry struct {
	ips     []netip.Addr
	expires time.Time
}

// resolver resolves hostnames to IPs in priority order:
//
//  0. positive cache (per-host, dnsCacheTTL) — shielded from a flaky
//     upstream resolver between cache entries
//  1. -dns override (queried over the tunnel)
//  2. each PUSH_REPLY DNS server (queried over the tunnel)
//  3. publicDNSFallback (1.1.1.1) over the tunnel — masks failures of the
//     provider's resolver while still keeping DNS *inside* the VPN
//  4. system net.Resolver — only when every tunneled option yielded
//     nothing; a throttled warning is logged so the user knows DNS leaked
type resolver struct {
	ns       *netstack.Net
	pushed   []netip.Addr
	override netip.AddrPort

	// lastSystemWarnNs is the UnixNano of the most recent
	// "DNS-over-tunnel failed → using system resolver" warning. We
	// throttle the message rather than fire it once-ever (a) so the user
	// sees if DNS leakage is one-off vs ongoing, and (b) so the log
	// doesn't spam when a streak of queries fails.
	lastSystemWarnNs atomic.Int64
	log              *slog.Logger

	cacheMu sync.Mutex
	cache   map[string]dnsCacheEntry

	// inflight deduplicates concurrent LookupIP calls for the same host.
	// Without it, a cold-cache page load (8-20 parallel sockets to one
	// origin) issues N parallel tunneled DNS queries each spawning two
	// gonet UDP conns (A + AAAA) — a documented contributor to upstream
	// UDP rate-limiting on v4-only ProtonVPN tunnels. The first caller
	// dispatches the lookup; the rest wait for the cached result.
	inflight singleflight.Group

	// Diagnostic counters surfaced by Stats / startStatsLogger so the
	// operator can see whether the DNS cache is doing useful work or
	// every lookup is paying the tunneled-query cost.
	statsCacheHit  atomic.Uint64
	statsCacheMiss atomic.Uint64

	// queryOverTunnelFn, when non-nil, replaces the default
	// queryOverTunnel implementation. Used by tests that need to
	// inject a deterministic resolver without standing up a netstack.
	// Production code leaves it nil.
	queryOverTunnelFn func(ctx context.Context, server netip.AddrPort, host string) ([]netip.Addr, error)

	// systemLookupFn, when non-nil, replaces net.DefaultResolver.
	// LookupNetIP for the system-fallback branch of LookupIP. Used by
	// tests to prove the fallback stays cold when a tunneled resolver
	// reported authoritative-negative — the highest-impact leak vector
	// the negative-cache logic prevents.
	systemLookupFn func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// systemWarnThrottle is the minimum gap between two consecutive "falling
// back to system resolver" warnings.
const systemWarnThrottle = 60 * time.Second

// dnsStatsLogPeriod is how often startStatsLogger emits a snapshot.
// Matched to the netstack stats logger period so the two interleave
// on the same cadence — easier to read in a live tail.
const dnsStatsLogPeriod = 30 * time.Second

// dnsCacheGCPeriod is how often the cache is swept for expired entries.
// Without an active sweep, entries that are never re-queried after expiry
// stay resident forever — a browser visiting thousands of distinct hosts
// (CDN subdomains, ad/tracker domains, etc.) accumulates one entry per
// hostname for the life of the daemon. The sweep also bounds the memory
// available to an adversarial client on a non-loopback bind that issues
// CONNECTs to `random-${i}.example.com`.
const dnsCacheGCPeriod = 5 * time.Minute

// dnsSharedResolveTimeout bounds a singleflight-shared resolution once it is
// detached from the leader caller's context. Generous enough to cover the full
// override → pushed → public-fallback chain (each qtype capped at ~3s) without
// running unbounded if every waiter has already given up.
const dnsSharedResolveTimeout = 30 * time.Second

// dnsCacheMaxEntries caps the cache to prevent unbounded growth between
// GC sweeps. When the cap is reached cacheSet evicts the soonest-expiring
// entry from a small random sample (O(1) amortised) rather than scanning the
// whole map, so a sustained unique-host stream can't pin the shared cache lock.
const dnsCacheMaxEntries = 8192

// Stats returns lifetime cumulative cache-hit and cache-miss counters.
// Snapshot is consistent per field but the two are read independently;
// the slight observation skew is acceptable for an observability counter.
func (r *resolver) Stats() (hits, misses uint64) {
	return r.statsCacheHit.Load(), r.statsCacheMiss.Load()
}

// dnsCacheHitRate returns the percentage of lookups served from cache
// in the supplied window, rounded to two decimal places so the log
// line stays readable (otherwise float64 prints noise like
// "25.925925925925927"). Returns 0 when the window is empty so the
// log line doesn't carry a misleading 100% for an idle interval.
// Pulled out as a pure function for direct unit testing.
func dnsCacheHitRate(hits, misses uint64) float64 {
	total := hits + misses
	if total == 0 {
		return 0
	}
	pct := 100 * float64(hits) / float64(total)
	return math.Round(pct*100) / 100
}

// startStatsLogger spawns a goroutine that logs DNS cache statistics
// every dnsStatsLogPeriod, both as deltas (the actionable form for
// the current window — "is the cache helping THIS window") and as
// lifetime totals (sanity check for long-running daemons). Exits on
// ctx.Done().
//
// Logged at Debug. Cache hit/miss ratios don't escalate to Warn on
// their own — a 0% hit rate during a window of one cold lookup is
// expected, not alarming. Use the netstack stats log line for "is
// data flowing at all" and this one for "are repeat lookups fast".
func (r *resolver) startStatsLogger(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(dnsStatsLogPeriod)
		defer ticker.Stop()
		var prevHits, prevMisses uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			hits, misses := r.Stats()
			dHits := hits - prevHits
			dMisses := misses - prevMisses
			prevHits, prevMisses = hits, misses
			// Skip emitting an all-zero line on a quiet tunnel —
			// nothing to say and the log gets noisier than the
			// signal warrants.
			if dHits == 0 && dMisses == 0 && hits == 0 && misses == 0 {
				continue
			}
			r.log.Debug("dns cache stats",
				"hits_total", hits,
				"misses_total", misses,
				"delta_hits", dHits,
				"delta_misses", dMisses,
				"hit_rate_pct", dnsCacheHitRate(dHits, dMisses),
				"hit_rate_pct_lifetime", dnsCacheHitRate(hits, misses),
			)
		}
	}()
}

func newResolver(ns *netstack.Net, pushed []netip.Addr, override netip.AddrPort, log *slog.Logger) *resolver {
	return &resolver{
		ns:       ns,
		pushed:   pushed,
		override: override,
		log:      log,
		cache:    make(map[string]dnsCacheEntry),
	}
}

// cacheGet returns cached IPs for host if the entry is still fresh.
func (r *resolver) cacheGet(host string) ([]netip.Addr, bool) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	e, ok := r.cache[host]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expires) {
		delete(r.cache, host)
		return nil, false
	}
	// Defensive copy so callers can mutate without poisoning the cache.
	out := make([]netip.Addr, len(e.ips))
	copy(out, e.ips)
	return out, true
}

// cacheSet stores ips for host with TTL dnsCacheTTL. When the cache is at
// dnsCacheMaxEntries it evicts the entry expiring soonest to make room —
// a simple bounded-memory backstop between dnsCacheGCPeriod sweeps.
func (r *resolver) cacheSet(host string, ips []netip.Addr) {
	if len(ips) == 0 {
		return
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if _, exists := r.cache[host]; !exists && len(r.cache) >= dnsCacheMaxEntries {
		// Evict from a small random sample rather than scanning the whole
		// map. Under a sustained stream of unique hosts the cache stays pinned
		// at the cap, so a full O(n) walk on every insert — under the global
		// lock that every cacheGet/cacheSet shares — would degrade resolve
		// latency for ALL clients, not just the one generating load. Sampling
		// K entries (Go map iteration is randomised) and evicting the
		// soonest-expiring among them is O(1) amortised and keeps eviction
		// quality close to true soonest-expiry.
		const evictSample = 8
		var evictKey string
		var evictAt time.Time
		seen := 0
		for k, e := range r.cache {
			if evictKey == "" || e.expires.Before(evictAt) {
				evictKey, evictAt = k, e.expires
			}
			if seen++; seen >= evictSample {
				break
			}
		}
		if evictKey != "" {
			delete(r.cache, evictKey)
		}
	}
	stored := make([]netip.Addr, len(ips))
	copy(stored, ips)
	r.cache[host] = dnsCacheEntry{ips: stored, expires: time.Now().Add(dnsCacheTTL)}
}

// cacheSweep removes every entry whose TTL has expired. Called by the
// periodic GC goroutine to bound resident memory across many distinct
// hostnames that are never re-queried.
func (r *resolver) cacheSweep() {
	now := time.Now()
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	for k, e := range r.cache {
		if now.After(e.expires) {
			delete(r.cache, k)
		}
	}
}

// startCacheGC spawns a goroutine that sweeps expired entries on every
// dnsCacheGCPeriod tick. Exits on ctx.Done().
func (r *resolver) startCacheGC(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(dnsCacheGCPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.cacheSweep()
			}
		}
	}()
}

// LookupIP returns the resolved A/AAAA records for host. If host is already
// an IP literal it is returned as-is.
//
// Resolution order with cache and tunnel-fallback:
//
//  0. cache (fresh entry, < dnsCacheTTL old) — shields the user from a
//     flaky upstream DNS server between cache windows
//  1. -dns override (over the tunnel)
//  2. each PUSH_REPLY DNS server (over the tunnel)
//  3. publicDNSFallback (1.1.1.1) over the tunnel — masks a broken
//     provider resolver while keeping DNS inside the VPN
//  4. system net.Resolver — last resort, emits the throttled leak warning
//
// Cache writes happen on every successful tunneled resolution (so
// fallback-resolved entries also serve future cache hits) but NOT on
// system-fallback resolutions — caching a system-resolved IP could
// accidentally prolong a DNS-leak window after the tunnel recovers.
func (r *resolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !isProxiableLiteral(ip) {
			return nil, fmt.Errorf("%w: %s", errDNSDisallowedLiteral, ip)
		}
		return []netip.Addr{ip}, nil
	}

	if ips, ok := r.cacheGet(host); ok {
		r.statsCacheHit.Add(1)
		return ips, nil
	}
	r.statsCacheMiss.Add(1)

	// Deduplicate concurrent misses for the same host. The shared resolution
	// is detached from the singleflight leader's context: whichever caller
	// became leader may have a shorter deadline than the followers waiting on
	// it, and they must not inherit the leader's (possibly imminent)
	// cancellation — otherwise a second browser tab resolving the same domain
	// spuriously fails just because the first tab's request started earlier.
	// context.WithoutCancel preserves ctx values; a fresh timeout bounds the
	// work. Each caller still waits via its OWN ctx in the select below, so a
	// caller with a tight deadline bails without poisoning the others.
	resCh := r.inflight.DoChan(host, func() (any, error) {
		shared, cancel := context.WithTimeout(context.WithoutCancel(ctx), dnsSharedResolveTimeout)
		defer cancel()
		return r.lookupIPUncached(shared, host)
	})
	select {
	case res := <-resCh:
		if res.Err != nil {
			return nil, res.Err
		}
		// Defensive copy: x/sync returns the same shared value to all
		// waiters, and downstream code may mutate the slice (filterUsableIPs).
		src := res.Val.([]netip.Addr)
		out := make([]netip.Addr, len(src))
		copy(out, src)
		return out, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// lookupIPUncached runs the full resolution chain (tunneled resolvers →
// public fallback → system) without consulting the cache. The caller
// (LookupIP) handles cache lookup and singleflight deduplication.
func (r *resolver) lookupIPUncached(ctx context.Context, host string) ([]netip.Addr, error) {
	tunnelAttempted := false
	sawAuthoritativeNoData := false

	// 1. -dns override.
	if r.override.IsValid() {
		tunnelAttempted = true
		ips, err := r.runTunneledQuery(ctx, r.override, host)
		if err == nil && len(ips) > 0 {
			r.cacheSet(host, ips)
			return ips, nil
		}
		if errors.Is(err, errDNSAuthoritativeNoData) {
			sawAuthoritativeNoData = true
		}
	}
	// 2. Pushed DNS servers, in order.
	for _, srv := range r.pushed {
		if !srv.IsValid() {
			continue
		}
		tunnelAttempted = true
		ap := netip.AddrPortFrom(srv, 53)
		ips, err := r.runTunneledQuery(ctx, ap, host)
		if err == nil && len(ips) > 0 {
			r.cacheSet(host, ips)
			return ips, nil
		}
		if errors.Is(err, errDNSAuthoritativeNoData) {
			sawAuthoritativeNoData = true
		}
	}
	// 3. publicDNSFallback over the tunnel — try a different resolver
	// before giving up to the system one. Only runs when the operator
	// hasn't explicitly overridden DNS (override is treated as
	// authoritative; if it's broken we honour the user's intent and
	// don't second-guess them).
	if !r.override.IsValid() {
		tunnelAttempted = true
		ips, err := r.runTunneledQuery(ctx, publicDNSFallback, host)
		if err == nil && len(ips) > 0 {
			r.log.Debug("DNS-over-tunnel fallback succeeded via public resolver",
				"host", host, "via", publicDNSFallback)
			r.cacheSet(host, ips)
			return ips, nil
		}
		if errors.Is(err, errDNSAuthoritativeNoData) {
			sawAuthoritativeNoData = true
		}
	}
	// Authoritative negative from any tunneled resolver is FINAL. Falling
	// back to the system resolver would just leak the host name to the
	// ISP DNS for no benefit — the tunneled resolver already told us the
	// record doesn't exist for our usable address families.
	if sawAuthoritativeNoData {
		return nil, fmt.Errorf("no records for %q (authoritative)", host)
	}
	// 4. System fallback. Tunnel DNS will be re-attempted on the *next*
	// LookupIP; this fallback is only for the current query. Result is
	// intentionally NOT cached — caching a system-resolved IP could
	// prolong DNS leakage after the tunnel recovers. The result is also
	// filtered to the tunnel's actual address families, so a v6 record
	// returned by the system resolver doesn't reach gVisor on a v4-only
	// tunnel (which would either error or, worse, retry through the
	// system resolver chain and leak again).
	if tunnelAttempted {
		r.maybeWarnSystemFallback(host)
	}
	lookup := r.systemLookupFn
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	ips, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	hasV4, hasV6 := true, true
	if r.ns != nil {
		hasV4 = r.ns.HasIPv4()
		hasV6 = r.ns.HasIPv6()
	}
	ips = filterUsableIPs(ips, hasV4, hasV6)
	if len(ips) == 0 {
		return nil, fmt.Errorf("no usable address family for %q from system resolver", host)
	}
	return ips, nil
}

// isProxiableLiteral reports whether the SOCKS5 proxy will carry traffic to
// the given IP literal. Loopback, unspecified, multicast and link-local
// addresses are filtered to prevent a SOCKS5 client from using us to probe
// the gVisor stack's internal address space (127.0.0.1, ::1) or to ship
// traffic to ranges that have no meaning over the tunnel (multicast,
// link-local). RFC1918 / ULA / CGNAT addresses are INTENTIONALLY allowed
// through — many VPN deployments host private services (admin panels,
// internal DNS, monitoring) inside the tunnel and refusing those classes
// would silently break access to them.
func isProxiableLiteral(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

// maybeWarnSystemFallback emits a throttled warning when we use the system
// resolver because DNS-over-tunnel failed for `host`. Fires at most once
// per systemWarnThrottle window so an ongoing leak stays visible but a
// burst of failures doesn't flood the log.
func (r *resolver) maybeWarnSystemFallback(host string) {
	now := time.Now().UnixNano()
	last := r.lastSystemWarnNs.Load()
	if now-last < int64(systemWarnThrottle) {
		return
	}
	if !r.lastSystemWarnNs.CompareAndSwap(last, now) {
		return
	}
	r.log.Warn("DNS-over-tunnel failed — this query falls back to system resolver (tunnel DNS will be retried on the next lookup)",
		"host", host)
}

// pickQueryTypes returns the DNS qtypes worth issuing for a host given
// the NIC's current address families. AAAA queries are pure overhead
// when the NIC has no IPv6 address — the response IPs are unreachable
// and filterUsableIPs would discard them anyway — so we skip them
// entirely to halve the DNS wire load on v4-only tunnels (which is the
// common case for ProtonVPN users without v6). Pulled out as a pure
// function for trivial unit-testing.
func pickQueryTypes(hasV4, hasV6 bool) []uint16 {
	qtypes := make([]uint16, 0, 2)
	if hasV4 {
		qtypes = append(qtypes, dnsTypeA)
	}
	if hasV6 {
		qtypes = append(qtypes, dnsTypeAAAA)
	}
	return qtypes
}

// runTunneledQuery dispatches a tunneled DNS query through the
// queryOverTunnelFn seam when set (tests), otherwise through the real
// queryOverTunnel. Centralising the dispatch keeps LookupIP free of
// per-call seam checks and gives one place to inject deterministic
// resolver behaviour from tests.
func (r *resolver) runTunneledQuery(ctx context.Context, server netip.AddrPort, host string) ([]netip.Addr, error) {
	if r.queryOverTunnelFn != nil {
		return r.queryOverTunnelFn(ctx, server, host)
	}
	return r.queryOverTunnel(ctx, server, host)
}

// queryOverTunnel sends the relevant DNS queries (A and/or AAAA, see
// pickQueryTypes) to server via the netstack in parallel and returns
// the merged answer IPs. Each qtype runs on its own gonet UDP conn
// with its own per-query deadline — that way a slow A response doesn't
// burn the whole deadline and force AAAA to fail without having even
// hit the wire (a real failure mode observed against ProtonVPN's
// pushed resolver). Issuing AAAA on a v4-only NIC is suppressed
// entirely; gratuitous AAAA queries are the single biggest source of
// DNS load against the tunnel under browser workloads and contributed
// directly to the upstream UDP rate-limit we've seen.
func (r *resolver) queryOverTunnel(ctx context.Context, server netip.AddrPort, host string) ([]netip.Addr, error) {
	type result struct {
		ips   []netip.Addr
		err   error
		qtype uint16
	}
	// Default to both families when ns is nil so unit tests that don't
	// wire up a netstack continue to exercise the merge path.
	hasV4, hasV6 := true, true
	if r.ns != nil {
		hasV4 = r.ns.HasIPv4()
		hasV6 = r.ns.HasIPv6()
	}
	qtypes := pickQueryTypes(hasV4, hasV6)
	if len(qtypes) == 0 {
		return nil, fmt.Errorf("no usable address family for DNS lookup of %q", host)
	}
	// Pick the per-qtype deadline as the min of our hard cap and any
	// shorter deadline the caller already imposed via ctx. Without this
	// every query waits the full 3s even when the caller passed e.g.
	// 100ms — and stays unresponsive to ctx cancellation in the receive
	// loop below until each goroutine independently times out.
	const perQtypeCap = 3 * time.Second
	qtypeTimeout := perQtypeCap
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem < qtypeTimeout {
			qtypeTimeout = rem
		}
	}
	ch := make(chan result, len(qtypes))
	for _, qt := range qtypes {
		go func(qt uint16) {
			qctx, cancel := context.WithTimeout(ctx, qtypeTimeout)
			defer cancel()
			conn, err := r.ns.DialContext(qctx, "udp", server.String())
			if err != nil {
				ch <- result{nil, err, qt}
				return
			}
			defer func() { _ = conn.Close() }()
			if dl, ok := qctx.Deadline(); ok {
				_ = conn.SetDeadline(dl)
			}
			ips, err := r.queryOne(conn, host, qt)
			ch <- result{ips, err, qt}
		}(qt)
	}
	var out []netip.Addr
	authoritativeNegatives := 0
	hadTransportErr := false
	// Watch ctx.Done so a parent cancellation (caller bailed) returns
	// promptly rather than waiting for every in-flight goroutine to
	// notice the cancellation independently. Goroutines still finish
	// their sends into the buffered ch (cap == len(qtypes), non-blocking)
	// and exit cleanly — no leak.
	for range qtypes {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-ch:
			if res.err != nil {
				r.log.Debug("DNS query failed", "server", server, "host", host, "qtype", res.qtype, "err", res.err)
				if errors.Is(res.err, errDNSAuthoritativeNoData) {
					authoritativeNegatives++
				} else {
					hadTransportErr = true
				}
				continue
			}
			out = append(out, res.ips...)
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	// Every qtype gave a definitive negative — signal to the caller that
	// this is a final answer and not a "try a different resolver" condition.
	if authoritativeNegatives > 0 && !hadTransportErr {
		return nil, fmt.Errorf("%w: %s via %s", errDNSAuthoritativeNoData, host, server)
	}
	return nil, fmt.Errorf("no records for %q from %s", host, server)
}

func (r *resolver) queryOne(conn net.Conn, host string, qtype uint16) ([]netip.Addr, error) {
	id, err := newDNSTxID()
	if err != nil {
		return nil, err
	}
	query, err := buildDNSQuery(id, host, qtype)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseDNSAnswers(buf[:n], id, qtype, host)
}

// newDNSTxID returns a cryptographically-random DNS transaction ID. Using
// time.Now-derived IDs is unsafe: parallel queries inside one microsecond
// would collide, and a malicious VPN server replacing the resolver could
// trivially spoof responses by predicting IDs.
func newDNSTxID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("dns: gen tx id: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// --- minimal RFC 1035 codec (only what we need: single QNAME, A/AAAA) ---

const (
	dnsTypeA     uint16 = 1
	dnsTypeCNAME uint16 = 5
	dnsTypeAAAA  uint16 = 28
)

// buildDNSQuery encodes a recursion-desired query for one QNAME / QTYPE.
func buildDNSQuery(id uint16, qname string, qtype uint16) ([]byte, error) {
	if len(qname) == 0 || len(qname) > 253 {
		return nil, fmt.Errorf("dns: invalid name %q", qname)
	}
	buf := make([]byte, 0, 64)
	hdr := [12]byte{}
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // QR=0 OPCODE=0 RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT
	buf = append(buf, hdr[:]...)

	for label := range labels(qname) {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("dns: invalid label in %q", qname)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0) // root
	var qfields [4]byte
	binary.BigEndian.PutUint16(qfields[0:2], qtype)
	binary.BigEndian.PutUint16(qfields[2:4], 1) // QCLASS=IN
	buf = append(buf, qfields[:]...)
	return buf, nil
}

// labels iterates over the dot-separated labels of name.
func labels(name string) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		start := 0
		for i := 0; i < len(name); i++ {
			if name[i] == '.' {
				if !yield(name[start:i]) {
					return
				}
				start = i + 1
			}
		}
		if start < len(name) {
			_ = yield(name[start:])
		}
	}
}

// parseDNSAnswers extracts A or AAAA records from a response for qname.
// Validates the header (ID/QR/TC/RCODE) and the owner name of every answer RR
// against qname and any CNAME chain it establishes, so records injected under
// a different name (off-path spoofing, a compromised resolver padding an
// otherwise-valid reply) are dropped.
func parseDNSAnswers(resp []byte, wantID uint16, wantType uint16, qname string) ([]netip.Addr, error) {
	if len(resp) < 12 {
		return nil, errors.New("dns: response too short")
	}
	id := binary.BigEndian.Uint16(resp[0:2])
	if id != wantID {
		return nil, fmt.Errorf("dns: id mismatch %d vs %d", id, wantID)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		return nil, errors.New("dns: not a response")
	}
	if flags&0x0200 != 0 {
		// TC (truncated): the answer didn't fit the UDP datagram. Do NOT let a
		// partial parse masquerade as an authoritative "no records" (which
		// would wrongly block the system-resolver fallback). Report a
		// transport-class failure so the caller tries another resolver. (A
		// full fix retries over TCP; A/AAAA rarely truncate, so we settle for
		// classifying it correctly rather than silently dropping records.)
		return nil, errors.New("dns: truncated response (TC set)")
	}
	rcode := flags & 0x000F
	switch rcode {
	case 0: // NOERROR — answers may still be empty (no record for this qtype).
	case 3: // NXDOMAIN — authoritative "does not exist".
		return nil, fmt.Errorf("%w: NXDOMAIN", errDNSAuthoritativeNoData)
	default:
		// SERVFAIL (2), REFUSED (5), etc — resolver couldn't answer.
		// Treated as a transport-class failure so the caller will try a
		// different resolver / fall back.
		return nil, fmt.Errorf("dns: rcode=%d", rcode)
	}
	qdcount := binary.BigEndian.Uint16(resp[4:6])
	ancount := binary.BigEndian.Uint16(resp[6:8])

	pos := 12
	// Skip questions.
	for i := 0; i < int(qdcount); i++ {
		var err error
		pos, err = skipName(resp, pos)
		if err != nil {
			return nil, err
		}
		if pos+4 > len(resp) {
			return nil, errors.New("dns: truncated question")
		}
		pos += 4 // QTYPE+QCLASS
	}

	// Names we trust as answer owners: the queried name plus any CNAME target
	// reached from an already-trusted name.
	accepted := map[string]bool{canonicalDNSName(qname): true}

	var out []netip.Addr
	for i := 0; i < int(ancount); i++ {
		var owner string
		var err error
		owner, pos, err = decodeName(resp, pos)
		if err != nil {
			return nil, err
		}
		if pos+10 > len(resp) {
			return nil, errors.New("dns: truncated answer header")
		}
		typ := binary.BigEndian.Uint16(resp[pos : pos+2])
		// class @+2..+4, ttl @+4..+8
		rdlen := int(binary.BigEndian.Uint16(resp[pos+8 : pos+10]))
		pos += 10
		if pos+rdlen > len(resp) {
			return nil, errors.New("dns: truncated rdata")
		}
		rdataStart := pos
		rdata := resp[pos : pos+rdlen]
		pos += rdlen

		if typ == dnsTypeCNAME {
			// Extend the trusted-name chain, but only from a name we already
			// trust — an attacker can't bootstrap trust with a CNAME whose
			// owner we never asked for.
			if accepted[owner] {
				if target, _, derr := decodeName(resp, rdataStart); derr == nil {
					accepted[target] = true
				}
			}
			continue
		}
		if typ != wantType {
			continue
		}
		// Drop A/AAAA records whose owner name is neither the queried name nor
		// a CNAME target we followed — i.e. injected under an unrelated name.
		if !accepted[owner] {
			continue
		}
		switch typ {
		case dnsTypeA:
			if len(rdata) != 4 {
				continue
			}
			out = append(out, netip.AddrFrom4([4]byte(rdata)))
		case dnsTypeAAAA:
			if len(rdata) != 16 {
				continue
			}
			out = append(out, netip.AddrFrom16([16]byte(rdata)))
		}
	}
	// NOERROR with zero answers of the requested type is an authoritative
	// "this host has no record of this family" — signal it explicitly so
	// callers don't promote a perfectly valid negative into a system-resolver
	// fallback (which would leak the name to the ISP DNS).
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: NOERROR / 0 answers", errDNSAuthoritativeNoData)
	}
	return out, nil
}

// skipName advances past a DNS name (compressed or uncompressed). Returns the
// new position. Doesn't decode the name — we don't need its value.
func skipName(buf []byte, pos int) (int, error) {
	for {
		if pos >= len(buf) {
			return 0, errors.New("dns: name overruns buffer")
		}
		c := buf[pos]
		if c == 0 {
			return pos + 1, nil
		}
		if c&0xC0 == 0xC0 {
			// Compression pointer — 2 bytes total.
			if pos+1 >= len(buf) {
				return 0, errors.New("dns: truncated compression pointer")
			}
			return pos + 2, nil
		}
		pos += 1 + int(c)
	}
}

// decodeName decodes a (possibly compressed) DNS name at pos into a canonical
// lowercase dotted string, and returns the position just past the name in the
// linear record stream (past the first compression pointer, if any).
// Compression pointers must point strictly backwards, which — together with a
// hard jump cap — prevents pointer loops.
func decodeName(buf []byte, pos int) (string, int, error) {
	var sb strings.Builder
	next := -1
	jumps := 0
	p := pos
	for {
		if p >= len(buf) {
			return "", 0, errors.New("dns: name overruns buffer")
		}
		c := buf[p]
		if c == 0 {
			if next < 0 {
				next = p + 1
			}
			break
		}
		if c&0xC0 == 0xC0 {
			if p+1 >= len(buf) {
				return "", 0, errors.New("dns: truncated compression pointer")
			}
			ptr := (int(c&0x3F) << 8) | int(buf[p+1])
			if next < 0 {
				next = p + 2
			}
			if ptr >= p {
				return "", 0, errors.New("dns: non-backward compression pointer")
			}
			p = ptr
			if jumps++; jumps > 32 {
				return "", 0, errors.New("dns: too many compression pointers")
			}
			continue
		}
		if c&0xC0 != 0 {
			return "", 0, errors.New("dns: bad label length")
		}
		ll := int(c)
		p++
		if p+ll > len(buf) {
			return "", 0, errors.New("dns: label overruns buffer")
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for _, b := range buf[p : p+ll] {
			sb.WriteByte(asciiLower(b))
		}
		p += ll
		if sb.Len() > 253 {
			return "", 0, errors.New("dns: name too long")
		}
	}
	return sb.String(), next, nil
}

// canonicalDNSName lowercases a hostname and strips any trailing dot so it
// compares equal to the names decodeName returns.
func canonicalDNSName(name string) string {
	name = strings.TrimSuffix(name, ".")
	b := []byte(name)
	for i, c := range b {
		b[i] = asciiLower(c)
	}
	return string(b)
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
