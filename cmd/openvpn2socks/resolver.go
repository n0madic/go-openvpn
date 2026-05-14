// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-openvpn/pkg/netstack"
)

// resolver resolves hostnames to IPs in priority order:
//
//  1. -dns override (queried over the tunnel)
//  2. each PUSH_REPLY DNS server (queried over the tunnel)
//  3. system net.Resolver — only if (1) and (2) yielded nothing; a single
//     warning is logged so the user knows DNS is not going through the VPN.
//
// Consecutive DNS-over-tunnel failures are a strong signal that the tunnel
// has gone "zombie" — the OpenVPN session is technically alive (control
// plane chats, server keepalives flow) but the data plane is dropping new
// queries. The OpenVPN ping-restart watchdog can't always detect this on
// its own, so the resolver exposes a `restartHook` that gets called after
// `restartThreshold` consecutive failures. The CLI wires this to
// `openvpn.Client.RequestRestart`, which triggers AutoReconnect.
type resolver struct {
	ns       *netstack.Net
	pushed   []netip.Addr
	override netip.AddrPort

	restartHook      func(reason string) // nil ⇒ feature off
	restartThreshold int                 // ≤0 disables
	consecutiveFails atomic.Int32

	// lastSystemWarnNs is the UnixNano of the most recent
	// "DNS-over-tunnel failed → using system resolver" warning. We
	// throttle the message rather than fire it once-ever (a) so the user
	// sees if DNS leakage is one-off vs ongoing, and (b) so the log
	// doesn't spam when a streak of queries fails.
	lastSystemWarnNs atomic.Int64
	log              *slog.Logger
}

// systemWarnThrottle is the minimum gap between two consecutive "falling
// back to system resolver" warnings.
const systemWarnThrottle = 60 * time.Second

func newResolver(ns *netstack.Net, pushed []netip.Addr, override netip.AddrPort, log *slog.Logger) *resolver {
	return &resolver{ns: ns, pushed: pushed, override: override, log: log}
}

// SetRestartHook wires the resolver to an application-level restart trigger
// (typically openvpn.Client.RequestRestart). threshold sets how many
// *consecutive* DNS-over-tunnel failures count as "tunnel is dead, get me a
// fresh session". A successful lookup clears the counter. Pass threshold<=0
// to disable.
func (r *resolver) SetRestartHook(hook func(reason string), threshold int) {
	r.restartHook = hook
	r.restartThreshold = threshold
}

// LookupIP returns the resolved A/AAAA records for host. If host is already
// an IP literal it is returned as-is.
func (r *resolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	tunnelAttempted := false

	// 1. -dns override.
	if r.override.IsValid() {
		tunnelAttempted = true
		if ips, err := r.queryOverTunnel(ctx, r.override, host); err == nil && len(ips) > 0 {
			r.consecutiveFails.Store(0)
			return ips, nil
		}
	}
	// 2. Pushed DNS servers, in order.
	for _, srv := range r.pushed {
		if !srv.IsValid() {
			continue
		}
		tunnelAttempted = true
		ap := netip.AddrPortFrom(srv, 53)
		if ips, err := r.queryOverTunnel(ctx, ap, host); err == nil && len(ips) > 0 {
			r.consecutiveFails.Store(0)
			return ips, nil
		}
	}
	// All tunnel DNS attempts failed (or none configured). When DNS is
	// supposed to go through the tunnel, repeated failures probably mean
	// the tunnel is in a half-broken zombie state — trigger AutoReconnect
	// after threshold so a fresh session restores DNS.
	if tunnelAttempted {
		r.handleTunnelFailure()
	}
	// 3. System fallback. Tunnel DNS will be re-attempted on the *next*
	// LookupIP; this fallback is only for the current query. Throttle the
	// warning so the user sees if leakage is one-off or ongoing without
	// spamming the log when a streak of queries fails.
	if tunnelAttempted {
		r.maybeWarnSystemFallback(host)
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return ips, nil
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

// handleTunnelFailure increments the consecutive-failure counter and, when
// it crosses the configured threshold, asks the OpenVPN client to drop the
// current session and reconnect. Counter is cleared on a successful tunnel
// query (see LookupIP) so a single transient hiccup never escalates.
func (r *resolver) handleTunnelFailure() {
	if r.restartHook == nil || r.restartThreshold <= 0 {
		return
	}
	n := r.consecutiveFails.Add(1)
	if int(n) < r.restartThreshold {
		return
	}
	// CAS-style reset: zero the counter before invoking the hook so a
	// reentrant call (or the next query racing the hook) starts fresh.
	r.consecutiveFails.Store(0)
	reason := fmt.Sprintf("DNS-over-tunnel failed %d consecutive times", n)
	r.log.Warn("requesting session restart from resolver", "reason", reason)
	r.restartHook(reason)
}

// queryOverTunnel sends parallel DNS A and AAAA queries to server via the
// netstack and returns the merged answer IPs. Each qtype runs on its own
// gonet UDP conn with its own per-query deadline — that way a slow A
// response doesn't burn the whole deadline and force AAAA to fail without
// having even hit the wire (a real failure mode observed against
// ProtonVPN's pushed resolver).
func (r *resolver) queryOverTunnel(ctx context.Context, server netip.AddrPort, host string) ([]netip.Addr, error) {
	type result struct {
		ips   []netip.Addr
		err   error
		qtype uint16
	}
	qtypes := []uint16{dnsTypeA, dnsTypeAAAA}
	ch := make(chan result, len(qtypes))
	for _, qt := range qtypes {
		go func(qt uint16) {
			qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
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
	for range qtypes {
		res := <-ch
		if res.err != nil {
			r.log.Debug("DNS query failed", "server", server, "host", host, "qtype", res.qtype, "err", res.err)
			continue
		}
		out = append(out, res.ips...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no records for %q from %s", host, server)
	}
	return out, nil
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
	return parseDNSAnswers(buf[:n], id, qtype)
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
	dnsTypeA    uint16 = 1
	dnsTypeAAAA uint16 = 28
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

// parseDNSAnswers extracts A or AAAA records from a response. Validates the
// header (ID/QR/RCODE) but does not strictly validate the question section —
// just skips past it to reach answers.
func parseDNSAnswers(resp []byte, wantID uint16, wantType uint16) ([]netip.Addr, error) {
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
	if rcode := flags & 0x000F; rcode != 0 {
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

	var out []netip.Addr
	for i := 0; i < int(ancount); i++ {
		var err error
		pos, err = skipName(resp, pos)
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
		rdata := resp[pos : pos+rdlen]
		pos += rdlen
		if typ != wantType {
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
