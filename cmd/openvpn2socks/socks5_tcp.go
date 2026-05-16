// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/n0madic/go-openvpn/pkg/netstack"
)

// handleConnect resolves the destination, dials TCP via the netstack, sends
// the SOCKS5 reply, and proxies bytes both ways.
func (s *socks5Server) handleConnect(ctx context.Context, client net.Conn, br *bufio.Reader, req *socksRequest) {
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	ips, err := s.resolver.LookupIP(dialCtx, req.host)
	if err != nil || len(ips) == 0 {
		s.log.Debug("CONNECT: resolve failed", "host", req.host, "err", err)
		_ = writeReply(client, repHostUnreach, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
		return
	}

	// Filter candidates to address families the tunnel actually supports.
	// Many providers push only IPv4 (no `ifconfig-ipv6`), so a v6 address in
	// the resolver output would invariably fail with "no route to host"
	// after a wasted gVisor round trip. For hostnames this transparently
	// prefers v4; for direct v6 literals it short-circuits to host-unreach.
	usable := filterUsableIPs(ips, s.ns.HasIPv4(), s.ns.HasIPv6())
	if len(usable) == 0 {
		// Expected case under happy-eyeballs: a v4-only tunnel sees
		// a v6 literal (or vice versa). REP=0x04 host unreachable
		// tells the SOCKS5 client to fall back to the other family
		// inside the same session — the system works as designed,
		// no log needed. Logging here floods -v output with one
		// pair of identical lines per client retry attempt without
		// adding diagnostic value.
		_ = writeReply(client, repHostUnreach, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
		return
	}

	target := usable[0]

	// Per-destination-IP connect-burst limit (aggregate across all
	// ports of the host). Misbehaving native clients (Telegram
	// Desktop, iCloud sync) have been observed opening 20+ CONNECTs
	// to the same address — split between :80 and :443 — in ~2
	// seconds, which trips upstream rate-limiting and cascades into
	// tunnel-wide degradation. A per-(IP,port) limiter let half of
	// the burst through; keying on the IP catches the aggregate,
	// which is what actually overloads the destination. Refusing
	// the excess locally with REP=0x05 keeps the tunnel healthy at
	// the cost of slowing the offending client.
	if s.connRate != nil && !s.connRate.allow(target) {
		s.log.Debug("CONNECT: per-host rate limit",
			"target", target, "port", req.port, "host", req.host)
		_ = writeReply(client, repConnRefused, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
		return
	}

	addr := net.JoinHostPort(usable[0].String(), strconv.Itoa(int(req.port)))
	remote, err := s.ns.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		s.log.Debug("CONNECT: dial failed", "addr", addr, "err", err)
		_ = writeReply(client, mapDialError(err), netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
		return
	}
	defer func() { _ = remote.Close() }()

	s.log.Debug("CONNECT", "client", client.RemoteAddr(), "target", addr, "resolved_from", req.host)

	bnd := localAddrPort(remote)
	if err := writeReply(client, repSucceeded, bnd); err != nil {
		s.log.Debug("CONNECT: reply failed", "err", err)
		return
	}

	s.proxy(ctx, client, br, remote)
}

// proxy copies bytes in both directions until either side closes. The bufio
// reader is drained first (the client may have prefetched into it during the
// greeting).
func (s *socks5Server) proxy(ctx context.Context, client net.Conn, br *bufio.Reader, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	idleDeadline := func() {
		if s.idle > 0 {
			_ = client.SetDeadline(time.Now().Add(s.idle))
			_ = remote.SetDeadline(time.Now().Add(s.idle))
		}
	}
	idleDeadline()

	go func() {
		defer wg.Done()
		// client → remote: include anything buffered in br.
		if buffered := br.Buffered(); buffered > 0 {
			b, _ := br.Peek(buffered)
			_, _ = remote.Write(b)
			_, _ = br.Discard(buffered)
		}
		_, _ = io.Copy(writeDeadliner{remote, s.idle}, client)
		// Half-close remote write side so the other goroutine sees EOF.
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = remote.Close()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(writeDeadliner{client, s.idle}, remote)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = client.Close()
		}
	}()
	// If the parent ctx is cancelled mid-flight, force-close everything.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = remote.Close()
		case <-done:
		}
	}()
	wg.Wait()
	close(done)
}

// writeDeadliner wraps a net.Conn so each Write extends the idle deadline.
type writeDeadliner struct {
	net.Conn
	idle time.Duration
}

func (w writeDeadliner) Write(p []byte) (int, error) {
	if w.idle > 0 {
		_ = w.SetDeadline(time.Now().Add(w.idle))
	}
	return w.Conn.Write(p)
}

// mapDialError translates a generic dial error into the closest SOCKS5
// reply code. Prefers errors.Is/As over string-matching where possible:
// gVisor returns wrapped *net.OpError values whose underlying causes
// can be inspected. String-matching remains a last-resort fallback.
func mapDialError(err error) byte {
	if err == nil {
		return repSucceeded
	}
	// netstack.ErrTunnelIPChanged means an AutoReconnect-driven IP swap
	// invalidated the in-flight dial. The conn has already been closed
	// by netstack; the SOCKS5 client should retry, so signal host-
	// unreachable rather than the generic failure code: most clients
	// (curl, browsers) treat host-unreachable as transient and re-issue,
	// while a generic failure terminates the request.
	if errors.Is(err, netstack.ErrTunnelIPChanged) {
		return repHostUnreach
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return repTTLExpired
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return repTTLExpired
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return repConnRefused
	}
	if errors.Is(err, syscall.EHOSTUNREACH) {
		return repHostUnreach
	}
	if errors.Is(err, syscall.ENETUNREACH) {
		return repNetworkUnreach
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Timeout() {
		return repTTLExpired
	}
	// Fallback: gVisor's tcpip.Error values stringify but don't wrap to
	// the standard syscall constants. Inspect the message text.
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "refused"):
		return repConnRefused
	case strings.Contains(msg, "no route"), strings.Contains(msg, "host is unreachable"),
		strings.Contains(msg, "unreachable host"), strings.Contains(msg, "no such host"):
		return repHostUnreach
	case strings.Contains(msg, "network is unreachable"), strings.Contains(msg, "unreach"):
		return repNetworkUnreach
	case strings.Contains(msg, "timed out"), strings.Contains(msg, "deadline exceeded"),
		strings.Contains(msg, "context canceled"):
		return repTTLExpired
	default:
		return repGeneralFailure
	}
}

// filterUsableIPs returns the entries of ips whose address family the tunnel
// can actually carry. Preserves input order, so a resolver result like
// [v4, v6, v4] with v6-only support yields [v6]; with v4-only support yields
// [v4, v4]. Pure function — easier to unit-test than inlining the predicate.
func filterUsableIPs(ips []netip.Addr, haveV4, haveV6 bool) []netip.Addr {
	out := ips[:0:0] // fresh backing array; never alias caller's slice
	for _, ip := range ips {
		if ip.Is4() && haveV4 {
			out = append(out, ip)
			continue
		}
		if ip.Is6() && haveV6 {
			out = append(out, ip)
		}
	}
	return out
}

// localAddrPort returns the conn's LocalAddr as a netip.AddrPort. Used for the
// BND fields in the SOCKS reply. Falls back to 0.0.0.0:0 on parse failures.
func localAddrPort(c net.Conn) netip.AddrPort {
	a := c.LocalAddr()
	if a == nil {
		return netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap
	}
	return netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
}
