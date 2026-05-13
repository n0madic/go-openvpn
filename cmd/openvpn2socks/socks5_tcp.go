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

	addr := net.JoinHostPort(ips[0].String(), strconv.Itoa(int(req.port)))
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
