// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-openvpn/pkg/netstack"
)

// --- SOCKS5 wire constants (RFC 1928 / 1929) ---

const (
	socksVer  = 0x05
	authVer   = 0x01
	authNone  = 0x00
	authUser  = 0x02
	authNoAcc = 0xFF // no acceptable methods

	cmdConnect    = 0x01
	cmdBind       = 0x02
	cmdAssociate  = 0x03
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
	rsv           = 0x00
	udpMaxPayload = 65507
)

// SOCKS5 reply codes.
const (
	repSucceeded       = 0x00
	repGeneralFailure  = 0x01
	repNetworkUnreach  = 0x03
	repHostUnreach     = 0x04
	repConnRefused     = 0x05
	repTTLExpired      = 0x06
	repCmdNotSupported = 0x07
)

// socks5Server is the entry point for SOCKS5 connections.
type socks5Server struct {
	ns       *netstack.Net
	resolver *resolver
	listen   string
	idle     time.Duration
	authUser string
	authPass string
	log      *slog.Logger

	// connRate refuses aggressive same-target burst from misbehaving
	// clients before they hit the tunnel. See connrate.go.
	connRate *connRateLimiter

	inflight atomic.Int64
}

func newSOCKS5(ns *netstack.Net, r *resolver, listen, authSpec string, idle time.Duration, log *slog.Logger) (*socks5Server, error) {
	s := &socks5Server{
		ns:       ns,
		resolver: r,
		listen:   listen,
		idle:     idle,
		log:      log,
		connRate: newConnRateLimiter(),
	}
	if authSpec != "" {
		// Reject malformed -socks-auth values rather than silently
		// dropping them, which would otherwise leave the server in
		// authNone mode AND suppress the "non-loopback without auth"
		// warning in main — the worst possible combo: open proxy with
		// an operator who believes auth is enabled.
		u, p, ok := strings.Cut(authSpec, ":")
		if !ok {
			return nil, fmt.Errorf("socks-auth: expected user:pass, got %q", authSpec)
		}
		if u == "" {
			return nil, fmt.Errorf("socks-auth: empty username (use 127.0.0.1 bind for unauthenticated access)")
		}
		s.authUser, s.authPass = u, p
	}
	return s, nil
}

// ListenAndServe binds s.listen and serves SOCKS5 until ctx is cancelled.
// Mirrors http.Server.ListenAndServe.
func (s *socks5Server) ListenAndServe(ctx context.Context) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.listen)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve runs the SOCKS5 protocol on the supplied listener until ctx is
// cancelled. The listener is closed before Serve returns. Lets callers
// (tests, supervisors) bind the socket themselves and learn the address.
func (s *socks5Server) Serve(ctx context.Context, ln net.Listener) error {
	defer func() { _ = ln.Close() }()

	// Close the listener when the context is cancelled so Accept unblocks.
	// `done` lets this goroutine exit on the happy path (Serve returning)
	// so each Serve call doesn't leak a goroutine that lives forever.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-done:
		}
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				s.log.Info("SOCKS5 shutdown complete")
				return nil
			}
			s.log.Warn("accept error", "err", err)
			continue
		}
		wg.Add(1)
		s.inflight.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer s.inflight.Add(-1)
			s.handle(ctx, c)
		}(conn)
	}
}

// handle is one accepted-conn lifetime: greet, auth, dispatch request.
//
// A ctx-watcher goroutine closes conn on shutdown so any in-flight Read
// (greet, readRequest with cleared deadline, or io.Copy(io.Discard, ctrl)
// inside handleAssociate) unblocks promptly. Without this, a SOCKS5
// client that connects and stalls — or a long-running UDP ASSOCIATE
// session — would pin Serve's wg.Wait() forever after ctx cancellation,
// which in turn would block the deferred cli.Close() in main and leave
// the process alive until SIGKILL.
func (s *socks5Server) handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)

	if err := s.greet(br, conn); err != nil {
		s.log.Debug("greet failed", "remote", conn.RemoteAddr(), "err", err)
		return
	}
	// Clear handshake deadline; per-command handlers manage their own.
	_ = conn.SetDeadline(time.Time{})

	req, err := readRequest(br)
	if err != nil {
		s.log.Debug("request parse failed", "remote", conn.RemoteAddr(), "err", err)
		_ = writeReply(conn, repGeneralFailure, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
		return
	}

	switch req.cmd {
	case cmdConnect:
		s.handleConnect(ctx, conn, br, req)
	case cmdAssociate:
		s.handleAssociate(ctx, conn, br, req)
	case cmdBind:
		_ = writeReply(conn, repCmdNotSupported, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	default:
		_ = writeReply(conn, repCmdNotSupported, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	}
}

// greet implements the method-selection + optional username/password
// subnegotiation. Returns nil iff the client is authenticated.
func (s *socks5Server) greet(br *bufio.Reader, w io.Writer) error {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return fmt.Errorf("read greet header: %w", err)
	}
	if hdr[0] != socksVer {
		return fmt.Errorf("bad version 0x%02x", hdr[0])
	}
	n := int(hdr[1])
	if n == 0 {
		return errors.New("zero methods")
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(br, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	want := byte(authNone)
	if s.authUser != "" {
		want = authUser
	}
	if !slices.Contains(methods, want) {
		_, _ = w.Write([]byte{socksVer, authNoAcc})
		return fmt.Errorf("no acceptable auth method (want=0x%02x)", want)
	}
	if _, err := w.Write([]byte{socksVer, want}); err != nil {
		return fmt.Errorf("write method: %w", err)
	}

	if want == authUser {
		return s.subnegUserPass(br, w)
	}
	return nil
}

// subnegUserPass runs RFC 1929 subnegotiation.
func (s *socks5Server) subnegUserPass(br *bufio.Reader, w io.Writer) error {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return fmt.Errorf("subneg header: %w", err)
	}
	if hdr[0] != authVer {
		return fmt.Errorf("bad subneg ver 0x%02x", hdr[0])
	}
	user := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, user); err != nil {
		return fmt.Errorf("subneg user: %w", err)
	}
	var plen [1]byte
	if _, err := io.ReadFull(br, plen[:]); err != nil {
		return fmt.Errorf("subneg plen: %w", err)
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(br, pass); err != nil {
		return fmt.Errorf("subneg pass: %w", err)
	}

	ok := string(user) == s.authUser && string(pass) == s.authPass
	status := byte(0x01)
	if ok {
		status = 0x00
	}
	if _, err := w.Write([]byte{authVer, status}); err != nil {
		return fmt.Errorf("subneg reply: %w", err)
	}
	if !ok {
		return errors.New("bad credentials")
	}
	return nil
}

// --- Request / Reply ---

type socksRequest struct {
	cmd  byte
	atyp byte
	host string // either a domain or an IP literal
	port uint16
}

// readRequest reads VER CMD RSV ATYP DST.ADDR DST.PORT.
func readRequest(br *bufio.Reader) (*socksRequest, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, fmt.Errorf("read request header: %w", err)
	}
	if hdr[0] != socksVer {
		return nil, fmt.Errorf("bad version 0x%02x", hdr[0])
	}
	req := &socksRequest{cmd: hdr[1], atyp: hdr[3]}
	switch req.atyp {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return nil, err
		}
		req.host = netip.AddrFrom4(b).String()
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return nil, err
		}
		req.host = netip.AddrFrom16(b).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return nil, err
		}
		buf := make([]byte, l[0])
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		req.host = string(buf)
	default:
		return req, fmt.Errorf("unsupported ATYP 0x%02x", req.atyp)
	}
	var p [2]byte
	if _, err := io.ReadFull(br, p[:]); err != nil {
		return nil, err
	}
	req.port = binary.BigEndian.Uint16(p[:])
	return req, nil
}

// writeReply emits VER REP RSV ATYP BND.ADDR BND.PORT. bnd is the bind addr
// to advertise (IPv4-unspecified is a fine "don't care" for CONNECT).
func writeReply(w io.Writer, rep byte, bnd netip.AddrPort) error {
	buf := []byte{socksVer, rep, rsv, atypIPv4}
	addr := bnd.Addr()
	var addrBytes []byte
	switch {
	case addr.Is4():
		buf[3] = atypIPv4
		b := addr.As4()
		addrBytes = b[:]
	case addr.Is6():
		buf[3] = atypIPv6
		b := addr.As16()
		addrBytes = b[:]
	default:
		buf[3] = atypIPv4
		addrBytes = []byte{0, 0, 0, 0}
	}
	buf = append(buf, addrBytes...)
	var portB [2]byte
	binary.BigEndian.PutUint16(portB[:], bnd.Port())
	buf = append(buf, portB[:]...)
	_, err := w.Write(buf)
	return err
}
