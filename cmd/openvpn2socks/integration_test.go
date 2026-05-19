// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

// End-to-end integration tests for the openvpn2socks daemon. They dial the
// docker-hosted OpenVPN server (same setup as pkg/netstack/), spin up the
// real SOCKS5 server, and exercise:
//
//   - SOCKS5 CONNECT happy path: TCP echo through the tunnel.
//   - SOCKS5 CONNECT to a closed port → REP=0x05 (connection refused).
//   - SOCKS5 with username/password auth: success + failure.
//   - SOCKS5 UDP ASSOCIATE: datagram round-trip through the tunnel.
//
// Pre-requisite: `make up && make wait` in test/integration.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn"
	"github.com/n0madic/go-openvpn/pkg/netstack"
)

const (
	dockerServer = "127.0.0.1:1194"
	dockerSNI    = "test-server"
	echoTarget   = "10.8.0.1:8080" // socat TCP+UDP echo inside the container
	closedTarget = "10.8.0.1:1"    // unused port — connection refused
)

// pkiPath resolves a file under test/integration/pki/.
func pkiPath(p string) string {
	return filepath.Join("..", "..", "test", "integration", "pki", p)
}

// dialDocker dials the docker server via the openvpn library. Mirrors the
// pkg/netstack helper but lives here so the test stays self-contained.
func dialDocker(t *testing.T) *openvpn.Client {
	t.Helper()
	caBytes, err := os.ReadFile(pkiPath("ca.crt"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		t.Fatal("no certs in CA file")
	}
	cert, err := tls.LoadX509KeyPair(pkiPath("client.crt"), pkiPath("client.key"))
	if err != nil {
		t.Fatalf("load client cert: %v", err)
	}
	tlsCrypt, err := os.ReadFile(pkiPath("tlscrypt.key"))
	if err != nil {
		t.Fatalf("read tls-crypt key: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	cli, err := openvpn.Dial(ctx, &openvpn.Config{
		Network:    "udp",
		RemoteAddr: dockerServer,
		TLSConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
			ServerName:   dockerSNI,
			MinVersion:   tls.VersionTLS12,
		},
		TLSCryptV1: tlsCrypt,
	})
	if err != nil {
		t.Fatalf("openvpn Dial: %v", err)
	}
	return cli
}

// startProxy spins up the whole openvpn2socks stack against the docker
// server on an ephemeral local port. Returns the listen address and a
// cleanup func. authSpec is the value normally passed via -socks-auth
// ("" disables auth).
func startProxy(t *testing.T, authSpec string) (string, func()) {
	t.Helper()
	cli := dialDocker(t)

	ns, err := netstack.New(cli)
	if err != nil {
		_ = cli.Close()
		t.Fatalf("netstack.New: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	r := newResolver(ns, cli.PushedOptions().DNS, netip.AddrPort{}, logger)
	srv, err := newSOCKS5(ns, r, "", authSpec, 0, logger)
	if err != nil {
		_ = ns.Close()
		_ = cli.Close()
		t.Fatalf("newSOCKS5: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = ns.Close()
		_ = cli.Close()
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx, ln)
		close(done)
	}()

	cleanup := func() {
		cancel()
		<-done
		_ = ns.Close()
		_ = cli.Close()
	}
	return addr, cleanup
}

// --- SOCKS5 client helpers (tiny in-line implementation, just enough to
//     drive the server during tests) ---

// socks5Connect performs a NoAuth greeting + CONNECT to host:port through
// the proxy. Returns the proxied net.Conn (bytes only — reply already
// consumed) and the REP byte from the SOCKS5 reply.
func socks5Connect(t *testing.T, proxyAddr, host string, port uint16, auth ...[2]string) (net.Conn, byte) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	method := byte(authNone)
	if len(auth) > 0 {
		method = authUser
	}
	// Greeting.
	if _, err := conn.Write([]byte{socksVer, 0x01, method}); err != nil {
		t.Fatalf("greet write: %v", err)
	}
	var greetReply [2]byte
	if _, err := io.ReadFull(conn, greetReply[:]); err != nil {
		t.Fatalf("greet read: %v", err)
	}
	if greetReply[0] != socksVer || greetReply[1] != method {
		t.Fatalf("greet reply = %x, want %02x %02x", greetReply, socksVer, method)
	}

	if method == authUser {
		ap := auth[0]
		req := []byte{authVer, byte(len(ap[0]))}
		req = append(req, ap[0]...)
		req = append(req, byte(len(ap[1])))
		req = append(req, ap[1]...)
		if _, err := conn.Write(req); err != nil {
			t.Fatalf("auth write: %v", err)
		}
		var ar [2]byte
		if _, err := io.ReadFull(conn, ar[:]); err != nil {
			t.Fatalf("auth read: %v", err)
		}
		if ar[1] != 0 {
			// Caller will see this as a hard failure of the entire request.
			return conn, 0xFE
		}
	}

	// CONNECT request — always domain ATYP so we don't bypass the resolver.
	// Tests that want a literal IP path can pass it as `host` and the
	// resolver short-circuits when it's already an IP.
	if len(host) > 255 {
		t.Fatalf("host too long: %d bytes", len(host))
	}
	reqHdr := []byte{socksVer, cmdConnect, rsv}
	if ip, err := netip.ParseAddr(host); err == nil {
		switch {
		case ip.Is4():
			b := ip.As4()
			reqHdr = append(reqHdr, atypIPv4)
			reqHdr = append(reqHdr, b[:]...)
		case ip.Is6():
			b := ip.As16()
			reqHdr = append(reqHdr, atypIPv6)
			reqHdr = append(reqHdr, b[:]...)
		}
	} else {
		reqHdr = append(reqHdr, atypDomain, byte(len(host)))
		reqHdr = append(reqHdr, host...)
	}
	var portB [2]byte
	binary.BigEndian.PutUint16(portB[:], port)
	reqHdr = append(reqHdr, portB[:]...)
	if _, err := conn.Write(reqHdr); err != nil {
		t.Fatalf("req write: %v", err)
	}

	// Reply.
	var rep [4]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		t.Fatalf("reply read: %v", err)
	}
	if rep[0] != socksVer {
		t.Fatalf("reply ver = 0x%02x", rep[0])
	}
	// Consume BND.ADDR + BND.PORT so subsequent reads on conn are pure data.
	switch rep[3] {
	case atypIPv4:
		var b [6]byte
		_, _ = io.ReadFull(conn, b[:])
	case atypIPv6:
		var b [18]byte
		_, _ = io.ReadFull(conn, b[:])
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			t.Fatalf("bnd domain len: %v", err)
		}
		buf := make([]byte, int(l[0])+2)
		_, _ = io.ReadFull(conn, buf)
	}
	return conn, rep[1]
}

func TestRealSOCKS5ConnectEcho(t *testing.T) {
	addr, stop := startProxy(t, "")
	defer stop()

	conn, rep := socks5Connect(t, addr, "10.8.0.1", 8080)
	if rep != repSucceeded {
		t.Fatalf("CONNECT returned REP=0x%02x, want 0x00", rep)
	}

	want := []byte("hello via socks5+vpn")
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo mismatch:\n got: %q\nwant: %q", got, want)
	}
	t.Logf("SOCKS5 CONNECT → TCP echo OK (%d bytes)", len(want))
}

func TestRealSOCKS5ConnectRefused(t *testing.T) {
	addr, stop := startProxy(t, "")
	defer stop()

	host, portStr, _ := net.SplitHostPort(closedTarget)
	var port uint16
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	_, rep := socks5Connect(t, addr, host, port)
	if rep != repConnRefused {
		t.Fatalf("CONNECT to closed port returned REP=0x%02x, want 0x05 (refused)", rep)
	}
}

func TestRealSOCKS5AuthSuccess(t *testing.T) {
	addr, stop := startProxy(t, "alice:wonderland")
	defer stop()

	conn, rep := socks5Connect(t, addr, "10.8.0.1", 8080, [2]string{"alice", "wonderland"})
	if rep != repSucceeded {
		t.Fatalf("authenticated CONNECT REP=0x%02x, want 0x00", rep)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("got %q, want %q", got, "ping")
	}
}

func TestRealSOCKS5AuthBadCreds(t *testing.T) {
	addr, stop := startProxy(t, "alice:wonderland")
	defer stop()

	_, rep := socks5Connect(t, addr, "10.8.0.1", 8080, [2]string{"alice", "bad"})
	// Our helper returns 0xFE on auth failure.
	if rep != 0xFE {
		t.Fatalf("bad-creds REP=0x%02x, want 0xFE (auth-failed sentinel)", rep)
	}
}

func TestRealSOCKS5UDPAssociate(t *testing.T) {
	addr, stop := startProxy(t, "")
	defer stop()

	// Open TCP control connection and request UDP ASSOCIATE.
	ctrl, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer ctrl.Close()
	_ = ctrl.SetDeadline(time.Now().Add(15 * time.Second))

	if _, err := ctrl.Write([]byte{socksVer, 0x01, authNone}); err != nil {
		t.Fatalf("greet: %v", err)
	}
	var greetReply [2]byte
	if _, err := io.ReadFull(ctrl, greetReply[:]); err != nil {
		t.Fatalf("greet read: %v", err)
	}

	// ASSOCIATE request: DST.ADDR=0.0.0.0:0 ("we'll tell you per-datagram").
	req := []byte{socksVer, cmdAssociate, rsv, atypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := ctrl.Write(req); err != nil {
		t.Fatalf("assoc write: %v", err)
	}

	// Read reply: 4 bytes header + ATYP-specific bnd + 2 bytes port.
	var rep [4]byte
	if _, err := io.ReadFull(ctrl, rep[:]); err != nil {
		t.Fatalf("assoc reply: %v", err)
	}
	if rep[1] != repSucceeded {
		t.Fatalf("ASSOCIATE REP=0x%02x", rep[1])
	}
	var bndIP net.IP
	switch rep[3] {
	case atypIPv4:
		b := make([]byte, 4)
		_, _ = io.ReadFull(ctrl, b)
		bndIP = b
	case atypIPv6:
		b := make([]byte, 16)
		_, _ = io.ReadFull(ctrl, b)
		bndIP = b
	default:
		t.Fatalf("unexpected ATYP 0x%02x", rep[3])
	}
	var portBuf [2]byte
	_, _ = io.ReadFull(ctrl, portBuf[:])
	bndPort := binary.BigEndian.Uint16(portBuf[:])
	relayAddr := &net.UDPAddr{IP: bndIP, Port: int(bndPort)}
	t.Logf("UDP relay at %s", relayAddr)

	// Send a wrapped UDP datagram to the relay.
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("local udp: %v", err)
	}
	defer udp.Close()

	payload := []byte("udp-via-socks5-proxy")
	dg := buildClientUDP("10.8.0.1", 8080, payload)
	if _, err := udp.WriteTo(dg, relayAddr); err != nil {
		t.Fatalf("send wrapped: %v", err)
	}

	// Read echoed datagram back.
	_ = udp.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := udp.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	gotHost, gotPort, gotPayload, err := parseUDPRequest(buf[:n])
	if err != nil {
		t.Fatalf("parse echo: %v", err)
	}
	if gotHost != "10.8.0.1" || gotPort != 8080 {
		t.Fatalf("echo header host=%s:%d, want 10.8.0.1:8080", gotHost, gotPort)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("echo payload mismatch:\n got: %q\nwant: %q", gotPayload, payload)
	}
	t.Logf("SOCKS5 UDP ASSOCIATE → UDP echo OK (%d bytes)", len(payload))
}

// buildClientUDP wraps a payload in a SOCKS5 UDP-relay datagram targeting
// host:port. The host may be an IP literal (encoded as ATYP=01/04) or a
// short string (ATYP=03).
func buildClientUDP(host string, port uint16, payload []byte) []byte {
	out := []byte{0, 0, 0} // RSV, FRAG=0
	if ip, err := netip.ParseAddr(host); err == nil {
		switch {
		case ip.Is4():
			b := ip.As4()
			out = append(out, atypIPv4)
			out = append(out, b[:]...)
		case ip.Is6():
			b := ip.As16()
			out = append(out, atypIPv6)
			out = append(out, b[:]...)
		}
	} else {
		out = append(out, atypDomain, byte(len(host)))
		out = append(out, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	out = append(out, p[:]...)
	out = append(out, payload...)
	return out
}

// silence "imports" lint when integration tag is off.
var _ = errors.New
