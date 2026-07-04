// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fakeConn is a *net.Conn-like helper backed by two bytes.Buffers — one for
// data we feed to the server-under-test, one for what the server writes back.
type fakeConn struct {
	in  *bytes.Buffer // server reads
	out *bytes.Buffer // server writes
}

func (c *fakeConn) Read(p []byte) (int, error)       { return c.in.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error)      { return c.out.Write(p) }
func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *fakeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestGreetNoAuth verifies the NoAuth method-selection happy path.
func TestGreetNoAuth(t *testing.T) {
	t.Parallel()
	srv := &socks5Server{log: discardLog()}
	conn := &fakeConn{
		in:  bytes.NewBuffer([]byte{0x05, 0x01, 0x00}), // VER=5 NMETHODS=1 METHOD=NOAUTH
		out: &bytes.Buffer{},
	}
	br := bufio.NewReader(conn)
	if err := srv.greet(br, conn); err != nil {
		t.Fatalf("greet: %v", err)
	}
	if got, want := conn.out.Bytes(), []byte{0x05, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

// TestGreetUserPassOK verifies the RFC 1929 subnegotiation success path.
func TestGreetUserPassOK(t *testing.T) {
	t.Parallel()
	srv := &socks5Server{log: discardLog(), authUser: "alice", authPass: "wonderland"}
	var in bytes.Buffer
	in.Write([]byte{0x05, 0x01, 0x02}) // VER=5 NMETHODS=1 METHOD=UserPass
	in.Write([]byte{0x01, 0x05, 'a', 'l', 'i', 'c', 'e', 0x0A, 'w', 'o', 'n', 'd', 'e', 'r', 'l', 'a', 'n', 'd'})
	conn := &fakeConn{in: &in, out: &bytes.Buffer{}}
	br := bufio.NewReader(conn)
	if err := srv.greet(br, conn); err != nil {
		t.Fatalf("greet: %v", err)
	}
	got := conn.out.Bytes()
	// First 2 bytes: method-selection reply (0x05 0x02). Next 2: subneg reply (0x01 0x00).
	if !bytes.Equal(got, []byte{0x05, 0x02, 0x01, 0x00}) {
		t.Fatalf("got %x, want 05 02 01 00", got)
	}
}

// TestGreetUserPassBad — wrong password yields subneg status=0x01 and an error.
func TestGreetUserPassBad(t *testing.T) {
	t.Parallel()
	srv := &socks5Server{log: discardLog(), authUser: "alice", authPass: "wonderland"}
	var in bytes.Buffer
	in.Write([]byte{0x05, 0x01, 0x02})
	in.Write([]byte{0x01, 0x05, 'a', 'l', 'i', 'c', 'e', 0x03, 'b', 'a', 'd'})
	conn := &fakeConn{in: &in, out: &bytes.Buffer{}}
	br := bufio.NewReader(conn)
	if err := srv.greet(br, conn); err == nil {
		t.Fatal("expected error on bad credentials")
	}
	if !bytes.Equal(conn.out.Bytes(), []byte{0x05, 0x02, 0x01, 0x01}) {
		t.Fatalf("got %x, want 05 02 01 01", conn.out.Bytes())
	}
}

// TestGreetNoOverlap — client offers only NOAUTH, server requires UserPass.
// Expect 0x05 0xFF and an error.
func TestGreetNoOverlap(t *testing.T) {
	t.Parallel()
	srv := &socks5Server{log: discardLog(), authUser: "alice", authPass: "wonderland"}
	conn := &fakeConn{
		in:  bytes.NewBuffer([]byte{0x05, 0x01, 0x00}),
		out: &bytes.Buffer{},
	}
	br := bufio.NewReader(conn)
	if err := srv.greet(br, conn); err == nil {
		t.Fatal("expected error")
	}
	if !bytes.Equal(conn.out.Bytes(), []byte{0x05, 0xFF}) {
		t.Fatalf("got %x, want 05 FF", conn.out.Bytes())
	}
}

// TestReadRequestATYPes verifies each ATYP path is parsed correctly.
func TestReadRequestATYPes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		buf  []byte
		want socksRequest
	}{
		{
			name: "IPv4",
			buf:  []byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB}, // CONNECT 1.2.3.4:443
			want: socksRequest{cmd: cmdConnect, atyp: atypIPv4, host: "1.2.3.4", port: 443},
		},
		{
			name: "Domain",
			buf:  []byte{0x05, 0x01, 0x00, 0x03, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00, 0x50}, // example.com:80
			want: socksRequest{cmd: cmdConnect, atyp: atypDomain, host: "example.com", port: 80},
		},
		{
			name: "IPv6",
			buf:  []byte{0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00, 0x50},
			want: socksRequest{cmd: cmdConnect, atyp: atypIPv6, host: "2001:db8::1", port: 80},
		},
		{
			name: "UDP ASSOCIATE",
			buf:  []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00},
			want: socksRequest{cmd: cmdAssociate, atyp: atypIPv4, host: "0.0.0.0", port: 0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReader(bytes.NewReader(tc.buf))
			got, err := readRequest(br)
			if err != nil {
				t.Fatalf("readRequest: %v", err)
			}
			if got.cmd != tc.want.cmd || got.atyp != tc.want.atyp ||
				got.host != tc.want.host || got.port != tc.want.port {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestWriteReplyEncoding — exact bytes for an IPv4 BND reply.
func TestWriteReplyEncoding(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	bnd := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 12345)
	if err := writeReply(buf, repSucceeded, bnd); err != nil {
		t.Fatal(err)
	}
	want := []byte{0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x30, 0x39}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("got %x, want %x", buf.Bytes(), want)
	}
}

// TestUDPHeaderRoundTrip — build, parse, verify.
func TestUDPHeaderRoundTrip(t *testing.T) {
	t.Parallel()
	body := []byte("hello tunnel")
	pkt := buildUDPReply("8.8.8.8", 53, body)
	host, port, payload, err := parseUDPRequest(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if host != "8.8.8.8" || port != 53 || !bytes.Equal(payload, body) {
		t.Fatalf("got host=%q port=%d payload=%q", host, port, payload)
	}
}

// TestUDPParseFRAGRejected — non-zero FRAG is unsupported, return error.
func TestUDPParseFRAGRejected(t *testing.T) {
	t.Parallel()
	pkt := []byte{0, 0, 0x01, atypIPv4, 1, 2, 3, 4, 0x00, 0x35, 'x'}
	if _, _, _, err := parseUDPRequest(pkt); err == nil {
		t.Fatal("expected error on FRAG=1")
	}
}

// TestUDPParseDomain — ATYP=03 domain parses to its string form.
func TestUDPParseDomain(t *testing.T) {
	t.Parallel()
	// 7-byte domain "example", port 53, payload "Q"
	pkt := append([]byte{0, 0, 0, atypDomain, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e'}, 0x00, 0x35, 'Q')
	host, port, payload, err := parseUDPRequest(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if host != "example" || port != 53 || string(payload) != "Q" {
		t.Fatalf("got host=%q port=%d payload=%q", host, port, payload)
	}
}

// TestParseDNSQueryAndAnswer — build a query, mimic a server response
// containing a single A record, and parse it back.
func TestParseDNSQueryAndAnswer(t *testing.T) {
	t.Parallel()
	q, err := buildDNSQuery(0x4242, "example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(q[0:2]) != 0x4242 {
		t.Fatalf("query id mismatch")
	}

	// Craft a minimal response: ID, flags=0x8000 (QR=1, RCODE=0), QDCOUNT=1,
	// ANCOUNT=1, the original question section, then one A record.
	var resp bytes.Buffer
	hdr := [12]byte{}
	binary.BigEndian.PutUint16(hdr[0:2], 0x4242)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180) // QR=1 RD=1 RA=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[6:8], 1)
	resp.Write(hdr[:])
	resp.Write(q[12:]) // question section verbatim
	// answer: name = pointer to offset 12, TYPE=A CLASS=IN TTL=300 RDLENGTH=4 RDATA=93.184.216.34
	resp.Write([]byte{0xC0, 0x0C})
	resp.Write([]byte{0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4, 93, 184, 216, 34})

	got, err := parseDNSAnswers(resp.Bytes(), 0x4242, dnsTypeA, "example.com")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 || got[0].String() != "93.184.216.34" {
		t.Fatalf("got %v", got)
	}
}

// TestParseDNSWrongID — mismatched ID is rejected.
func TestParseDNSWrongID(t *testing.T) {
	t.Parallel()
	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:2], 0xDEAD)
	binary.BigEndian.PutUint16(resp[2:4], 0x8000)
	if _, err := parseDNSAnswers(resp, 0xBEEF, dnsTypeA, "example.com"); err == nil {
		t.Fatal("expected id mismatch error")
	}
}

// TestMapDialError ensures every error string we expect from net/transport
// failures gets mapped to the appropriate SOCKS5 reply code.
func TestMapDialError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		err   error
		wantR byte
	}{
		{"nil success", nil, repSucceeded},
		{"connection refused", errString("connection refused"), repConnRefused},
		{"connection refused mixed case", errString("Connection Refused"), repConnRefused},
		{"no route to host", errString("dial tcp 1.2.3.4:80: connect: no route to host"), repHostUnreach},
		{"unreachable host", errString("unreachable host"), repHostUnreach},
		{"network unreachable", errString("network is unreachable"), repNetworkUnreach},
		{"plain unreach", errString("unreach"), repNetworkUnreach},
		{"i/o timeout", errString("dial tcp: i/o timed out"), repTTLExpired},
		{"context deadline", errString("context deadline exceeded"), repTTLExpired},
		{"context canceled", errString("context canceled"), repTTLExpired},
		{"unknown failure", errString("EOF"), repGeneralFailure},
		{"connection reset", errString("connection reset by peer"), repGeneralFailure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapDialError(tc.err); got != tc.wantR {
				t.Fatalf("mapDialError(%v) = 0x%02x, want 0x%02x", tc.err, got, tc.wantR)
			}
		})
	}
}

// errString is a fmt.Stringer-style helper error type for table-driven tests.
type errString string

func (e errString) Error() string { return string(e) }

// TestFilterUsableIPs covers the family-filtering helper used to skip
// resolver candidates the tunnel can't actually dial.
func TestFilterUsableIPs(t *testing.T) {
	t.Parallel()
	v4a := netip.MustParseAddr("1.2.3.4")
	v4b := netip.MustParseAddr("5.6.7.8")
	v6a := netip.MustParseAddr("2001:db8::1")
	v6b := netip.MustParseAddr("2001:db8::2")

	for _, tc := range []struct {
		name           string
		ips            []netip.Addr
		haveV4, haveV6 bool
		want           []netip.Addr
	}{
		{
			name: "v4-only tunnel drops v6 candidates",
			ips:  []netip.Addr{v6a, v4a, v6b, v4b}, haveV4: true, haveV6: false,
			want: []netip.Addr{v4a, v4b},
		},
		{
			name: "v6-only tunnel drops v4 candidates",
			ips:  []netip.Addr{v6a, v4a, v6b, v4b}, haveV4: false, haveV6: true,
			want: []netip.Addr{v6a, v6b},
		},
		{
			name: "dual-stack preserves order",
			ips:  []netip.Addr{v6a, v4a, v6b}, haveV4: true, haveV6: true,
			want: []netip.Addr{v6a, v4a, v6b},
		},
		{
			name: "no families configured yields empty",
			ips:  []netip.Addr{v4a, v6a}, haveV4: false, haveV6: false,
			want: nil,
		},
		{
			name: "v4-only tunnel, v6-only resolver yields empty (fast-fail)",
			ips:  []netip.Addr{v6a, v6b}, haveV4: true, haveV6: false,
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := filterUsableIPs(tc.ips, tc.haveV4, tc.haveV6)
			if len(got) != len(tc.want) {
				t.Fatalf("len(got)=%d, want %d (got=%v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("got[%d]=%v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestServeShutdownReleasesStuckHandler reproduces the production deadlock
// where Serve's wg.Wait() blocked forever because an in-flight handler was
// stalled on a Read with no ctx awareness (greet succeeded, readRequest was
// blocked waiting for client bytes that never came). Without the ctx-watcher
// inside handle, this test hangs indefinitely; with it, Serve returns
// promptly after ctx cancellation.
func TestServeShutdownReleasesStuckHandler(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	srv := &socks5Server{
		log:      discardLog(),
		connRate: newConnRateLimiter(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, ln) }()

	// Client: connect, finish greet (so the handler clears its 30s deadline
	// and moves on to readRequest), then go silent. Without the handle
	// ctx-watcher the server now blocks on conn.Read forever.
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greet: %v", err)
	}
	var greetResp [2]byte
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, greetResp[:]); err != nil {
		t.Fatalf("read greet reply: %v", err)
	}
	_ = client.SetReadDeadline(time.Time{})
	if greetResp != [2]byte{0x05, 0x00} {
		t.Fatalf("unexpected greet reply: %x", greetResp)
	}

	// Trigger graceful shutdown.
	cancel()

	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return within 3s after ctx cancellation — handle ctx-watcher missing?")
	}
}

// TestParseDNSFlag covers the three accepted shapes and one rejected one
// for the -dns command-line flag.
func TestParseDNSFlag(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		in        string
		wantAddr  string
		wantPort  uint16
		expectErr bool
	}{
		{"ipv4 with explicit port", "1.2.3.4:5353", "1.2.3.4", 5353, false},
		{"ipv4 default port 53", "1.2.3.4", "1.2.3.4", 53, false},
		{"ipv6 with port", "[2001:db8::1]:53", "2001:db8::1", 53, false},
		{"ipv6 default port", "2001:db8::1", "2001:db8::1", 53, false},
		{"empty string", "", "", 0, true},
		{"garbage", "not-an-ip", "", 0, true},
		{"missing port after colon", "1.2.3.4:", "", 0, true},
		{"port out of range", "1.2.3.4:70000", "", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDNSFlag(tc.in)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %v", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDNSFlag(%q): %v", tc.in, err)
			}
			if got.Addr().String() != tc.wantAddr || got.Port() != tc.wantPort {
				t.Fatalf("parseDNSFlag(%q) = %s, want %s:%d",
					tc.in, got, tc.wantAddr, tc.wantPort)
			}
		})
	}
}
