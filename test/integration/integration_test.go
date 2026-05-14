// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

// Package integration_test runs the go-openvpn client against a real
// OpenVPN 2.6.x server in Docker. See test/integration/README.md for the
// orchestration flow (`make all`).
//
// These tests are intentionally NOT compiled under the default build tag —
// they require a running server reachable at 127.0.0.1:1194 and a generated
// PKI in ./pki/. Run via `make test` from this directory.
package integration_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn"
)

const (
	serverAddr = "127.0.0.1:1194"
	serverSNI  = "test-server"
)

// pkiDir is the path to the PKI directory relative to this file. Resolved
// once via the test working directory.
var pkiDir = "./pki"

func loadTLSConfig(tb testing.TB) *tls.Config {
	tb.Helper()
	caBytes, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		tb.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		tb.Fatal("no certs in CA file")
	}
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(pkiDir, "client.crt"),
		filepath.Join(pkiDir, "client.key"),
	)
	if err != nil {
		tb.Fatalf("load client cert: %v", err)
	}
	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverSNI,
		MinVersion:   tls.VersionTLS12,
	}
}

func loadTLSCrypt(tb testing.TB) []byte {
	tb.Helper()
	b, err := os.ReadFile(filepath.Join(pkiDir, "tlscrypt.key"))
	if err != nil {
		tb.Fatalf("read tls-crypt key: %v", err)
	}
	return b
}

// TestRealHandshakeUDP verifies that the full OpenVPN 2.6 handshake completes
// against a real server: hard reset → TLS 1.3 → KEY_METHOD 2 → PUSH_REPLY,
// with EKM-derived data keys.
//
// This is the single most valuable integration test: if the handshake passes,
// every layer below the data channel has been validated against the real
// protocol implementation.
func TestRealHandshakeUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cli, err := openvpn.Dial(ctx, &openvpn.Config{
		Network:    "udp",
		RemoteAddr: serverAddr,
		TLSConfig:  loadTLSConfig(t),
		TLSCryptV1: loadTLSCrypt(t),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cli.Close()

	pr := cli.PushedOptions()
	t.Logf("session up: local=%s gw=%s cipher=%s peer_id=%d mtu=%d topology=%s",
		pr.LocalIP, pr.Gateway, pr.Cipher, pr.PeerID, pr.MTU, pr.Topology)

	if !pr.LocalIP.IsValid() {
		t.Error("no LocalIP in PUSH_REPLY")
	}
	if pr.Cipher == "" {
		t.Error("no cipher negotiated")
	}
	if pr.Topology != "subnet" {
		t.Logf("topology = %q (expected 'subnet' from server config)", pr.Topology)
	}
	if pr.MTU == 0 {
		t.Log("no tun-mtu pushed — client falls back to 1500")
	}
}

// TestRealPingGateway sends an ICMP echo to the server's tunnel-side IP
// (10.8.0.1) and expects a reply. The container kernel auto-replies to ICMP
// echo on any local IP, so this exercises the full data path: client encrypts
// → server decrypts → kernel responds → server encrypts → client decrypts.
func TestRealPingGateway(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cli, err := openvpn.Dial(ctx, &openvpn.Config{
		Network:    "udp",
		RemoteAddr: serverAddr,
		TLSConfig:  loadTLSConfig(t),
		TLSCryptV1: loadTLSCrypt(t),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cli.Close()

	pr := cli.PushedOptions()
	if !pr.LocalIP.Is4() || !pr.Gateway.Is4() {
		t.Skipf("non-IPv4 push reply (%s → %s) — skipping IPv4 ICMP test", pr.LocalIP, pr.Gateway)
	}
	conn := cli.Tunnel()

	if !roundTripPing(t, conn, pr, 1, 5*time.Second) {
		t.Fatal("no ICMP reply within 5s")
	}
	t.Logf("ICMP echo reply received from %s", pr.Gateway)
}

// TestRealCipherNegotiation pins each AEAD cipher in turn and verifies the
// server picks it (so client + server NCP both work).
func TestRealCipherNegotiation(t *testing.T) {
	cases := []struct {
		name    string
		ciphers []string
	}{
		{"AES-256-GCM", []string{"AES-256-GCM"}},
		{"CHACHA20-POLY1305", []string{"CHACHA20-POLY1305"}},
		{"AES-128-GCM", []string{"AES-128-GCM"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			cli, err := openvpn.Dial(ctx, &openvpn.Config{
				Network:    "udp",
				RemoteAddr: serverAddr,
				TLSConfig:  loadTLSConfig(t),
				TLSCryptV1: loadTLSCrypt(t),
				Ciphers:    tc.ciphers,
			})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer cli.Close()

			if got := cli.PushedOptions().Cipher; got != tc.name {
				t.Errorf("negotiated cipher = %q, want %q", got, tc.name)
			}
		})
	}
}

// TestRealExitNotify verifies that Close() emits a clean EXIT control
// message which OpenVPN logs as "received exit notification". Dials, then
// Closes, then greps the docker logs for the marker.
func TestRealExitNotify(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cli, err := openvpn.Dial(ctx, &openvpn.Config{
		Network:    "udp",
		RemoteAddr: serverAddr,
		TLSConfig:  loadTLSConfig(t),
		TLSCryptV1: loadTLSCrypt(t),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Logf("session up: %s", cli.PushedOptions().LocalIP)

	beforeClose := time.Now()
	if err := cli.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Poll docker logs for the EXIT marker. OpenVPN 2.6 logs
	// "CC-EEN exit message received by peer" when it processes the EXIT
	// control message from a client that advertised IV_PROTO_CC_EXIT_NOTIFY.
	if !waitForServerLog(t, "CC-EEN exit message received", beforeClose, 5*time.Second) {
		t.Fatal("server did not log CC-EEN exit notification within 5s of Close")
	}
}

// waitForServerLog polls `docker compose logs` for a marker that was emitted
// after `since`. Returns true on success, false on timeout.
func waitForServerLog(t *testing.T, marker string, since time.Time, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "compose", "logs", "--since",
			since.Add(-time.Second).Format(time.RFC3339), "openvpn").Output()
		if err == nil && strings.Contains(string(out), marker) {
			t.Logf("server log contains %q", marker)
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// TestRealRekey verifies that an explicit Client.Rekey() against a real
// server completes the soft-reset flow and data continues to flow.
//
// KNOWN ISSUE: our internal rekey roundtrip (TestRekeySoftReset against the
// simulated server) succeeds — the client and a server-side simulator agree
// on the new keys. Against the real OpenVPN 2.6 server, however, the
// pre-rekey ping works but post-rekey packets are dropped by the server with
// "Key [1] not initialized (yet)" until ~1 second after the rekey handshake.
// Even after the state transitions, the server does not seem to accept our
// post-rekey data packets — likely a per-key-id state-machine detail
// (transition window, S_PRE_START → S_ACTIVE handshake confirmation) we
// haven't fully matched. Skipped pending root-cause analysis.
func TestRealRekey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cli, err := openvpn.Dial(ctx, &openvpn.Config{
		Network:    "udp",
		RemoteAddr: serverAddr,
		TLSConfig:  loadTLSConfig(t),
		TLSCryptV1: loadTLSCrypt(t),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cli.Close()

	pr := cli.PushedOptions()
	conn := cli.Tunnel()

	// Pre-rekey: ping must work on the very first try.
	if !roundTripPing(t, conn, pr, 1, 5*time.Second) {
		t.Fatal("pre-rekey ping failed")
	}

	if err := cli.Rekey(ctx); err != nil {
		t.Fatalf("Rekey: %v", err)
	}

	// Post-rekey: a single long-running reader collects any incoming IP
	// packet (it doesn't matter which seq we get back — we just need one
	// valid echo reply to prove the data channel works on the new key-id).
	// We send one ping every second; the reader runs until we see ANY
	// valid ICMP echo reply, or 15s elapse.
	type rd struct {
		n   int
		err error
	}
	buf := make([]byte, 1500)
	rch := make(chan rd, 1)
	go func() {
		n, err := conn.Read(buf)
		rch <- rd{n, err}
	}()

	// Trickle pings while the reader waits.
	sender := time.NewTicker(1 * time.Second)
	defer sender.Stop()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	seq := uint16(2)
	// Send an immediate first ping.
	if _, err := conn.Write(buildICMPEcho(pr.LocalIP.As4(), pr.Gateway.As4(), 0xBEEF, seq, []byte("post-rekey-1"))); err != nil {
		t.Fatalf("write: %v", err)
	}
	seq++

	for {
		select {
		case res := <-rch:
			if res.err != nil {
				t.Fatalf("read: %v", res.err)
			}
			if res.n > 0 && buf[0]>>4 == 4 && buf[9] == 1 && buf[20] == 0 {
				t.Logf("post-rekey ICMP echo reply received: %d bytes", res.n)
				return
			}
			t.Fatalf("got non-ICMP-echo reply: first=%02x proto=%d type=%d",
				buf[0], buf[9], buf[20])
		case <-sender.C:
			pkt := buildICMPEcho(pr.LocalIP.As4(), pr.Gateway.As4(), 0xBEEF, seq, []byte("post-rekey"))
			seq++
			if _, err := conn.Write(pkt); err != nil {
				t.Fatalf("write: %v", err)
			}
		case <-deadline.C:
			t.Fatal("post-rekey ping never returned within 15s")
		}
	}
}

// roundTripPing sends one ICMP echo and waits up to timeout for the reply.
// Returns (success, fatalError). Timeouts are NOT recorded as test errors
// so the caller can retry without failing the suite.
func roundTripPing(t *testing.T, conn interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
}, pr openvpn.PushReply, seq uint16, timeout time.Duration) bool {
	t.Helper()
	pkt := buildICMPEcho(pr.LocalIP.As4(), pr.Gateway.As4(), 0xBEEF, seq,
		[]byte("ping-seq-"+itoa(int(seq))))
	if _, err := conn.Write(pkt); err != nil {
		t.Logf("write: %v", err)
		return false
	}
	buf := make([]byte, 1500)
	type r struct {
		n   int
		err error
	}
	rch := make(chan r, 1)
	go func() {
		n, err := conn.Read(buf)
		rch <- r{n, err}
	}()
	select {
	case res := <-rch:
		if res.err != nil {
			t.Logf("read: %v", res.err)
			return false
		}
		return res.n > 0 && buf[0]>>4 == 4 && buf[9] == 1 && buf[20] == 0
	case <-time.After(timeout):
		return false
	}
}

// buildICMPEcho assembles an IPv4 + ICMP echo request datagram.
func buildICMPEcho(src, dst [4]byte, id, seq uint16, payload []byte) []byte {
	icmpLen := 8 + len(payload)
	ipLen := 20 + icmpLen
	pkt := make([]byte, ipLen)

	pkt[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen))
	pkt[6] = 0x40 // DF flag, frag offset 0
	pkt[8] = 64   // TTL
	pkt[9] = 1    // protocol = ICMP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[10:12], inetChecksum(pkt[0:20]))

	pkt[20] = 8 // echo request
	binary.BigEndian.PutUint16(pkt[24:26], id)
	binary.BigEndian.PutUint16(pkt[26:28], seq)
	copy(pkt[28:], payload)
	binary.BigEndian.PutUint16(pkt[22:24], inetChecksum(pkt[20:]))
	return pkt
}

func inetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
