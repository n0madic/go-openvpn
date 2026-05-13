// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

// This test runs the gVisor netstack adapter against a real OpenVPN 2.6.x
// server. It depends on the same docker compose setup as the root
// integration package (test/integration/Makefile: `make up && make wait`).
//
// Run via the integration Makefile target or directly:
//
//	cd test/integration && make up && make wait
//	cd examples/netstack && go test -tags=integration -count=1 -v ./...
//
// The test dials the OpenVPN server, builds a userspace TCP/IP stack on top
// of the tunnel, and TCP-dials the in-container socat echo on 10.8.0.1:8080.
// A successful round-trip proves: VPN handshake + AEAD data channel + IPv4
// routing through netstack + TCP three-way handshake + bidirectional data.
package netstack

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn"
)

const (
	serverAddr = "127.0.0.1:1194"
	serverSNI  = "test-server"
	echoAddr   = "10.8.0.1:8080"
)

// pkiPath resolves a file under test/integration/pki relative to this package.
func pkiPath(p string) string {
	return filepath.Join("..", "..", "test", "integration", "pki", p)
}

func loadTLSConfig(t *testing.T) *tls.Config {
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
	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverSNI,
		MinVersion:   tls.VersionTLS12,
	}
}

func loadTLSCrypt(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(pkiPath("tlscrypt.key"))
	if err != nil {
		t.Fatalf("read tls-crypt key: %v", err)
	}
	return b
}

// TestRealNetstackTCPEcho dials the real OpenVPN server, stands up a gVisor
// netstack on top of the tunnel, and exchanges bytes with the in-container
// socat echo on 10.8.0.1:8080.
func TestRealNetstackTCPEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cli, err := openvpn.Dial(ctx, &openvpn.Config{
		Network:    "udp",
		RemoteAddr: serverAddr,
		TLSConfig:  loadTLSConfig(t),
		TLSCryptV1: loadTLSCrypt(t),
	})
	if err != nil {
		t.Fatalf("openvpn Dial: %v", err)
	}
	defer cli.Close()

	pr := cli.PushedOptions()
	t.Logf("VPN up: local=%s gw=%s mtu=%d cipher=%s", pr.LocalIP, pr.Gateway, pr.MTU, pr.Cipher)
	if !pr.LocalIP.IsValid() {
		t.Fatal("no local IP pushed")
	}

	ns, err := New(cli)
	if err != nil {
		t.Fatalf("netstack.New: %v", err)
	}
	defer ns.Close()

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()

	conn, err := ns.DialContext(dialCtx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext via netstack: %v", err)
	}
	defer conn.Close()
	t.Logf("TCP connected: %s -> %s", conn.LocalAddr(), conn.RemoteAddr())

	want := []byte("netstack-tcp-echo-payload-2026")
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read full: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo mismatch:\ngot:  %q\nwant: %q", got, want)
	}
	t.Logf("echo round-trip OK (%d bytes)", len(want))
}

// TestRealNetstackTCPLargeTransfer pushes a larger blob through TCP via
// netstack to exercise window scaling, retransmits, and MTU splitting on
// both directions of the tunnel.
func TestRealNetstackTCPLargeTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cli, err := openvpn.Dial(ctx, &openvpn.Config{
		Network:    "udp",
		RemoteAddr: serverAddr,
		TLSConfig:  loadTLSConfig(t),
		TLSCryptV1: loadTLSCrypt(t),
	})
	if err != nil {
		t.Fatalf("openvpn Dial: %v", err)
	}
	defer cli.Close()

	ns, err := New(cli)
	if err != nil {
		t.Fatalf("netstack.New: %v", err)
	}
	defer ns.Close()

	conn, err := ns.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// 256 KB payload — enough to cross the IPv4-over-UDP MSS several times.
	want := make([]byte, 256*1024)
	for i := range want {
		want[i] = byte(i)
	}

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	doneWrite := make(chan error, 1)
	go func() {
		_, err := conn.Write(want)
		doneWrite <- err
	}()

	// Read exactly len(want) bytes back. Avoids relying on FIN propagation
	// from the server's `cat` (which adds a few-second tail delay under
	// OpenVPN 2.7 when the same client cert was used by a just-disconnected
	// previous test).
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read full: %v", err)
	}
	if err := <-doneWrite; err != nil {
		t.Fatalf("write goroutine: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("blob mismatch: got %d bytes, want %d bytes", len(got), len(want))
	}
	t.Logf("256KB echo round-trip OK")
}
