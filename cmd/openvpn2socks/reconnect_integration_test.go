// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

// Real-server integration tests that exercise the AutoReconnect path end to
// end. The local Docker server reuses the same client IP across sessions,
// so we drive the IP-change branch manually via Client.FireOnReconnect.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn"
	"github.com/n0madic/go-openvpn/pkg/netstack"
)

// dialDockerReconnect dials the docker server with AutoReconnect=true.
func dialDockerReconnect(t *testing.T) *openvpn.Client {
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
		TLSCryptV1:    tlsCrypt,
		AutoReconnect: true,
	})
	if err != nil {
		t.Fatalf("openvpn Dial: %v", err)
	}
	return cli
}

// TestRealReconnectWithIPChangeRefreshesNIC is the exact production
// reproducer: real providers (ProtonVPN) issue a fresh tunnel IP each
// session. We simulate that by manually invoking FireOnReconnect with a
// doctored PushReply that has a *different* LocalIP, then verify a
// freshly-dialed UDP socket binds to the new IP — proving the
// OnReconnect → applyPushReply chain refreshes the gVisor NIC end to end.
func TestRealReconnectWithIPChangeRefreshesNIC(t *testing.T) {
	cli := dialDockerReconnect(t)
	defer func() { _ = cli.Close() }()

	originalPR := cli.PushedOptions()

	ns, err := netstack.New(cli)
	if err != nil {
		t.Fatalf("netstack.New: %v", err)
	}
	defer func() { _ = ns.Close() }()

	if got := ns.LocalIP(); got != originalPR.LocalIP {
		t.Fatalf("ns.LocalIP() = %s, want %s after New", got, originalPR.LocalIP)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	pre, err := ns.DialContext(ctx, "udp", "10.8.0.1:8080")
	if err != nil {
		t.Fatalf("pre-reconnect DialContext: %v", err)
	}
	preLocal := pre.LocalAddr().String()
	_ = pre.Close()
	if !strings.HasPrefix(preLocal, originalPR.LocalIP.String()+":") {
		t.Fatalf("pre-reconnect socket bound to %s, want %s:...", preLocal, originalPR.LocalIP)
	}

	// Simulate "reconnect handed us a new IP".
	newIP := netip.MustParseAddr("10.8.0.7")
	cli.FireOnReconnect(openvpn.PushReply{
		LocalIP: newIP,
		Netmask: originalPR.Netmask,
		Gateway: originalPR.Gateway,
		MTU:     originalPR.MTU,
		Cipher:  originalPR.Cipher,
		PeerID:  originalPR.PeerID + 100,
	})

	if got := ns.LocalIP(); got != newIP {
		t.Fatalf("ns.LocalIP() = %s after FireOnReconnect, want %s", got, newIP)
	}

	post, err := ns.DialContext(ctx, "udp", "10.8.0.1:8080")
	if err != nil {
		t.Fatalf("post-reconnect DialContext: %v", err)
	}
	postLocal := post.LocalAddr().String()
	_ = post.Close()
	if !strings.HasPrefix(postLocal, newIP.String()+":") {
		t.Fatalf("post-reconnect socket bound to %s, want %s:... — NIC was not refreshed",
			postLocal, newIP)
	}
}
