// SPDX-License-Identifier: AGPL-3.0-or-later

package openvpn

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn/internal/proto"
	"github.com/n0madic/go-openvpn/internal/transport"
)

// TestDialTransportFactoryError verifies that an error from a custom
// Config.DialTransport surfaces from Dial, wrapped, without a panic.
func TestDialTransportFactoryError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("proxy unreachable")
	_, err := Dial(context.Background(), &Config{
		TLSCryptV1: make([]byte, 256), // satisfy control-channel validation
		DialTransport: func(ctx context.Context, network, addr string) (Transport, error) {
			return nil, sentinel
		},
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Dial error = %v, want wrapped %v", err, sentinel)
	}
}

// TestDialTransportNilTransport verifies the defensive check for a
// DialTransport that returns (nil, nil).
func TestDialTransportNilTransport(t *testing.T) {
	t.Parallel()
	_, err := Dial(context.Background(), &Config{
		TLSCryptV1: make([]byte, 256), // satisfy control-channel validation
		DialTransport: func(ctx context.Context, network, addr string) (Transport, error) {
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("expected error when DialTransport returns a nil Transport")
	}
}

// TestDialTransportCarriesTraffic verifies that a Transport handed back by
// Config.DialTransport is actually wired into the session: the factory is
// called once with the Config's network/addr hints, and the first OpenVPN
// packet the client emits (P_CONTROL_HARD_RESET_CLIENT_V2) reaches the far
// end of the injected transport. A full handshake is out of scope here —
// there is no server — so Dial is expected to fail after HandshakeTimeout.
func TestDialTransportCarriesTraffic(t *testing.T) {
	t.Parallel()

	cTr, sTr := transport.MemoryPair()
	defer func() { _ = sTr.Close() }()

	var (
		gotNetwork, gotAddr string
		calls               int
	)
	cfg := &Config{
		Network:    "udp",
		RemoteAddr: "vpn.example:1194",
		// InsecureSkipVerify so the TLS handshake progresses past config
		// validation — otherwise it fails instantly and shutdown can close
		// the transport before the HARD_RESET writeLoop runs.
		TLSConfig:        &tls.Config{InsecureSkipVerify: true},
		TLSCryptV1:       make([]byte, 256),
		HandshakeTimeout: 500 * time.Millisecond,
		DialTransport: func(ctx context.Context, network, addr string) (Transport, error) {
			calls++
			gotNetwork, gotAddr = network, addr
			return cTr, nil
		},
	}

	// Read the far end of the injected transport concurrently with Dial.
	type pkt struct {
		b   []byte
		err error
	}
	rch := make(chan pkt, 1)
	go func() {
		rctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		b, err := sTr.ReadPacket(rctx)
		rch <- pkt{b, err}
	}()

	// Dial fails (no server); we only care that it drove the transport.
	_, _ = Dial(context.Background(), cfg)

	select {
	case r := <-rch:
		if r.err != nil {
			t.Fatalf("server end read: %v", r.err)
		}
		if len(r.b) == 0 {
			t.Fatal("server end received an empty packet")
		}
		op, _ := proto.UnpackOpcodeKID(r.b[0])
		if op != proto.PControlHardResetClientV2 {
			t.Fatalf("first packet opcode = %s, want P_CONTROL_HARD_RESET_CLIENT_V2", op)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server end never received the client handshake packet")
	}

	// DialTransport runs synchronously inside Dial, so these reads race-free.
	if calls != 1 {
		t.Fatalf("DialTransport called %d times, want 1", calls)
	}
	if gotNetwork != "udp" || gotAddr != "vpn.example:1194" {
		t.Fatalf("DialTransport got (%q, %q), want (udp, vpn.example:1194)", gotNetwork, gotAddr)
	}
}
