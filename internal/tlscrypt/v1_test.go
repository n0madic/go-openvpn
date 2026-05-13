// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscrypt

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// makeKey produces a deterministic 256-byte static key where each byte equals
// its index modulo 251 (a prime — avoids accidental zeros aligning).
func makeKey() [StaticKeyLen]byte {
	var k [StaticKeyLen]byte
	for i := range k {
		k[i] = byte(i % 251)
	}
	return k
}

func TestParseStaticKeyPEM(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	// Build the PEM-ish envelope: 16 lines of 32 hex chars.
	var sb strings.Builder
	sb.WriteString("-----BEGIN OpenVPN Static Key V1-----\n")
	for i := 0; i < StaticKeyLen; i += 16 {
		for j := range 16 {
			sb.WriteString("0123456789abcdef"[raw[i+j]>>4 : raw[i+j]>>4+1])
			sb.WriteString("0123456789abcdef"[raw[i+j]&0xF : raw[i+j]&0xF+1])
		}
		sb.WriteByte('\n')
	}
	sb.WriteString("-----END OpenVPN Static Key V1-----\n")

	got, err := ParseStaticKey([]byte(sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], raw[:]) {
		t.Fatal("PEM round-trip mismatch")
	}
}

func TestParseStaticKeyBinary(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	got, err := ParseStaticKey(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != raw {
		t.Fatal("binary round-trip mismatch")
	}
}

func TestParseStaticKeyRejectsBadLen(t *testing.T) {
	t.Parallel()
	if _, err := ParseStaticKey([]byte("-----BEGIN OpenVPN Static Key V1-----\nABCD\n-----END OpenVPN Static Key V1-----\n")); err == nil {
		t.Fatal("expected error on short key")
	}
}

// TestClientServerInteropClient and Server wrappers wrap each other's traffic.
// This validates that DirectionInverse and DirectionNormal use the matching
// quadrants of the shared key.
func TestClientServerInterop(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	client, err := New(raw, DirectionInverse)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(raw, DirectionNormal)
	if err != nil {
		t.Fatal(err)
	}

	const opcodeKID = 0x38 // P_CONTROL_HARD_RESET_CLIENT_V2 << 3 | 0
	const sid = uint64(0xCAFEBABEDEADBEEF)

	payloads := [][]byte{
		[]byte(""), // empty plaintext is legal (e.g. hard reset)
		[]byte("hello"),
		bytes.Repeat([]byte{0x42}, 1000),
	}

	for _, plain := range payloads {
		wrapped := client.Wrap(opcodeKID, sid, plain)
		op, gotSID, _, dec, err := server.Unwrap(wrapped)
		if err != nil {
			t.Fatalf("server unwrap failed: %v", err)
		}
		if op != opcodeKID || gotSID != sid {
			t.Fatalf("header diverged: op=%02x sid=%x", op, gotSID)
		}
		if !bytes.Equal(dec, plain) {
			t.Fatalf("plaintext diverged: got %d bytes, want %d", len(dec), len(plain))
		}
	}

	// And the reverse direction (server → client).
	wrapped := server.Wrap(opcodeKID, sid, []byte("server reply"))
	_, _, _, dec, err := client.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("client unwrap failed: %v", err)
	}
	if string(dec) != "server reply" {
		t.Fatalf("got %q", dec)
	}
}

func TestUnwrapDetectsTamperedHMAC(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	cw, _ := New(raw, DirectionInverse)
	sw, _ := New(raw, DirectionNormal)

	wrapped := cw.Wrap(0x20, 1, []byte("payload"))
	wrapped[15] ^= 0x01 // flip a byte inside the HMAC slot
	if _, _, _, _, err := sw.Unwrap(wrapped); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v, want ErrAuthFailed", err)
	}
}

func TestUnwrapDetectsTamperedCiphertext(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	cw, _ := New(raw, DirectionInverse)
	sw, _ := New(raw, DirectionNormal)

	wrapped := cw.Wrap(0x20, 1, []byte("payload"))
	wrapped[len(wrapped)-1] ^= 0x80 // flip a ciphertext byte
	if _, _, _, _, err := sw.Unwrap(wrapped); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v, want ErrAuthFailed", err)
	}
}

func TestReplayDetection(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	cw, _ := New(raw, DirectionInverse)
	sw, _ := New(raw, DirectionNormal)

	wrapped := cw.Wrap(0x20, 1, []byte("p"))
	if _, _, _, _, err := sw.Unwrap(wrapped); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := sw.Unwrap(wrapped); err == nil {
		t.Fatal("expected replay rejection")
	}
}

func TestOutOfOrderWithinWindow(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	cw, _ := New(raw, DirectionInverse)
	sw, _ := New(raw, DirectionNormal)

	// Generate 10 packets but feed them out-of-order to the receiver.
	pkts := make([][]byte, 10)
	for i := range pkts {
		pkts[i] = cw.Wrap(0x20, 1, []byte{byte(i)})
	}
	order := []int{0, 2, 1, 4, 3, 9, 7, 5, 6, 8}
	for _, idx := range order {
		_, _, _, _, err := sw.Unwrap(pkts[idx])
		if err != nil {
			t.Fatalf("packet %d (order %v): %v", idx, order, err)
		}
	}
	// Replaying any of them must now fail.
	if _, _, _, _, err := sw.Unwrap(pkts[5]); err == nil {
		t.Fatal("expected replay rejection of in-window pid")
	}
}

func TestWindowAccept(t *testing.T) {
	t.Parallel()
	var w pidWindow
	if w.Accept(0) {
		t.Error("pid 0 must be rejected")
	}
	for _, p := range []uint32{1, 2, 3, 5} {
		if !w.Accept(p) {
			t.Errorf("accept %d failed", p)
		}
	}
	if w.Accept(2) {
		t.Error("replay of 2 accepted")
	}
	if !w.Accept(4) {
		t.Error("in-window 4 rejected")
	}
	// Far-future pid resets to a 1-bit window.
	if !w.Accept(1000) {
		t.Error("future 1000 rejected")
	}
	if w.Accept(900) {
		t.Error("too-old 900 accepted")
	}
}

func TestKeyDirectionMappingIsSymmetric(t *testing.T) {
	t.Parallel()
	// Verify that DirectionInverse send quadrants == DirectionNormal recv
	// quadrants, i.e. client outbound HMAC == server inbound HMAC. This is
	// the property that makes interop work and is the most error-prone
	// spec point.
	raw := makeKey()
	c := DeriveKeys(raw, DirectionInverse)
	s := DeriveKeys(raw, DirectionNormal)
	if c.SendHMAC != s.RecvHMAC || c.SendCipher != s.RecvCipher {
		t.Error("client send != server recv (HMAC/cipher mismatch)")
	}
	if c.RecvHMAC != s.SendHMAC || c.RecvCipher != s.SendCipher {
		t.Error("client recv != server send (HMAC/cipher mismatch)")
	}
}
