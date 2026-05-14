// SPDX-License-Identifier: AGPL-3.0-or-later

package data

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/n0madic/go-openvpn/internal/proto"
)

// makeKeyPair returns a c→s and s→c key bundle for the named cipher: keys
// for both directions plus the 8-byte implicit IVs. Random for testing.
func makeKeyPair(t *testing.T, cipher string) (cKey, sKey []byte, cIV, sIV [ImplicitIVLen]byte) {
	t.Helper()
	keyLen := 32
	if cipher == "AES-128-GCM" {
		keyLen = 16
	}
	cKey = make([]byte, keyLen)
	sKey = make([]byte, keyLen)
	rand.Read(cKey)
	rand.Read(sKey)
	rand.Read(cIV[:])
	rand.Read(sIV[:])
	return
}

// makeInteropSlots returns (clientSlot, serverSlot) where each can decrypt
// what the other encrypts. Mirrors the OpenVPN convention where c2s keys
// are used by client.send / server.recv and vice versa.
func makeInteropSlots(t *testing.T, cipher string, peerID uint32, keyID uint8) (*Slot, *Slot) {
	t.Helper()
	cKey, sKey, cIV, sIV := makeKeyPair(t, cipher)
	clientSlot, err := NewSlot(SlotConfig{
		KeyID: keyID, PeerID: peerID, Cipher: cipher,
		SendKey: cKey, SendIV: cIV, // c→s
		RecvKey: sKey, RecvIV: sIV, // s→c
	})
	if err != nil {
		t.Fatal(err)
	}
	serverSlot, err := NewSlot(SlotConfig{
		KeyID: keyID, PeerID: peerID, Cipher: cipher,
		SendKey: sKey, SendIV: sIV, // s→c
		RecvKey: cKey, RecvIV: cIV, // c→s
	})
	if err != nil {
		t.Fatal(err)
	}
	return clientSlot, serverSlot
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()
	for _, cipher := range []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"} {
		t.Run(cipher, func(t *testing.T) {
			t.Parallel()
			client, server := makeInteropSlots(t, cipher, 42, 0)

			plaintexts := [][]byte{
				[]byte("hi"),
				bytes.Repeat([]byte{0xAB}, 100),
				bytes.Repeat([]byte{0x55}, 1500), // typical MTU
			}
			for _, pt := range plaintexts {
				wire, err := client.Seal(pt)
				if err != nil {
					t.Fatalf("seal: %v", err)
				}
				if len(wire) != proto.DataV2HeaderLen+len(pt)+TagLen {
					t.Errorf("packet size %d, want %d", len(wire), proto.DataV2HeaderLen+len(pt)+TagLen)
				}
				// First byte must be (9<<3)|0 = 0x48 for PDataV2 key-id 0.
				if wire[0] != 0x48 {
					t.Errorf("opcode_kid byte = %02x, want 48", wire[0])
				}
				// peer-id bytes
				if wire[1] != 0 || wire[2] != 0 || wire[3] != 42 {
					t.Errorf("peer-id bytes %x", wire[1:4])
				}
				dec, err := server.Open(wire)
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				if !bytes.Equal(dec, pt) {
					t.Fatalf("decrypted mismatch: %d vs %d bytes", len(dec), len(pt))
				}
			}
		})
	}
}

func TestOpenRejectsTamperedTag(t *testing.T) {
	t.Parallel()
	client, server := makeInteropSlots(t, "AES-256-GCM", 1, 0)
	wire, _ := client.Seal([]byte("hello"))
	// Flip a tag byte (last byte of packet).
	wire[len(wire)-1] ^= 0x80
	if _, err := server.Open(wire); err == nil {
		t.Fatal("expected AEAD open to fail on tampered tag")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()
	client, server := makeInteropSlots(t, "AES-256-GCM", 1, 0)
	wire, _ := client.Seal([]byte("hello"))
	// Flip a ciphertext byte (not the tag, not the header).
	wire[proto.DataV2HeaderLen] ^= 0x80
	if _, err := server.Open(wire); err == nil {
		t.Fatal("expected AEAD open to fail on tampered ciphertext")
	}
}

func TestOpenRejectsAADTampering(t *testing.T) {
	t.Parallel()
	client, server := makeInteropSlots(t, "AES-256-GCM", 1, 0)
	wire, _ := client.Seal([]byte("hello"))
	// Flip the peer-id which is part of the AAD.
	wire[3] ^= 0x01
	if _, err := server.Open(wire); err == nil {
		t.Fatal("expected AEAD open to fail on tampered AAD")
	}
}

func TestSendPIDMonotonic(t *testing.T) {
	t.Parallel()
	client, _ := makeInteropSlots(t, "AES-256-GCM", 1, 0)
	for i := uint32(1); i <= 10; i++ {
		if _, err := client.Seal([]byte{0x00}); err != nil {
			t.Fatal(err)
		}
		if client.SendPID() != i {
			t.Errorf("send pid %d, want %d", client.SendPID(), i)
		}
	}
}

func TestReplayProtection(t *testing.T) {
	t.Parallel()
	client, server := makeInteropSlots(t, "AES-256-GCM", 1, 0)
	wire, _ := client.Seal([]byte("first"))
	if _, err := server.Open(wire); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Open(wire); err == nil {
		t.Fatal("expected replay rejection")
	}
}

func TestOutOfOrderWithinWindow(t *testing.T) {
	t.Parallel()
	client, server := makeInteropSlots(t, "AES-256-GCM", 1, 0)
	wires := make([][]byte, 10)
	for i := range wires {
		wires[i], _ = client.Seal([]byte{byte(i)})
	}
	order := []int{0, 2, 1, 4, 3, 9, 8, 6, 5, 7}
	for _, idx := range order {
		if _, err := server.Open(wires[idx]); err != nil {
			t.Errorf("idx %d: %v", idx, err)
		}
	}
	if _, err := server.Open(wires[5]); err == nil {
		t.Fatal("expected replay rejection of in-window pid")
	}
}

// TestReplayWindowAcceptsLargeReorder is the regression test for the
// production failure where 46+ packets arrived reordered by more than the
// old 64-packet window and were all silently dropped as out-of-window.
// With DefaultReplayWindow = 1024 a "burst-then-stragglers" delivery
// pattern of up to ~1000 packets reordered must still leave all of them
// accepted.
func TestReplayWindowAcceptsLargeReorder(t *testing.T) {
	t.Parallel()
	w := NewReplayWindow(0) // default size 1024

	// 1) Advance highest to 1000 (simulates the "future" burst landing first).
	if !w.Accept(1000) {
		t.Fatal("first accept of pid=1000 should succeed")
	}

	// 2) Now deliver the older stragglers, pid 1..999. All must be accepted
	//    because they're within DefaultReplayWindow (1024) of highest.
	for pid := uint32(1); pid <= 999; pid++ {
		if !w.Accept(pid) {
			t.Fatalf("straggler pid=%d rejected — window too small? (DefaultReplayWindow=%d)",
				pid, DefaultReplayWindow)
		}
	}

	// 3) Re-delivering any of those is a genuine replay → rejected.
	for pid := uint32(1); pid <= 1000; pid++ {
		if w.Accept(pid) {
			t.Fatalf("replay of pid=%d unexpectedly accepted", pid)
		}
	}

	// 4) A pid beyond the window must be rejected as truly out-of-window
	//    — security property must hold. Advance highest to 2000, then
	//    test pid=100 (which is 1900 behind, well past 1024).
	if !w.Accept(2000) {
		t.Fatal("advance to pid=2000 should succeed")
	}
	if w.Accept(100) {
		t.Fatalf("pid=100 is >1024 behind highest=2000, should be rejected")
	}
}

// TestReplayWindowLargeAdvance covers the bitmap-shift path when the
// jump between consecutive accepted pids is larger than 64 (a single
// uint64 worth of bits). Used to underflow when DefaultReplayWindow was
// 64; now must work for any size.
func TestReplayWindowLargeAdvance(t *testing.T) {
	t.Parallel()
	w := NewReplayWindow(0)
	if !w.Accept(1) {
		t.Fatal("accept pid=1")
	}
	// Big jump past one full uint64 worth of bits.
	if !w.Accept(1000) {
		t.Fatal("accept pid=1000 after big jump")
	}
	// pid=1 must now register as "seen" — it's still within 1024 of
	// highest=1000 and we accepted it earlier.
	if w.Accept(1) {
		t.Fatal("pid=1 should be rejected as replay (still in window)")
	}
}

func TestPacketIDExhaustion(t *testing.T) {
	t.Parallel()
	client, _ := makeInteropSlots(t, "AES-256-GCM", 1, 0)
	// Wind the counter to one below the threshold.
	// First Seal: counter → threshold-1, succeeds (last safe pid).
	// Second Seal: counter → threshold, rejected.
	client.sendPID.Store(PacketIDRekeyThreshold - 2)
	if _, err := client.Seal([]byte("ok")); err != nil {
		t.Fatalf("unexpected err on last safe pid: %v", err)
	}
	_, err := client.Seal([]byte("trip"))
	if !errors.Is(err, ErrPacketIDExhausted) {
		t.Fatalf("got %v, want ErrPacketIDExhausted", err)
	}
}

func TestKeyIDMismatchRejected(t *testing.T) {
	t.Parallel()
	client, server := makeInteropSlots(t, "AES-256-GCM", 1, 0)
	wire, _ := client.Seal([]byte("x"))
	// Mangle the key-id in the first byte (low 3 bits).
	wire[0] = (wire[0] & 0xF8) | 0x03
	if _, err := server.Open(wire); err == nil {
		t.Fatal("expected key-id mismatch rejection")
	}
}

func TestUnsupportedCipher(t *testing.T) {
	t.Parallel()
	_, err := NewAEAD("BF-CBC", make([]byte, 16))
	if err == nil {
		t.Fatal("expected error on unsupported cipher")
	}
}

func TestPeerIDOverflowRejected(t *testing.T) {
	t.Parallel()
	cKey, sKey, cIV, sIV := makeKeyPair(t, "AES-256-GCM")
	_, err := NewSlot(SlotConfig{
		KeyID: 0, PeerID: 0x01000000, Cipher: "AES-256-GCM",
		SendKey: cKey, SendIV: cIV,
		RecvKey: sKey, RecvIV: sIV,
	})
	if err == nil {
		t.Fatal("expected error on peer-id > 24 bits")
	}
}
