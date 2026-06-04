// SPDX-License-Identifier: AGPL-3.0-or-later

package tlsauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // mirrors the package's default digest under test
	"encoding/binary"
	"errors"
	"hash"
	"testing"

	"github.com/n0madic/go-openvpn/internal/tlscrypt"
)

// makeKey produces a deterministic 256-byte static key where each byte equals
// its index modulo 251 (a prime — avoids accidental zeros aligning).
func makeKey() [tlscrypt.StaticKeyLen]byte {
	var k [tlscrypt.StaticKeyLen]byte
	for i := range k {
		k[i] = byte(i % 251)
	}
	return k
}

// digestCases is the set of `auth` digests we support, parametrising the
// round-trip / interop / tamper tests.
var digestCases = []struct {
	name string
	hlen int
}{
	{"", 20},       // default → SHA1
	{"SHA1", 20},   // explicit SHA1
	{"SHA256", 32}, // SHA256
	{"SHA512", 64}, // SHA512
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	payloads := [][]byte{
		[]byte(""), // empty plaintext is legal (e.g. hard reset)
		[]byte("hello"),
		bytes.Repeat([]byte{0x42}, 1500),
	}
	const opcodeKID = 0x38 // P_CONTROL_HARD_RESET_CLIENT_V2 << 3 | 0
	const sid = uint64(0xCAFEBABEDEADBEEF)

	for _, dc := range digestCases {
		t.Run("digest="+dc.name, func(t *testing.T) {
			t.Parallel()
			client, err := New(raw, tlscrypt.DirectionInverse, dc.name)
			if err != nil {
				t.Fatal(err)
			}
			server, err := New(raw, tlscrypt.DirectionNormal, dc.name)
			if err != nil {
				t.Fatal(err)
			}
			if client.hlen != dc.hlen {
				t.Fatalf("hlen = %d, want %d", client.hlen, dc.hlen)
			}
			for _, plain := range payloads {
				wrapped := client.Wrap(opcodeKID, sid, plain)
				if len(wrapped) != MinWrappedLen(dc.hlen)+len(plain) {
					t.Fatalf("wrapped len = %d, want %d", len(wrapped), MinWrappedLen(dc.hlen)+len(plain))
				}
				op, gotSID, _, dec, err := server.Unwrap(wrapped)
				if err != nil {
					t.Fatalf("server unwrap: %v", err)
				}
				if op != opcodeKID || gotSID != sid {
					t.Fatalf("header diverged: op=%02x sid=%x", op, gotSID)
				}
				if !bytes.Equal(dec, plain) {
					t.Fatalf("plaintext diverged: got %d bytes, want %d", len(dec), len(plain))
				}
			}
			// Reverse direction (server → client).
			wrapped := server.Wrap(opcodeKID, sid, []byte("server reply"))
			_, _, _, dec, err := client.Unwrap(wrapped)
			if err != nil {
				t.Fatalf("client unwrap: %v", err)
			}
			if string(dec) != "server reply" {
				t.Fatalf("got %q", dec)
			}
		})
	}
}

func TestUnwrapDetectsTamperedHMAC(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	cw, _ := New(raw, tlscrypt.DirectionInverse, "SHA256")
	sw, _ := New(raw, tlscrypt.DirectionNormal, "SHA256")

	wrapped := cw.Wrap(0x20, 1, []byte("payload"))
	wrapped[10] ^= 0x01 // flip a byte inside the HMAC slot (offset 9..9+32)
	if _, _, _, _, err := sw.Unwrap(wrapped); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v, want ErrAuthFailed", err)
	}
}

func TestUnwrapDetectsTamperedPayload(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	cw, _ := New(raw, tlscrypt.DirectionInverse, "SHA256")
	sw, _ := New(raw, tlscrypt.DirectionNormal, "SHA256")

	wrapped := cw.Wrap(0x20, 1, []byte("payload"))
	wrapped[len(wrapped)-1] ^= 0x80 // flip a payload byte
	if _, _, _, _, err := sw.Unwrap(wrapped); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v, want ErrAuthFailed", err)
	}
}

func TestReplayDetection(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	cw, _ := New(raw, tlscrypt.DirectionInverse, "SHA1")
	sw, _ := New(raw, tlscrypt.DirectionNormal, "SHA1")

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
	cw, _ := New(raw, tlscrypt.DirectionInverse, "SHA256")
	sw, _ := New(raw, tlscrypt.DirectionNormal, "SHA256")

	pkts := make([][]byte, 10)
	for i := range pkts {
		pkts[i] = cw.Wrap(0x20, 1, []byte{byte(i)})
	}
	order := []int{0, 2, 1, 4, 3, 9, 7, 5, 6, 8}
	for _, idx := range order {
		if _, _, _, _, err := sw.Unwrap(pkts[idx]); err != nil {
			t.Fatalf("packet %d (order %v): %v", idx, order, err)
		}
	}
	if _, _, _, _, err := sw.Unwrap(pkts[5]); err == nil {
		t.Fatal("expected replay rejection of in-window pid")
	}
}

func TestUnwrapRejectsShortPacket(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	sw, _ := New(raw, tlscrypt.DirectionNormal, "SHA1")
	if _, _, _, _, err := sw.Unwrap([]byte{0x38, 0x00}); err == nil {
		t.Fatal("expected error on short packet")
	}
}

func TestNewRejectsUnknownDigest(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	if _, err := New(raw, tlscrypt.DirectionInverse, "MD5"); err == nil {
		t.Fatal("expected error on unsupported digest")
	}
}

// referenceHMAC independently computes the tls-auth tag in OpenVPN's
// authenticated order, used to pin the wire format byte-for-byte.
func referenceHMAC(newHash func() hash.Hash, key []byte, opcodeKID byte, sid uint64, pid, netTime uint32, payload []byte) []byte {
	var hdr [authHdrLen]byte
	binary.BigEndian.PutUint32(hdr[0:4], pid)
	binary.BigEndian.PutUint32(hdr[4:8], netTime)
	hdr[8] = opcodeKID
	binary.BigEndian.PutUint64(hdr[9:17], sid)
	mac := hmac.New(newHash, key)
	mac.Write(hdr[:])
	mac.Write(payload)
	return mac.Sum(nil)
}

// TestKnownAnswerWire pins the exact on-wire byte layout against an independent
// HMAC computation, then round-trips the hand-built packet through Unwrap.
func TestKnownAnswerWire(t *testing.T) {
	t.Parallel()
	raw := makeKey()
	const (
		opcodeKID = byte(0x38)
		sid       = uint64(0xCAFEBABEDEADBEEF)
		pid       = uint32(1)
		netTime   = uint32(0x60000000)
		hlen      = 20 // SHA1
	)
	payload := []byte("hello")

	// Client (Inverse) send key == server (Normal) recv key.
	clientSend, _ := deriveHMACKeys(raw, tlscrypt.DirectionInverse, hlen)
	_, serverRecv := deriveHMACKeys(raw, tlscrypt.DirectionNormal, hlen)
	if !bytes.Equal(clientSend, serverRecv) {
		t.Fatal("client send key != server recv key — direction mapping broken")
	}

	tag := referenceHMAC(sha1.New, clientSend, opcodeKID, sid, pid, netTime, payload)

	// Hand-build the wire packet:
	// opcode(1) | sid(8) | HMAC(20) | pid(4) | net_time(4) | payload.
	var wire []byte
	wire = append(wire, opcodeKID)
	wire = binary.BigEndian.AppendUint64(wire, sid)
	wire = append(wire, tag...)
	wire = binary.BigEndian.AppendUint32(wire, pid)
	wire = binary.BigEndian.AppendUint32(wire, netTime)
	wire = append(wire, payload...)

	if len(wire) != MinWrappedLen(hlen)+len(payload) {
		t.Fatalf("wire len = %d, want %d", len(wire), MinWrappedLen(hlen)+len(payload))
	}

	server, _ := New(raw, tlscrypt.DirectionNormal, "SHA1")
	op, gotSID, gotPID, dec, err := server.Unwrap(wire)
	if err != nil {
		t.Fatalf("server unwrap of hand-built packet: %v", err)
	}
	if op != opcodeKID || gotSID != sid || gotPID != pid {
		t.Fatalf("fields diverged: op=%02x sid=%x pid=%d", op, gotSID, gotPID)
	}
	if !bytes.Equal(dec, payload) {
		t.Fatalf("payload = %q, want %q", dec, payload)
	}

	// And confirm Wrap reproduces the same HMAC for the same fields: extract
	// pid/net_time from a freshly wrapped packet and recompute independently.
	client, _ := New(raw, tlscrypt.DirectionInverse, "SHA1")
	wrapped := client.Wrap(opcodeKID, sid, payload)
	gotTag := wrapped[9 : 9+hlen]
	wpid := binary.BigEndian.Uint32(wrapped[9+hlen : 9+hlen+4])
	wtime := binary.BigEndian.Uint32(wrapped[9+hlen+4 : 9+hlen+8])
	if wpid != 1 {
		t.Fatalf("first Wrap pid = %d, want 1", wpid)
	}
	want := referenceHMAC(sha1.New, clientSend, opcodeKID, sid, wpid, wtime, payload)
	if !bytes.Equal(gotTag, want) {
		t.Fatalf("Wrap HMAC mismatch:\n got %x\nwant %x", gotTag, want)
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
	if !w.Accept(1000) {
		t.Error("future 1000 rejected")
	}
	if w.Accept(900) {
		t.Error("too-old 900 accepted")
	}
}
