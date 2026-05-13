// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// On-wire offsets inside a tls-crypt wrapped packet (after opcode_kid and
// session-id). HMAC length is fixed at 32 bytes (SHA-256 output, untruncated).
//
// OpenVPN's packet_id for tls-crypt is in "long form": 4-byte monotonic
// counter (BE) followed by 4-byte Unix timestamp (BE) — 8 bytes total.
const (
	hmacLen       = 32
	pidLen        = 8 // long-form: counter(4) + net_time(4)
	wrapPrefixLen = pidLen + hmacLen
)

// HeaderLen is the byte length of the tls-crypt outer header (opcode_kid +
// session_id) which the caller writes before the wrap fields.
const HeaderLen = 1 + 8

// MinWrappedLen is the absolute minimum size of a wrapped packet that has
// the outer header + tls-crypt prefix but zero-length plaintext.
const MinWrappedLen = HeaderLen + wrapPrefixLen

// ErrAuthFailed signals an HMAC mismatch on unwrap. Treat as a packet drop.
var ErrAuthFailed = errors.New("tlscrypt: HMAC verification failed")

// Wrapper holds the directional keys and PID counters for a single peer.
// Concurrent Wrap/Unwrap from different goroutines is safe.
type Wrapper struct {
	keys      Keys
	sendBlock cipher.Block // AES-256 with SendCipher
	recvBlock cipher.Block

	sendPID atomic.Uint32

	recvMu  sync.Mutex
	recvWin pidWindow

	// firstWrapTrailer, if non-nil, is appended verbatim after the
	// AES-CTR ciphertext on the very next Wrap call (then cleared). Used
	// by tls-crypt-v2 to ferry WKc on the initial P_CONTROL_HARD_RESET_CLIENT_V3
	// packet.
	firstMu          sync.Mutex
	firstWrapTrailer []byte
}

// New constructs a Wrapper from a parsed static key + the local direction.
func New(rawKey [StaticKeyLen]byte, dir Direction) (*Wrapper, error) {
	k := DeriveKeys(rawKey, dir)
	sb, err := aes.NewCipher(k.SendCipher[:])
	if err != nil {
		return nil, fmt.Errorf("tlscrypt: new send cipher: %w", err)
	}
	rb, err := aes.NewCipher(k.RecvCipher[:])
	if err != nil {
		return nil, fmt.Errorf("tlscrypt: new recv cipher: %w", err)
	}
	return &Wrapper{keys: k, sendBlock: sb, recvBlock: rb}, nil
}

// Wrap encrypts and authenticates plaintext, producing a complete on-wire
// packet using the OpenVPN tls-crypt SIV (synthetic IV) construction:
//
//		opcode_kid (1) || session_id (8) || pid (8: counter 4 || net_time 4) || HMAC (32) || AES-CTR(plaintext)
//
//	 1. HMAC-SHA256 over (opcode_kid || sid || pid || plaintext) → tag (32B).
//	 2. AES-256-CTR IV = tag[0:16]. The tag is BOTH the authenticator AND the
//	    nonce, so unique tags imply unique nonces (no reuse).
//	 3. Encrypt plaintext under that IV.
//
// Verified against OpenVPN src/openvpn/tls_crypt.c::tls_crypt_wrap.
func (w *Wrapper) Wrap(opcodeKID byte, sessionID uint64, plaintext []byte) []byte {
	pid := w.sendPID.Add(1)
	netTime := uint32(time.Now().Unix())

	w.firstMu.Lock()
	trailer := w.firstWrapTrailer
	w.firstWrapTrailer = nil
	w.firstMu.Unlock()

	const adLen = 1 + 8 + 8 // opcode_kid + sid + pid(counter+net_time)
	out := make([]byte, adLen+hmacLen+len(plaintext), adLen+hmacLen+len(plaintext)+len(trailer))
	out[0] = opcodeKID
	binary.BigEndian.PutUint64(out[1:9], sessionID)
	binary.BigEndian.PutUint32(out[9:13], pid)
	binary.BigEndian.PutUint32(out[13:17], netTime)
	hmacSlot := out[17 : 17+hmacLen]
	cipherSlot := out[17+hmacLen:]

	// 1) HMAC over op || sid || pid || plaintext (the HMAC slot itself is
	// excluded — we write into it after).
	mac := hmac.New(sha256.New, w.keys.SendHMAC[:])
	mac.Write(out[0:adLen])
	mac.Write(plaintext)
	mac.Sum(hmacSlot[:0])

	// 2) AES-256-CTR with IV = first 16 bytes of the HMAC tag (SIV).
	stream := cipher.NewCTR(w.sendBlock, hmacSlot[:aes.BlockSize])
	// 3) Encrypt plaintext into cipherSlot.
	stream.XORKeyStream(cipherSlot, plaintext)

	// tls-crypt-v2: append WKc verbatim after the encrypted block.
	if len(trailer) > 0 {
		out = append(out, trailer...)
	}
	return out
}

// SetFirstWrapTrailer registers bytes to append to the very next Wrap call
// (and only that one). Used by tls-crypt-v2 to attach WKc to the initial
// P_CONTROL_HARD_RESET_CLIENT_V3 packet.
func (w *Wrapper) SetFirstWrapTrailer(b []byte) {
	w.firstMu.Lock()
	w.firstWrapTrailer = append([]byte(nil), b...)
	w.firstMu.Unlock()
}

// Unwrap verifies and decrypts a wrapped packet (SIV mode). On success
// returns (opcode_kid, session_id, packet_id, plaintext, nil). On HMAC
// mismatch returns ErrAuthFailed. On replay returns a non-nil error.
//
// Algorithm (mirroring OpenVPN tls_crypt_unwrap):
//  1. Extract tag (32B at offset 13). The first 16 bytes are the AES-CTR IV.
//  2. AES-256-CTR decrypt ciphertext → plaintext candidate.
//  3. Recompute HMAC over (opcode_kid || sid || pid || plaintext) using the
//     recv HMAC key; constant-time compare with the received tag.
//
// The returned plaintext slice is freshly allocated and owned by the caller.
func (w *Wrapper) Unwrap(packet []byte) (opcodeKID byte, sessionID uint64, packetID uint32, plaintext []byte, err error) {
	if len(packet) < MinWrappedLen {
		return 0, 0, 0, nil, fmt.Errorf("tlscrypt: packet too short: %d", len(packet))
	}
	const adLen = 1 + 8 + 8 // op + sid + pid(8)
	opcodeKID = packet[0]
	sessionID = binary.BigEndian.Uint64(packet[1:9])
	packetID = binary.BigEndian.Uint32(packet[9:13])
	// packet[13:17] is the net_time portion of the pid — included in HMAC AD.
	gotHMAC := packet[17 : 17+hmacLen]
	cipherText := packet[17+hmacLen:]

	// 1+2) Decrypt ciphertext using the tag (first 16 bytes) as IV.
	plain := make([]byte, len(cipherText))
	stream := cipher.NewCTR(w.recvBlock, gotHMAC[:aes.BlockSize])
	stream.XORKeyStream(plain, cipherText)

	// Replay pre-check (read-only): drop obvious replays before computing
	// HMAC. The window is only advanced after HMAC verification succeeds,
	// so an attacker cannot poison it with bogus high packet-ids.
	w.recvMu.Lock()
	fresh := w.recvWin.Test(packetID)
	w.recvMu.Unlock()
	if !fresh {
		return 0, 0, 0, nil, fmt.Errorf("tlscrypt: replay or out-of-window pid %d", packetID)
	}

	// Verify HMAC over op || sid || pid || plaintext.
	mac := hmac.New(sha256.New, w.keys.RecvHMAC[:])
	mac.Write(packet[0:adLen])
	mac.Write(plain)
	expectedHMAC := mac.Sum(nil)
	if !hmac.Equal(gotHMAC, expectedHMAC) {
		return 0, 0, 0, nil, ErrAuthFailed
	}

	// Mark the packet-id as seen only after authenticity is confirmed.
	w.recvMu.Lock()
	accepted := w.recvWin.Accept(packetID)
	w.recvMu.Unlock()
	if !accepted {
		return 0, 0, 0, nil, fmt.Errorf("tlscrypt: replay or out-of-window pid %d", packetID)
	}

	return opcodeKID, sessionID, packetID, plain, nil
}

// SendPID returns the last packet-id produced by Wrap. Useful for tests.
func (w *Wrapper) SendPID() uint32 { return w.sendPID.Load() }

// pidWindow is a sliding 64-entry replay-protection bitmap.
type pidWindow struct {
	highest uint32
	bitmap  uint64 // bit i = 1 → pid (highest - i) has been seen
}

const windowSize = 64

// Accept reports whether pid is fresh (not yet seen and within the window).
// It records the pid for future replay checks. Must be called under the
// caller's mutex.
func (w *pidWindow) Accept(pid uint32) bool {
	if pid == 0 {
		return false // OpenVPN packet-ids start at 1
	}
	switch {
	case pid > w.highest:
		// Slide the window forward.
		shift := pid - w.highest
		if shift >= windowSize {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.highest = pid
		return true
	case w.highest-pid >= windowSize:
		// Too old.
		return false
	default:
		offset := w.highest - pid
		mask := uint64(1) << offset
		if w.bitmap&mask != 0 {
			return false // already seen
		}
		w.bitmap |= mask
		return true
	}
}

// Test reports whether pid would be Accept-ed without recording it. Used to
// drop obvious replays before HMAC verification; the window only advances
// for authenticated packets. Must be called under the caller's mutex.
func (w *pidWindow) Test(pid uint32) bool {
	if pid == 0 {
		return false
	}
	switch {
	case pid > w.highest:
		return true
	case w.highest-pid >= windowSize:
		return false
	default:
		return w.bitmap&(uint64(1)<<(w.highest-pid)) == 0
	}
}
