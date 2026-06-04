// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tlsauth implements OpenVPN's tls-auth control-channel
// authentication layer. Unlike tls-crypt (which both encrypts AND
// authenticates every control packet), tls-auth only prepends an HMAC — the
// inner TLS session already provides confidentiality, so the control channel
// is merely authenticated, not encrypted.
//
// It reuses the key-parsing and direction infrastructure of the sibling
// tlscrypt package (the static-key layout and KEY_DIRECTION mapping are
// identical) but derives only the HMAC sub-keys, at the digest-specific length.
package tlsauth

import (
	"crypto/hmac"
	// crypto/sha1 is required here: SHA1 is OpenVPN's default control-channel
	// HMAC digest (`auth` unset), and tls-auth peers commonly rely on it.
	// This is an authentication MAC over an already-TLS-protected channel,
	// not a content hash, so SHA1's collision weakness is not in scope.
	"crypto/sha1" //nolint:gosec // OpenVPN default control-channel HMAC
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-openvpn/internal/tlscrypt"
)

// ErrAuthFailed signals an HMAC mismatch on Unwrap. Treat it as a packet drop.
var ErrAuthFailed = errors.New("tlsauth: HMAC verification failed")

// authHdrLen is the size of the HMAC input header that precedes the payload,
// in OpenVPN's "authenticated order" (packet-id first):
//
//	packet_id(4) || net_time(4) || opcode_kid(1) || session_id(8)
const authHdrLen = 4 + 4 + 1 + 8

// MinWrappedLen returns the smallest valid wrapped packet for an HMAC of hlen
// bytes: opcode_kid(1) + session_id(8) + HMAC(hlen) + packet_id(4) +
// net_time(4), with a zero-length payload. It is also the on-wire header
// length, since the payload is appended verbatim after it.
func MinWrappedLen(hlen int) int { return 1 + 8 + hlen + 4 + 4 }

// Authenticator holds the directional HMAC keys and packet-id state for a
// single peer. Concurrent Wrap/Unwrap from different goroutines is safe.
type Authenticator struct {
	sendHMAC []byte // HMAC key for wrapping outbound packets (length == hlen)
	recvHMAC []byte // HMAC key for verifying inbound packets (length == hlen)
	newHash  func() hash.Hash
	hlen     int // digest output size (SHA1=20, SHA256=32, SHA512=64)

	sendPID atomic.Uint32

	recvMu  sync.Mutex
	recvWin pidWindow
}

// New constructs an Authenticator from a parsed 256-byte static key, the local
// direction (client = DirectionInverse, server = DirectionNormal) and the
// control-channel digest name ("" / "SHA1" / "SHA256" / "SHA512").
func New(raw [tlscrypt.StaticKeyLen]byte, dir tlscrypt.Direction, digest string) (*Authenticator, error) {
	newHash, hlen, err := parseDigest(digest)
	if err != nil {
		return nil, err
	}
	send, recv := deriveHMACKeys(raw, dir, hlen)
	return &Authenticator{
		sendHMAC: send,
		recvHMAC: recv,
		newHash:  newHash,
		hlen:     hlen,
	}, nil
}

// Wrap authenticates plaintext and produces a complete on-wire tls-auth
// control packet. The on-wire layout is:
//
//	opcode_kid(1) || session_id(8) || HMAC(hlen) || packet_id(4) || net_time(4) || plaintext
//
// The HMAC, however, is computed over the bytes in OpenVPN's "authenticated
// order" — the packet-id (counter || net_time) is moved to the FRONT, ahead of
// the opcode and session-id:
//
//	HMAC( packet_id(4) || net_time(4) || opcode_kid(1) || session_id(8) || plaintext )
//
// This reordering is the effect of swap_hmac in src/openvpn/ssl_pkt.c, which
// swaps the [HMAC|packet_id] block with the [opcode|session_id] block between
// the authenticated form and the wire form. Getting the order wrong makes a
// real server silently drop the packet. The HMAC is NOT truncated: hlen equals
// the full digest output size.
func (a *Authenticator) Wrap(opcodeKID byte, sessionID uint64, plaintext []byte) []byte {
	pid := a.sendPID.Add(1)
	netTime := uint32(time.Now().Unix())

	var authHdr [authHdrLen]byte
	binary.BigEndian.PutUint32(authHdr[0:4], pid)
	binary.BigEndian.PutUint32(authHdr[4:8], netTime)
	authHdr[8] = opcodeKID
	binary.BigEndian.PutUint64(authHdr[9:17], sessionID)

	mac := hmac.New(a.newHash, a.sendHMAC)
	mac.Write(authHdr[:])
	mac.Write(plaintext)
	tag := mac.Sum(nil)

	out := make([]byte, MinWrappedLen(a.hlen)+len(plaintext))
	out[0] = opcodeKID
	binary.BigEndian.PutUint64(out[1:9], sessionID)
	copy(out[9:9+a.hlen], tag)
	off := 9 + a.hlen
	binary.BigEndian.PutUint32(out[off:off+4], pid)
	binary.BigEndian.PutUint32(out[off+4:off+8], netTime)
	copy(out[off+8:], plaintext)
	return out
}

// Unwrap verifies a wrapped packet. On success it returns (opcode_kid,
// session_id, packet_id, plaintext, nil). On HMAC mismatch it returns
// ErrAuthFailed; on replay it returns a non-nil error. The returned plaintext
// is a fresh copy owned by the caller (so the reliability layer's reorder
// buffer may retain it past the transport's buffer reuse).
func (a *Authenticator) Unwrap(pkt []byte) (opcodeKID byte, sessionID uint64, packetID uint32, plaintext []byte, err error) {
	if len(pkt) < MinWrappedLen(a.hlen) {
		return 0, 0, 0, nil, fmt.Errorf("tlsauth: packet too short: %d", len(pkt))
	}
	opcodeKID = pkt[0]
	sessionID = binary.BigEndian.Uint64(pkt[1:9])
	gotHMAC := pkt[9 : 9+a.hlen]
	off := 9 + a.hlen
	packetID = binary.BigEndian.Uint32(pkt[off : off+4])
	netTime := pkt[off+4 : off+8]
	rest := pkt[off+8:]

	// Replay pre-check (read-only): drop obvious replays before computing the
	// HMAC. The window is only advanced after authenticity is confirmed, so an
	// attacker cannot poison it with bogus high packet-ids.
	a.recvMu.Lock()
	fresh := a.recvWin.Test(packetID)
	a.recvMu.Unlock()
	if !fresh {
		return 0, 0, 0, nil, fmt.Errorf("tlsauth: replay or out-of-window pid %d", packetID)
	}

	// Recompute the HMAC in authenticated order (packet-id first).
	var authHdr [authHdrLen]byte
	binary.BigEndian.PutUint32(authHdr[0:4], packetID)
	copy(authHdr[4:8], netTime)
	authHdr[8] = opcodeKID
	binary.BigEndian.PutUint64(authHdr[9:17], sessionID)

	mac := hmac.New(a.newHash, a.recvHMAC)
	mac.Write(authHdr[:])
	mac.Write(rest)
	if !hmac.Equal(gotHMAC, mac.Sum(nil)) {
		return 0, 0, 0, nil, ErrAuthFailed
	}

	// Mark the packet-id as seen only after authenticity is confirmed.
	a.recvMu.Lock()
	accepted := a.recvWin.Accept(packetID)
	a.recvMu.Unlock()
	if !accepted {
		return 0, 0, 0, nil, fmt.Errorf("tlsauth: replay or out-of-window pid %d", packetID)
	}

	plaintext = make([]byte, len(rest))
	copy(plaintext, rest)
	return opcodeKID, sessionID, packetID, plaintext, nil
}

// SendPID returns the last packet-id produced by Wrap. Useful for tests.
func (a *Authenticator) SendPID() uint32 { return a.sendPID.Load() }

// parseDigest maps an OpenVPN `auth` digest name to a hash constructor and its
// output size. The empty string defaults to SHA1 (OpenVPN's default when the
// `auth` directive is absent).
func parseDigest(name string) (func() hash.Hash, int, error) {
	switch normalizeDigest(name) {
	case "", "SHA1":
		return sha1.New, sha1.Size, nil
	case "SHA256":
		return sha256.New, sha256.Size, nil
	case "SHA512":
		return sha512.New, sha512.Size, nil
	default:
		return nil, 0, fmt.Errorf("tlsauth: unsupported auth digest %q (want SHA1, SHA256 or SHA512)", name)
	}
}

// normalizeDigest upper-cases and strips dashes so "sha-256" and "SHA256" match.
func normalizeDigest(name string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(name)), "-", "")
}

// deriveHMACKeys extracts the send/recv HMAC sub-keys of length hlen from a
// 256-byte OpenVPN static key, honouring the direction→slot mapping documented
// in tlscrypt.DeriveKeys. tls-auth uses ONLY the HMAC halves; the cipher halves
// are unused.
//
// The HMAC key length equals the digest output size (SHA1=20, SHA256=32,
// SHA512=64), matching OpenVPN's hmac_ctx_init, which keys the HMAC with
// EVP_MD_size(digest) bytes. This is why we cannot reuse tlscrypt.Keys, whose
// HMAC fields are fixed at 32 bytes: that would over-feed SHA1 (32 vs 20 bytes
// → a different HMAC → server drops the packet) and truncate SHA512 (need 64).
func deriveHMACKeys(raw [tlscrypt.StaticKeyLen]byte, dir tlscrypt.Direction, hlen int) (send, recv []byte) {
	const (
		hmac0Off = 64  // key0.hmac slot (64 bytes available)
		hmac1Off = 192 // key1.hmac slot (64 bytes available)
	)
	// DirectionInverse (client): out=key1, in=key0. DirectionNormal (server):
	// out=key0, in=key1.
	sendOff, recvOff := hmac1Off, hmac0Off
	if dir == tlscrypt.DirectionNormal {
		sendOff, recvOff = hmac0Off, hmac1Off
	}
	send = append([]byte(nil), raw[sendOff:sendOff+hlen]...)
	recv = append([]byte(nil), raw[recvOff:recvOff+hlen]...)
	return send, recv
}

// pidWindow is a sliding 64-entry replay-protection bitmap. It is a verbatim
// copy of tlscrypt's window (the type there is unexported, so it cannot be
// shared across packages without leaking it into tlscrypt's public API).
type pidWindow struct {
	highest uint32
	bitmap  uint64 // bit i = 1 → pid (highest - i) has been seen
}

const windowSize = 64

// Accept reports whether pid is fresh (not yet seen and within the window) and
// records it for future replay checks. Must be called under the caller's mutex.
func (w *pidWindow) Accept(pid uint32) bool {
	if pid == 0 {
		return false // OpenVPN packet-ids start at 1
	}
	switch {
	case pid > w.highest:
		shift := pid - w.highest
		if shift >= windowSize {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.highest = pid
		return true
	case w.highest-pid >= windowSize:
		return false
	default:
		offset := w.highest - pid
		mask := uint64(1) << offset
		if w.bitmap&mask != 0 {
			return false
		}
		w.bitmap |= mask
		return true
	}
}

// Test reports whether pid would be Accept-ed without recording it. Used to
// drop obvious replays before HMAC verification. Must be called under the
// caller's mutex.
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
