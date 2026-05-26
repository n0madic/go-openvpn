// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"context"
	"net"
)

// ScrambleMode selects a non-standard per-packet XOR / permutation layer
// applied to every wire packet. Bit-for-bit compatible with the de-facto
// clayface/openvpn_xorpatch algorithm used by Tunnelblick, OPNsense and
// similar OpenVPN forks. The transform sits below the OpenVPN protocol,
// so it covers both the control channel (TLS-encapsulated handshake)
// and the data channel — starting with the very first
// P_CONTROL_HARD_RESET_CLIENT_V2 packet.
type ScrambleMode uint8

const (
	// ScrambleNone disables the wrapper. NewScramble returns the inner
	// PacketConn unchanged.
	ScrambleNone ScrambleMode = iota
	// ScrambleXorMask XORs every byte with key[i % len(key)] (the OpenVPN
	// opcode byte at index 0 is included).
	ScrambleXorMask
	// ScrambleXorPtrPos XORs every byte with byte(i+1) (the opcode byte
	// is XORed with 1).
	ScrambleXorPtrPos
	// ScrambleReverse reverses bytes 1..n-1, leaving the opcode byte at
	// index 0 untouched.
	ScrambleReverse
	// ScrambleObfuscate is the layered cascade
	// xorPtrPos → reverse → xorPtrPos → xorMask on send, and the exact
	// inverse on receive.
	ScrambleObfuscate
)

// xorMask XORs buf[i] with key[i % len(key)] for every i, in place.
func xorMask(buf, key []byte) {
	if len(key) == 0 {
		return
	}
	for i := range buf {
		buf[i] ^= key[i%len(key)]
	}
}

// xorPtrPos XORs buf[i] with byte(i+1) for every i, in place.
func xorPtrPos(buf []byte) {
	for i := range buf {
		buf[i] ^= byte(i + 1)
	}
}

// reverseBytes reverses buf[1:] in place. buf[0] is intentionally
// preserved so the OpenVPN opcode byte remains in its natural position
// once the other primitives are applied or undone.
func reverseBytes(buf []byte) {
	if len(buf) < 3 {
		return
	}
	for i, j := 1, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
}

// scrambleSend mutates buf in place to apply the configured mode in the
// send direction.
func scrambleSend(buf []byte, mode ScrambleMode, key []byte) {
	switch mode {
	case ScrambleXorMask:
		xorMask(buf, key)
	case ScrambleXorPtrPos:
		xorPtrPos(buf)
	case ScrambleReverse:
		reverseBytes(buf)
	case ScrambleObfuscate:
		xorPtrPos(buf)
		reverseBytes(buf)
		xorPtrPos(buf)
		xorMask(buf, key)
	}
}

// scrambleRecv mutates buf in place to apply the configured mode in the
// receive direction. For self-inverse modes (xormask, xorptrpos, reverse)
// it is identical to scrambleSend; for obfuscate the order is the exact
// functional inverse of scrambleSend.
func scrambleRecv(buf []byte, mode ScrambleMode, key []byte) {
	switch mode {
	case ScrambleXorMask:
		xorMask(buf, key)
	case ScrambleXorPtrPos:
		xorPtrPos(buf)
	case ScrambleReverse:
		reverseBytes(buf)
	case ScrambleObfuscate:
		xorMask(buf, key)
		xorPtrPos(buf)
		reverseBytes(buf)
		xorPtrPos(buf)
	}
}

// scrambleConn wraps a PacketConn with an in-line scramble layer. It
// implements PacketConn itself, so it slots into any place that accepts
// a PacketConn (the built-in UDP/TCP transports, an in-memory pair, or a
// user-supplied DialTransport result).
type scrambleConn struct {
	inner PacketConn
	mode  ScrambleMode
	key   []byte
}

// NewScramble wraps inner with the configured scramble layer. Pass
// ScrambleNone to opt out (the inner PacketConn is returned unchanged).
// The key is defensively copied so the caller cannot mutate it after
// construction. For modes that do not consume a key (ScrambleXorPtrPos,
// ScrambleReverse) the key argument is ignored.
func NewScramble(inner PacketConn, mode ScrambleMode, key []byte) PacketConn {
	if mode == ScrambleNone {
		return inner
	}
	var k []byte
	if mode == ScrambleXorMask || mode == ScrambleObfuscate {
		k = append([]byte(nil), key...)
	}
	return &scrambleConn{inner: inner, mode: mode, key: k}
}

func (s *scrambleConn) ReadPacket(ctx context.Context) ([]byte, error) {
	p, err := s.inner.ReadPacket(ctx)
	if err != nil {
		return nil, err
	}
	scrambleRecv(p, s.mode, s.key)
	return p, nil
}

func (s *scrambleConn) WritePacket(ctx context.Context, p []byte) error {
	// Defensive copy: callers (session.WriteCtx, reliable layer, ...)
	// commonly reuse their outbound buffer once WritePacket returns.
	// Mutating it in place would corrupt their next send.
	buf := append([]byte(nil), p...)
	scrambleSend(buf, s.mode, s.key)
	return s.inner.WritePacket(ctx, buf)
}

func (s *scrambleConn) LocalAddr() net.Addr  { return s.inner.LocalAddr() }
func (s *scrambleConn) RemoteAddr() net.Addr { return s.inner.RemoteAddr() }
func (s *scrambleConn) Close() error         { return s.inner.Close() }
