// SPDX-License-Identifier: AGPL-3.0-or-later

// Package proto contains wire-format primitives for OpenVPN 2.6+ packets.
// All functions here are pure (no I/O, no goroutines). Crypto-related
// transformations (tls-crypt wrap, AEAD seal) live in sibling packages and
// build on these primitives.
package proto

import "errors"

// Opcode is the 5-bit OpenVPN packet opcode.
type Opcode uint8

// Opcodes implemented by this library. Legacy ones (HARD_RESET_*_V1, P_DATA_V1)
// are intentionally absent — OpenVPN 2.6+ supports modern variants only.
const (
	PControlSoftResetV1       Opcode = 3
	PControlV1                Opcode = 4
	PAckV1                    Opcode = 5
	PControlHardResetClientV2 Opcode = 7
	PControlHardResetServerV2 Opcode = 8
	PDataV2                   Opcode = 9
	PControlHardResetClientV3 Opcode = 10
	PControlWKCV1             Opcode = 11
)

// IsControl reports whether this opcode is part of the reliability-layer
// control channel.
func (op Opcode) IsControl() bool {
	switch op {
	case PControlSoftResetV1, PControlV1, PAckV1,
		PControlHardResetClientV2, PControlHardResetServerV2,
		PControlHardResetClientV3, PControlWKCV1:
		return true
	}
	return false
}

// IsData reports whether this is a data-channel packet (P_DATA_V2).
func (op Opcode) IsData() bool { return op == PDataV2 }

// String returns a human-readable opcode name (for logging).
func (op Opcode) String() string {
	switch op {
	case PControlSoftResetV1:
		return "P_CONTROL_SOFT_RESET_V1"
	case PControlV1:
		return "P_CONTROL_V1"
	case PAckV1:
		return "P_ACK_V1"
	case PControlHardResetClientV2:
		return "P_CONTROL_HARD_RESET_CLIENT_V2"
	case PControlHardResetServerV2:
		return "P_CONTROL_HARD_RESET_SERVER_V2"
	case PDataV2:
		return "P_DATA_V2"
	case PControlHardResetClientV3:
		return "P_CONTROL_HARD_RESET_CLIENT_V3"
	case PControlWKCV1:
		return "P_CONTROL_WKC_V1"
	}
	return "UNKNOWN"
}

// PackOpcodeKID returns the leading byte of every OpenVPN packet:
// (opcode << 3) | (key_id & 0x07).
func PackOpcodeKID(op Opcode, keyID uint8) byte {
	return byte(op)<<3 | (keyID & 0x07)
}

// UnpackOpcodeKID splits the leading byte into opcode (top 5 bits) and key_id
// (bottom 3 bits).
func UnpackOpcodeKID(b byte) (Opcode, uint8) {
	return Opcode(b >> 3), b & 0x07
}

// ErrShortPacket is returned when a parser runs out of bytes.
var ErrShortPacket = errors.New("proto: short packet")

// ErrUnknownOpcode signals an opcode this client does not implement.
var ErrUnknownOpcode = errors.New("proto: unknown or unsupported opcode")
