// SPDX-License-Identifier: AGPL-3.0-or-later

package proto

import (
	"encoding/binary"
	"fmt"
)

// MaxAcks caps the per-packet ACK array length (acks_count field is uint8).
const MaxAcks = 255

// ControlHeader is the always-plaintext prefix of every control-channel
// packet: opcode_kid byte + 8-byte session-id. The bytes following depend on
// whether tls-crypt is wrapping the rest of the packet:
//
//   - With tls-crypt: pid (4) || HMAC-SHA256 (32) || AES-CTR(ControlPayload)
//   - Without wrap (not used in this library): plain ControlPayload bytes
//
// AckPayload follows the same prefix when opcode == PAckV1.
type ControlHeader struct {
	Opcode    Opcode
	KeyID     uint8
	SessionID uint64
}

// HeaderLen is the wire length of a ControlHeader prefix.
const HeaderLen = 1 + 8

// AppendBinary serialises the header into dst.
func (h ControlHeader) AppendBinary(dst []byte) []byte {
	dst = append(dst, PackOpcodeKID(h.Opcode, h.KeyID))
	return binary.BigEndian.AppendUint64(dst, h.SessionID)
}

// ParseControlHeader peels the opcode_kid byte + session-id; returns the
// remaining bytes (everything past the session-id field).
func ParseControlHeader(pkt []byte) (h ControlHeader, rest []byte, err error) {
	if len(pkt) < HeaderLen {
		return ControlHeader{}, nil, fmt.Errorf("%w: control header needs %d bytes, have %d",
			ErrShortPacket, HeaderLen, len(pkt))
	}
	h.Opcode, h.KeyID = UnpackOpcodeKID(pkt[0])
	h.SessionID = binary.BigEndian.Uint64(pkt[1:9])
	return h, pkt[9:], nil
}

// ControlPayload is the post-tls-crypt-decryption content of a P_CONTROL_V1,
// P_CONTROL_HARD_RESET_*_V2/V3, or P_CONTROL_SOFT_RESET_V1 packet.
//
// Wire layout:
//
//	ack_count (1) || ack_pids (4·N BE) || [remote_session_id (8) if N>0] ||
//	msg_pid (4 BE) || body...
//
// Body holds the inner TLS record bytes (or is empty for the very first hard
// reset packet that triggers the handshake).
type ControlPayload struct {
	Acks            []uint32
	RemoteSessionID uint64
	MessagePID      uint32
	Body            []byte
}

// MarshalControlPayload encodes the payload into a new slice.
func MarshalControlPayload(cp ControlPayload) ([]byte, error) {
	if len(cp.Acks) > MaxAcks {
		return nil, fmt.Errorf("proto: too many acks: %d", len(cp.Acks))
	}
	size := 1 + 4*len(cp.Acks)
	if len(cp.Acks) > 0 {
		size += 8 // remote_session_id
	}
	size += 4 + len(cp.Body)

	out := make([]byte, 0, size)
	out = append(out, byte(len(cp.Acks)))
	for _, a := range cp.Acks {
		out = binary.BigEndian.AppendUint32(out, a)
	}
	if len(cp.Acks) > 0 {
		out = binary.BigEndian.AppendUint64(out, cp.RemoteSessionID)
	}
	out = binary.BigEndian.AppendUint32(out, cp.MessagePID)
	out = append(out, cp.Body...)
	return out, nil
}

// ParseControlPayload decodes a tls-crypt-unwrapped control payload.
func ParseControlPayload(data []byte) (ControlPayload, error) {
	if len(data) < 1 {
		return ControlPayload{}, fmt.Errorf("%w: missing ack_count", ErrShortPacket)
	}
	n := int(data[0])
	off := 1
	need := off + 4*n
	if n > 0 {
		need += 8
	}
	need += 4 // msg_pid
	if len(data) < need {
		return ControlPayload{}, fmt.Errorf("%w: control payload truncated (need %d, have %d)",
			ErrShortPacket, need, len(data))
	}

	cp := ControlPayload{}
	if n > 0 {
		cp.Acks = make([]uint32, n)
		for i := range n {
			cp.Acks[i] = binary.BigEndian.Uint32(data[off : off+4])
			off += 4
		}
		cp.RemoteSessionID = binary.BigEndian.Uint64(data[off : off+8])
		off += 8
	}
	cp.MessagePID = binary.BigEndian.Uint32(data[off : off+4])
	off += 4
	if off < len(data) {
		cp.Body = append([]byte(nil), data[off:]...)
	}
	return cp, nil
}

// AckPayload is the post-tls-crypt-decryption content of a P_ACK_V1 packet.
// Unlike ControlPayload there is no msg_pid and no body.
type AckPayload struct {
	Acks            []uint32
	RemoteSessionID uint64
}

// MarshalAckPayload encodes the ack-only payload.
func MarshalAckPayload(ap AckPayload) ([]byte, error) {
	if len(ap.Acks) == 0 {
		return nil, fmt.Errorf("proto: P_ACK_V1 with zero acks is illegal")
	}
	if len(ap.Acks) > MaxAcks {
		return nil, fmt.Errorf("proto: too many acks: %d", len(ap.Acks))
	}
	out := make([]byte, 0, 1+4*len(ap.Acks)+8)
	out = append(out, byte(len(ap.Acks)))
	for _, a := range ap.Acks {
		out = binary.BigEndian.AppendUint32(out, a)
	}
	out = binary.BigEndian.AppendUint64(out, ap.RemoteSessionID)
	return out, nil
}

// ParseAckPayload decodes a tls-crypt-unwrapped ack payload.
func ParseAckPayload(data []byte) (AckPayload, error) {
	if len(data) < 1 {
		return AckPayload{}, fmt.Errorf("%w: missing ack_count", ErrShortPacket)
	}
	n := int(data[0])
	if n == 0 {
		return AckPayload{}, fmt.Errorf("proto: P_ACK_V1 with zero acks")
	}
	need := 1 + 4*n + 8
	if len(data) < need {
		return AckPayload{}, fmt.Errorf("%w: ack payload truncated (need %d, have %d)",
			ErrShortPacket, need, len(data))
	}
	ap := AckPayload{Acks: make([]uint32, n)}
	off := 1
	for i := range n {
		ap.Acks[i] = binary.BigEndian.Uint32(data[off : off+4])
		off += 4
	}
	ap.RemoteSessionID = binary.BigEndian.Uint64(data[off : off+8])
	return ap, nil
}

// DataV2Header is the plaintext prefix of every P_DATA_V2 packet:
// opcode_kid (1) || peer_id (3 BE) || packet_id (4 BE). The remainder of the
// packet is AEAD ciphertext + 16-byte tag.
type DataV2Header struct {
	KeyID    uint8
	PeerID   uint32 // 24-bit; upper 8 bits MUST be zero
	PacketID uint32
}

// DataV2HeaderLen is the wire length of a DataV2Header.
const DataV2HeaderLen = 1 + 3 + 4

// AppendBinary serialises the data header into dst.
func (h DataV2Header) AppendBinary(dst []byte) []byte {
	dst = append(dst, PackOpcodeKID(PDataV2, h.KeyID))
	dst = append(dst, byte(h.PeerID>>16), byte(h.PeerID>>8), byte(h.PeerID))
	return binary.BigEndian.AppendUint32(dst, h.PacketID)
}

// ParseDataV2Header peels the 8-byte header.
func ParseDataV2Header(pkt []byte) (h DataV2Header, rest []byte, err error) {
	if len(pkt) < DataV2HeaderLen {
		return DataV2Header{}, nil, fmt.Errorf("%w: data v2 header needs %d bytes",
			ErrShortPacket, DataV2HeaderLen)
	}
	op, kid := UnpackOpcodeKID(pkt[0])
	if op != PDataV2 {
		return DataV2Header{}, nil, fmt.Errorf("proto: not a data v2 packet (opcode=%s)", op)
	}
	h.KeyID = kid
	h.PeerID = uint32(pkt[1])<<16 | uint32(pkt[2])<<8 | uint32(pkt[3])
	h.PacketID = binary.BigEndian.Uint32(pkt[4:8])
	return h, pkt[8:], nil
}
