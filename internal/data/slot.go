// SPDX-License-Identifier: AGPL-3.0-or-later

package data

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/n0madic/go-openvpn/internal/proto"
)

// sealBufSize is the working size for outbound packet buffers used by
// Slot.Seal: one MTU-class IP packet (1500) plus OpenVPN data-channel
// overhead (8B header + 16B tag + 16B scratch for in-place AEAD seal).
// Anything larger than this falls back to a per-call allocation; in
// practice IP packets are bounded by the tunnel MTU and stay well under
// this number.
const sealBufSize = 1500 + proto.DataV2HeaderLen + 2*TagLen

// sealBufPool recycles outbound Seal buffers across calls. The caller of
// Seal owns the returned slice and is responsible for handing it back via
// ReleaseSealedBuf once the on-wire packet has been written (or dropped).
// Skipping the release just sends the slice to GC — correct, just less
// efficient.
var sealBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, sealBufSize)
		return &b
	},
}

// ReleaseSealedBuf returns a buffer produced by Slot.Seal to the pool. The
// slice must be one that Seal returned (or a sub-slice with the original
// backing array). Buffers larger than sealBufSize are dropped — they were
// allocated per-call, never from the pool.
func ReleaseSealedBuf(b []byte) {
	if cap(b) != sealBufSize {
		return
	}
	full := b[:sealBufSize]
	sealBufPool.Put(&full)
}

// ErrPacketIDExhausted is returned when the outbound packet-id has crossed
// the soft-rekey threshold; the session should perform a soft reset before
// the counter saturates at 2^32 (which would risk nonce reuse).
var ErrPacketIDExhausted = errors.New("data: outbound packet-id exhausted, rekey required")

// PacketIDRekeyThreshold is the outbound counter value at which we signal
// the rekey logic to start a soft reset. ~2^31 leaves a generous safety
// margin before nonce reuse would actually occur at 2^32.
const PacketIDRekeyThreshold uint32 = 1 << 31

// Slot is a per-direction-pair AEAD state: one key-id worth of inbound and
// outbound state. The session may hold up to two Slots simultaneously during
// rekey transition.
type Slot struct {
	KeyID  uint8
	PeerID uint32

	sendAEAD *AEAD
	sendIV   [ImplicitIVLen]byte
	sendPID  atomic.Uint32

	recvAEAD *AEAD
	recvIV   [ImplicitIVLen]byte
	recvWin  *ReplayWindow
}

// SlotConfig configures a Slot.
type SlotConfig struct {
	KeyID      uint8
	PeerID     uint32 // 24-bit; the upper 8 bits must be zero
	Cipher     string // e.g. "AES-256-GCM"
	SendKey    []byte
	SendIV     [ImplicitIVLen]byte
	RecvKey    []byte
	RecvIV     [ImplicitIVLen]byte
	ReplaySize uint // 0 ⇒ default 64
}

// NewSlot constructs a Slot for one key-id.
func NewSlot(cfg SlotConfig) (*Slot, error) {
	if cfg.PeerID&^0x00FFFFFF != 0 {
		return nil, fmt.Errorf("data: peer-id 0x%x exceeds 24 bits", cfg.PeerID)
	}
	sa, err := NewAEAD(cfg.Cipher, cfg.SendKey)
	if err != nil {
		return nil, fmt.Errorf("data: send AEAD: %w", err)
	}
	ra, err := NewAEAD(cfg.Cipher, cfg.RecvKey)
	if err != nil {
		return nil, fmt.Errorf("data: recv AEAD: %w", err)
	}
	return &Slot{
		KeyID:    cfg.KeyID,
		PeerID:   cfg.PeerID,
		sendAEAD: sa,
		sendIV:   cfg.SendIV,
		recvAEAD: ra,
		recvIV:   cfg.RecvIV,
		recvWin:  NewReplayWindow(cfg.ReplaySize),
	}, nil
}

// Seal encrypts plaintext (one IP packet) and returns the on-wire P_DATA_V2
// packet in OpenVPN 2.6 layout:
//
//	opcode_kid (1) || peer_id (3) || packet_id (4) || tag (16) || ciphertext
//
// Note: the AEAD tag sits BEFORE the ciphertext, not at the end (matches
// crypto.c::openvpn_encrypt_aead). Go's cipher.AEAD.Seal writes
// ciphertext||tag, so we Seal into a scratch tail of the same buffer and
// then move the trailing tag into its final position right after the header.
// This keeps Seal to a single allocation per packet.
func (s *Slot) Seal(plaintext []byte) ([]byte, error) {
	pid := s.sendPID.Add(1)
	if pid >= PacketIDRekeyThreshold {
		return nil, ErrPacketIDExhausted
	}
	opcodeKID := proto.PackOpcodeKID(proto.PDataV2, s.KeyID)
	nonce := makeNonce(pid, s.sendIV)
	aad := makeAAD(opcodeKID, s.PeerID, pid)

	pktLen := proto.DataV2HeaderLen + TagLen + len(plaintext)
	// Allocate one buffer big enough to also hold AEAD's output (ct||tag) in
	// place: that needs len(plaintext)+TagLen bytes starting right after the
	// header+tag slot. Layout while we work:
	//   [hdr | tag-slot | space-for-Seal-output (cap=len(pt)+TagLen)]
	want := pktLen + TagLen
	var buf []byte
	if want <= sealBufSize {
		bufPtr := sealBufPool.Get().(*[]byte)
		buf = (*bufPtr)[:want]
	} else {
		buf = make([]byte, want)
	}
	buf[0] = opcodeKID
	buf[1] = byte(s.PeerID >> 16)
	buf[2] = byte(s.PeerID >> 8)
	buf[3] = byte(s.PeerID)
	binary.BigEndian.PutUint32(buf[4:8], pid)

	dstStart := proto.DataV2HeaderLen + TagLen
	sealed := s.sendAEAD.aead.Seal(buf[dstStart:dstStart], nonce[:], plaintext, aad[:])
	if len(sealed) != len(plaintext)+TagLen {
		return nil, fmt.Errorf("data: unexpected Seal output length %d", len(sealed))
	}
	// Move the trailing tag from the end of Seal's output to the on-wire
	// position right after the header. Ciphertext is already where it
	// belongs at buf[dstStart : dstStart+len(plaintext)].
	tagSrc := dstStart + len(plaintext)
	copy(buf[proto.DataV2HeaderLen:proto.DataV2HeaderLen+TagLen], buf[tagSrc:tagSrc+TagLen])
	return buf[:pktLen], nil
}

// Open decrypts an on-wire P_DATA_V2 packet using OpenVPN's tag-before-CT
// layout. Re-assembles ciphertext||tag (the form Go AEAD expects) before
// calling Open.
//
// Flow mirrors OpenVPN's openvpn_decrypt_aead: cheap pre-checks (key-id,
// peer-id, replay-window) first, then AEAD verify+decrypt, then mark the
// packet-id as seen. Splitting Test from Accept ensures the replay window
// only advances for *authenticated* packets — an attacker cannot poison
// the window with bogus high packet-ids.
func (s *Slot) Open(packet []byte) ([]byte, error) {
	hdr, body, err := proto.ParseDataV2Header(packet)
	if err != nil {
		return nil, err
	}
	if hdr.KeyID != s.KeyID {
		return nil, fmt.Errorf("data: packet key-id %d does not match slot %d", hdr.KeyID, s.KeyID)
	}
	// Defence-in-depth: reject packets whose on-wire peer-id does not match
	// the slot's authoritative value before invoking AEAD. The AAD also
	// covers peer-id so a wire-modified value would fail AEAD anyway, but
	// rejecting here avoids the decrypt cost on bogus traffic.
	if hdr.PeerID != s.PeerID {
		return nil, fmt.Errorf("data: packet peer-id %d does not match slot %d", hdr.PeerID, s.PeerID)
	}
	if len(body) < TagLen {
		return nil, fmt.Errorf("data: packet too short for AEAD tag: %d", len(body))
	}
	// Replay pre-check (read-only). Drops obvious replays before AEAD.
	if !s.recvWin.Test(hdr.PacketID) {
		return nil, fmt.Errorf("data: replay or out-of-window pid %d", hdr.PacketID)
	}
	tag := body[:TagLen]
	ct := body[TagLen:]
	// Reorder to Go's expected ciphertext||tag layout.
	ctTag := make([]byte, len(ct)+TagLen)
	copy(ctTag, ct)
	copy(ctTag[len(ct):], tag)

	opcodeKID := packet[0]
	nonce := makeNonce(hdr.PacketID, s.recvIV)
	aad := makeAAD(opcodeKID, hdr.PeerID, hdr.PacketID)
	plaintext, err := s.recvAEAD.open(nonce[:], ctTag, aad[:])
	if err != nil {
		return nil, fmt.Errorf("data: AEAD open: %w", err)
	}
	// Mark only after authenticity is confirmed. Accept may return false in
	// the rare case of a concurrent identical-pid acceptance (single-threaded
	// readLoop makes this practically impossible) — surface as replay.
	if !s.recvWin.Accept(hdr.PacketID) {
		return nil, fmt.Errorf("data: replay or out-of-window pid %d", hdr.PacketID)
	}
	return plaintext, nil
}

// SendPID returns the current outbound packet-id (for diagnostics and rekey
// trigger).
func (s *Slot) SendPID() uint32 { return s.sendPID.Load() }
