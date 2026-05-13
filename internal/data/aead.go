// SPDX-License-Identifier: AGPL-3.0-or-later

package data

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD is the contract every supported data-channel cipher satisfies: a
// 12-byte nonce, configurable key length, 16-byte tag at packet end.
type AEAD struct {
	aead cipher.AEAD
}

// NonceLen and TagLen match all three supported ciphers.
const (
	NonceLen = 12
	TagLen   = 16
)

// NewAEAD constructs an AEAD for the named OpenVPN cipher using key.
// Supported: AES-256-GCM (32B key), AES-128-GCM (16B key),
// CHACHA20-POLY1305 (32B key).
func NewAEAD(cipherName string, key []byte) (*AEAD, error) {
	switch cipherName {
	case "AES-256-GCM":
		if len(key) != 32 {
			return nil, fmt.Errorf("data: AES-256-GCM needs 32-byte key, have %d", len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		a, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		return &AEAD{aead: a}, nil
	case "AES-128-GCM":
		if len(key) != 16 {
			return nil, fmt.Errorf("data: AES-128-GCM needs 16-byte key, have %d", len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		a, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		return &AEAD{aead: a}, nil
	case "CHACHA20-POLY1305":
		if len(key) != 32 {
			return nil, fmt.Errorf("data: CHACHA20-POLY1305 needs 32-byte key, have %d", len(key))
		}
		a, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		return &AEAD{aead: a}, nil
	default:
		return nil, fmt.Errorf("data: unsupported AEAD %q", cipherName)
	}
}

// Overhead is the byte overhead added by Seal: just the 16-byte tag at end.
// (The 8-byte header containing opcode_kid + peer_id + packet_id is the
// caller's responsibility — see Slot.Seal.)
func (a *AEAD) Overhead() int { return a.aead.Overhead() }

// makeNonce constructs the AEAD nonce per OpenVPN's convention:
//
//	nonce = packet_id (4 BE) || implicit_iv (8)
func makeNonce(packetID uint32, implicitIV [ImplicitIVLen]byte) [NonceLen]byte {
	var n [NonceLen]byte
	binary.BigEndian.PutUint32(n[0:4], packetID)
	copy(n[4:], implicitIV[:])
	return n
}

// makeAAD constructs the 8-byte AAD for a P_DATA_V2 packet:
//
//	AAD = opcode_kid (1) || peer_id (3 BE) || packet_id (4 BE)
func makeAAD(opcodeKID byte, peerID, packetID uint32) [8]byte {
	var aad [8]byte
	aad[0] = opcodeKID
	aad[1] = byte(peerID >> 16)
	aad[2] = byte(peerID >> 8)
	aad[3] = byte(peerID)
	binary.BigEndian.PutUint32(aad[4:], packetID)
	return aad
}

// ImplicitIVLen is the length of OpenVPN's implicit nonce suffix (8 bytes).
const ImplicitIVLen = 8

// ErrShortPacket signals a ciphertext shorter than the tag (corrupt or
// truncated).
var ErrShortPacket = errors.New("data: ciphertext shorter than AEAD tag")

// open decrypts ciphertext (which must include the 16-byte tag at end).
func (a *AEAD) open(nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < a.aead.Overhead() {
		return nil, ErrShortPacket
	}
	return a.aead.Open(nil, nonce, ciphertext, aad)
}
