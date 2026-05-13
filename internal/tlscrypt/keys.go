// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tlscrypt implements OpenVPN's tls-crypt (v1) and tls-crypt-v2
// control-channel encryption layer. It wraps every control packet in
// HMAC-SHA256 + AES-256-CTR before transport.
package tlscrypt

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// StaticKeyLen is the on-disk size of an OpenVPN static key (2048 bits).
const StaticKeyLen = 256

// Direction encodes whether keys are read in the OpenVPN "normal" (server) or
// "inverse" (client) orientation. The two roles use opposite halves of the
// 256-byte key blob for encrypt vs decrypt.
type Direction int

const (
	// DirectionNormal is the server-side mapping (KEY_DIRECTION_NORMAL).
	DirectionNormal Direction = 0
	// DirectionInverse is the client-side mapping (KEY_DIRECTION_INVERSE).
	DirectionInverse Direction = 1
)

const (
	hmacKeyLen   = 32 // first 32 bytes of each 64-byte slot
	cipherKeyLen = 32 // first 32 bytes of each 64-byte slot
	slotLen      = 64
)

// Keys is a parsed static key split into the four directional sub-keys this
// library actually uses. Send* are used to wrap outgoing packets, Recv* to
// unwrap incoming.
type Keys struct {
	SendHMAC   [hmacKeyLen]byte
	SendCipher [cipherKeyLen]byte
	RecvHMAC   [hmacKeyLen]byte
	RecvCipher [cipherKeyLen]byte
}

// ParseStaticKey decodes an OpenVPN static-key file. Accepts both the
// "-----BEGIN OpenVPN Static key V1-----" envelope (as emitted by
// `openvpn --genkey secret`, with lowercase "key") and raw 256-byte binary.
// The marker match is case-insensitive on the "Key/key" word, since some
// documentation and older tools use the capitalised form. Hex inside the
// envelope is whitespace-tolerant.
func ParseStaticKey(data []byte) ([StaticKeyLen]byte, error) {
	var key [StaticKeyLen]byte

	bi, beginLen := findMarker(data, "-----BEGIN OpenVPN Static ", " V1-----")
	if bi < 0 {
		if len(data) == StaticKeyLen {
			copy(key[:], data)
			return key, nil
		}
		return key, errors.New("tlscrypt: missing OpenVPN Static Key V1 envelope and not 256-byte binary")
	}
	ei, _ := findMarker(data, "-----END OpenVPN Static ", " V1-----")
	if ei < 0 || ei < bi {
		return key, errors.New("tlscrypt: missing OpenVPN Static Key V1 end marker")
	}
	body := string(data[bi+beginLen : ei])
	// Strip all whitespace; the remainder should be hex.
	body = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, body)
	if len(body) != StaticKeyLen*2 {
		return key, fmt.Errorf("tlscrypt: static key body has %d hex chars, want %d",
			len(body), StaticKeyLen*2)
	}
	decoded, err := hex.DecodeString(body)
	if err != nil {
		return key, fmt.Errorf("tlscrypt: hex decode: %w", err)
	}
	copy(key[:], decoded)
	return key, nil
}

// findMarker locates a PEM-like marker in data, accepting either "Key" or
// "key" (case-insensitive on that single word) between the prefix and suffix.
// Returns (index, fullMarkerLength) or (-1, 0).
func findMarker(data []byte, prefix, suffix string) (int, int) {
	for _, word := range []string{"Key", "key"} {
		marker := prefix + word + suffix
		i := strings.Index(string(data), marker)
		if i >= 0 {
			return i, len(marker)
		}
	}
	return -1, 0
}

// DeriveKeys splits a 256-byte static key into directional sub-keys.
//
// OpenVPN's on-disk layout (crypto/keys.h struct key + read_key_file_compat):
// 256 bytes = 2 × `struct key`, each = cipher[64] || hmac[64], only the first
// 32 bytes of each sub-slot used for AES-256 / HMAC-SHA256:
//
//	bytes [  0.. 64)  key0.cipher (first 32B used)
//	bytes [ 64..128)  key0.hmac   (first 32B used)
//	bytes [128..192)  key1.cipher
//	bytes [192..256)  key1.hmac
//
// key_direction_state_init (ssl_pkt.c) maps direction → key index pair:
//
//	KEY_DIRECTION_NORMAL  (server): out=key0, in=key1
//	KEY_DIRECTION_INVERSE (client): out=key1, in=key0
//
// So a CLIENT sends with key1 (cipher@128, hmac@192) and receives with key0
// (cipher@0, hmac@64). Mirror for the server.
func DeriveKeys(raw [StaticKeyLen]byte, dir Direction) Keys {
	// Slot byte offsets within each 128-byte `struct key`.
	const (
		cipher0Off = 0
		hmac0Off   = slotLen
		cipher1Off = 2 * slotLen
		hmac1Off   = 3 * slotLen
	)
	var k Keys
	switch dir {
	case DirectionInverse: // client — out=key1, in=key0
		copy(k.SendCipher[:], raw[cipher1Off:cipher1Off+cipherKeyLen])
		copy(k.SendHMAC[:], raw[hmac1Off:hmac1Off+hmacKeyLen])
		copy(k.RecvCipher[:], raw[cipher0Off:cipher0Off+cipherKeyLen])
		copy(k.RecvHMAC[:], raw[hmac0Off:hmac0Off+hmacKeyLen])
	default: // DirectionNormal (server) — out=key0, in=key1
		copy(k.SendCipher[:], raw[cipher0Off:cipher0Off+cipherKeyLen])
		copy(k.SendHMAC[:], raw[hmac0Off:hmac0Off+hmacKeyLen])
		copy(k.RecvCipher[:], raw[cipher1Off:cipher1Off+cipherKeyLen])
		copy(k.RecvHMAC[:], raw[hmac1Off:hmac1Off+hmacKeyLen])
	}
	return k
}
