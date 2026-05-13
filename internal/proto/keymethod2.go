// SPDX-License-Identifier: AGPL-3.0-or-later

package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// PreMasterLen is the size of the pre-master secret embedded in the client's
// KEY_METHOD 2 message. Even when TLS-EKM is negotiated for key derivation,
// the field is still serialised so that older PRF-based servers can fall back
// — we just don't use the bytes ourselves.
const PreMasterLen = 48

// RandomLen is the size of random1 / random2 in KEY_METHOD 2.
const RandomLen = 32

// KeyMethod2 is the binary message exchanged in both directions immediately
// after the TLS handshake completes. The client sends it first; the server
// echoes a similar message back without the pre_master field.
//
// Wire layout (client → server):
//
//	[4]byte{0,0,0,0}              // legacy zero prefix
//	uint8   key_method = 2
//	[48]byte pre_master           // client only; server side omits this
//	[32]byte random1
//	[32]byte random2
//	uint16 BE options_len + options_str (NUL-terminated)
//	if auth_user_pass:
//	  uint16 BE username_len + username (NUL-terminated)
//	  uint16 BE password_len + password (NUL-terminated)
//	uint16 BE peer_info_len + peer_info (NUL-terminated)
type KeyMethod2 struct {
	IsServer     bool // when true, pre_master is omitted on encode and not expected on decode
	PreMaster    [PreMasterLen]byte
	Random1      [RandomLen]byte
	Random2      [RandomLen]byte
	Options      string // comma-separated, e.g. "V4,dev-type tun,link-mtu 1559,..."
	Username     string // optional; encoded only if AuthUserPass
	Password     string // optional; encoded only if AuthUserPass
	AuthUserPass bool
	PeerInfo     string // KEY=VALUE\n lines, NUL-terminated on wire
}

// MarshalKeyMethod2 serialises km into a slice ready to be written into the
// TLS control channel.
//
// Note: OpenVPN ALWAYS writes username/password fields, even when not using
// --auth-user-pass — in that case they are 2-byte zero-length placeholders
// (`write_empty_string`). Same on the server side. The AuthUserPass flag
// only governs whether real credentials are filled in.
func MarshalKeyMethod2(km KeyMethod2) ([]byte, error) {
	if err := validateString(km.Options, "options"); err != nil {
		return nil, err
	}
	if km.AuthUserPass {
		if err := validateString(km.Username, "username"); err != nil {
			return nil, err
		}
		if err := validateString(km.Password, "password"); err != nil {
			return nil, err
		}
	}
	if err := validateString(km.PeerInfo, "peer_info"); err != nil {
		return nil, err
	}

	size := 4 + 1 + RandomLen*2
	if !km.IsServer {
		size += PreMasterLen
	}
	size += 2 + len(km.Options) + 1
	// username + password — always present, possibly empty (2-byte 0 len)
	if km.AuthUserPass {
		size += 2 + len(km.Username) + 1
		size += 2 + len(km.Password) + 1
	} else {
		size += 2 + 2 // two empty-string length prefixes
	}
	size += 2 + len(km.PeerInfo) + 1

	out := make([]byte, 0, size)
	out = append(out, 0, 0, 0, 0)
	out = append(out, 2) // key_method = 2
	if !km.IsServer {
		out = append(out, km.PreMaster[:]...)
	}
	out = append(out, km.Random1[:]...)
	out = append(out, km.Random2[:]...)
	out = appendLengthPrefixed(out, km.Options)
	if km.AuthUserPass {
		out = appendLengthPrefixed(out, km.Username)
		out = appendLengthPrefixed(out, km.Password)
	} else {
		out = appendEmptyString(out)
		out = appendEmptyString(out)
	}
	out = appendLengthPrefixed(out, km.PeerInfo)
	return out, nil
}

// appendEmptyString writes a 2-byte zero length field — the "no value"
// placeholder for username/password when auth-user-pass is not in use.
func appendEmptyString(out []byte) []byte { return append(out, 0, 0) }

// ParseKeyMethod2 decodes a KEY_METHOD 2 message. The caller indicates whether
// it is parsing a server-side message (no pre_master) and whether auth was
// expected.
func ParseKeyMethod2(data []byte, isServer, authUserPass bool) (KeyMethod2, error) {
	km := KeyMethod2{IsServer: isServer, AuthUserPass: authUserPass}
	off := 0
	if len(data) < 5 {
		return km, fmt.Errorf("%w: key_method 2 prefix", ErrShortPacket)
	}
	if data[0] != 0 || data[1] != 0 || data[2] != 0 || data[3] != 0 {
		return km, errors.New("proto: KEY_METHOD 2 missing zero prefix")
	}
	off += 4
	if data[off] != 2 {
		return km, fmt.Errorf("proto: unsupported key_method %d (only 2 is allowed)", data[off])
	}
	off++

	if !isServer {
		if len(data) < off+PreMasterLen {
			return km, fmt.Errorf("%w: pre_master", ErrShortPacket)
		}
		copy(km.PreMaster[:], data[off:off+PreMasterLen])
		off += PreMasterLen
	}
	if len(data) < off+RandomLen*2 {
		return km, fmt.Errorf("%w: random1/random2", ErrShortPacket)
	}
	copy(km.Random1[:], data[off:off+RandomLen])
	off += RandomLen
	copy(km.Random2[:], data[off:off+RandomLen])
	off += RandomLen

	var err error
	km.Options, off, err = readLengthPrefixed(data, off, "options")
	if err != nil {
		return km, err
	}
	// Username + password are ALWAYS present (zero-length when not used),
	// regardless of authUserPass.
	km.Username, off, err = readLengthOrEmpty(data, off, "username")
	if err != nil {
		return km, err
	}
	km.Password, off, err = readLengthOrEmpty(data, off, "password")
	if err != nil {
		return km, err
	}
	km.PeerInfo, _, err = readLengthOrEmpty(data, off, "peer_info")
	if err != nil {
		return km, err
	}
	return km, nil
}

// readLengthOrEmpty reads a uint16 BE length and then that many bytes.
// length == 0 returns the empty string. Otherwise the last byte must be NUL.
func readLengthOrEmpty(data []byte, off int, name string) (string, int, error) {
	if len(data) < off+2 {
		return "", off, fmt.Errorf("%w: %s length", ErrShortPacket, name)
	}
	n := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if n == 0 {
		return "", off, nil
	}
	if len(data) < off+n {
		return "", off, fmt.Errorf("%w: %s body (need %d, have %d)",
			ErrShortPacket, name, n, len(data)-off)
	}
	if data[off+n-1] != 0 {
		return "", off, fmt.Errorf("proto: %s missing NUL terminator", name)
	}
	s := string(data[off : off+n-1])
	off += n
	return s, off, nil
}

// appendLengthPrefixed writes [uint16 BE length-including-NUL] [s] [0x00].
func appendLengthPrefixed(out []byte, s string) []byte {
	totalLen := len(s) + 1
	out = binary.BigEndian.AppendUint16(out, uint16(totalLen))
	out = append(out, s...)
	return append(out, 0)
}

// readLengthPrefixed reads a uint16 BE length, then that many bytes (the last
// must be a NUL). Returns the string sans the trailing NUL and the new offset.
func readLengthPrefixed(data []byte, off int, name string) (string, int, error) {
	if len(data) < off+2 {
		return "", off, fmt.Errorf("%w: %s length", ErrShortPacket, name)
	}
	n := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if n == 0 {
		return "", off, fmt.Errorf("proto: %s zero-length (must include NUL)", name)
	}
	if len(data) < off+n {
		return "", off, fmt.Errorf("%w: %s body (need %d, have %d)",
			ErrShortPacket, name, n, len(data)-off)
	}
	if data[off+n-1] != 0 {
		return "", off, fmt.Errorf("proto: %s missing NUL terminator", name)
	}
	s := string(data[off : off+n-1])
	off += n
	return s, off, nil
}

func validateString(s, name string) error {
	if len(s)+1 > math.MaxUint16 {
		return fmt.Errorf("proto: %s too long (%d bytes)", name, len(s))
	}
	for i := range len(s) {
		if s[i] == 0 {
			return fmt.Errorf("proto: %s contains NUL byte at offset %d", name, i)
		}
	}
	return nil
}
