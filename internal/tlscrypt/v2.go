// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
)

// Tls-crypt-v2 wire artefacts.
//
// Client bundle (PEM-wrapped):
//
//	-----BEGIN OpenVPN tls-crypt-v2 client key-----
//	base64(Kc || WKc)
//	-----END OpenVPN tls-crypt-v2 client key-----
//
// Where:
//
//	Kc  = 256-byte client tls-crypt-v2 key, used as a normal v1 static key
//	WKc = wrapped client key blob (server unwraps on first packet)
//
// WKc layout:
//
//	T          (32 bytes)   = HMAC-SHA256(Ka, htons(wkc_len) || Kc || metadata)
//	ciphertext (variable)   = AES-256-CTR(Ke, IV=T[:16], Kc || metadata)
//	wkc_len    (2 BE)       = total length of WKc INCLUDING this length field
const (
	// V2BundlePEMType is the PEM type used in client key files.
	V2BundlePEMType = "OpenVPN tls-crypt-v2 client key"
	// V2TagLen is the HMAC-SHA256 tag prefix of WKc.
	V2TagLen = 32
	// V2LenLen is the trailing 2-byte length field of WKc.
	V2LenLen = 2
	// V2MinWKcLen is a WKc with empty metadata: T + Kc + length.
	V2MinWKcLen = V2TagLen + StaticKeyLen + V2LenLen
)

// V2Bundle is a parsed tls-crypt-v2 client bundle.
type V2Bundle struct {
	Kc  [StaticKeyLen]byte
	WKc []byte // opaque; passed through to the server on the first packet
}

// ParseClientBundleV2 decodes a PEM-wrapped tls-crypt-v2 client key file.
func ParseClientBundleV2(data []byte) (*V2Bundle, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("tlscrypt: tls-crypt-v2 bundle: no PEM block")
	}
	if block.Type != V2BundlePEMType {
		return nil, fmt.Errorf("tlscrypt: tls-crypt-v2 bundle: unexpected PEM type %q", block.Type)
	}
	body := block.Bytes
	if len(body) < StaticKeyLen+V2MinWKcLen {
		return nil, fmt.Errorf("tlscrypt: tls-crypt-v2 bundle too short: %d bytes", len(body))
	}
	b := &V2Bundle{}
	copy(b.Kc[:], body[:StaticKeyLen])
	b.WKc = append([]byte(nil), body[StaticKeyLen:]...)
	// Sanity-check the trailing length field.
	declared := binary.BigEndian.Uint16(b.WKc[len(b.WKc)-V2LenLen:])
	if int(declared) != len(b.WKc) {
		return nil, fmt.Errorf("tlscrypt: tls-crypt-v2 WKc length mismatch (declared %d, actual %d)",
			declared, len(b.WKc))
	}
	return b, nil
}

// EncodeClientBundleV2 produces a PEM-wrapped client bundle from Kc and a
// pre-built WKc. Used by tests.
func EncodeClientBundleV2(kc [StaticKeyLen]byte, wkc []byte) []byte {
	body := make([]byte, 0, len(kc)+len(wkc))
	body = append(body, kc[:]...)
	body = append(body, wkc...)
	return pem.EncodeToMemory(&pem.Block{Type: V2BundlePEMType, Bytes: body})
}

// WrapWKc constructs WKc from a client key Kc and optional metadata using
// the server's master keys (Ka authenticates, Ke encrypts). Server-side
// operation — exposed here so tests can mint bundles without an external
// `openvpn --tls-crypt-v2-genkey` invocation.
func WrapWKc(kc [StaticKeyLen]byte, metadata []byte, ka, ke [32]byte) ([]byte, error) {
	plaintextLen := StaticKeyLen + len(metadata)
	wkcLen := V2TagLen + plaintextLen + V2LenLen
	if wkcLen > 0xFFFF {
		return nil, fmt.Errorf("tlscrypt: WKc too large (%d bytes)", wkcLen)
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(wkcLen))

	// T = HMAC-SHA256(Ka, htons(wkc_len) || Kc || metadata)
	h := hmac.New(sha256.New, ka[:])
	h.Write(lenBuf[:])
	h.Write(kc[:])
	h.Write(metadata)
	t := h.Sum(nil)

	// AES-256-CTR with IV = first 16 bytes of T.
	block, err := aes.NewCipher(ke[:])
	if err != nil {
		return nil, fmt.Errorf("tlscrypt: WKc AES key: %w", err)
	}
	stream := cipher.NewCTR(block, t[:aes.BlockSize])

	plaintext := make([]byte, 0, plaintextLen)
	plaintext = append(plaintext, kc[:]...)
	plaintext = append(plaintext, metadata...)
	ct := make([]byte, plaintextLen)
	stream.XORKeyStream(ct, plaintext)

	out := make([]byte, 0, wkcLen)
	out = append(out, t...)
	out = append(out, ct...)
	out = append(out, lenBuf[:]...)
	return out, nil
}

// UnwrapWKc is the server-side inverse of WrapWKc — verifies HMAC and
// recovers (Kc, metadata).
func UnwrapWKc(wkc []byte, ka, ke [32]byte) ([StaticKeyLen]byte, []byte, error) {
	var kc [StaticKeyLen]byte
	if len(wkc) < V2MinWKcLen {
		return kc, nil, fmt.Errorf("tlscrypt: WKc too short: %d", len(wkc))
	}
	declared := binary.BigEndian.Uint16(wkc[len(wkc)-V2LenLen:])
	if int(declared) != len(wkc) {
		return kc, nil, fmt.Errorf("tlscrypt: WKc length field mismatch")
	}
	tag := wkc[:V2TagLen]
	ct := wkc[V2TagLen : len(wkc)-V2LenLen]
	plaintextLen := len(ct)
	if plaintextLen < StaticKeyLen {
		return kc, nil, fmt.Errorf("tlscrypt: WKc plaintext shorter than Kc")
	}

	block, err := aes.NewCipher(ke[:])
	if err != nil {
		return kc, nil, fmt.Errorf("tlscrypt: WKc AES key: %w", err)
	}
	stream := cipher.NewCTR(block, tag[:aes.BlockSize])
	plain := make([]byte, plaintextLen)
	stream.XORKeyStream(plain, ct)

	// Verify HMAC.
	h := hmac.New(sha256.New, ka[:])
	h.Write(wkc[len(wkc)-V2LenLen:]) // htons(wkc_len)
	h.Write(plain)
	expected := h.Sum(nil)
	if !hmac.Equal(tag, expected) {
		return kc, nil, errors.New("tlscrypt: WKc HMAC verification failed")
	}

	copy(kc[:], plain[:StaticKeyLen])
	meta := append([]byte(nil), plain[StaticKeyLen:]...)
	return kc, meta, nil
}
