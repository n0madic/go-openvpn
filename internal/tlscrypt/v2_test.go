// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscrypt

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func makeRandomKey() (k [32]byte) {
	rand.Read(k[:])
	return
}

func TestWKcWrapUnwrapRoundTrip(t *testing.T) {
	t.Parallel()
	ka := makeRandomKey()
	ke := makeRandomKey()
	var kc [StaticKeyLen]byte
	rand.Read(kc[:])
	metadata := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x66, 0x14, 0x0F, 0xAB} // type=0x01 + 8B time

	wkc, err := WrapWKc(kc, metadata, ka, ke)
	if err != nil {
		t.Fatal(err)
	}
	if len(wkc) != V2TagLen+StaticKeyLen+len(metadata)+V2LenLen {
		t.Fatalf("WKc len = %d, want %d", len(wkc), V2TagLen+StaticKeyLen+len(metadata)+V2LenLen)
	}
	gotKc, gotMeta, err := UnwrapWKc(wkc, ka, ke)
	if err != nil {
		t.Fatal(err)
	}
	if gotKc != kc {
		t.Error("Kc round-trip mismatch")
	}
	if !bytes.Equal(gotMeta, metadata) {
		t.Errorf("metadata round-trip mismatch: %x vs %x", gotMeta, metadata)
	}
}

func TestUnwrapWKcRejectsTampered(t *testing.T) {
	t.Parallel()
	ka := makeRandomKey()
	ke := makeRandomKey()
	var kc [StaticKeyLen]byte
	rand.Read(kc[:])
	wkc, _ := WrapWKc(kc, nil, ka, ke)

	// Tamper a ciphertext byte.
	wkc[V2TagLen+10] ^= 0x80
	if _, _, err := UnwrapWKc(wkc, ka, ke); err == nil {
		t.Fatal("expected HMAC failure on tampered ciphertext")
	}
}

func TestUnwrapWKcRejectsWrongMasterKey(t *testing.T) {
	t.Parallel()
	ka := makeRandomKey()
	ke := makeRandomKey()
	var kc [StaticKeyLen]byte
	rand.Read(kc[:])
	wkc, _ := WrapWKc(kc, nil, ka, ke)

	// Different ka.
	wrongKa := makeRandomKey()
	if _, _, err := UnwrapWKc(wkc, wrongKa, ke); err == nil {
		t.Fatal("expected HMAC failure with wrong Ka")
	}
}

func TestClientBundleRoundTrip(t *testing.T) {
	t.Parallel()
	ka := makeRandomKey()
	ke := makeRandomKey()
	var kc [StaticKeyLen]byte
	rand.Read(kc[:])
	metadata := []byte{0x00, 0xDE, 0xAD, 0xBE, 0xEF}

	wkc, err := WrapWKc(kc, metadata, ka, ke)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := EncodeClientBundleV2(kc, wkc)

	parsed, err := ParseClientBundleV2(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Kc != kc {
		t.Error("Kc mismatch")
	}
	if !bytes.Equal(parsed.WKc, wkc) {
		t.Error("WKc mismatch")
	}

	// Server-side decode: unwrap parsed.WKc with master keys, recover Kc.
	gotKc, gotMeta, err := UnwrapWKc(parsed.WKc, ka, ke)
	if err != nil {
		t.Fatal(err)
	}
	if gotKc != kc {
		t.Error("server-side Kc mismatch")
	}
	if !bytes.Equal(gotMeta, metadata) {
		t.Error("server-side metadata mismatch")
	}
}

func TestFirstWrapTrailerCarried(t *testing.T) {
	t.Parallel()
	// Verify that SetFirstWrapTrailer attaches the bytes to one Wrap call
	// and clears itself afterwards.
	var raw [StaticKeyLen]byte
	for i := range raw {
		raw[i] = byte(i)
	}
	w, _ := New(raw, DirectionInverse)
	trailer := []byte("WKC_TRAILER_BYTES")
	w.SetFirstWrapTrailer(trailer)

	pkt1 := w.Wrap(0x50, 1, []byte("hello"))
	if !bytes.HasSuffix(pkt1, trailer) {
		t.Fatal("first wrap did not carry trailer")
	}
	pkt2 := w.Wrap(0x20, 1, []byte("world"))
	if bytes.HasSuffix(pkt2, trailer) {
		t.Fatal("second wrap erroneously carried trailer")
	}
}
