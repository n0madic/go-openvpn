// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"bytes"
	"context"
	"math/rand/v2"
	"testing"
	"time"
)

// randomBytes returns n pseudo-random bytes from a seeded PRNG so tests
// are reproducible.
func randomBytes(seed uint64, n int) []byte {
	r := rand.New(rand.NewPCG(seed, seed^0xa5a5a5a5))
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(r.Uint32())
	}
	return out
}

func TestXorMaskSelfInverse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		key  []byte
	}{
		{"single", []byte{0x5a}},
		{"short", []byte("ab")},
		{"obfuscate-typical", []byte("mysecret")},
		{"long", randomBytes(7, 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, n := range []int{1, 2, 16, 1500} {
				orig := randomBytes(uint64(n), n)
				buf := append([]byte(nil), orig...)
				xorMask(buf, tc.key)
				xorMask(buf, tc.key)
				if !bytes.Equal(buf, orig) {
					t.Fatalf("len=%d: not self-inverse", n)
				}
			}
		})
	}
}

func TestXorPtrPosSelfInverse(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 2, 16, 1500} {
		orig := randomBytes(uint64(n)+100, n)
		buf := append([]byte(nil), orig...)
		xorPtrPos(buf)
		xorPtrPos(buf)
		if !bytes.Equal(buf, orig) {
			t.Fatalf("len=%d: not self-inverse", n)
		}
	}
}

func TestReverseSelfInverse(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 2, 3, 16, 1500} {
		orig := randomBytes(uint64(n)+200, n)
		buf := append([]byte(nil), orig...)
		reverseBytes(buf)
		reverseBytes(buf)
		if !bytes.Equal(buf, orig) {
			t.Fatalf("len=%d: not self-inverse", n)
		}
		// And the opcode byte (index 0) must always survive intact
		// after a single reverse.
		buf2 := append([]byte(nil), orig...)
		reverseBytes(buf2)
		if len(buf2) > 0 && buf2[0] != orig[0] {
			t.Fatalf("len=%d: opcode byte mutated: got %#x want %#x", n, buf2[0], orig[0])
		}
	}
}

func TestScrambleSendRecvRoundTrip(t *testing.T) {
	t.Parallel()
	modes := []struct {
		name string
		mode ScrambleMode
		key  []byte
	}{
		{"xormask", ScrambleXorMask, []byte("k")},
		{"xormask-long", ScrambleXorMask, []byte("mysecret-and-some-more")},
		{"xorptrpos", ScrambleXorPtrPos, nil},
		{"reverse", ScrambleReverse, nil},
		{"obfuscate", ScrambleObfuscate, []byte("mysecret")},
		{"obfuscate-1byte-key", ScrambleObfuscate, []byte{0xa5}},
		{"obfuscate-32byte-key", ScrambleObfuscate, randomBytes(42, 32)},
	}
	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, n := range []int{1, 2, 16, 100, 1500} {
				orig := randomBytes(uint64(n)+uint64(tc.mode), n)
				buf := append([]byte(nil), orig...)
				scrambleSend(buf, tc.mode, tc.key)
				scrambleRecv(buf, tc.mode, tc.key)
				if !bytes.Equal(buf, orig) {
					t.Fatalf("len=%d mode=%v: round-trip mismatch", n, tc.mode)
				}
			}
		})
	}
}

func TestScrambleConnMemoryPairRoundTrip(t *testing.T) {
	t.Parallel()
	modes := []struct {
		name string
		mode ScrambleMode
		key  []byte
	}{
		{"xormask", ScrambleXorMask, []byte("k")},
		{"xorptrpos", ScrambleXorPtrPos, nil},
		{"reverse", ScrambleReverse, nil},
		{"obfuscate", ScrambleObfuscate, []byte("mysecret")},
	}
	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rawA, rawB := MemoryPair()
			a := NewScramble(rawA, tc.mode, tc.key)
			b := NewScramble(rawB, tc.mode, tc.key)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			for _, n := range []int{1, 2, 16, 1500} {
				want := randomBytes(uint64(n)+0xbeef, n)
				if err := a.WritePacket(ctx, want); err != nil {
					t.Fatalf("len=%d write: %v", n, err)
				}
				got, err := b.ReadPacket(ctx)
				if err != nil {
					t.Fatalf("len=%d read: %v", n, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("len=%d round-trip mismatch", n)
				}
			}
		})
	}
}

func TestScrambleConnDoesNotMutateCallerBuffer(t *testing.T) {
	t.Parallel()
	rawA, rawB := MemoryPair()
	a := NewScramble(rawA, ScrambleObfuscate, []byte("mysecret"))
	_ = rawB

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	orig := randomBytes(0xcafe, 256)
	send := append([]byte(nil), orig...)
	if err := a.WritePacket(ctx, send); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(send, orig) {
		t.Fatalf("WritePacket mutated caller buffer")
	}
}

func TestNewScrambleNoneReturnsInner(t *testing.T) {
	t.Parallel()
	rawA, _ := MemoryPair()
	got := NewScramble(rawA, ScrambleNone, nil)
	if got != rawA {
		t.Fatalf("ScrambleNone must return inner verbatim, got wrapper")
	}
}
