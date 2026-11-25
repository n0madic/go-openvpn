// SPDX-License-Identifier: MPL-2.0

package session

import (
	"crypto/rand"
	"testing"

	"github.com/n0madic/go-openvpn/internal/tlsauth"
	"github.com/n0madic/go-openvpn/internal/tlscrypt"
)

func TestBuildWrapperHonorsTLSAuthKeyDirection(t *testing.T) {
	var key [tlscrypt.StaticKeyLen]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		set             bool
		direction       int
		serverDirection tlscrypt.Direction
	}{
		{name: "explicit normal", set: true, direction: 0, serverDirection: tlscrypt.DirectionInverse},
		{name: "explicit inverse", set: true, direction: 1, serverDirection: tlscrypt.DirectionNormal},
		{name: "unset defaults to inverse", set: false, direction: 0, serverDirection: tlscrypt.DirectionNormal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _, err := buildWrapper(Config{
				TLSAuth:         key[:],
				KeyDirection:    tt.direction,
				KeyDirectionSet: tt.set,
			})
			if err != nil {
				t.Fatalf("buildWrapper: %v", err)
			}
			server, err := tlsauth.New(key, tt.serverDirection, "SHA1")
			if err != nil {
				t.Fatalf("tlsauth.New(server): %v", err)
			}
			want := []byte("directional tls-auth test")
			packet := client.Wrap(0x20, 0x0102030405060708, want)
			_, _, _, got, err := server.Unwrap(packet)
			if err != nil {
				t.Fatalf("server Unwrap: %v", err)
			}
			if string(got) != string(want) {
				t.Fatalf("payload = %q, want %q", got, want)
			}
		})
	}
}

func TestBuildWrapperRejectsInvalidTLSAuthKeyDirection(t *testing.T) {
	var key [tlscrypt.StaticKeyLen]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := buildWrapper(Config{TLSAuth: key[:], KeyDirection: 2, KeyDirectionSet: true}); err == nil {
		t.Fatal("expected invalid key direction to be rejected")
	}
}
