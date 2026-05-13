// SPDX-License-Identifier: AGPL-3.0-or-later

// Package control implements the OpenVPN 2.6+ client-side control-channel
// state machine: hard reset → TLS handshake → KEY_METHOD 2 exchange →
// PUSH_REQUEST/PUSH_REPLY → TLS-EKM data-key derivation.
package control

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/n0madic/go-openvpn/internal/proto"
)

// MaxControlMessageLen caps any NUL-terminated control-channel message
// (PUSH_REPLY, AUTH_FAILED, INFO, ...). 16 KiB is well above any realistic
// PUSH_REPLY size while staying defensive against a hostile server.
const MaxControlMessageLen = 16 * 1024

// ReadKeyMethod2 streams a KEY_METHOD 2 message off the TLS connection.
// serverSide indicates which side authored the message (server messages omit
// the 48-byte pre_master). authUserPass mirrors the client's --auth-user-pass
// flag and affects whether username/password fields appear.
func ReadKeyMethod2(r io.Reader, serverSide, authUserPass bool) (proto.KeyMethod2, error) {
	km := proto.KeyMethod2{IsServer: serverSide, AuthUserPass: authUserPass}

	var prefix [5]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return km, fmt.Errorf("control: read km2 prefix: %w", err)
	}
	if prefix[0]|prefix[1]|prefix[2]|prefix[3] != 0 {
		return km, errors.New("control: KEY_METHOD 2 missing zero prefix")
	}
	if prefix[4] != 2 {
		return km, fmt.Errorf("control: unsupported key_method %d", prefix[4])
	}

	if !serverSide {
		// Client-authored message includes pre_master.
		if _, err := io.ReadFull(r, km.PreMaster[:]); err != nil {
			return km, fmt.Errorf("control: read pre_master: %w", err)
		}
	}
	if _, err := io.ReadFull(r, km.Random1[:]); err != nil {
		return km, fmt.Errorf("control: read random1: %w", err)
	}
	if _, err := io.ReadFull(r, km.Random2[:]); err != nil {
		return km, fmt.Errorf("control: read random2: %w", err)
	}

	var err error
	if km.Options, err = readLengthString(r, "options"); err != nil {
		return km, err
	}
	// username + password are ALWAYS on the wire (empty when not in use) —
	// see OpenVPN ssl.c::key_method_2_write which always emits the fields.
	// The authUserPass flag only governs whether they carry real values.
	if km.Username, err = readLengthString(r, "username"); err != nil {
		return km, err
	}
	if km.Password, err = readLengthString(r, "password"); err != nil {
		return km, err
	}
	if km.PeerInfo, err = readLengthString(r, "peer_info"); err != nil {
		return km, err
	}
	return km, nil
}

// readLengthString reads a uint16 BE length followed by that many bytes. The
// last must be a NUL terminator (the returned string excludes it).
//
// length == 0 is tolerated and treated as an absent field — real OpenVPN
// 2.6 servers send zero-length peer_info when nothing is configured to push.
// length == 1 is also valid (an empty NUL-terminated string).
func readLengthString(r io.Reader, name string) (string, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", fmt.Errorf("control: read %s length: %w", name, err)
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return "", nil
	}
	if int(n) > MaxControlMessageLen {
		return "", fmt.Errorf("control: %s length %d exceeds max", name, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", fmt.Errorf("control: read %s body: %w", name, err)
	}
	if body[n-1] != 0 {
		return "", fmt.Errorf("control: %s missing NUL terminator", name)
	}
	return string(body[:n-1]), nil
}

// ReadControlMessage reads a NUL-terminated text message (PUSH_REPLY,
// AUTH_FAILED, INFO, RESTART, ...) from the TLS stream. The returned string
// excludes the terminating NUL.
//
// When r is a *bufio.Reader, the read uses ReadByte for buffered I/O —
// fast (one call per buffered byte, no syscalls) yet bounded: a hostile
// or broken server that never sends a terminating NUL is capped at
// MaxControlMessageLen rather than forcing unbounded buffering inside
// bufio. Callers that read many messages from a long-lived TLS conn
// (e.g. controlChannelReader) should wrap the conn in a bufio.Reader
// once and reuse it.
func ReadControlMessage(r io.Reader) (string, error) {
	if br, ok := r.(*bufio.Reader); ok {
		buf := make([]byte, 0, 256)
		for {
			if len(buf) > MaxControlMessageLen {
				return "", errors.New("control: text message too long")
			}
			b, err := br.ReadByte()
			if err != nil {
				return "", err
			}
			if b == 0 {
				return string(buf), nil
			}
			buf = append(buf, b)
		}
	}
	buf := make([]byte, 0, 256)
	var one [1]byte
	for {
		if len(buf) > MaxControlMessageLen {
			return "", errors.New("control: text message too long")
		}
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return "", err
		}
		if one[0] == 0 {
			return string(buf), nil
		}
		buf = append(buf, one[0])
	}
}

// WriteControlMessage writes s followed by a NUL byte.
func WriteControlMessage(w io.Writer, s string) error {
	if _, err := w.Write([]byte(s)); err != nil {
		return err
	}
	_, err := w.Write([]byte{0})
	return err
}
