// SPDX-License-Identifier: AGPL-3.0-or-later

// Package transport provides the wire-level packet I/O abstraction used by
// the OpenVPN client. A PacketConn delivers one OpenVPN packet per ReadPacket
// call (preserving datagram boundaries even when the underlying socket is a
// TCP stream).
package transport

import (
	"context"
	"errors"
	"net"
)

// ErrClosed is returned by ReadPacket/WritePacket after Close.
var ErrClosed = errors.New("transport: closed")

// PacketConn carries a single OpenVPN packet per call. Implementations must be
// safe for concurrent use: in particular, one goroutine reading while another
// writes is the expected mode.
type PacketConn interface {
	// ReadPacket returns one complete OpenVPN packet. The returned slice is
	// owned by the caller until the next ReadPacket call on this connection.
	ReadPacket(ctx context.Context) ([]byte, error)

	// WritePacket sends one OpenVPN packet atomically. For UDP this is a
	// single datagram; for TCP it prepends a 16-bit big-endian length prefix.
	WritePacket(ctx context.Context, p []byte) error

	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}

// Dialer constructs a PacketConn for the given network/address.
type Dialer interface {
	Dial(ctx context.Context, network, addr string) (PacketConn, error)
}

// Dial chooses the implementation by network: "udp"/"udp4"/"udp6" uses the
// UDP transport, "tcp"/"tcp4"/"tcp6" uses the TCP length-prefixed transport.
func Dial(ctx context.Context, network, addr string) (PacketConn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return dialUDP(ctx, network, addr)
	case "tcp", "tcp4", "tcp6":
		return dialTCP(ctx, network, addr)
	default:
		return nil, errors.New("transport: unsupported network " + network)
	}
}
