// SPDX-License-Identifier: AGPL-3.0-or-later

package proto

// PingMagic is the 16-byte fixed payload OpenVPN uses to mark a data-channel
// keepalive ping. Verified against OpenVPN's src/openvpn/ping.c::ping_string.
// Either peer transmits these at the negotiated `ping` interval and treats
// any inbound data packet (PING or otherwise) as proof the peer is alive.
//
// First nibble is 0x2 (an "IP version" of 2 — not 4 or 6), so a netstack
// that filters on IP version naturally drops PING payloads.
var PingMagic = [16]byte{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
}

// IsPing reports whether b is exactly the OpenVPN PING payload.
func IsPing(b []byte) bool {
	if len(b) != len(PingMagic) {
		return false
	}
	for i := range PingMagic {
		if b[i] != PingMagic[i] {
			return false
		}
	}
	return true
}
