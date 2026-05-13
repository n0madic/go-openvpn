// SPDX-License-Identifier: AGPL-3.0-or-later

package proto

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
)

// IV_PROTO bit values used in this client. Values exactly match
// src/openvpn/ssl.h in OpenVPN 2.6.x.
//
//nolint:revive // names mirror the upstream macro identifiers exactly
const (
	IVProtoDataV2        = 1 << 1 // peer supports P_DATA_V2 with peer-id
	IVProtoRequestPush   = 1 << 2 // client will send PUSH_REQUEST
	IVProtoTLSKeyExport  = 1 << 3 // RFC 5705 EKM data-key derivation (--key-derivation tls-ekm)
	IVProtoAuthPendingKW = 1 << 4 // supports keyword-form AUTH_PENDING
	IVProtoNCPP2P        = 1 << 5 // peer-to-peer NCP support
	IVProtoDNSOption     = 1 << 6 // supports modern dns option
	IVProtoCCExitNotify  = 1 << 7 // control-channel exit-notify
	IVProtoAuthFailTemp  = 1 << 8 // supports AUTH_FAILED,TEMP
	IVProtoDynTLSCrypt   = 1 << 9 // dynamic tls-crypt key update
)

// DefaultClientIVProto is the IV_PROTO bitfield this client advertises:
//
//   - DATA_V2:        peer-id-aware P_DATA_V2 framing
//   - REQUEST_PUSH:   we'll send PUSH_REQUEST after handshake
//   - TLS_KEY_EXPORT: RFC 5705 EKM key derivation
//   - CC_EXIT_NOTIFY: control-channel exit notification on Close
//
// Other bits are deliberately omitted: we don't implement dyn-tls-crypt,
// AUTH_PENDING handling, or NCP peer-to-peer mode.
const DefaultClientIVProto = IVProtoDataV2 |
	IVProtoRequestPush |
	IVProtoTLSKeyExport |
	IVProtoCCExitNotify

// PeerInfo accumulates IV_* (and arbitrary UV_*) key=value lines that go into
// the peer_info field of KEY_METHOD 2.
type PeerInfo struct {
	fields map[string]string
}

// NewPeerInfo builds a PeerInfo with the standard set of OpenVPN 2.6+ fields
// populated. Caller adds anything else via Set.
//
// ciphers is the colon-separated IV_CIPHERS list (priority order).
func NewPeerInfo(version, platform string, ivProto int, ciphers string, mtu int) *PeerInfo {
	pi := &PeerInfo{fields: map[string]string{}}
	pi.Set("IV_VER", version)
	pi.Set("IV_PLAT", platform)
	pi.Set("IV_PROTO", fmt.Sprintf("%d", ivProto))
	pi.Set("IV_NCP", "2")
	pi.Set("IV_CIPHERS", ciphers)
	pi.Set("IV_MTU", fmt.Sprintf("%d", mtu))
	return pi
}

// DefaultPeerInfo returns a PeerInfo pre-populated with sensible defaults for
// this build of the library.
func DefaultPeerInfo(ciphers string) *PeerInfo {
	return NewPeerInfo("2.6.0", runtime.GOOS, DefaultClientIVProto, ciphers, 1500)
}

// Set adds or overrides a peer-info field. Empty value is allowed.
func (pi *PeerInfo) Set(key, value string) {
	pi.fields[key] = value
}

// Encode serialises peer-info as "KEY=VALUE\n..." with a trailing newline.
// Keys are sorted to keep the output deterministic (helpful in tests; server
// does not care about order).
func (pi *PeerInfo) Encode() string {
	keys := make([]string, 0, len(pi.fields))
	for k := range pi.fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(pi.fields[k])
		b.WriteByte('\n')
	}
	return b.String()
}
