// SPDX-License-Identifier: AGPL-3.0-or-later

package control

import (
	"crypto/tls"
	"fmt"
)

// ExportLabel is the RFC 5705 EKM label OpenVPN 2.6+ uses for data-channel
// keys when --key-derivation tls-ekm is in effect. Confirmed against
// src/openvpn/ssl.c::tls_session_generate_data_channel_keys, which calls
// SSL_export_keying_material with use_context=0 (empty context).
const ExportLabel = "EXPORTER-OpenVPN-datakeys"

// DataKeyMaterialLen is the byte length of the EKM export OpenVPN expects.
const DataKeyMaterialLen = 256

// AEAD nonce overhead: GCM and Poly1305 both use a 12-byte nonce. OpenVPN
// constructs it as packet_id (4 BE) || implicit_iv (8). The 8 bytes come from
// the first 8 of each direction's "hmac slot" of the EKM export.
const ImplicitIVLen = 8

// DataKeyMaterial is the 256-byte EKM export split into the four OpenVPN
// directional slots:
//
//	[  0.. 64)  client→server cipher slot (key occupies the first N bytes,
//	            N=32 for AES-256/ChaCha20, 16 for AES-128)
//	[ 64..128)  client→server "hmac" slot (we use the first 8 bytes as the
//	            implicit IV; remaining bytes unused for AEAD)
//	[128..192)  server→client cipher slot
//	[192..256)  server→client "hmac" slot (first 8 bytes = implicit IV)
type DataKeyMaterial [DataKeyMaterialLen]byte

// ClientToServerCipherKey returns the first keyLen bytes of the c→s cipher
// slot. Use 32 for AES-256-GCM / CHACHA20-POLY1305, 16 for AES-128-GCM.
func (m *DataKeyMaterial) ClientToServerCipherKey(keyLen int) []byte {
	return m[0:keyLen]
}

// ClientToServerImplicitIV returns the 8-byte implicit nonce suffix for the
// c→s direction.
func (m *DataKeyMaterial) ClientToServerImplicitIV() [ImplicitIVLen]byte {
	var iv [ImplicitIVLen]byte
	copy(iv[:], m[64:64+ImplicitIVLen])
	return iv
}

// ServerToClientCipherKey returns the first keyLen bytes of the s→c cipher
// slot.
func (m *DataKeyMaterial) ServerToClientCipherKey(keyLen int) []byte {
	return m[128 : 128+keyLen]
}

// ServerToClientImplicitIV returns the 8-byte implicit nonce suffix for the
// s→c direction.
func (m *DataKeyMaterial) ServerToClientImplicitIV() [ImplicitIVLen]byte {
	var iv [ImplicitIVLen]byte
	copy(iv[:], m[192:192+ImplicitIVLen])
	return iv
}

// DeriveDataKeys runs RFC 5705 EKM on the established TLS session to produce
// 256 bytes of OpenVPN data-channel keying material. The context input is
// empty (use_context=0 on the OpenVPN side).
func DeriveDataKeys(state tls.ConnectionState) (DataKeyMaterial, error) {
	out, err := state.ExportKeyingMaterial(ExportLabel, nil, DataKeyMaterialLen)
	if err != nil {
		return DataKeyMaterial{}, fmt.Errorf("control: TLS-EKM export: %w", err)
	}
	if len(out) != DataKeyMaterialLen {
		return DataKeyMaterial{}, fmt.Errorf("control: TLS-EKM returned %d bytes, want %d",
			len(out), DataKeyMaterialLen)
	}
	var m DataKeyMaterial
	copy(m[:], out)
	return m, nil
}

// AEADKeyLen returns the cipher key length for one of the supported AEAD
// algorithms.
func AEADKeyLen(cipher string) (int, error) {
	switch cipher {
	case "AES-256-GCM", "CHACHA20-POLY1305":
		return 32, nil
	case "AES-128-GCM":
		return 16, nil
	default:
		return 0, fmt.Errorf("control: unsupported data cipher %q", cipher)
	}
}
