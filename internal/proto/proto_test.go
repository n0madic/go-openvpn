// SPDX-License-Identifier: AGPL-3.0-or-later

package proto

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestOpcodeKIDPackRoundTrip(t *testing.T) {
	t.Parallel()
	for op := range 32 {
		for kid := range 8 {
			b := PackOpcodeKID(Opcode(op), uint8(kid))
			gotOp, gotKID := UnpackOpcodeKID(b)
			if gotOp != Opcode(op) || gotKID != uint8(kid) {
				t.Fatalf("op=%d kid=%d round-tripped to op=%d kid=%d", op, kid, gotOp, gotKID)
			}
		}
	}
}

func TestOpcodeKIDByteValues(t *testing.T) {
	t.Parallel()
	// Spot checks for hand-computed values.
	cases := []struct {
		op   Opcode
		kid  uint8
		want byte
	}{
		{PControlHardResetClientV2, 0, 0x38}, // (7 << 3) | 0
		{PControlV1, 0, 0x20},                // (4 << 3) | 0
		{PAckV1, 0, 0x28},                    // (5 << 3) | 0
		{PDataV2, 0, 0x48},                   // (9 << 3) | 0
		{PDataV2, 7, 0x4F},                   // (9 << 3) | 7
		{PControlHardResetClientV3, 0, 0x50}, // (10 << 3) | 0
	}
	for _, c := range cases {
		if got := PackOpcodeKID(c.op, c.kid); got != c.want {
			t.Errorf("%s kid=%d: got 0x%02x, want 0x%02x", c.op, c.kid, got, c.want)
		}
	}
}

func TestControlHeaderRoundTrip(t *testing.T) {
	t.Parallel()
	h := ControlHeader{
		Opcode:    PControlV1,
		KeyID:     3,
		SessionID: 0x0102030405060708,
	}
	buf := h.AppendBinary(nil)
	if len(buf) != HeaderLen {
		t.Fatalf("header len %d, want %d", len(buf), HeaderLen)
	}
	got, rest, err := ParseControlHeader(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("rest %d bytes, want 0", len(rest))
	}
	if got != h {
		t.Fatalf("got %+v, want %+v", got, h)
	}
}

func TestControlPayloadRoundTrip(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cp   ControlPayload
	}{
		{"empty acks no body", ControlPayload{MessagePID: 1}},
		{"one ack no body", ControlPayload{Acks: []uint32{42}, RemoteSessionID: 0xdead, MessagePID: 2}},
		{"acks with body", ControlPayload{Acks: []uint32{1, 2, 3}, RemoteSessionID: 0xbeef, MessagePID: 5, Body: []byte("hello tls")}},
		{"no acks with body", ControlPayload{MessagePID: 100, Body: bytes.Repeat([]byte{0xCC}, 1024)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, err := MarshalControlPayload(tc.cp)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseControlPayload(b)
			if err != nil {
				t.Fatal(err)
			}
			// Body comparison via bytes.Equal handles nil/empty slice issue.
			if got.MessagePID != tc.cp.MessagePID ||
				got.RemoteSessionID != tc.cp.RemoteSessionID ||
				!bytes.Equal(got.Body, tc.cp.Body) ||
				!sliceEqual(got.Acks, tc.cp.Acks) {
				t.Fatalf("round-trip diverged:\n got=%+v\nwant=%+v", got, tc.cp)
			}
		})
	}
}

func TestAckPayloadRoundTrip(t *testing.T) {
	t.Parallel()
	ap := AckPayload{Acks: []uint32{10, 20}, RemoteSessionID: 0xabcd}
	b, err := MarshalAckPayload(ap)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAckPayload(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.RemoteSessionID != ap.RemoteSessionID || !sliceEqual(got.Acks, ap.Acks) {
		t.Fatalf("got %+v, want %+v", got, ap)
	}
}

func TestAckPayloadZeroAcksRejected(t *testing.T) {
	t.Parallel()
	if _, err := MarshalAckPayload(AckPayload{}); err == nil {
		t.Fatal("expected error for zero-ack P_ACK_V1")
	}
}

func TestDataV2HeaderRoundTrip(t *testing.T) {
	t.Parallel()
	h := DataV2Header{KeyID: 5, PeerID: 0x123456, PacketID: 0xdeadbeef}
	buf := h.AppendBinary(nil)
	if len(buf) != DataV2HeaderLen {
		t.Fatalf("data v2 header len %d, want %d", len(buf), DataV2HeaderLen)
	}
	// First byte is (9<<3)|5 = 0x4D
	if buf[0] != 0x4D {
		t.Errorf("first byte 0x%02x, want 0x4D", buf[0])
	}
	// peer-id at [1..4) is 0x12 0x34 0x56
	if buf[1] != 0x12 || buf[2] != 0x34 || buf[3] != 0x56 {
		t.Errorf("peer-id bytes %x, want 12 34 56", buf[1:4])
	}
	got, _, err := ParseDataV2Header(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Fatalf("got %+v, want %+v", got, h)
	}
}

func TestKeyMethod2ClientRoundTrip(t *testing.T) {
	t.Parallel()
	km := KeyMethod2{
		IsServer:     false,
		Options:      "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth SHA256,keysize 256,key-method 2,tls-client",
		AuthUserPass: true,
		Username:     "alice",
		Password:     "s3cr3t",
		PeerInfo:     "IV_VER=2.6.0\nIV_PLAT=linux\nIV_PROTO=8\nIV_CIPHERS=AES-256-GCM\n",
	}
	for i := range PreMasterLen {
		km.PreMaster[i] = byte(i)
	}
	for i := range RandomLen {
		km.Random1[i] = byte(0x80 + i)
		km.Random2[i] = byte(0xC0 + i)
	}
	b, err := MarshalKeyMethod2(km)
	if err != nil {
		t.Fatal(err)
	}
	// 4 zero prefix bytes
	if b[0] != 0 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		t.Fatalf("missing zero prefix: %x", b[:4])
	}
	if b[4] != 2 {
		t.Fatalf("key_method byte = %d, want 2", b[4])
	}
	got, err := ParseKeyMethod2(b, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Options != km.Options || got.Username != km.Username ||
		got.Password != km.Password || got.PeerInfo != km.PeerInfo ||
		got.PreMaster != km.PreMaster || got.Random1 != km.Random1 || got.Random2 != km.Random2 {
		t.Fatalf("round-trip diverged")
	}
}

func TestKeyMethod2ClientNoAuth(t *testing.T) {
	t.Parallel()
	km := KeyMethod2{
		Options:  "V4,cipher AES-256-GCM",
		PeerInfo: "IV_VER=2.6.0\n",
	}
	b, err := MarshalKeyMethod2(km)
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: with auth disabled, username/password are still present as
	// zero-length placeholders (matches OpenVPN's wire format).
	// Layout: 4 zero | 1 key_method | 48 PM | 64 random | options-tlv |
	//         empty-u(2) | empty-p(2) | peer-info-tlv.
	expected := 4 + 1 + PreMasterLen + 2*RandomLen + (2 + len(km.Options) + 1) + 2 + 2 + (2 + len(km.PeerInfo) + 1)
	if len(b) != expected {
		t.Fatalf("len %d, want %d", len(b), expected)
	}
	got, err := ParseKeyMethod2(b, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Options != km.Options || got.PeerInfo != km.PeerInfo {
		t.Fatal("round-trip diverged")
	}
}

func TestKeyMethod2ServerNoPreMaster(t *testing.T) {
	t.Parallel()
	km := KeyMethod2{
		IsServer: true,
		Options:  "V4,cipher AES-256-GCM",
		PeerInfo: "IV_VER=2.6.0\n",
	}
	// Server side: pre_master is not serialised, but u/p placeholders still are.
	b, err := MarshalKeyMethod2(km)
	if err != nil {
		t.Fatal(err)
	}
	expected := 4 + 1 + 2*RandomLen + (2 + len(km.Options) + 1) + 2 + 2 + (2 + len(km.PeerInfo) + 1)
	if len(b) != expected {
		t.Fatalf("server len %d, want %d", len(b), expected)
	}
	if _, err := ParseKeyMethod2(b, true, false); err != nil {
		t.Fatal(err)
	}
}

func TestKeyMethod2RejectsNULInString(t *testing.T) {
	t.Parallel()
	if _, err := MarshalKeyMethod2(KeyMethod2{Options: "foo\x00bar", PeerInfo: "x=y\n"}); err == nil {
		t.Fatal("expected error for NUL in options")
	}
}

func TestKeyMethod2RejectsMissingNUL(t *testing.T) {
	t.Parallel()
	// Hand-craft a buffer that lies about the length field.
	b := []byte{0, 0, 0, 0, 2}
	b = append(b, make([]byte, PreMasterLen+RandomLen*2)...)
	b = append(b, 0x00, 0x04, 'a', 'b', 'c', 'd') // claims 4 bytes "abcd" — no NUL
	if _, err := ParseKeyMethod2(b, false, false); err == nil {
		t.Fatal("expected NUL-terminator error")
	}
}

func TestPeerInfoDeterministic(t *testing.T) {
	t.Parallel()
	pi := DefaultPeerInfo("AES-256-GCM:CHACHA20-POLY1305")
	got := pi.Encode()
	pi2 := DefaultPeerInfo("AES-256-GCM:CHACHA20-POLY1305")
	if pi.Encode() != pi2.Encode() {
		t.Fatal("Encode not deterministic")
	}
	if !strings.Contains(got, "IV_VER=2.6.0\n") {
		t.Errorf("missing IV_VER:\n%s", got)
	}
	if !strings.Contains(got, "IV_CIPHERS=AES-256-GCM:CHACHA20-POLY1305\n") {
		t.Errorf("missing IV_CIPHERS:\n%s", got)
	}
	if !strings.Contains(got, "IV_NCP=2\n") {
		t.Errorf("missing IV_NCP:\n%s", got)
	}
}

func TestParsePushReply(t *testing.T) {
	t.Parallel()
	// Real-ish PUSH_REPLY captured from openvpn 2.6 server.
	s := "PUSH_REPLY,route 10.8.0.1,topology subnet,ping 10,ping-restart 60,ifconfig 10.8.0.6 255.255.255.0,peer-id 0,cipher AES-256-GCM,tun-mtu 1500,dhcp-option DNS 8.8.8.8,dhcp-option DNS 1.1.1.1,route-gateway 10.8.0.1"
	pr, err := ParsePushReply(s)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pr.LocalIP, netip.MustParseAddr("10.8.0.6"); got != want {
		t.Errorf("LocalIP %s, want %s", got, want)
	}
	if got, want := pr.Netmask, netip.MustParseAddr("255.255.255.0"); got != want {
		t.Errorf("Netmask %s, want %s", got, want)
	}
	if got, want := pr.Gateway, netip.MustParseAddr("10.8.0.1"); got != want {
		t.Errorf("Gateway %s, want %s", got, want)
	}
	if pr.Cipher != "AES-256-GCM" {
		t.Errorf("Cipher %q, want AES-256-GCM", pr.Cipher)
	}
	if pr.MTU != 1500 {
		t.Errorf("MTU %d, want 1500", pr.MTU)
	}
	if pr.Topology != "subnet" {
		t.Errorf("Topology %q, want subnet", pr.Topology)
	}
	if pr.PingInterval.Seconds() != 10 {
		t.Errorf("PingInterval %s, want 10s", pr.PingInterval)
	}
	if pr.PingRestart.Seconds() != 60 {
		t.Errorf("PingRestart %s, want 60s", pr.PingRestart)
	}
	if len(pr.DNS) != 2 {
		t.Errorf("DNS len %d, want 2", len(pr.DNS))
	}
	if len(pr.Routes) != 1 {
		t.Errorf("Routes len %d, want 1", len(pr.Routes))
	}
}

func TestParsePushReplyIPv6(t *testing.T) {
	t.Parallel()
	// Real-world dual-stack PUSH_REPLY shape: ifconfig + ifconfig-ipv6 +
	// per-family default routes (or route-ipv6 ::/0 alternatives).
	s := "PUSH_REPLY,ifconfig 10.8.0.6 255.255.255.0,ifconfig-ipv6 2001:db8:abcd::7/64 fe80::1,topology subnet,peer-id 0,cipher AES-256-GCM,tun-mtu 1500,route-gateway 10.8.0.1,route-ipv6 ::/0,route-ipv6 2000::/3,dhcp-option DNS 2001:db8::53"
	pr, err := ParsePushReply(s)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pr.LocalIP6.String(), "2001:db8:abcd::7/64"; got != want {
		t.Errorf("LocalIP6 = %q, want %q", got, want)
	}
	if got, want := pr.RemoteIP6.String(), "fe80::1"; got != want {
		t.Errorf("RemoteIP6 = %q, want %q", got, want)
	}
	if len(pr.Routes6) != 2 {
		t.Fatalf("Routes6 len %d, want 2", len(pr.Routes6))
	}
	if got, want := pr.Routes6[0].String(), "::/0"; got != want {
		t.Errorf("Routes6[0] = %q, want %q", got, want)
	}
	if got, want := pr.Routes6[1].String(), "2000::/3"; got != want {
		t.Errorf("Routes6[1] = %q, want %q", got, want)
	}
	if len(pr.DNS) != 1 || !pr.DNS[0].Is6() {
		t.Errorf("DNS = %v, want one IPv6 entry", pr.DNS)
	}
}

func TestParsePushReplyWithRouteMask(t *testing.T) {
	t.Parallel()
	pr, err := ParsePushReply("PUSH_REPLY,route 10.0.0.0 255.255.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if got := pr.Routes[0].String(); got != "10.0.0.0/16" {
		t.Errorf("route %q, want 10.0.0.0/16", got)
	}
}

func TestParsePushReplyRejectsMalformed(t *testing.T) {
	t.Parallel()
	if _, err := ParsePushReply("hello world"); err == nil {
		t.Fatal("expected error for missing PUSH_REPLY prefix")
	}
}

func TestShortPacketErrors(t *testing.T) {
	t.Parallel()
	if _, _, err := ParseControlHeader([]byte{1, 2, 3}); !errors.Is(err, ErrShortPacket) {
		t.Errorf("got %v, want ErrShortPacket", err)
	}
	if _, _, err := ParseDataV2Header([]byte{1, 2}); !errors.Is(err, ErrShortPacket) {
		t.Errorf("got %v, want ErrShortPacket", err)
	}
	if _, err := ParseControlPayload(nil); !errors.Is(err, ErrShortPacket) {
		t.Errorf("got %v, want ErrShortPacket", err)
	}
}

func sliceEqual(a, b []uint32) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
