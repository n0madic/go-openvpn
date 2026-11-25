// SPDX-License-Identifier: MPL-2.0

package openvpn

import (
	"net/netip"
	"testing"

	"github.com/n0madic/go-openvpn/internal/proto"
)

func TestPushReplyFromProtoIncludesRemoteIPAndClonesSlices(t *testing.T) {
	original := proto.PushReply{
		LocalIP:  netip.MustParseAddr("10.8.0.2"),
		RemoteIP: netip.MustParseAddr("10.8.0.1"),
		Routes: []netip.Prefix{
			netip.MustParsePrefix("10.20.0.0/16"),
		},
		Routes6: []netip.Prefix{
			netip.MustParsePrefix("2001:db8:20::/48"),
		},
		DNS: []netip.Addr{
			netip.MustParseAddr("10.8.0.1"),
		},
	}

	got := pushReplyFromProto(original)
	if got.RemoteIP != original.RemoteIP {
		t.Fatalf("RemoteIP=%s, want %s", got.RemoteIP, original.RemoteIP)
	}

	wantRoute := original.Routes[0]
	wantRoute6 := original.Routes6[0]
	wantDNS := original.DNS[0]

	got.Routes[0] = netip.MustParsePrefix("192.0.2.0/24")
	got.Routes6[0] = netip.MustParsePrefix("2001:db8:ffff::/48")
	got.DNS[0] = netip.MustParseAddr("192.0.2.53")

	if original.Routes[0] != wantRoute {
		t.Errorf("mutating public Routes changed source: got %s, want %s", original.Routes[0], wantRoute)
	}
	if original.Routes6[0] != wantRoute6 {
		t.Errorf("mutating public Routes6 changed source: got %s, want %s", original.Routes6[0], wantRoute6)
	}
	if original.DNS[0] != wantDNS {
		t.Errorf("mutating public DNS changed source: got %s, want %s", original.DNS[0], wantDNS)
	}

	// Mutating the source after projection must not change the returned snapshot.
	original.Routes[0] = netip.MustParsePrefix("198.51.100.0/24")
	original.Routes6[0] = netip.MustParsePrefix("2001:db8:abcd::/48")
	original.DNS[0] = netip.MustParseAddr("198.51.100.53")

	if got.Routes[0] != netip.MustParsePrefix("192.0.2.0/24") {
		t.Errorf("source mutation changed public Routes: got %s", got.Routes[0])
	}
	if got.Routes6[0] != netip.MustParsePrefix("2001:db8:ffff::/48") {
		t.Errorf("source mutation changed public Routes6: got %s", got.Routes6[0])
	}
	if got.DNS[0] != netip.MustParseAddr("192.0.2.53") {
		t.Errorf("source mutation changed public DNS: got %s", got.DNS[0])
	}
}

func TestPushReplyFromProtoPreservesNilSlices(t *testing.T) {
	got := pushReplyFromProto(proto.PushReply{})
	if got.Routes != nil || got.Routes6 != nil || got.DNS != nil {
		t.Fatalf("nil source slices should remain nil: Routes=%v Routes6=%v DNS=%v", got.Routes, got.Routes6, got.DNS)
	}
}
