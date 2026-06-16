// SPDX-License-Identifier: AGPL-3.0-or-later

package netstack

import (
	"net/netip"
	"reflect"
	"testing"

	openvpn "github.com/n0madic/go-openvpn"
	tun2net "github.com/n0madic/go-tun2net"
)

// clientTunnel must satisfy go-tun2net's PacketTunnel interface.
var _ tun2net.PacketTunnel = clientTunnel{}

func TestPushReplyToTunConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   openvpn.PushReply
		want tun2net.TunConfig
	}{
		{
			name: "empty",
			in:   openvpn.PushReply{},
			want: tun2net.TunConfig{},
		},
		{
			name: "ipv4 only",
			in: openvpn.PushReply{
				LocalIP: netip.MustParseAddr("10.8.0.6"),
				Netmask: netip.MustParseAddr("255.255.255.0"),
				Gateway: netip.MustParseAddr("10.8.0.1"),
				Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
				DNS:     []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				MTU:     1400,
			},
			want: tun2net.TunConfig{
				LocalIP: netip.MustParseAddr("10.8.0.6"),
				Netmask: netip.MustParseAddr("255.255.255.0"),
				Gateway: netip.MustParseAddr("10.8.0.1"),
				Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
				DNS:     []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				MTU:     1400,
			},
		},
		{
			name: "dual stack",
			in: openvpn.PushReply{
				LocalIP:   netip.MustParseAddr("10.8.0.6"),
				Netmask:   netip.MustParseAddr("255.255.255.0"),
				Gateway:   netip.MustParseAddr("10.8.0.1"),
				LocalIP6:  netip.MustParsePrefix("fd00::1000/64"),
				RemoteIP6: netip.MustParseAddr("fd00::1"),
				Routes:    []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")},
				Routes6:   []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
				DNS:       []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")},
				MTU:       1500,
			},
			want: tun2net.TunConfig{
				LocalIP:   netip.MustParseAddr("10.8.0.6"),
				Netmask:   netip.MustParseAddr("255.255.255.0"),
				Gateway:   netip.MustParseAddr("10.8.0.1"),
				LocalIP6:  netip.MustParsePrefix("fd00::1000/64"),
				RemoteIP6: netip.MustParseAddr("fd00::1"),
				Routes:    []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")},
				Routes6:   []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
				DNS:       []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")},
				MTU:       1500, // not clamped here — go-tun2net clamps internally
			},
		},
		{
			name: "zero mtu maps to zero",
			in: openvpn.PushReply{
				LocalIP: netip.MustParseAddr("10.8.0.6"),
				MTU:     0,
			},
			want: tun2net.TunConfig{
				LocalIP: netip.MustParseAddr("10.8.0.6"),
				MTU:     0,
			},
		},
		{
			name: "negative mtu maps to zero",
			in: openvpn.PushReply{
				LocalIP: netip.MustParseAddr("10.8.0.6"),
				MTU:     -1,
			},
			want: tun2net.TunConfig{
				LocalIP: netip.MustParseAddr("10.8.0.6"),
				MTU:     0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := pushReplyToTunConfig(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pushReplyToTunConfig() mismatch\n got: %+v\nwant: %+v", got, tt.want)
			}
		})
	}
}
