// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

// TestIsLoopbackListen verifies that the LAN-exposure warning suppresses
// for every common loopback-listen form (IP literal, hostname, IPv6
// bracketed) and fires for everything else. The "localhost:port" form
// used to fall through netip.ParseAddrPort (which rejects hostnames)
// and produce a spurious warning even on a perfectly safe listen.
func TestIsLoopbackListen(t *testing.T) {
	t.Parallel()
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:1080", true},
		{"127.0.0.5:1080", true},
		{"[::1]:1080", true},
		{"localhost:1080", true},
		{"0.0.0.0:1080", false},
		{"[::]:1080", false},
		{":1080", false},
		{"192.168.1.5:1080", false},
		{"example.com:1080", false},
		{"", false},
		// Defensive: malformed inputs must NOT short-circuit to "loopback"
		// (which would silence the warning on real misconfigurations).
		{"not-an-address", false},
		{"127.0.0.1", false}, // no port → SplitHostPort fails
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			t.Parallel()
			if got := isLoopbackListen(tc.addr); got != tc.want {
				t.Errorf("isLoopbackListen(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}
