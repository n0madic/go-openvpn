// SPDX-License-Identifier: AGPL-3.0-or-later

package openvpn

import (
	"net/netip"
	"sync"
	"testing"
)

// TestOnReconnectDispatch verifies that all registered callbacks fire, in
// order, with the supplied PushReply when fireOnReconnect runs.
func TestOnReconnectDispatch(t *testing.T) {
	t.Parallel()

	c := &Client{}
	var (
		mu      sync.Mutex
		gotIPs  []netip.Addr
		order   []int
		hookIdx int
	)
	for i := range 3 {
		idx := i
		c.OnReconnect(func(pr PushReply) {
			mu.Lock()
			gotIPs = append(gotIPs, pr.LocalIP)
			order = append(order, idx)
			mu.Unlock()
		})
		hookIdx++
	}

	want := netip.MustParseAddr("10.0.0.7")
	c.FireOnReconnect(PushReply{LocalIP: want})

	mu.Lock()
	defer mu.Unlock()
	if len(gotIPs) != 3 {
		t.Fatalf("got %d invocations, want 3", len(gotIPs))
	}
	for i, ip := range gotIPs {
		if ip != want {
			t.Errorf("hook %d: got %v, want %v", i, ip, want)
		}
		if order[i] != i {
			t.Errorf("hook %d fired at position %d, want %d", i, order[i], i)
		}
	}
}

// TestOnReconnectNilSkip verifies that registering nil is silently dropped
// (we don't want fireOnReconnect to panic dereferencing a nil entry).
func TestOnReconnectNilSkip(t *testing.T) {
	t.Parallel()

	c := &Client{}
	c.OnReconnect(nil) // must not be added
	c.OnReconnect(nil)

	// fireOnReconnect must not panic with no real hooks installed.
	c.FireOnReconnect(PushReply{})
}
