// SPDX-License-Identifier: AGPL-3.0-or-later

package netstack

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// newTestNet builds a minimal *Net wrapping a net.Pipe-backed endpoint and a
// freshly-initialised gVisor stack — no openvpn.Client needed. Sufficient
// for exercising applyPushReply / DialContext binding.
func newTestNet(t *testing.T) (*Net, func()) {
	t.Helper()
	cli, srv := net.Pipe()
	ep := newEndpoint(cli, 1500)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6,
		},
	})
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		t.Fatalf("SetSpoofing: %s", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		t.Fatalf("SetPromiscuousMode: %s", err)
	}
	n := &Net{stack: s, ep: ep}
	cleanup := func() {
		s.Close()
		ep.Close()
		_ = srv.Close()
	}
	return n, cleanup
}

// TestApplyPushReplyUpdatesNICAddress checks that the second applyPushReply
// (simulating a reconnect with a new tunnel IP) replaces the previous NIC
// address rather than leaving both registered.
func TestApplyPushReplyUpdatesNICAddress(t *testing.T) {
	t.Parallel()
	n, cleanup := newTestNet(t)
	defer cleanup()

	pr1 := openvpn.PushReply{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		Netmask: netip.MustParseAddr("255.255.255.0"),
		Gateway: netip.MustParseAddr("10.0.0.1"),
	}
	if err := n.applyPushReply(pr1); err != nil {
		t.Fatalf("applyPushReply(pr1): %v", err)
	}
	if got := n.LocalIP().String(); got != "10.0.0.5" {
		t.Errorf("after pr1, LocalIP = %q, want 10.0.0.5", got)
	}

	pr2 := openvpn.PushReply{
		LocalIP: netip.MustParseAddr("10.0.0.99"),
		Netmask: netip.MustParseAddr("255.255.255.0"),
		Gateway: netip.MustParseAddr("10.0.0.1"),
	}
	if err := n.applyPushReply(pr2); err != nil {
		t.Fatalf("applyPushReply(pr2): %v", err)
	}
	if got := n.LocalIP().String(); got != "10.0.0.99" {
		t.Errorf("after pr2, LocalIP = %q, want 10.0.0.99", got)
	}

	// Inspect gVisor's NIC: the old address must be gone, new one present.
	addrs := n.stack.NICInfo()[nicID].ProtocolAddresses
	var haveNew, haveOld bool
	for _, a := range addrs {
		switch a.AddressWithPrefix.Address.String() {
		case "10.0.0.99":
			haveNew = true
		case "10.0.0.5":
			haveOld = true
		}
	}
	if !haveNew {
		t.Errorf("new address 10.0.0.99 not registered on NIC; got addrs=%v", addrs)
	}
	if haveOld {
		t.Errorf("old address 10.0.0.5 still on NIC after replacement; got addrs=%v", addrs)
	}
}

// TestPostReconnectDialUsesNewIP is the smoking-gun regression test: it
// reproduces the production bug where post-reconnect UDP sockets kept
// binding to the original tunnel IP, so server-side traffic for the new IP
// was dropped. After applyPushReply with a fresh PushReply, a newly-dialed
// UDP socket MUST bind to the new local IP.
func TestPostReconnectDialUsesNewIP(t *testing.T) {
	t.Parallel()
	n, cleanup := newTestNet(t)
	defer cleanup()

	pr1 := openvpn.PushReply{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		Netmask: netip.MustParseAddr("255.255.255.0"),
		Gateway: netip.MustParseAddr("10.0.0.1"),
	}
	if err := n.applyPushReply(pr1); err != nil {
		t.Fatalf("applyPushReply(pr1): %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	c1, err := n.DialContext(ctx, "udp", "10.0.0.1:53")
	if err != nil {
		t.Fatalf("Dial1: %v", err)
	}
	addr1 := c1.LocalAddr().String()
	_ = c1.Close()
	if !strings.HasPrefix(addr1, "10.0.0.5:") {
		t.Fatalf("addr1 = %q, want 10.0.0.5:... (initial)", addr1)
	}

	// Reconnect to a new tunnel IP.
	pr2 := openvpn.PushReply{
		LocalIP: netip.MustParseAddr("10.0.0.99"),
		Netmask: netip.MustParseAddr("255.255.255.0"),
		Gateway: netip.MustParseAddr("10.0.0.1"),
	}
	if err := n.applyPushReply(pr2); err != nil {
		t.Fatalf("applyPushReply(pr2): %v", err)
	}

	c2, err := n.DialContext(ctx, "udp", "10.0.0.1:53")
	if err != nil {
		t.Fatalf("Dial2: %v", err)
	}
	addr2 := c2.LocalAddr().String()
	_ = c2.Close()
	if !strings.HasPrefix(addr2, "10.0.0.99:") {
		t.Fatalf("addr2 = %q, want 10.0.0.99:... — NIC IP was not refreshed on reconnect", addr2)
	}
}

// TestApplyPushReplyInstallsIPv6Address verifies that when the server pushes
// "ifconfig-ipv6 <addr>/<plen> <peer>" we (a) install the v6 address with the
// pushed prefix length, (b) record it for currentLocalFullAddress(v6=false),
// and (c) synthesise a ::/0 → RemoteIP6 default route. Regression for the
// "no route to host" failure on IPv6 destinations.
func TestApplyPushReplyInstallsIPv6Address(t *testing.T) {
	t.Parallel()
	n, cleanup := newTestNet(t)
	defer cleanup()

	pr := openvpn.PushReply{
		LocalIP:   netip.MustParseAddr("10.0.0.5"),
		Netmask:   netip.MustParseAddr("255.255.255.0"),
		Gateway:   netip.MustParseAddr("10.0.0.1"),
		LocalIP6:  netip.MustParsePrefix("2001:db8:abcd::7/64"),
		RemoteIP6: netip.MustParseAddr("fe80::1"),
	}
	if err := n.applyPushReply(pr); err != nil {
		t.Fatalf("applyPushReply: %v", err)
	}
	if got := n.LocalIP6().String(); got != "2001:db8:abcd::7" {
		t.Errorf("LocalIP6 = %q, want 2001:db8:abcd::7", got)
	}

	addrs := n.stack.NICInfo()[nicID].ProtocolAddresses
	var v6 *tcpip.AddressWithPrefix
	for i, a := range addrs {
		if a.Protocol == ipv6.ProtocolNumber && a.AddressWithPrefix.Address.String() == "2001:db8:abcd::7" {
			v6 = &addrs[i].AddressWithPrefix
			break
		}
	}
	if v6 == nil {
		t.Fatalf("v6 address not installed; got addrs=%v", addrs)
	}
	if v6.PrefixLen != 64 {
		t.Errorf("v6 PrefixLen = %d, want 64", v6.PrefixLen)
	}

	// Default v6 route must exist with gateway = RemoteIP6.
	var sawDefault6 bool
	for _, r := range n.stack.GetRouteTable() {
		if r.Destination.Prefix() == 0 && r.Destination.ID().Len() == 16 {
			if r.Gateway.String() == "fe80::1" {
				sawDefault6 = true
			}
		}
	}
	if !sawDefault6 {
		t.Errorf("default v6 route via fe80::1 missing; got routes=%v", n.stack.GetRouteTable())
	}
}

// TestDialContextIPv6UsesNICAddress confirms that an outgoing v6 dial after
// applyPushReply binds to the NIC's v6 source address (not "auto-pick" /
// "nil laddr"). If the NIC v6 path is broken the dial fails with
// ErrHostUnreachable, mirroring the production "no route to host" symptom.
func TestDialContextIPv6UsesNICAddress(t *testing.T) {
	t.Parallel()
	n, cleanup := newTestNet(t)
	defer cleanup()

	pr := openvpn.PushReply{
		LocalIP:   netip.MustParseAddr("10.0.0.5"),
		Netmask:   netip.MustParseAddr("255.255.255.0"),
		Gateway:   netip.MustParseAddr("10.0.0.1"),
		LocalIP6:  netip.MustParsePrefix("2001:db8:abcd::7/64"),
		RemoteIP6: netip.MustParseAddr("fe80::1"),
	}
	if err := n.applyPushReply(pr); err != nil {
		t.Fatalf("applyPushReply: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	// UDP because gonet.DialUDP is non-blocking — we don't need a server to
	// observe a successful bind. TCP would attempt SYN which the test
	// endpoint can't ACK.
	c, err := n.DialContext(ctx, "udp", "[2001:db8:abcd::1]:53")
	if err != nil {
		t.Fatalf("DialContext v6: %v", err)
	}
	defer func() { _ = c.Close() }()
	addr := c.LocalAddr().String()
	if !strings.HasPrefix(addr, "[2001:db8:abcd::7]:") {
		t.Fatalf("LocalAddr = %q, want [2001:db8:abcd::7]:... — NIC v6 source not bound", addr)
	}
}

// TestApplyPushReplyIdempotent verifies that calling applyPushReply twice
// with identical values doesn't churn the NIC or duplicate routes.
func TestApplyPushReplyIdempotent(t *testing.T) {
	t.Parallel()
	n, cleanup := newTestNet(t)
	defer cleanup()

	pr := openvpn.PushReply{
		LocalIP: netip.MustParseAddr("10.0.0.5"),
		Netmask: netip.MustParseAddr("255.255.255.0"),
		Gateway: netip.MustParseAddr("10.0.0.1"),
	}
	if err := n.applyPushReply(pr); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := n.applyPushReply(pr); err != nil {
		t.Fatalf("second apply (same values): %v", err)
	}
	addrs := n.stack.NICInfo()[nicID].ProtocolAddresses
	count := 0
	for _, a := range addrs {
		if a.AddressWithPrefix.Address.String() == "10.0.0.5" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("10.0.0.5 registered %d times after idempotent calls, want 1", count)
	}
}
