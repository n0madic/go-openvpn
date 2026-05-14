// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netstack adapts an openvpn.Client tunnel net.Conn to a gVisor
// userspace TCP/IP stack. The stack receives the IP packets that the OpenVPN
// data channel produces and emits IP packets that the data channel encrypts
// and sends to the peer.
//
// Usage:
//
//	cli, err := openvpn.Dial(ctx, cfg)
//	if err != nil { ... }
//	defer cli.Close()
//
//	ns, err := netstack.New(cli)
//	if err != nil { ... }
//	defer ns.Close()
//
//	httpClient := &http.Client{Transport: &http.Transport{DialContext: ns.DialContext}}
//	resp, err := httpClient.Get("http://10.8.0.1:8080/")
package netstack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-openvpn"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// nicID is the only NIC we register inside the stack.
const nicID tcpip.NICID = 1

// endpoint is a stack.LinkEndpoint backed by a tunnel net.Conn that carries
// raw IP datagrams (one Read = one IP packet, one Write = one IP packet).
type endpoint struct {
	conn    net.Conn
	mtu     atomic.Uint32
	closeMu sync.Mutex
	closed  bool
	done    chan struct{}

	mu         sync.RWMutex
	dispatcher stack.NetworkDispatcher
	linkAddr   tcpip.LinkAddress

	onClose func()
}

// Compile-time guard.
var _ stack.LinkEndpoint = (*endpoint)(nil)

// newEndpoint wraps the given conn into a LinkEndpoint with the given MTU.
func newEndpoint(conn net.Conn, mtu uint32) *endpoint {
	e := &endpoint{
		conn: conn,
		done: make(chan struct{}),
	}
	e.mtu.Store(mtu)
	return e
}

func (e *endpoint) MTU() uint32 { return e.mtu.Load() }

func (e *endpoint) SetMTU(m uint32) { e.mtu.Store(m) }

func (*endpoint) MaxHeaderLength() uint16 { return 0 }

func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.linkAddr
}

func (e *endpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.linkAddr = addr
}

func (*endpoint) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }

// Attach starts the reader goroutine that pumps inbound IP packets up the
// stack. Called once by stack.Stack.CreateNIC.
func (e *endpoint) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = d
	e.mu.Unlock()
	if d != nil {
		go e.readLoop()
	}
}

func (e *endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

func (e *endpoint) Wait() {
	<-e.done
}

func (*endpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

func (*endpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader on a header-less endpoint is a no-op that always succeeds.
func (*endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

// Close shuts the endpoint. The reader goroutine exits as soon as the
// underlying Conn returns from Read with an error and sees e.closed=true.
//
// openvpn.tunnel.Close() is a documented no-op (the tunnel handle survives
// across reconnects, so closing it doesn't tear down the VPN session). To
// unblock readLoop's pending Read we therefore poke SetReadDeadline first;
// the subsequent Read returns os.ErrDeadlineExceeded, the loop checks
// e.closed and exits cleanly. conn.Close() is still called so non-tunnel
// net.Conn implementations behave normally.
func (e *endpoint) Close() {
	e.closeMu.Lock()
	already := e.closed
	e.closed = true
	cb := e.onClose
	e.closeMu.Unlock()
	if already {
		return
	}
	if d, ok := e.conn.(interface {
		SetReadDeadline(time.Time) error
	}); ok {
		// Unix(1, 0) is in the past — already-blocked Read wakes immediately
		// and any subsequent Read returns ErrDeadlineExceeded without a
		// syscall. Avoid time.Time{} (zero) because that clears the deadline.
		_ = d.SetReadDeadline(time.Unix(1, 0))
	}
	_ = e.conn.Close()
	if cb != nil {
		cb()
	}
}

func (e *endpoint) SetOnCloseAction(f func()) {
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	e.onClose = f
}

// readLoop reads IP packets from the tunnel and delivers them upward.
//
// The read buffer is sized for the maximum IP packet plus jumbo-frame
// slack. Using a fixed maxBufSize (rather than e.MTU()+64 at startup)
// avoids silent truncation if SetMTU bumps the MTU at runtime: net.Conn
// for a packet-oriented tunnel doesn't signal truncation.
const maxIPPacketLen = 65535 + 64

func (e *endpoint) readLoop() {
	defer close(e.done)
	buf := make([]byte, maxIPPacketLen)
	for {
		n, err := e.conn.Read(buf)
		if err != nil {
			// Any error on a closed endpoint terminates the loop.
			e.closeMu.Lock()
			closed := e.closed
			e.closeMu.Unlock()
			if closed {
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) ||
				errors.Is(err, net.ErrClosed) {
				return
			}
			// On a transient error the conn is still alive — loop again.
			// On a permanent error we'll see EOF on the next read.
			continue
		}
		if n < 1 {
			continue
		}

		// IP version is in the first nibble of the first byte.
		var proto tcpip.NetworkProtocolNumber
		switch buf[0] >> 4 {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			continue
		}

		e.mu.RLock()
		d := e.dispatcher
		e.mu.RUnlock()
		if d == nil {
			return
		}

		// gVisor takes ownership of the PacketBuffer's payload, so we hand
		// over a freshly-allocated copy of the slice we just read.
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), buf[:n]...)),
		})
		d.DeliverNetworkPacket(proto, pkt)
		pkt.DecRef()
	}
}

// WritePackets serialises each PacketBuffer to a single IP datagram and
// writes it to the underlying tunnel Conn.
func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	var wrote int
	for _, pkt := range pkts.AsSlice() {
		v := pkt.ToView()
		data := v.AsSlice()
		_, err := e.conn.Write(data)
		v.Release()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
				return wrote, &tcpip.ErrClosedForSend{}
			}
			return wrote, &tcpip.ErrAborted{}
		}
		wrote++
	}
	return wrote, nil
}

// Net is a thin facade over *stack.Stack that exposes net-like helpers
// (DialContext / Listen / etc.) wired up to gVisor's gonet adapters.
//
// The NIC's IPv4/IPv6 addresses and route table are *not* fixed at
// construction time: when the underlying openvpn.Client reconnects (and the
// server hands out a fresh tunnel IP / gateway / routes), `Net` reapplies
// the new PushReply automatically via an openvpn.Client OnReconnect hook
// registered in `New`. Without this, packets sent from gVisor after a
// reconnect would carry the old source IP and the server would silently
// drop them.
type Net struct {
	stack *stack.Stack
	ep    *endpoint
	log   *slog.Logger

	// nicMu protects the fields below — they're rewritten on every
	// reconnect when applyPushReply runs.
	nicMu   sync.Mutex
	localV4 netip.Addr
	localV6 netip.Addr
	hasV4   bool
	hasV6   bool

	closeMu sync.Mutex
	closed  bool
	cli     *openvpn.Client
}

// New builds a userspace TCP/IP stack on top of an openvpn.Client. The Client
// must already be Dialed. The returned *Net manages a single NIC with the
// IPv4 address from PUSH_REPLY and a default route through the pushed gateway
// (or the on-link tunnel network if no gateway is pushed).
//
// Closing the Net releases the stack but does NOT close the underlying
// openvpn.Client — the caller owns the Client lifecycle. (Use CloseAll if you
// want both torn down at once.)
func New(cli *openvpn.Client) (*Net, error) {
	if cli == nil {
		return nil, errors.New("netstack: nil openvpn client")
	}

	pr := cli.PushedOptions()
	mtu := cli.TunnelMTU()
	if mtu <= 0 {
		mtu = 1500
	}

	ep := newEndpoint(cli.Tunnel(), uint32(mtu))

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: false,
	})

	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("CreateNIC: %s", err)
	}
	// We are NAT/SNAT for ourselves — the OpenVPN endpoint already strips
	// link layer.  Spoofing & promiscuous keep the address-check liberal so
	// pushed-server-side replies reach us regardless of exact source.
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("SetSpoofing: %s", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("SetPromiscuousMode: %s", err)
	}

	n := &Net{stack: s, ep: ep, cli: cli, log: cli.Logger()}

	if err := n.applyPushReply(pr); err != nil {
		return nil, err
	}

	// Track future reconnects: every successful AutoReconnect-driven session
	// replacement hands us a fresh tunnel IP / gateway. Without re-syncing
	// the NIC, post-reconnect packets carry the OLD source IP and the
	// server silently drops them.
	cli.OnReconnect(func(pr openvpn.PushReply) {
		if err := n.applyPushReply(pr); err != nil && n.log != nil {
			n.log.Error("netstack applyPushReply failed on reconnect", "err", err)
		}
		if pr.MTU > 0 {
			n.ep.SetMTU(uint32(pr.MTU))
		}
	})

	return n, nil
}

// applyPushReply (re)installs the NIC's IPv4/IPv6 protocol addresses and
// route table from the supplied PushReply. Designed to be idempotent and
// safe to call from a reconnect hook: it adds the new address first, then
// removes the prior one (if different), so there's no window where the NIC
// has no address.
//
// Existing TCP/UDP gVisor connections that were bound to the OLD address
// continue to exist but their outbound packets carry the old source IP and
// will be dropped by the OpenVPN server in the new session — that's
// expected behaviour; client apps retry and the new conns bind to the
// fresh local IP.
func (n *Net) applyPushReply(pr openvpn.PushReply) error {
	n.nicMu.Lock()
	defer n.nicMu.Unlock()

	oldV4, oldHasV4 := n.localV4, n.hasV4
	oldV6, oldHasV6 := n.localV6, n.hasV6

	if pr.LocalIP.IsValid() && pr.LocalIP.Is4() && (!oldHasV4 || oldV4 != pr.LocalIP) {
		ip := pr.LocalIP.As4()
		addrProto := tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom4(ip),
				PrefixLen: maskPrefixLen(pr.Netmask),
			},
		}
		if err := n.stack.AddProtocolAddress(nicID, addrProto, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("AddProtocolAddress v4: %s", err)
		}
		n.localV4 = pr.LocalIP
		n.hasV4 = true
	}
	// IPv6 NIC address comes from "ifconfig-ipv6 <local>/<plen> <peer>" and
	// is parsed into pr.LocalIP6 (a Prefix). The peer address is RemoteIP6
	// and serves as the default v6 gateway, mirroring how "route-gateway"
	// supplies the IPv4 default.
	if v6 := pr.LocalIP6; v6.IsValid() && v6.Addr().Is6() && (!oldHasV6 || oldV6 != v6.Addr()) {
		ip := v6.Addr().As16()
		prefixLen := v6.Bits()
		if prefixLen < 0 || prefixLen > 128 {
			prefixLen = 128
		}
		addrProto := tcpip.ProtocolAddress{
			Protocol: ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom16(ip),
				PrefixLen: prefixLen,
			},
		}
		if err := n.stack.AddProtocolAddress(nicID, addrProto, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("AddProtocolAddress v6: %s", err)
		}
		n.localV6 = v6.Addr()
		n.hasV6 = true
	}

	// Reinstall the route table verbatim — SetRouteTable replaces (not
	// merges), so any old default-via-gateway entries get cleaned up
	// automatically.
	n.stack.SetRouteTable(buildRoutes(pr))

	// Drop the stale address last so there's no instant where the NIC has
	// no IPv4/IPv6 configured.
	if oldHasV4 && oldV4 != n.localV4 {
		_ = n.stack.RemoveAddress(nicID, tcpip.AddrFrom4(oldV4.As4()))
	}
	if oldHasV6 && oldV6 != n.localV6 {
		_ = n.stack.RemoveAddress(nicID, tcpip.AddrFrom16(oldV6.As16()))
	}

	return nil
}

// buildRoutes converts a PushReply's gateway+routes into a gVisor route
// table. Same logic the initial setup used; factored out so applyPushReply
// can reuse it on reconnect.
func buildRoutes(pr openvpn.PushReply) []tcpip.Route {
	var routes []tcpip.Route
	if pr.Gateway.IsValid() && pr.Gateway.Is4() {
		gw := pr.Gateway.As4()
		routes = append(routes, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			Gateway:     tcpip.AddrFrom4(gw),
			NIC:         nicID,
		})
	}
	// IPv6 has no dedicated "route-gateway" directive; the standard OpenVPN
	// behaviour is to use the peer address from "ifconfig-ipv6" as the v6
	// default next-hop unless the server pushes an explicit "route-ipv6 ::/0".
	// gVisor's destination-match is first-hit, so synthesising the default
	// here is safe even when Routes6 also contains ::/0.
	if pr.RemoteIP6.IsValid() && pr.RemoteIP6.Is6() {
		gw := pr.RemoteIP6.As16()
		routes = append(routes, tcpip.Route{
			Destination: header.IPv6EmptySubnet,
			Gateway:     tcpip.AddrFrom16(gw),
			NIC:         nicID,
		})
	}
	for _, p := range pr.Routes {
		if !p.Addr().IsValid() {
			continue
		}
		net, err := tcpipSubnetFromPrefix(p)
		if err != nil {
			continue
		}
		routes = append(routes, tcpip.Route{Destination: net, NIC: nicID})
	}
	for _, p := range pr.Routes6 {
		if !p.Addr().IsValid() {
			continue
		}
		net, err := tcpipSubnetFromPrefix(p)
		if err != nil {
			continue
		}
		routes = append(routes, tcpip.Route{Destination: net, NIC: nicID})
	}
	if len(routes) == 0 {
		// On-link route over the NIC so the stack knows traffic should head
		// out via the endpoint even with no gateway pushed.
		routes = append(routes, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		})
	}
	return routes
}

// Stack returns the underlying *stack.Stack so callers can register their own
// listeners, packet endpoints, sockopts, etc.
func (n *Net) Stack() *stack.Stack { return n.stack }

// LocalIP returns the IPv4 address assigned to the tunnel (from PUSH_REPLY).
func (n *Net) LocalIP() netip.Addr {
	n.nicMu.Lock()
	defer n.nicMu.Unlock()
	return n.localV4
}

// LocalIP6 returns the IPv6 address assigned to the tunnel (from PUSH_REPLY's
// "ifconfig-ipv6" directive). Returns a zero value when the server did not
// push an IPv6 address.
func (n *Net) LocalIP6() netip.Addr {
	n.nicMu.Lock()
	defer n.nicMu.Unlock()
	return n.localV6
}

// HasIPv4 reports whether the NIC has an IPv4 address from the latest
// PUSH_REPLY. Callers use this to skip v4 dials when no v4 is configured.
func (n *Net) HasIPv4() bool {
	n.nicMu.Lock()
	defer n.nicMu.Unlock()
	return n.hasV4
}

// HasIPv6 reports whether the NIC has an IPv6 address from the latest
// PUSH_REPLY. Callers use this to fail fast on v6 dials when the server
// did not push an IPv6 address — gVisor would otherwise spend a route
// lookup and return ErrHostUnreachable, which is slower and noisier.
func (n *Net) HasIPv6() bool {
	n.nicMu.Lock()
	defer n.nicMu.Unlock()
	return n.hasV6
}

// Close tears down the netstack but leaves the underlying openvpn.Client
// running. The tunnel Conn it was using is closed (so further Read/Write on
// it will fail), but Client.Close() is still the caller's responsibility.
func (n *Net) Close() error {
	n.closeMu.Lock()
	defer n.closeMu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	n.stack.Close()
	n.ep.Close()
	return nil
}

// CloseAll tears down BOTH the netstack and the openvpn.Client.
func (n *Net) CloseAll() error {
	err1 := n.Close()
	err2 := n.cli.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// DialContext is suitable as a Transport.DialContext callback or net.Resolver
// Dial hook. Supports "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6". The host
// in addr must be a literal IP — the netstack package does no DNS resolution.
func (n *Net) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("netstack: bad port %q: %w", portStr, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// We deliberately do NOT do DNS resolution here — callers that need
		// it should resolve via their own resolver and call DialContext
		// with a literal IP.
		return nil, fmt.Errorf("netstack: DialContext requires literal IP, got %q", host)
	}

	var (
		proto tcpip.NetworkProtocolNumber
		full  tcpip.FullAddress
	)
	switch {
	case ip.Is4():
		proto = ipv4.ProtocolNumber
		full = tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(ip.As4()), Port: uint16(port64)}
	case ip.Is6():
		proto = ipv6.ProtocolNumber
		full = tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom16(ip.As16()), Port: uint16(port64)}
	default:
		return nil, fmt.Errorf("netstack: unsupported address %q", host)
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		return gonet.DialContextTCP(ctx, n.stack, full, proto)
	case "udp", "udp4", "udp6":
		// gonet.DialUDP has no Context variant; it returns immediately because
		// UDP is connectionless. We honor ctx best-effort by checking it first.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Pass an explicit local address for UDP. Without this gVisor picks
		// from the NIC's address list via route lookup; passing laddr makes
		// the bind track reconnect-driven IP changes 1:1.
		return gonet.DialUDP(n.stack, n.currentLocalFullAddress(ip.Is4()), &full, proto)
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("netstack: unsupported network")}
	}
}

// currentLocalFullAddress returns a FullAddress suitable as `laddr` for a
// gonet Dial, snapshotting the NIC's current IPv4 or IPv6 address under the
// nicMu lock. Returns nil if no address of the requested family is
// installed — gonet treats nil laddr as "auto-pick", matching the prior
// behaviour for that edge case.
func (n *Net) currentLocalFullAddress(v4 bool) *tcpip.FullAddress {
	n.nicMu.Lock()
	defer n.nicMu.Unlock()
	if v4 {
		if !n.hasV4 {
			return nil
		}
		a := n.localV4.As4()
		return &tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(a)}
	}
	if !n.hasV6 {
		return nil
	}
	a := n.localV6.As16()
	return &tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom16(a)}
}

// maskPrefixLen converts a 4-byte IPv4 netmask address into a prefix length
// by counting LEADING ones (a contiguous mask is required by RFC 4632).
// Rejects non-contiguous masks by returning /32.
func maskPrefixLen(a netip.Addr) int {
	if !a.IsValid() || !a.Is4() {
		return 32
	}
	b := a.As4()
	prefix := 0
	seenZero := false
	for _, x := range b {
		for bit := 7; bit >= 0; bit-- {
			if x&(1<<bit) != 0 {
				if seenZero {
					return 32
				}
				prefix++
			} else {
				seenZero = true
			}
		}
	}
	return prefix
}

// tcpipSubnetFromPrefix converts a netip.Prefix into a tcpip.Subnet.
func tcpipSubnetFromPrefix(p netip.Prefix) (tcpip.Subnet, error) {
	addr := p.Addr()
	bits := p.Bits()
	switch {
	case addr.Is4():
		full := addr.As4()
		mask := net.CIDRMask(bits, 32)
		var masked [4]byte
		for i := range masked {
			masked[i] = full[i] & mask[i]
		}
		return tcpip.NewSubnet(tcpip.AddrFrom4(masked), tcpip.MaskFromBytes(mask))
	case addr.Is6():
		full := addr.As16()
		mask := net.CIDRMask(bits, 128)
		var masked [16]byte
		for i := range masked {
			masked[i] = full[i] & mask[i]
		}
		return tcpip.NewSubnet(tcpip.AddrFrom16(masked), tcpip.MaskFromBytes(mask))
	}
	return tcpip.Subnet{}, fmt.Errorf("netstack: unsupported address family in prefix %s", p)
}
