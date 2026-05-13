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
type Net struct {
	stack   *stack.Stack
	ep      *endpoint
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

	n := &Net{stack: s, ep: ep, cli: cli}

	if pr.LocalIP.IsValid() && pr.LocalIP.Is4() {
		ip := pr.LocalIP.As4()
		addrProto := tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom4(ip),
				PrefixLen: maskPrefixLen(pr.Netmask),
			},
		}
		if err := s.AddProtocolAddress(nicID, addrProto, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("AddProtocolAddress v4: %s", err)
		}
		n.localV4 = pr.LocalIP
		n.hasV4 = true
	}
	if pr.LocalIP.IsValid() && pr.LocalIP.Is6() {
		ip := pr.LocalIP.As16()
		addrProto := tcpip.ProtocolAddress{
			Protocol: ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom16(ip),
				PrefixLen: 128,
			},
		}
		if err := s.AddProtocolAddress(nicID, addrProto, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("AddProtocolAddress v6: %s", err)
		}
		n.localV6 = pr.LocalIP
		n.hasV6 = true
	}

	// Routes — default route to the tunnel gateway, plus any extra
	// PUSH_REPLY-supplied prefixes.
	var routes []tcpip.Route
	if pr.Gateway.IsValid() && pr.Gateway.Is4() {
		gw := pr.Gateway.As4()
		routes = append(routes, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			Gateway:     tcpip.AddrFrom4(gw),
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
		// At minimum, an on-link route over the NIC so the stack knows
		// any traffic should head out via the endpoint.
		routes = append(routes, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		})
	}
	s.SetRouteTable(routes)

	return n, nil
}

// Stack returns the underlying *stack.Stack so callers can register their own
// listeners, packet endpoints, sockopts, etc.
func (n *Net) Stack() *stack.Stack { return n.stack }

// LocalIP returns the IPv4 address assigned to the tunnel (from PUSH_REPLY).
func (n *Net) LocalIP() netip.Addr { return n.localV4 }

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
		return gonet.DialUDP(n.stack, nil, &full, proto)
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("netstack: unsupported network")}
	}
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
