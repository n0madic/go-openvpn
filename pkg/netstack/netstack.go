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

// safeInnerMTU caps the gVisor NIC's MTU so that, after OpenVPN
// encryption + UDP/IP outer headers, the resulting wire datagram
// fits within the lowest common path MTU we'll realistically see.
//
// Budget per wire datagram (worst case):
//
//	outer IPv4 header (20) + UDP header (8) +
//	OpenVPN encap (1 opcode + 3 peer-id + 4 pkt-id + 16 AEAD tag = 24)
//	= 52 bytes of overhead
//
// 1400 inner IP → 1452 outer wire. That fits 1500-MTU ethernet,
// 1492-MTU PPPoE, 1480-MTU VPN-in-VPN, and several other common
// "almost-1500" paths with margin. Setting the NIC MTU here is
// architecturally equivalent to the official OpenVPN client's
// runtime MSS clamping (`mssfix=1492` rewriting TCP SYN options on
// every packet, src/openvpn/mss.c): gVisor *is* the OS for apps
// inside the tunnel, so configuring its NIC MTU directly is
// sufficient — TCP MSS auto-negotiates to NIC_MTU - 40 = 1360 on
// every SYN gVisor generates, and apps respect it. Without this,
// a default 1500 inner MTU produces ~1552-byte outer datagrams
// that fragment or silently drop on any path with a strict
// 1500-byte MTU, which manifests as "tunnel works for a while
// then degrades under sustained TCP load".
const safeInnerMTU = 1400

// clampInnerMTU returns the smaller of `pushed` and safeInnerMTU,
// floored sensibly. Used both at New time and on every reconnect
// so a server pushing a different MTU still gets clamped.
func clampInnerMTU(pushed uint32) uint32 {
	if pushed == 0 || pushed > safeInnerMTU {
		return safeInnerMTU
	}
	return pushed
}

// endpoint is a stack.LinkEndpoint backed by a tunnel net.Conn that carries
// raw IP datagrams (one Read = one IP packet, one Write = one IP packet).
type endpoint struct {
	conn    net.Conn
	mtu     atomic.Uint32
	closeMu sync.Mutex
	closed  bool
	done    chan struct{}
	doneCh  sync.Once // closes done at most once (readLoop OR Close)

	// directDelivery, when true, signals Attach to skip starting the
	// reader goroutine: inbound IP packets are delivered via
	// deliverInbound from the openvpn session's read loop, not by
	// pulling them from e.conn here. Avoids one goroutine handoff and
	// one defensive memcpy per inbound packet.
	directDelivery bool

	mu         sync.RWMutex
	dispatcher stack.NetworkDispatcher
	linkAddr   tcpip.LinkAddress

	onClose func()

	// Diagnostic counters. Independent from session.statsOutboundOK
	// (which counts every WritePacket on the underlying transport,
	// including PINGs and other non-gVisor traffic). These count only
	// IP packets that traverse the gVisor LinkEndpoint, so a divergence
	// between (statsOutPackets here) and (statsOutboundOK in session)
	// localises whether a stuck data path is above or below this layer.
	statsOutPackets atomic.Uint64 // IP packets gVisor pushed to tunnel
	statsOutErrors  atomic.Uint64 // conn.Write failures
	statsInPackets  atomic.Uint64 // IP packets delivered up to gVisor
	statsInUnknown  atomic.Uint64 // bad IP version, dropped

	// Per-L4-protocol counters for the inbound stream. Sniff the IP
	// header at the LinkEndpoint level (before gVisor sees the packet),
	// so we can compare "did UDP responses physically arrive from the
	// tunnel" (statsInUDP) against "did gVisor's UDP layer process them"
	// (UDP.PacketsReceived). A growing statsInUDP with flat UDP.PacketsReceived
	// pinpoints gVisor's IP-or-UDP demux as the loss point; a flat
	// statsInUDP rules our code out and indicts the network/server.
	statsInTCP   atomic.Uint64
	statsInUDP   atomic.Uint64
	statsInICMP  atomic.Uint64
	statsInOther atomic.Uint64
}

// Compile-time guard.
var _ stack.LinkEndpoint = (*endpoint)(nil)

// newEndpoint wraps the given conn into a LinkEndpoint with the given MTU.
// When directDelivery is true the endpoint does NOT spawn a reader
// goroutine in Attach; inbound packets arrive via deliverInbound.
func newEndpoint(conn net.Conn, mtu uint32, directDelivery bool) *endpoint {
	e := &endpoint{
		conn:           conn,
		done:           make(chan struct{}),
		directDelivery: directDelivery,
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

// Attach wires the dispatcher and (unless directDelivery is set) starts
// the reader goroutine that pumps inbound IP packets up the stack.
// Called once by stack.Stack.CreateNIC.
//
// In directDelivery mode the readLoop is skipped: inbound packets reach
// the dispatcher via deliverInbound called from the openvpn session's
// own read loop. The endpoint still uses conn for outbound (WritePackets).
func (e *endpoint) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = d
	e.mu.Unlock()
	if d != nil && !e.directDelivery {
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
	// In directDelivery mode readLoop never runs, so nothing else closes
	// e.done — drive it from Close. sync.Once makes the double-close from
	// the legacy path (readLoop's `defer close(e.done)` + an explicit
	// Close()) harmless. Wait() therefore returns the moment Close ran.
	if e.directDelivery {
		e.doneCh.Do(func() { close(e.done) })
	}
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
	defer e.doneCh.Do(func() { close(e.done) })
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
		if e.dispatchInbound(buf[:n]) {
			// dispatcher missing — Attach hasn't wired one or the NIC
			// was removed. Without a sink there's nothing to do, so
			// terminate the loop cleanly.
			return
		}
	}
}

// deliverInbound is the fast-path entry for direct delivery from the
// openvpn session's read loop. ip is the plaintext IP datagram returned
// by the AEAD decrypt; the caller is free to reuse the backing memory
// once this returns (buffer.MakeWithData copies, see comments below).
//
// Stats counters and L4 bucketing mirror readLoop's behaviour so the
// monitoring view is identical regardless of which path delivers a
// given packet.
func (e *endpoint) deliverInbound(ip []byte) {
	// dispatcher-missing is treated as a per-packet drop here — the
	// session keeps calling deliverInbound on subsequent packets, and a
	// late Attach (unlikely under direct delivery, but possible during
	// startup) will resume normal flow without restarting anything.
	_ = e.dispatchInbound(ip)
}

// dispatchInbound is the shared body used by both readLoop (legacy
// channel-then-Tunnel.Read path, used by tests and any pre-Net.New
// consumer) and deliverInbound (direct fast path, used by netstack.Net).
//
// Returns dispatcherMissing=true when no dispatcher is attached; the
// readLoop interprets that as a terminal "no sink" signal, while
// deliverInbound just drops the packet and moves on.
func (e *endpoint) dispatchInbound(ip []byte) (dispatcherMissing bool) {
	n := len(ip)
	if n < 1 {
		return false
	}
	// IP version is in the first nibble of the first byte.
	var proto tcpip.NetworkProtocolNumber
	var l4 uint8 // 0 == unknown/skip-bucketing
	switch ip[0] >> 4 {
	case 4:
		proto = header.IPv4ProtocolNumber
		// IPv4 protocol field is byte 9. Minimum IHL=5 (20 bytes).
		if n >= 20 {
			l4 = ip[9]
		}
	case 6:
		proto = header.IPv6ProtocolNumber
		// IPv6 NextHeader is byte 6. Strictly, NH may be a chain of
		// extension headers (HBH/Routing/Fragment); we don't walk
		// them here. Mis-bucketing a fragmented or extension-laden
		// packet as "other" is harmless for this diagnostic — we're
		// only counting frequency, not correctness.
		if n >= 40 {
			l4 = ip[6]
		}
	default:
		e.statsInUnknown.Add(1)
		return false
	}
	switch l4 {
	case 6: // TCP
		e.statsInTCP.Add(1)
	case 17: // UDP
		e.statsInUDP.Add(1)
	case 1, 58: // ICMP, ICMPv6
		e.statsInICMP.Add(1)
	default:
		e.statsInOther.Add(1)
	}

	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d == nil {
		return true
	}
	// buffer.MakeWithData copies (verified in gVisor view.go:
	// NewViewWithData → newChunk(len(data)) + v.Write(data) → copy(...)).
	// The input slice is NOT retained, so it's safe to pass ip directly —
	// no defensive `append([]byte(nil), ip...)` needed even when the
	// caller (readLoop or session.handleDataIn) reuses the backing array.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(ip),
	})
	d.DeliverNetworkPacket(proto, pkt)
	pkt.DecRef()
	e.statsInPackets.Add(1)
	return false
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
			e.statsOutErrors.Add(1)
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
				return wrote, &tcpip.ErrClosedForSend{}
			}
			return wrote, &tcpip.ErrAborted{}
		}
		e.statsOutPackets.Add(1)
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

	// statsStop closes when the periodic stats logger should exit.
	// Started in New, drained in Close.
	statsStop chan struct{}

	// activeConns tracks every net.Conn handed out by DialContext so
	// they can be force-closed when the tunnel IP changes (see
	// closeActiveOnReconnect). Without this, gVisor TCP endpoints
	// bound to the OLD tunnel IP keep retransmitting with a
	// now-invalid src IP — the server drops those packets and
	// gVisor's TCP retransmit takes 60-120s to give up. Force-
	// closing matches what an OS kernel does via RTM_CHANGE when
	// a utun interface's address changes: apps see an immediate
	// ECONNRESET and retry on the new local IP. Keys are
	// *trackedConn (which embeds net.Conn). Map operations are
	// safe for concurrent use.
	activeConns sync.Map
}

// trackedConn wraps a net.Conn returned by Net.DialContext so the
// Net can force-close it on reconnect. The original conn is exposed
// via embedding for everything except Close (which deregisters from
// the tracker) and CloseWrite/CloseRead (which forward to the
// underlying conn if it supports them — gVisor's *TCPConn does,
// *UDPConn does not, and existing SOCKS5 callers depend on the
// type assertion `interface{ CloseWrite() error }` working when
// the underlying is TCP).
type trackedConn struct {
	net.Conn
	n      *Net
	closed atomic.Bool
}

// Close removes the conn from the active-conns tracker and closes
// the underlying conn. Idempotent. Safe to call from any goroutine.
func (t *trackedConn) Close() error {
	err := t.Conn.Close()
	if t.closed.CompareAndSwap(false, true) {
		t.n.activeConns.Delete(t)
	}
	return err
}

// CloseWrite forwards to the underlying conn if it supports half-
// close (gVisor's *TCPConn does). For conns that don't (UDP), it's
// a no-op returning nil — the type assertion succeeds but does
// nothing meaningful, which matches the "do half-close if possible,
// else nothing" pattern callers expect.
func (t *trackedConn) CloseWrite() error {
	if cw, ok := t.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// CloseRead is symmetric to CloseWrite.
func (t *trackedConn) CloseRead() error {
	if cr, ok := t.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// trackConn wraps a fresh conn from gonet into a trackedConn and
// registers it in activeConns. The returned conn is always safe to
// Close even if called multiple times.
func (n *Net) trackConn(c net.Conn) net.Conn {
	if c == nil {
		return nil
	}
	tc := &trackedConn{Conn: c, n: n}
	n.activeConns.Store(tc, struct{}{})
	return tc
}

// closeActiveOnReconnect force-closes every active conn handed out
// by DialContext. Called from the OnReconnect hook AFTER the new
// PUSH_REPLY's addresses have been installed on the NIC, so any
// retry by the app's higher-level code immediately binds to the
// fresh local IP. Returns the number of conns closed (for logging).
func (n *Net) closeActiveOnReconnect() int {
	closed := 0
	n.activeConns.Range(func(k, _ any) bool {
		if tc, ok := k.(*trackedConn); ok {
			_ = tc.Close()
			closed++
		}
		return true
	})
	return closed
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
	rawMTU := cli.TunnelMTU()
	if rawMTU <= 0 {
		rawMTU = 1500
	}
	mtu := clampInnerMTU(uint32(rawMTU))

	ep := newEndpoint(cli.Tunnel(), mtu, true /* directDelivery */)

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

	n := &Net{stack: s, ep: ep, cli: cli, log: cli.Logger(), statsStop: make(chan struct{})}

	if err := n.applyPushReply(pr); err != nil {
		return nil, err
	}

	// Wire the fast-path: every decrypted inbound IP packet from the
	// session lands here synchronously on the session's read loop,
	// skipping ingressCh + Tunnel.Read + endpoint.readLoop. Net.Close
	// will detach via SetIngressHandler(nil) — that call drains any
	// in-flight handler invocations before returning, so the subsequent
	// stack.Close() is race-free.
	cli.SetIngressHandler(ep.deliverInbound)

	// Track future reconnects: every successful AutoReconnect-driven session
	// replacement hands us a fresh tunnel IP / gateway. Without re-syncing
	// the NIC, post-reconnect packets carry the OLD source IP and the
	// server silently drops them.
	cli.OnReconnect(func(pr openvpn.PushReply) {
		// Snapshot the pre-reconnect local addresses so we can decide
		// whether existing conns are still valid (same tunnel IP) or
		// have become zombies (new tunnel IP). The server hands us
		// back the same IP often enough — observed in production when
		// the edge keeps session state cached — that doing a blind
		// force-close on every reconnect would needlessly disrupt
		// app conns that would otherwise have kept working.
		n.nicMu.Lock()
		oldV4, oldV6 := n.localV4, n.localV6
		n.nicMu.Unlock()

		if err := n.applyPushReply(pr); err != nil && n.log != nil {
			n.log.Error("netstack applyPushReply failed on reconnect", "err", err)
		}
		if pr.MTU > 0 {
			n.ep.SetMTU(clampInnerMTU(uint32(pr.MTU)))
		}

		n.nicMu.Lock()
		newV4, newV6 := n.localV4, n.localV6
		n.nicMu.Unlock()

		ipChanged := oldV4 != newV4 || oldV6 != newV6
		if !ipChanged {
			// Same tunnel IP across reconnect → existing gVisor TCP
			// 4-tuples remain valid (server's NAT/conntrack routes
			// by IP, not by OpenVPN peer-id), so active conns are
			// NOT zombies and we leave them alone. Apps see a brief
			// blip during the protocol handshake, then traffic
			// resumes on the same conns.
			if n.log != nil {
				n.log.Info("netstack: reconnect kept same tunnel IP, leaving active conns intact",
					"local_v4", newV4, "local_v6", newV6)
			}
			return
		}
		// Tunnel IP changed → existing conns are bound to the OLD
		// local IP, their packets now carry an IP the server no
		// longer routes for our session. Force-close them so apps
		// see ECONNRESET immediately and retry on the new local IP,
		// instead of waiting 60-120s for gVisor's TCP retransmit to
		// give up. Architectural equivalent of the OS kernel's
		// RTM_CHANGE on utun when the interface address changes.
		if closed := n.closeActiveOnReconnect(); closed > 0 && n.log != nil {
			n.log.Info("netstack: force-closed conns bound to old tunnel IP after reconnect",
				"count", closed,
				"old_v4", oldV4, "new_v4", newV4,
				"old_v6", oldV6, "new_v6", newV6,
			)
		}
	})

	// Start the periodic stats logger so operators can see whether
	// stuck data flows correspond to a problem in gVisor (e.g. growing
	// retransmits / send errors / endpoint leak) or below it. Pure
	// observability — does not take action on anything.
	go n.statsLoggerLoop()

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
	// Detach the fast-path BEFORE tearing down the stack. The session's
	// SetIngressHandler is RWMutex-guarded: this call blocks until every
	// in-flight ep.deliverInbound returns, so stack.Close runs on a
	// quiescent gVisor stack with no risk of a straggler
	// DeliverNetworkPacket racing the teardown.
	if n.cli != nil {
		n.cli.SetIngressHandler(nil)
	}
	close(n.statsStop)
	n.stack.Close()
	n.ep.Close()
	return nil
}

// statsLogPeriod is how often statsLoggerLoop emits a snapshot. Matched
// to the session's stats period so the two logs interleave on the same
// cadence and operators can correlate them.
const statsLogPeriod = 30 * time.Second

// statsLoggerLoop periodically logs a structured snapshot of the
// LinkEndpoint counters and key gVisor stack.Stats() fields. Designed
// to localise stuck data paths:
//
//   - Endpoint outPackets delta ≈ 0 while session outbound_ok is growing
//     → the stuck traffic is non-gVisor (e.g. keepalive only); apps
//     stopped sending through the netstack.
//   - Endpoint outPackets delta growing AND tcp_retransmits delta growing
//     → packets enter the tunnel from gVisor but aren't being acked;
//     either the wire is dropping them or the server's data path is sick.
//   - tcp_segment_send_errors > 0 → gVisor's own send path is failing;
//     usually means our WritePackets returned an error.
//   - udp_send_errors growing → ditto for UDP (DNS queries via gonet).
//   - tcp_current_established climbing without bound → endpoint leak;
//     our SOCKS5 layer isn't releasing TCP endpoints after Close.
//   - ip_packets_received delta vs endpoint inPackets delta: if endpoint
//     in is growing but IP received isn't, gVisor's IP layer is rejecting
//     the inbound (look at ip_malformed for confirmation).
func (n *Net) statsLoggerLoop() {
	t := time.NewTicker(statsLogPeriod)
	defer t.Stop()

	var (
		prevOutPkts, prevOutErr, prevInPkts uint64
		prevInTCP, prevInUDP, prevInICMP    uint64
		prevTCPSent, prevTCPSendErr         uint64
		prevTCPRetrans, prevTCPResetsRcvd   uint64
		prevTCPFailedOpens                  uint64
		prevUDPSent, prevUDPSendErr         uint64
		prevUDPRcvd, prevUDPUnknownPort     uint64
		prevIPSent, prevIPRcvd              uint64
		prevIPMalformed                     uint64
		prevDropped                         uint64
	)

	snap := func() (
		outPkts, outErr, inPkts, inTCP, inUDP, inICMP uint64,
		tcpSent, tcpSendErr, tcpRetrans, tcpResetsRcvd, tcpFailedOpens, tcpCurEst uint64,
		udpSent, udpSendErr, udpRcvd, udpUnknownPort uint64,
		ipSent, ipRcvd, ipMalformed uint64,
		dropped uint64,
	) {
		outPkts = n.ep.statsOutPackets.Load()
		outErr = n.ep.statsOutErrors.Load()
		inPkts = n.ep.statsInPackets.Load()
		inTCP = n.ep.statsInTCP.Load()
		inUDP = n.ep.statsInUDP.Load()
		inICMP = n.ep.statsInICMP.Load()
		st := n.stack.Stats()
		tcpSent = st.TCP.SegmentsSent.Value()
		tcpSendErr = st.TCP.SegmentSendErrors.Value()
		tcpRetrans = st.TCP.Retransmits.Value()
		tcpResetsRcvd = st.TCP.ResetsReceived.Value()
		tcpFailedOpens = st.TCP.FailedConnectionAttempts.Value()
		tcpCurEst = st.TCP.CurrentEstablished.Value()
		udpSent = st.UDP.PacketsSent.Value()
		udpSendErr = st.UDP.PacketSendErrors.Value()
		udpRcvd = st.UDP.PacketsReceived.Value()
		udpUnknownPort = st.UDP.UnknownPortErrors.Value()
		ipSent = st.IP.PacketsSent.Value()
		ipRcvd = st.IP.PacketsReceived.Value()
		ipMalformed = st.IP.MalformedPacketsReceived.Value()
		dropped = st.DroppedPackets.Value()
		return
	}

	for {
		select {
		case <-n.statsStop:
			return
		case <-t.C:
		}

		outPkts, outErr, inPkts, inTCP, inUDP, inICMP,
			tcpSent, tcpSendErr, tcpRetrans, tcpResetsRcvd, tcpFailedOpens, tcpCurEst,
			udpSent, udpSendErr, udpRcvd, udpUnknownPort,
			ipSent, ipRcvd, ipMalformed,
			dropped := snap()

		dOutPkts := outPkts - prevOutPkts
		dOutErr := outErr - prevOutErr
		dInPkts := inPkts - prevInPkts
		dInTCP := inTCP - prevInTCP
		dInUDP := inUDP - prevInUDP
		dInICMP := inICMP - prevInICMP
		dTCPSent := tcpSent - prevTCPSent
		dTCPSendErr := tcpSendErr - prevTCPSendErr
		dTCPRetrans := tcpRetrans - prevTCPRetrans
		dTCPResetsRcvd := tcpResetsRcvd - prevTCPResetsRcvd
		dTCPFailedOpens := tcpFailedOpens - prevTCPFailedOpens
		dUDPSent := udpSent - prevUDPSent
		dUDPSendErr := udpSendErr - prevUDPSendErr
		dUDPRcvd := udpRcvd - prevUDPRcvd
		dUDPUnknownPort := udpUnknownPort - prevUDPUnknownPort
		dIPSent := ipSent - prevIPSent
		dIPRcvd := ipRcvd - prevIPRcvd
		dIPMalformed := ipMalformed - prevIPMalformed
		dDropped := dropped - prevDropped

		prevOutPkts = outPkts
		prevOutErr = outErr
		prevInPkts = inPkts
		prevInTCP = inTCP
		prevInUDP = inUDP
		prevInICMP = inICMP
		prevTCPSent = tcpSent
		prevTCPSendErr = tcpSendErr
		prevTCPRetrans = tcpRetrans
		prevTCPResetsRcvd = tcpResetsRcvd
		prevTCPFailedOpens = tcpFailedOpens
		prevUDPSent = udpSent
		prevUDPSendErr = udpSendErr
		prevUDPRcvd = udpRcvd
		prevUDPUnknownPort = udpUnknownPort
		prevIPSent = ipSent
		prevIPRcvd = ipRcvd
		prevIPMalformed = ipMalformed
		prevDropped = dropped

		// Anything that looks like a real symptom escalates to WARN so
		// it surfaces without -v: outright errors, sustained
		// retransmits, malformed packets, generic dropped packets, or
		// UDP responses landing on closed endpoints.
		//
		// `delta_tcp_resets_rcvd` is intentionally NOT included even
		// though it's surfaced in the message body for diagnosis. A
		// busy browsing session naturally produces a steady trickle
		// of RSTs because Apple/Google/Telegram services close
		// short-lived TCP via RST rather than graceful FIN, so any
		// > 0 threshold makes the line WARN on a perfectly healthy
		// tunnel. Same reasoning that retired the RST-storm watchdog
		// trigger — the metric is noise as a binary signal.
		level := slog.LevelDebug
		if dOutErr > 0 || dTCPSendErr > 0 || dUDPSendErr > 0 ||
			dTCPRetrans > 5 ||
			dIPMalformed > 0 || dDropped > 0 || dUDPUnknownPort > 0 {
			level = slog.LevelWarn
		}

		if n.log != nil {
			n.log.Log(context.Background(), level, "netstack stats",
				"interval", statsLogPeriod,
				// LinkEndpoint counters (deltas + totals).
				"delta_ep_out", dOutPkts,
				"delta_ep_out_err", dOutErr,
				"delta_ep_in", dInPkts,
				"delta_ep_in_tcp", dInTCP,
				"delta_ep_in_udp", dInUDP,
				"delta_ep_in_icmp", dInICMP,
				"ep_out_total", outPkts,
				"ep_out_err_total", outErr,
				"ep_in_total", inPkts,
				"ep_in_udp_total", inUDP,
				// gVisor TCP.
				"delta_tcp_sent", dTCPSent,
				"delta_tcp_send_err", dTCPSendErr,
				"delta_tcp_retrans", dTCPRetrans,
				"delta_tcp_resets_rcvd", dTCPResetsRcvd,
				"delta_tcp_failed_opens", dTCPFailedOpens,
				"tcp_current_established", tcpCurEst,
				// gVisor UDP.
				"delta_udp_sent", dUDPSent,
				"delta_udp_send_err", dUDPSendErr,
				"delta_udp_rcvd", dUDPRcvd,
				"delta_udp_unknown_port", dUDPUnknownPort,
				// gVisor IP.
				"delta_ip_sent", dIPSent,
				"delta_ip_rcvd", dIPRcvd,
				"delta_ip_malformed", dIPMalformed,
				// Catch-all.
				"delta_dropped", dDropped,
			)
		}
	}
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
		c, err := gonet.DialContextTCP(ctx, n.stack, full, proto)
		if err != nil {
			return nil, err
		}
		return n.trackConn(c), nil
	case "udp", "udp4", "udp6":
		// gonet.DialUDP has no Context variant; it returns immediately because
		// UDP is connectionless. We honor ctx best-effort by checking it first.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Pass an explicit local address for UDP. Without this gVisor picks
		// from the NIC's address list via route lookup; passing laddr makes
		// the bind track reconnect-driven IP changes 1:1.
		c, err := gonet.DialUDP(n.stack, n.currentLocalFullAddress(ip.Is4()), &full, proto)
		if err != nil {
			return nil, err
		}
		return n.trackConn(c), nil
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
