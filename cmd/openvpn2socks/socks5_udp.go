// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// handleAssociate implements SOCKS5 UDP ASSOCIATE (CMD=0x03).
//
// Flow:
//  1. Open a local UDP socket reachable from the control client.
//  2. Reply REP=0 with that socket's address as BND.ADDR/BND.PORT.
//  3. Pump:
//     client → udpConn → parse SOCKS5 UDP header → ns.DialContext("udp", target)
//     target → udpConn → wrap SOCKS5 UDP header → udpConn.WriteToUDP(client)
//  4. Tear down when the TCP control connection closes (per RFC 1928).
//
// Source validation: the UDP source IP must match the TCP control conn's
// remote IP. If the SOCKS5 request specified a non-zero DST.ADDR/DST.PORT
// (RFC 1928 §4 — "expected source"), we also require those to match.
// Once the client has sent its first datagram, the (IP, port) pair is
// locked in — subsequent packets from a different (IP, port) are dropped.
func (s *socks5Server) handleAssociate(ctx context.Context, ctrl net.Conn, _ *bufio.Reader, req *socksRequest) {
	// Choose a UDP bind address reachable by the client. If the TCP control
	// connection landed on a specific local IP (true even when listening on
	// 0.0.0.0 — Accept resolves to the actual destination IP), bind UDP on
	// that same IP so BND.ADDR is reachable.
	listenIP := udpBindIPForCtrl(ctrl, s.listen)
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", net.JoinHostPort(listenIP, "0"))
	if err != nil {
		s.log.Debug("UDP ASSOCIATE: bind failed", "err", err)
		_ = writeReply(ctrl, repGeneralFailure, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
		return
	}
	udpConn := pc.(*net.UDPConn)
	defer func() { _ = udpConn.Close() }()

	bnd := localAddrPortFromUDP(udpConn)
	if err := writeReply(ctrl, repSucceeded, bnd); err != nil {
		s.log.Debug("UDP ASSOCIATE: reply failed", "err", err)
		return
	}

	// Pre-authorised source IP comes from the TCP control conn. The client's
	// UDP source port is unknown until the first datagram arrives; we lock
	// the full (IP, port) pair on first valid datagram.
	expectedIP := tcpRemoteIP(ctrl)

	// RFC 1928 §4: if the ASSOCIATE request carried a non-zero DST.ADDR/PORT
	// the client is asserting its UDP source. Honour it by tightening the
	// (IP, port) lock to those exact values. Zero values mean "unknown".
	var expectedPort uint16
	if req != nil {
		if reqIP, ok := parseHostAsIP(req.host); ok && !reqIP.IsUnspecified() {
			expectedIP = reqIP
		}
		if req.port != 0 {
			expectedPort = req.port
		}
	}
	s.log.Debug("UDP ASSOCIATE", "client_ctrl", ctrl.RemoteAddr(), "bnd", bnd,
		"expected_src_ip", expectedIP, "expected_src_port", expectedPort)

	// Per-flow state. SOCKS5 allows multiple targets from one client during
	// an associate; we cache the netstack UDP conn per target addr.
	mgr := newUDPRelayMgr(s, udpConn, expectedIP, expectedPort)
	defer mgr.closeAll()

	// Read-loop on the SOCKS UDP socket (client → tunnel).
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-subCtx.Done()
		_ = udpConn.SetReadDeadline(time.Unix(1, 0))
	}()
	go mgr.pumpClientToTunnel(subCtx)

	// Block on the control TCP conn — when it closes, tear everything down.
	// We just read into a discard buffer; clients aren't expected to send
	// data here, but EOF/error means "we're done".
	_, _ = io.Copy(io.Discard, ctrl)
	cancel()
}

// tcpRemoteIP extracts the remote IP from a TCP control conn. Returns the
// zero value if not parseable.
func tcpRemoteIP(c net.Conn) netip.Addr {
	if c == nil {
		return netip.Addr{}
	}
	a, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.Addr{}
	}
	return ip.Unmap()
}

// udpRelay tracks one client ↔ target UDP flow.
type udpRelay struct {
	target     net.Conn // gonet.UDPConn via netstack
	clientAddr *net.UDPAddr
	dstHost    string // domain/IP from SOCKS UDP header — used as source on reply
	dstPort    uint16
	lastUseNs  atomic.Int64 // nanoseconds since epoch; written from multiple goroutines
}

func (r *udpRelay) touch() { r.lastUseNs.Store(time.Now().UnixNano()) }

// udpRelayMgr is a per-associate registry of active relays.
type udpRelayMgr struct {
	s       *socks5Server
	udpConn *net.UDPConn
	mu      sync.Mutex
	relays  map[string]*udpRelay
	// inflight tracks in-flight DialContext calls keyed by targetAddr so a
	// burst of datagrams to the same target only spawns one dial (and one
	// relay), eliminating the leak where a losing-race conn was orphaned.
	inflight map[string]*sync.WaitGroup

	// expectedIP is the source IP we trust for this associate session
	// (TCP-control client IP, optionally narrowed by the client-supplied
	// DST.ADDR in the ASSOCIATE request). Zero means "no IP pre-screening".
	expectedIP netip.Addr
	// expectedPort, if non-zero, narrows the trusted source to a specific
	// port (from the client's DST.PORT in ASSOCIATE).
	expectedPort uint16

	clientMu sync.Mutex
	client   *net.UDPAddr // locked-in client (IP,port) from first valid datagram
}

func newUDPRelayMgr(s *socks5Server, udpConn *net.UDPConn, expectedIP netip.Addr, expectedPort uint16) *udpRelayMgr {
	return &udpRelayMgr{
		s:            s,
		udpConn:      udpConn,
		relays:       map[string]*udpRelay{},
		inflight:     map[string]*sync.WaitGroup{},
		expectedIP:   expectedIP,
		expectedPort: expectedPort,
	}
}

func (m *udpRelayMgr) closeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.relays {
		_ = r.target.Close()
	}
	m.relays = nil
}

// authorise checks that src is allowed to talk through this associate.
// First valid datagram locks the (IP,port) pair; later packets must match.
// Returns the locked-in client address (for diagnostics) on success.
func (m *udpRelayMgr) authorise(src *net.UDPAddr) (*net.UDPAddr, bool) {
	srcIP, ok := netip.AddrFromSlice(src.IP)
	if !ok {
		return nil, false
	}
	srcIP = srcIP.Unmap()
	if m.expectedIP.IsValid() && srcIP != m.expectedIP {
		return nil, false
	}
	if m.expectedPort != 0 && uint16(src.Port) != m.expectedPort {
		return nil, false
	}
	m.clientMu.Lock()
	defer m.clientMu.Unlock()
	if m.client == nil {
		// First datagram — lock the full (IP,port).
		m.client = src
		return src, true
	}
	if m.client.IP.Equal(src.IP) && m.client.Port == src.Port {
		return m.client, true
	}
	return nil, false
}

// lockedClient returns the (IP,port) pair locked in by authorise, if any.
func (m *udpRelayMgr) lockedClient() *net.UDPAddr {
	m.clientMu.Lock()
	defer m.clientMu.Unlock()
	return m.client
}

// pumpClientToTunnel reads SOCKS5-wrapped datagrams from the client and
// forwards them via netstack. Drops datagrams whose source IP/port does
// not match the authorised client.
func (m *udpRelayMgr) pumpClientToTunnel(ctx context.Context) {
	buf := make([]byte, udpMaxPayload)
	for {
		if ctx.Err() != nil {
			return
		}
		n, src, err := m.udpConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			m.s.log.Debug("UDP relay: read client failed", "err", err)
			continue
		}
		client, ok := m.authorise(src)
		if !ok {
			m.s.log.Debug("UDP relay: dropping datagram from unauthorised source",
				"src", src, "expected_ip", m.expectedIP)
			continue
		}

		host, port, payload, err := parseUDPRequest(buf[:n])
		if err != nil {
			m.s.log.Debug("UDP relay: bad datagram", "src", src, "err", err)
			continue
		}

		// Resolve domain if needed.
		ips, err := m.s.resolver.LookupIP(ctx, host)
		if err != nil || len(ips) == 0 {
			m.s.log.Debug("UDP relay: resolve failed", "host", host, "err", err)
			continue
		}
		targetAddr := net.JoinHostPort(ips[0].String(), strconv.Itoa(int(port)))

		relay, err := m.getOrCreate(ctx, host, port, targetAddr, client)
		if err != nil {
			m.s.log.Debug("UDP relay: dial failed", "target", targetAddr, "err", err)
			continue
		}
		_ = relay.target.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := relay.target.Write(payload); err != nil {
			m.s.log.Debug("UDP relay: target write failed", "target", targetAddr, "err", err)
		}
		relay.touch()
	}
}

// getOrCreate looks up (or creates) a relay keyed by target address. When
// creating, spawns a tunnel→client reader goroutine for that target.
//
// Concurrency: dialing the netstack can take milliseconds. We hold m.mu for
// the cheap lookup; if not present, we register a sync.WaitGroup as an
// "in-flight" marker so concurrent calls block on it instead of racing to
// dial duplicate conns (the previous design leaked one *gonet.UDPConn +
// one pumpTunnelToClient goroutine per losing race).
func (m *udpRelayMgr) getOrCreate(ctx context.Context, dstHost string, dstPort uint16, targetAddr string, client *net.UDPAddr) (*udpRelay, error) {
	for {
		m.mu.Lock()
		if r, ok := m.relays[targetAddr]; ok {
			m.mu.Unlock()
			return r, nil
		}
		if wg, ok := m.inflight[targetAddr]; ok {
			m.mu.Unlock()
			wg.Wait() // another goroutine is dialing; spin and re-check.
			continue
		}
		wg := &sync.WaitGroup{}
		wg.Add(1)
		m.inflight[targetAddr] = wg
		m.mu.Unlock()

		conn, err := m.s.ns.DialContext(ctx, "udp", targetAddr)
		m.mu.Lock()
		delete(m.inflight, targetAddr)
		if err != nil {
			m.mu.Unlock()
			wg.Done()
			return nil, err
		}
		r := &udpRelay{
			target:     conn,
			clientAddr: client,
			dstHost:    dstHost,
			dstPort:    dstPort,
		}
		r.touch()
		m.relays[targetAddr] = r
		m.mu.Unlock()
		wg.Done()

		go m.pumpTunnelToClient(ctx, targetAddr, r)
		return r, nil
	}
}

// removeRelay deletes r from the registry, closing the target conn.
func (m *udpRelayMgr) removeRelay(targetAddr string) {
	m.mu.Lock()
	r, ok := m.relays[targetAddr]
	if ok {
		delete(m.relays, targetAddr)
	}
	m.mu.Unlock()
	if ok && r != nil {
		_ = r.target.Close()
	}
}

// pumpTunnelToClient reads replies from the netstack conn and writes them
// back to the client wrapped in a SOCKS5 UDP header. On read error / idle
// timeout the relay is removed from the registry so the next client
// datagram can spawn a fresh one.
func (m *udpRelayMgr) pumpTunnelToClient(ctx context.Context, targetAddr string, r *udpRelay) {
	defer m.removeRelay(targetAddr)
	buf := make([]byte, udpMaxPayload)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = r.target.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := r.target.Read(buf)
		if err != nil {
			// Idle / closed — exit. The next client packet to this target
			// will spawn a fresh relay.
			return
		}
		client := m.lockedClient()
		if client == nil {
			continue
		}
		out := buildUDPReply(r.dstHost, r.dstPort, buf[:n])
		_, _ = m.udpConn.WriteToUDP(out, client)
		r.touch()
	}
}

// --- SOCKS5 UDP header codec (RFC 1928 §7) ---
//
//   +----+------+------+----------+----------+----------+
//   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//   +----+------+------+----------+----------+----------+
//   | 2  |  1   |  1   |  Variable|    2     | Variable |
//   +----+------+------+----------+----------+----------+

func parseUDPRequest(b []byte) (host string, port uint16, payload []byte, err error) {
	if len(b) < 4 {
		return "", 0, nil, errors.New("udp datagram too short")
	}
	// RSV must be 0x0000; we accept anything (some clients don't zero it).
	frag := b[2]
	if frag != 0 {
		return "", 0, nil, fmt.Errorf("fragment %d not supported", frag)
	}
	atyp := b[3]
	pos := 4
	switch atyp {
	case atypIPv4:
		if len(b) < pos+4+2 {
			return "", 0, nil, errors.New("v4 truncated")
		}
		host = netip.AddrFrom4([4]byte(b[pos : pos+4])).String()
		pos += 4
	case atypIPv6:
		if len(b) < pos+16+2 {
			return "", 0, nil, errors.New("v6 truncated")
		}
		host = netip.AddrFrom16([16]byte(b[pos : pos+16])).String()
		pos += 16
	case atypDomain:
		if len(b) < pos+1 {
			return "", 0, nil, errors.New("domain truncated")
		}
		l := int(b[pos])
		pos++
		if len(b) < pos+l+2 {
			return "", 0, nil, errors.New("domain truncated")
		}
		host = string(b[pos : pos+l])
		pos += l
	default:
		return "", 0, nil, fmt.Errorf("bad ATYP 0x%02x", atyp)
	}
	port = binary.BigEndian.Uint16(b[pos : pos+2])
	pos += 2
	payload = b[pos:]
	return host, port, payload, nil
}

// buildUDPReply formats a reply datagram (same header layout). dstHost is
// echoed back as DST.ADDR (so the client matches it against its request),
// but we encode it as an IP literal when possible to avoid sending a
// domain in the reverse path (RFC 1928 expects literal IPs in replies).
func buildUDPReply(dstHost string, dstPort uint16, data []byte) []byte {
	out := make([]byte, 0, 22+len(data))
	out = append(out, 0, 0, 0) // RSV, FRAG=0
	if ip, err := netip.ParseAddr(dstHost); err == nil {
		switch {
		case ip.Is4():
			out = append(out, atypIPv4)
			b := ip.As4()
			out = append(out, b[:]...)
		case ip.Is6():
			out = append(out, atypIPv6)
			b := ip.As16()
			out = append(out, b[:]...)
		}
	} else {
		// Echo the domain back. Allowed by spec, harmless for clients that
		// match by their original request.
		if len(dstHost) > 255 {
			dstHost = dstHost[:255]
		}
		out = append(out, atypDomain, byte(len(dstHost)))
		out = append(out, dstHost...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], dstPort)
	out = append(out, p[:]...)
	out = append(out, data...)
	return out
}

// udpBindIPForCtrl picks an IP to bind the UDP ASSOCIATE socket on so the
// client can reach it. Preference order:
//  1. The TCP control conn's LocalAddr — this is the actual destination IP
//     the client used to reach us (correct even when the listener was on
//     0.0.0.0).
//  2. The configured listen address, if it's a literal IP.
//  3. 127.0.0.1 (safe default).
//
// Avoids the prior bug where listening on 0.0.0.0 caused BND.ADDR=127.0.0.1
// to be sent to non-loopback clients, who couldn't reach it.
func udpBindIPForCtrl(ctrl net.Conn, listenAddr string) string {
	if ctrl != nil {
		if a, ok := ctrl.LocalAddr().(*net.TCPAddr); ok && a.IP != nil && !a.IP.IsUnspecified() {
			return a.IP.String()
		}
	}
	if host, _, err := net.SplitHostPort(listenAddr); err == nil {
		if host != "" && host != "0.0.0.0" && host != "::" {
			return host
		}
	}
	return "127.0.0.1"
}

// parseHostAsIP returns the netip.Addr form of host if host is a literal
// IPv4/IPv6 address. Returns ok=false for domain names.
func parseHostAsIP(host string) (netip.Addr, bool) {
	if host == "" {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func localAddrPortFromUDP(c *net.UDPConn) netip.AddrPort {
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			return ap
		}
	}
	return netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
}
