// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netstack adapts an *openvpn.Client to the github.com/n0madic/go-tun2net
// userspace gVisor TCP/IP stack.
//
// The heavy stack implementation (gVisor LinkEndpoint, reconnect resync, zombie-
// connection force-close, MTU clamping, IPv6 plumbing, data-path observability)
// now lives upstream in go-tun2net. This package is a thin shim: it implements
// go-tun2net's PacketTunnel interface on top of *openvpn.Client and re-exports
// the resulting Net type so existing callers keep using netstack.New / netstack.Net
// unchanged.
package netstack

import (
	"net"

	openvpn "github.com/n0madic/go-openvpn"
	tun2net "github.com/n0madic/go-tun2net"
)

// Net is the userspace TCP/IP stack over the tunnel. It is re-exported from
// go-tun2net so callers can keep referring to netstack.Net / *netstack.Net. It
// exposes DialContext, HasIPv4, HasIPv6, Close, CloseAll, LocalIP, LocalIP6 and
// Stack — see github.com/n0madic/go-tun2net for the full API.
type Net = tun2net.Net

// ErrTunnelIPChanged is returned by (*Net).DialContext when an AutoReconnect-driven
// tunnel reconfiguration races the dial. Re-exported so callers can keep matching
// it with errors.Is(err, netstack.ErrTunnelIPChanged).
var ErrTunnelIPChanged = tun2net.ErrTunnelIPChanged

// New builds a userspace TCP/IP stack on top of an already-dialed OpenVPN client.
// The client lifecycle stays with the caller; (*Net).Close tears down only the
// stack, while (*Net).CloseAll also closes the client.
func New(cli *openvpn.Client) (*Net, error) {
	return tun2net.New(clientTunnel{cli: cli}, cli.Logger())
}

// clientTunnel adapts *openvpn.Client to tun2net.PacketTunnel.
type clientTunnel struct{ cli *openvpn.Client }

// TunnelConn returns the datagram-oriented tunnel net.Conn (1 Write = 1 IP packet).
func (t clientTunnel) TunnelConn() net.Conn { return t.cli.Tunnel() }

// Config snapshots the current PUSH_REPLY as a go-tun2net TunConfig.
func (t clientTunnel) Config() tun2net.TunConfig {
	return pushReplyToTunConfig(t.cli.PushedOptions())
}

// SetInbound registers the stack's inbound IP-packet handler on the client's
// fast-path ingress; the returned detach unregisters it.
func (t clientTunnel) SetInbound(fn func([]byte)) func() { return t.cli.SetIngressHandler(fn) }

// OnReconfigure forwards every AutoReconnect session swap to the stack as a fresh
// TunConfig so it can re-sync NIC address/routes/MTU and reset stale connections.
func (t clientTunnel) OnReconfigure(fn func(tun2net.TunConfig)) func() {
	return t.cli.OnReconnect(func(pr openvpn.PushReply) { fn(pushReplyToTunConfig(pr)) })
}

// Close closes the underlying client. Implementing io.Closer makes
// (*Net).CloseAll tear the client down too (parity with the old netstack.Net.CloseAll).
func (t clientTunnel) Close() error { return t.cli.Close() }

// pushReplyToTunConfig maps OpenVPN's pushed options to go-tun2net's TunConfig.
// The fields are 1:1 except MTU (int → uint32); go-tun2net clamps the MTU itself.
func pushReplyToTunConfig(pr openvpn.PushReply) tun2net.TunConfig {
	var mtu uint32
	if pr.MTU > 0 {
		mtu = uint32(pr.MTU)
	}
	return tun2net.TunConfig{
		LocalIP:   pr.LocalIP,
		Netmask:   pr.Netmask,
		Gateway:   pr.Gateway,
		LocalIP6:  pr.LocalIP6,
		RemoteIP6: pr.RemoteIP6,
		Routes:    pr.Routes,
		Routes6:   pr.Routes6,
		DNS:       pr.DNS,
		MTU:       mtu,
	}
}
