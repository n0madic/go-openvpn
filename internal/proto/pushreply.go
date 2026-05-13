// SPDX-License-Identifier: AGPL-3.0-or-later

package proto

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// PushReply is the parsed server response to PUSH_REQUEST. Only fields this
// client honours are decoded; unknown options are silently ignored (which is
// what OpenVPN itself does on the client side for non-mandatory directives).
type PushReply struct {
	LocalIP, RemoteIP netip.Addr   // from "ifconfig"
	Netmask           netip.Addr   // from "ifconfig" when topology=subnet
	LocalIP6          netip.Prefix // from "ifconfig-ipv6" (addr/prefix-len)
	RemoteIP6         netip.Addr
	Routes            []netip.Prefix // from "route"
	Routes6           []netip.Prefix // from "route-ipv6"
	Gateway           netip.Addr     // from "route-gateway"
	DNS               []netip.Addr   // from "dhcp-option DNS"
	MTU               int            // from "tun-mtu"
	Cipher            string         // from "cipher"
	PeerID            uint32         // from "peer-id"
	PingInterval      time.Duration  // from "ping"
	PingRestart       time.Duration  // from "ping-restart"
	Topology          string         // "subnet" | "net30" | "p2p"; defaults to "net30" per OpenVPN
	Raw               string         // the original PUSH_REPLY text, sans prefix and NUL
}

// PushReplyPrefix is the literal token PUSH_REPLY messages start with.
const PushReplyPrefix = "PUSH_REPLY,"

// ParsePushReply decodes a PUSH_REPLY,... string (without the trailing NUL).
// The "PUSH_REPLY," prefix is required.
func ParsePushReply(s string) (PushReply, error) {
	if !strings.HasPrefix(s, PushReplyPrefix) {
		preview := s
		if len(preview) > 80 {
			preview = preview[:80] + "..."
		}
		return PushReply{}, fmt.Errorf("proto: not a PUSH_REPLY message: got %q", preview)
	}
	body := s[len(PushReplyPrefix):]
	pr := PushReply{Raw: body, Topology: "net30"}

	for opt := range strings.SplitSeq(body, ",") {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		if err := pr.applyOption(opt); err != nil {
			return PushReply{}, fmt.Errorf("proto: PUSH_REPLY %q: %w", opt, err)
		}
	}
	return pr, nil
}

func (pr *PushReply) applyOption(opt string) error {
	fields := strings.Fields(opt)
	if len(fields) == 0 {
		return nil
	}
	switch fields[0] {
	case "ifconfig":
		if len(fields) < 3 {
			return errors.New("ifconfig needs 2 args")
		}
		a, err := netip.ParseAddr(fields[1])
		if err != nil {
			return fmt.Errorf("ifconfig local: %w", err)
		}
		b, err := netip.ParseAddr(fields[2])
		if err != nil {
			return fmt.Errorf("ifconfig peer/mask: %w", err)
		}
		pr.LocalIP = a
		// Interpretation depends on topology, which may appear before or after
		// in the option list. Store as RemoteIP (for net30/p2p) and Netmask
		// (for subnet) — same value. The consumer chooses based on Topology.
		pr.RemoteIP = b
		pr.Netmask = b
	case "ifconfig-ipv6":
		if len(fields) < 3 {
			return errors.New("ifconfig-ipv6 needs 2 args")
		}
		p, err := netip.ParsePrefix(fields[1])
		if err != nil {
			return fmt.Errorf("ifconfig-ipv6 local: %w", err)
		}
		r, err := netip.ParseAddr(fields[2])
		if err != nil {
			return fmt.Errorf("ifconfig-ipv6 remote: %w", err)
		}
		pr.LocalIP6 = p
		pr.RemoteIP6 = r
	case "route":
		if len(fields) < 2 {
			return errors.New("route needs network")
		}
		p, err := routeToPrefix(fields[1:])
		if err != nil {
			return err
		}
		pr.Routes = append(pr.Routes, p)
	case "route-ipv6":
		if len(fields) < 2 {
			return errors.New("route-ipv6 needs prefix")
		}
		p, err := netip.ParsePrefix(fields[1])
		if err != nil {
			return fmt.Errorf("route-ipv6: %w", err)
		}
		pr.Routes6 = append(pr.Routes6, p)
	case "route-gateway":
		if len(fields) < 2 {
			return errors.New("route-gateway needs address")
		}
		gw, err := netip.ParseAddr(fields[1])
		if err != nil {
			return fmt.Errorf("route-gateway: %w", err)
		}
		pr.Gateway = gw
	case "dhcp-option":
		if len(fields) >= 3 && strings.EqualFold(fields[1], "DNS") {
			a, err := netip.ParseAddr(fields[2])
			if err != nil {
				return fmt.Errorf("dhcp-option DNS: %w", err)
			}
			pr.DNS = append(pr.DNS, a)
		}
	case "tun-mtu":
		if len(fields) < 2 {
			return errors.New("tun-mtu needs value")
		}
		v, err := strconv.Atoi(fields[1])
		if err != nil {
			return fmt.Errorf("tun-mtu: %w", err)
		}
		pr.MTU = v
	case "cipher":
		if len(fields) < 2 {
			return errors.New("cipher needs name")
		}
		pr.Cipher = fields[1]
	case "peer-id":
		if len(fields) < 2 {
			return errors.New("peer-id needs value")
		}
		v, err := strconv.ParseUint(fields[1], 10, 24)
		if err != nil {
			return fmt.Errorf("peer-id: %w", err)
		}
		pr.PeerID = uint32(v)
	case "ping":
		if len(fields) < 2 {
			return errors.New("ping needs seconds")
		}
		s, err := strconv.Atoi(fields[1])
		if err != nil {
			return fmt.Errorf("ping: %w", err)
		}
		pr.PingInterval = time.Duration(s) * time.Second
	case "ping-restart":
		if len(fields) < 2 {
			return errors.New("ping-restart needs seconds")
		}
		s, err := strconv.Atoi(fields[1])
		if err != nil {
			return fmt.Errorf("ping-restart: %w", err)
		}
		pr.PingRestart = time.Duration(s) * time.Second
	case "topology":
		if len(fields) < 2 {
			return errors.New("topology needs value")
		}
		pr.Topology = fields[1]
	}
	// Unknown options are tolerated.
	return nil
}

// routeToPrefix converts "10.8.0.0 255.255.255.0 [gateway]" into a netip.Prefix.
// The optional gateway/metric args are ignored.
func routeToPrefix(args []string) (netip.Prefix, error) {
	if len(args) < 1 {
		return netip.Prefix{}, errors.New("route: missing network")
	}
	net, err := netip.ParseAddr(args[0])
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("route net: %w", err)
	}
	prefixLen := 32
	if !net.Is4() {
		prefixLen = 128
	}
	if len(args) >= 2 {
		mask, err := netip.ParseAddr(args[1])
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("route mask: %w", err)
		}
		pl, ok := maskToPrefixLen(mask)
		if !ok {
			return netip.Prefix{}, fmt.Errorf("route mask %s is not contiguous", mask)
		}
		prefixLen = pl
	}
	return net.Prefix(prefixLen)
}

// maskToPrefixLen converts a dotted-quad mask (e.g. 255.255.255.0) into a
// CIDR prefix length. Returns false if the mask is non-contiguous.
func maskToPrefixLen(mask netip.Addr) (int, bool) {
	bs := mask.As16() // 16-byte mapped representation
	if mask.Is4() {
		bs = [16]byte{}
		copy(bs[:], mask.AsSlice())
	}
	prefix := 0
	seenZero := false
	for _, b := range bs {
		for bit := 7; bit >= 0; bit-- {
			if b&(1<<bit) != 0 {
				if seenZero {
					return 0, false
				}
				prefix++
			} else {
				seenZero = true
			}
		}
	}
	return prefix, true
}
