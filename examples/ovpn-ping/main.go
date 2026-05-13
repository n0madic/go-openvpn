// SPDX-License-Identifier: AGPL-3.0-or-later

// Command ovpn-ping connects to an OpenVPN server using a standard .ovpn
// profile and sends one ICMP echo through the tunnel to the pushed gateway.
//
// Demonstrates the full happy path of the library:
//
//  1. Parse the .ovpn file via pkg/ovpn into a ready *openvpn.Config.
//  2. Supply auth-user-pass credentials (here: from CLI flags or env vars).
//  3. Dial the server.
//  4. Read PUSH_REPLY (assigned tunnel IP, gateway, cipher).
//  5. Write one IP datagram (ICMP echo to the gateway) into the tunnel
//     net.Conn and read one back.
//
// Usage:
//
//	ovpn-ping -config md-23.protonvpn.udp.ovpn \
//	          -user "$PROTON_USER" -pass "$PROTON_PASS"
//
//	# Or with environment variables instead of flags:
//	export OVPN_USER='your-openvpn-username'
//	export OVPN_PASS='your-openvpn-password'
//	ovpn-ping -config md-23.protonvpn.udp.ovpn
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/n0madic/go-openvpn"
	"github.com/n0madic/go-openvpn/pkg/ovpn"
)

func main() {
	var (
		configPath = flag.String("config", "", ".ovpn profile path (required)")
		user       = flag.String("user", os.Getenv("OVPN_USER"), "username for auth-user-pass (default: $OVPN_USER)")
		pass       = flag.String("pass", os.Getenv("OVPN_PASS"), "password for auth-user-pass (default: $OVPN_PASS)")
		port       = flag.String("port", "", "force a specific remote port (e.g. 1194) when the profile lists several")
		serverName = flag.String("sni", "", "override TLS ServerName (verify-x509-name); default: chain-only verify if profile has none")
		verbose    = flag.Bool("v", false, "verbose logging")
		timeout    = flag.Duration("timeout", 45*time.Second, "overall timeout")
	)
	flag.Parse()

	if *configPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: levelFromVerbose(*verbose),
	}))

	parsed, err := ovpn.ParseFile(*configPath, &ovpn.ParseOptions{
		Username:           *user,
		Password:           *pass,
		ServerNameOverride: *serverName,
		PickRemote: func(remotes []ovpn.Remote) ovpn.Remote {
			if *port != "" {
				for _, r := range remotes {
					if r.Port == *port {
						return r
					}
				}
			}
			return remotes[0]
		},
		Warn: func(line int, dir, reason string) {
			logger.Debug("parser warning",
				"line", line, "directive", dir, "reason", reason)
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}

	if parsed.AuthUserPass && (parsed.Config.Username == "" || parsed.Config.Password == "") {
		fmt.Fprintln(os.Stderr, "this profile requires auth-user-pass (provide -user/-pass or $OVPN_USER/$OVPN_PASS)")
		os.Exit(2)
	}

	parsed.Config.Logger = logger
	parsed.Config.HandshakeTimeout = *timeout

	logger.Info("dialing",
		"target", parsed.Config.RemoteAddr,
		"network", parsed.Config.Network,
		"ciphers", parsed.Config.Ciphers,
		"user", parsed.Config.Username)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout+10*time.Second)
	defer cancel()

	cli, err := openvpn.Dial(ctx, parsed.Config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer func() { _ = cli.Close() }()

	pr := cli.PushedOptions()
	logger.Info("tunnel up",
		"local", pr.LocalIP, "gateway", pr.Gateway,
		"cipher", pr.Cipher, "mtu", pr.MTU)

	if !pr.LocalIP.Is4() || !pr.Gateway.Is4() {
		fmt.Fprintf(os.Stderr, "non-IPv4 PUSH_REPLY (local=%s gw=%s); ICMP echo demo needs IPv4\n",
			pr.LocalIP, pr.Gateway)
		return
	}

	conn := cli.Tunnel()
	pkt := buildICMPEcho(pr.LocalIP.As4(), pr.Gateway.As4(), 0xBEEF, 1, []byte("hello from go-openvpn"))

	start := time.Now()
	if _, err := conn.Write(pkt); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}

	buf := make([]byte, pr.MTU)
	type readResult struct {
		n   int
		err error
	}
	rch := make(chan readResult, 1)
	go func() {
		n, err := conn.Read(buf)
		rch <- readResult{n, err}
	}()

	select {
	case res := <-rch:
		if res.err != nil {
			fmt.Fprintln(os.Stderr, "read:", res.err)
			os.Exit(1)
		}
		rtt := time.Since(start)
		if res.n >= 21 && buf[0]>>4 == 4 && buf[9] == 1 && buf[20] == 0 {
			fmt.Printf("\n✓ ICMP echo reply from %s in %v (%d bytes)\n",
				pr.Gateway, rtt, res.n)
		} else {
			fmt.Printf("\n? got %d bytes (first=0x%02x proto=%d), expected ICMP echo reply\n",
				res.n, buf[0], buf[9])
			os.Exit(1)
		}
	case <-time.After(5 * time.Second):
		fmt.Fprintln(os.Stderr, "\n✗ no ICMP reply within 5s")
		os.Exit(1)
	}
}

func levelFromVerbose(v bool) slog.Level {
	if v {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

// buildICMPEcho assembles an IPv4 + ICMP echo request datagram. Deliberately
// minimal — production code should use golang.org/x/net/{ipv4,icmp}.
func buildICMPEcho(src, dst [4]byte, id, seq uint16, payload []byte) []byte {
	icmpLen := 8 + len(payload)
	ipLen := 20 + icmpLen
	pkt := make([]byte, ipLen)
	pkt[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen))
	pkt[6] = 0x40 // DF flag
	pkt[8] = 64   // TTL
	pkt[9] = 1    // ICMP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[10:12], inetChecksum(pkt[:20]))
	pkt[20] = 8 // echo request
	binary.BigEndian.PutUint16(pkt[24:26], id)
	binary.BigEndian.PutUint16(pkt[26:28], seq)
	copy(pkt[28:], payload)
	binary.BigEndian.PutUint16(pkt[22:24], inetChecksum(pkt[20:]))
	return pkt
}

func inetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
