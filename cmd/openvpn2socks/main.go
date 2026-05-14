// SPDX-License-Identifier: AGPL-3.0-or-later

// Command openvpn2socks dials an OpenVPN server (using a .ovpn profile or
// manual flags) and exposes the tunnel as a local SOCKS5 proxy. Any process
// can then send traffic through the VPN by pointing its SOCKS5 client at the
// proxy (e.g. `curl --socks5-hostname 127.0.0.1:1080 https://example.com`).
//
// No kernel TUN device required: the IP packets that the OpenVPN client
// emits are fed into a userspace gVisor TCP/IP stack, and the SOCKS5 server
// dials TCP/UDP through that stack.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/n0madic/go-openvpn"
	"github.com/n0madic/go-openvpn/pkg/netstack"
)

type cliOpts struct {
	// OpenVPN endpoint inputs.
	configFile     string
	server         string
	network        string
	user           string
	pass           string
	caFile         string
	certFile       string
	keyFile        string
	tlsCryptFile   string
	tlsCryptV2File string
	ciphers        string
	port           string
	sni            string
	handshakeT     time.Duration

	// SOCKS5 listen + auth.
	listen    string
	socksAuth string

	// DNS strategy.
	dns string

	// Misc.
	idle               time.Duration
	dnsRestartFailures int
	verbose            bool
}

func parseFlags() *cliOpts {
	o := &cliOpts{}

	// OpenVPN endpoint.
	flag.StringVar(&o.configFile, "config", "", ".ovpn profile path (alternative to manual -server/-ca/-cert/... flags)")
	flag.StringVar(&o.server, "server", "", "OpenVPN remote (host:port)")
	flag.StringVar(&o.network, "network", "udp", "transport: udp or tcp")
	flag.StringVar(&o.user, "user", os.Getenv("OVPN_USER"), "auth-user-pass username (default: $OVPN_USER)")
	flag.StringVar(&o.pass, "pass", os.Getenv("OVPN_PASS"), "auth-user-pass password (default: $OVPN_PASS)")
	flag.StringVar(&o.caFile, "ca", "", "PEM file with CA certificate(s)")
	flag.StringVar(&o.certFile, "cert", "", "PEM file with client certificate (optional)")
	flag.StringVar(&o.keyFile, "key", "", "PEM file with client private key (optional)")
	flag.StringVar(&o.tlsCryptFile, "tls-crypt", "", "tls-crypt v1 static key file")
	flag.StringVar(&o.tlsCryptV2File, "tls-crypt-v2", "", "tls-crypt-v2 client bundle file")
	flag.StringVar(&o.ciphers, "ciphers", "", "colon-separated AEAD cipher list (default: AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM)")
	flag.StringVar(&o.port, "port", "", "when -config lists multiple remotes, force this port (e.g. 1194)")
	flag.StringVar(&o.sni, "sni", "", "override TLS ServerName / verify-x509-name")
	flag.DurationVar(&o.handshakeT, "timeout", 45*time.Second, "OpenVPN handshake timeout")

	// SOCKS5.
	flag.StringVar(&o.listen, "listen", "127.0.0.1:1080", "SOCKS5 listen address")
	flag.StringVar(&o.socksAuth, "socks-auth", "", "optional SOCKS5 username:password (RFC 1929)")

	// Resolver.
	flag.StringVar(&o.dns, "dns", "", "override DNS server (queried via tunnel UDP). Format: IP or IP:53")

	// Misc.
	flag.DurationVar(&o.idle, "idle", 10*time.Minute, "close idle proxied TCP after this duration (0 disables)")
	flag.IntVar(&o.dnsRestartFailures, "dns-restart-failures", 3,
		"after N consecutive DNS-over-tunnel timeouts, request a session restart so AutoReconnect dials a fresh peer/NAT mapping (0 disables; useful when only -dns/PUSH_REPLY DNS is configured)")
	flag.BoolVar(&o.verbose, "v", false, "verbose logging (slog Debug)")
	flag.Parse()

	return o
}

func main() {
	opts := parseFlags()

	level := slog.LevelInfo
	if opts.verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if err := run(opts, logger); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(opts *cliOpts, logger *slog.Logger) error {
	cfg, err := loadConfig(opts, logger)
	if err != nil {
		return err
	}
	cfg.Logger = logger
	cfg.HandshakeTimeout = opts.handshakeT
	cfg.AutoReconnect = true

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// VPN dial (separate timeout — we want the dial to give up before the
	// process-wide ctx is cancelled, so we can shut down cleanly).
	dialCtx, dialCancel := context.WithTimeout(rootCtx, opts.handshakeT+10*time.Second)
	defer dialCancel()

	logger.Info("dialing OpenVPN",
		"target", cfg.RemoteAddr, "network", cfg.Network,
		"user", cfg.Username, "ciphers", cfg.Ciphers)
	cli, err := openvpn.Dial(dialCtx, cfg)
	if err != nil {
		return fmt.Errorf("openvpn dial: %w", err)
	}
	defer func() {
		_ = cli.Close()
	}()

	pr := cli.PushedOptions()
	logger.Info("VPN up",
		"local", pr.LocalIP, "gateway", pr.Gateway,
		"cipher", pr.Cipher, "mtu", pr.MTU, "dns", pr.DNS)

	ns, err := netstack.New(cli)
	if err != nil {
		return fmt.Errorf("netstack: %w", err)
	}
	defer func() { _ = ns.Close() }()

	// Resolver: -dns override > PUSH_REPLY > system fallback.
	var override netip.AddrPort
	if opts.dns != "" {
		override, err = parseDNSFlag(opts.dns)
		if err != nil {
			return err
		}
	}
	r := newResolver(ns, pr.DNS, override, logger)
	if opts.dnsRestartFailures > 0 {
		r.SetRestartHook(cli.RequestRestart, opts.dnsRestartFailures)
	}

	srv := newSOCKS5(ns, r, opts.listen, opts.socksAuth, opts.idle, logger)
	logger.Info("SOCKS5 listening", "addr", opts.listen)

	return srv.ListenAndServe(rootCtx)
}

// parseDNSFlag accepts "IP" or "IP:port". Default port is 53.
func parseDNSFlag(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("-dns: %w", err)
	}
	return netip.AddrPortFrom(ip, 53), nil
}
