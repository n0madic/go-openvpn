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
	"net"
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
	idle                  time.Duration
	verbose               bool
	allowNoServerIdentity bool
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
	flag.BoolVar(&o.verbose, "v", false, "verbose logging (slog Debug)")
	flag.BoolVar(&o.allowNoServerIdentity, "allow-no-server-identity", false,
		"accept a .ovpn profile that has no verify-x509-name and an IP-only remote (the TLS chain is still validated against the CA, but any cert from that CA passes — MITM risk on multi-tenant CAs). Use only if you know the operator and explicitly trust the CA pool.")
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

	// Shutdown policy:
	//   - First signal: cancel rootCtx so graceful shutdown begins.
	//   - Second signal OR forceExitGrace elapsed: os.Exit(130).
	//
	// The deadline path matters because graceful shutdown traverses
	// cli.Close → session.shutdown → workers.Wait, and any one stuck
	// goroutine (TLS Read on a half-dead UDP socket post-suspend, a
	// kernel close that never returns) could otherwise leave the
	// process alive until the user reaches for a second Ctrl-C.
	// session.shutdown carries its own internal bounded Wait, but this
	// deadline backstops every other layer too (netstack close, dial in
	// flight, etc.).
	//
	// Own one signal channel from the very start so there is no window
	// between "first signal cancelled the ctx" and "second-signal handler
	// installed" during which a fast second SIGINT could be absorbed by
	// the runtime and silently lost.
	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	const forceExitGrace = 5 * time.Second
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-rootCtx.Done():
			return
		}
		select {
		case <-sigCh:
			logger.Warn("second signal received during shutdown; force-exiting")
		case <-time.After(forceExitGrace):
			logger.Warn("graceful shutdown grace period elapsed; force-exiting",
				"grace", forceExitGrace)
		}
		os.Exit(130)
	}()

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
		// Match -dns address family against the tunnel's actual NIC.
		// Without this, an IPv6 -dns target on a v4-only ProtonVPN
		// tunnel (the common case) silently fails every query, which
		// then trips the resolver's system-fallback path and leaks
		// query names to the ISP DNS for every lookup. Hard error
		// up-front is much friendlier than the slow degradation.
		if override.Addr().Is4() && !ns.HasIPv4() {
			return fmt.Errorf("-dns is IPv4 (%s) but tunnel has no IPv4 address", override)
		}
		if override.Addr().Is6() && !ns.HasIPv6() {
			return fmt.Errorf("-dns is IPv6 (%s) but tunnel has no IPv6 address", override)
		}
	}
	r := newResolver(ns, pr.DNS, override, logger)
	r.startStatsLogger(rootCtx)

	// Warn loudly when the SOCKS5 listener is bound to a non-loopback
	// interface without SOCKS5 authentication: anyone on the LAN can
	// route their traffic through this user's VPN. The CLI default is
	// 127.0.0.1:1080 so this almost always indicates an intentional
	// "expose to LAN" with a forgotten -socks-auth.
	if opts.socksAuth == "" && !isLoopbackListen(opts.listen) {
		logger.Warn("SOCKS5 is open without authentication on a non-loopback address — anyone on the network can use this VPN",
			"listen", opts.listen,
			"hint", "set -socks-auth user:pass or bind to 127.0.0.1")
	}

	srv := newSOCKS5(ns, r, opts.listen, opts.socksAuth, opts.idle, logger)
	logger.Info("SOCKS5 listening", "addr", opts.listen)

	return srv.ListenAndServe(rootCtx)
}

// isLoopbackListen reports whether the SOCKS5 listen address binds only to
// the loopback interface. Recognises both IP-literal forms
// ("127.0.0.1:1080", "[::1]:1080") and the symbolic "localhost:1080".
// Empty host (bare ":1080") binds to 0.0.0.0/[::] — NOT loopback — so
// the warning fires as expected.
func isLoopbackListen(addr string) bool {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().IsLoopback()
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback()
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
