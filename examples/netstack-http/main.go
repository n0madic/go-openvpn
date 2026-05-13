// SPDX-License-Identifier: AGPL-3.0-or-later

// Command netstack-http dials an OpenVPN server, stands up a userspace
// gVisor TCP/IP stack on top of the tunnel, and issues an HTTP GET through
// it. Demonstrates how to compose go-openvpn with gVisor without any
// kernel-level tun interface.
//
// Usage:
//
//	netstack-http \
//	  -server vpn.example:1194 \
//	  -ca ca.pem -cert client.pem -key client.key \
//	  -tlscrypt tc.key \
//	  -url http://10.8.0.1:8080/
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/n0madic/go-openvpn"
	"github.com/n0madic/go-openvpn/pkg/netstack"
)

func main() {
	var (
		server      = flag.String("server", "", "host:port of the OpenVPN server")
		caPath      = flag.String("ca", "", "PEM file with CA certificate(s)")
		certPath    = flag.String("cert", "", "PEM file with client certificate")
		keyPath     = flag.String("key", "", "PEM file with client key")
		tlsCryptKey = flag.String("tlscrypt", "", "OpenVPN static tls-crypt key file")
		network     = flag.String("net", "udp", "udp or tcp")
		serverName  = flag.String("name", "", "TLS ServerName / SNI (defaults to hostname of -server)")
		url         = flag.String("url", "", "URL to fetch through the tunnel (must use a literal IP)")
		timeout     = flag.Duration("timeout", 30*time.Second, "overall timeout")
	)
	flag.Parse()

	if *server == "" || *caPath == "" || *certPath == "" || *keyPath == "" ||
		*tlsCryptKey == "" || *url == "" {
		flag.Usage()
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	caBytes, err := os.ReadFile(*caPath)
	if err != nil {
		logger.Error("read CA", "err", err)
		os.Exit(1)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBytes) {
		logger.Error("no certs in CA file")
		os.Exit(1)
	}

	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		logger.Error("load client cert", "err", err)
		os.Exit(1)
	}

	tlsCrypt, err := os.ReadFile(*tlsCryptKey)
	if err != nil {
		logger.Error("read tls-crypt key", "err", err)
		os.Exit(1)
	}

	sni := *serverName
	if sni == "" {
		host, _, err := net.SplitHostPort(*server)
		if err == nil {
			sni = host
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	cli, err := openvpn.Dial(ctx, &openvpn.Config{
		Network:    *network,
		RemoteAddr: *server,
		TLSConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{cert},
			ServerName:   sni,
			MinVersion:   tls.VersionTLS12,
		},
		TLSCryptV1: tlsCrypt,
		Logger:     logger,
	})
	if err != nil {
		logger.Error("VPN Dial", "err", err)
		os.Exit(1)
	}
	defer func() { _ = cli.Close() }()

	pr := cli.PushedOptions()
	logger.Info("tunnel up",
		"local", pr.LocalIP, "gateway", pr.Gateway,
		"cipher", pr.Cipher, "mtu", pr.MTU)

	ns, err := netstack.New(cli)
	if err != nil {
		logger.Error("netstack.New", "err", err)
		os.Exit(1)
	}
	defer func() { _ = ns.Close() }()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: ns.DialContext,
		},
		Timeout: *timeout,
	}

	logger.Info("HTTP GET via netstack", "url", *url)
	req, err := http.NewRequestWithContext(ctx, "GET", *url, nil)
	if err != nil {
		logger.Error("NewRequest", "err", err)
		os.Exit(1)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Error("HTTP Do", "err", err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("read body", "err", err)
		os.Exit(1)
	}
	fmt.Printf("HTTP %s\n", resp.Status)
	fmt.Printf("---\n%s\n", body)
}
