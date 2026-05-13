// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/n0madic/go-openvpn"
	"github.com/n0madic/go-openvpn/pkg/ovpn"
)

// loadConfig assembles a ready-to-Dial *openvpn.Config from CLI flags. Either
// `-config FILE` is used (with optional overrides from -user/-pass/-sni/-port)
// OR all of -server/-ca/-cert?/-key?/-tls-crypt? are provided manually.
func loadConfig(opts *cliOpts, logger *slog.Logger) (*openvpn.Config, error) {
	if opts.configFile != "" {
		return loadFromOvpnFile(opts, logger)
	}
	return loadFromFlags(opts, logger)
}

// loadFromOvpnFile parses a .ovpn profile and applies flag overrides.
func loadFromOvpnFile(opts *cliOpts, logger *slog.Logger) (*openvpn.Config, error) {
	parsed, err := ovpn.ParseFile(opts.configFile, &ovpn.ParseOptions{
		Username:           opts.user,
		Password:           opts.pass,
		ServerNameOverride: opts.sni,
		PickRemote: func(remotes []ovpn.Remote) ovpn.Remote {
			if opts.port != "" {
				for _, r := range remotes {
					if r.Port == opts.port {
						return r
					}
				}
			}
			return remotes[0]
		},
		Warn: func(line int, dir, reason string) {
			logger.Debug("ovpn parser warning",
				"line", line, "directive", dir, "reason", reason)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("parse .ovpn: %w", err)
	}
	if parsed.AuthUserPass && (parsed.Config.Username == "" || parsed.Config.Password == "") {
		return nil, errors.New("the profile requires auth-user-pass; provide -user/-pass or $OVPN_USER/$OVPN_PASS")
	}
	// -ciphers overrides the profile's data-ciphers list (same semantics as
	// in the all-flag path). Empty value keeps the parsed list.
	if opts.ciphers != "" {
		parsed.Config.Ciphers = strings.Split(opts.ciphers, ":")
	}
	return parsed.Config, nil
}

// loadFromFlags constructs a Config from manual flag set (no .ovpn file).
func loadFromFlags(opts *cliOpts, _ *slog.Logger) (*openvpn.Config, error) {
	if opts.server == "" {
		return nil, errors.New("either -config or -server is required")
	}
	if opts.tlsCryptFile == "" && opts.tlsCryptV2File == "" {
		return nil, errors.New("tls-crypt or tls-crypt-v2 is required (modern control-channel encryption)")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.sni != "" {
		tlsCfg.ServerName = opts.sni
	}

	if opts.caFile != "" {
		b, err := os.ReadFile(opts.caFile)
		if err != nil {
			return nil, fmt.Errorf("read -ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("read -ca: no certificates parsed")
		}
		tlsCfg.RootCAs = pool
	}
	if (opts.certFile == "") != (opts.keyFile == "") {
		return nil, errors.New("-cert and -key must both be set or both omitted")
	}
	if opts.certFile != "" {
		pair, err := tls.LoadX509KeyPair(opts.certFile, opts.keyFile)
		if err != nil {
			return nil, fmt.Errorf("load -cert/-key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}

	cfg := &openvpn.Config{
		Network:    opts.network,
		RemoteAddr: opts.server,
		TLSConfig:  tlsCfg,
		Username:   opts.user,
		Password:   opts.pass,
	}
	if opts.tlsCryptFile != "" {
		b, err := os.ReadFile(opts.tlsCryptFile)
		if err != nil {
			return nil, fmt.Errorf("read -tls-crypt: %w", err)
		}
		cfg.TLSCryptV1 = b
	}
	if opts.tlsCryptV2File != "" {
		b, err := os.ReadFile(opts.tlsCryptV2File)
		if err != nil {
			return nil, fmt.Errorf("read -tls-crypt-v2: %w", err)
		}
		cfg.TLSCryptV2 = b
	}
	if opts.ciphers != "" {
		cfg.Ciphers = strings.Split(opts.ciphers, ":")
	}
	return cfg, nil
}
