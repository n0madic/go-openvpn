// SPDX-License-Identifier: MPL-2.0

package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromOvpnFilePreservesExplicitTLSAuthKeyDirection(t *testing.T) {
	tests := []struct {
		name             string
		directive        string
		wantDirection    int
		wantDirectionSet bool
	}{
		{name: "explicit normal", directive: "key-direction 0", wantDirection: 0, wantDirectionSet: true},
		{name: "omitted defaults to inverse", directive: "", wantDirection: 1, wantDirectionSet: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			profilePath := filepath.Join(dir, "client.ovpn")
			overrideKeyPath := filepath.Join(dir, "override.key")
			profile := "client\ndev tun\nproto udp\nremote vpn.example 1194\nverify-x509-name vpn.example name\n<tls-auth>\ninline placeholder key\n</tls-auth>\n"
			if tt.directive != "" {
				profile += tt.directive + "\n"
			}
			if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(overrideKeyPath, []byte("replacement key"), 0o600); err != nil {
				t.Fatal(err)
			}

			cfg, err := loadFromOvpnFile(&cliOpts{
				configFile:  profilePath,
				tlsAuthFile: overrideKeyPath,
			}, slog.Default())
			if err != nil {
				t.Fatalf("loadFromOvpnFile: %v", err)
			}
			if cfg.KeyDirection != tt.wantDirection {
				t.Errorf("KeyDirection=%d, want %d", cfg.KeyDirection, tt.wantDirection)
			}
			if cfg.KeyDirectionSet != tt.wantDirectionSet {
				t.Errorf("KeyDirectionSet=%v, want %v", cfg.KeyDirectionSet, tt.wantDirectionSet)
			}
		})
	}
}
