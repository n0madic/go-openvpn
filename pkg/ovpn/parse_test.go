// SPDX-License-Identifier: AGPL-3.0-or-later

package ovpn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	openvpn "github.com/n0madic/go-openvpn"
)

func TestParseMinimal(t *testing.T) {
	t.Parallel()
	src := `client
dev tun
proto udp
remote vpn.example.test 1194
remote-random

cipher AES-256-GCM
data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM
auth SHA256
reneg-sec 3600
tls-version-min 1.2

verify-x509-name test-server name
remote-cert-tls server
auth-user-pass

persist-key
persist-tun
nobind

<ca>
` + caInline() + `</ca>

<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`
	p, err := Parse(strings.NewReader(src), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := p.Config

	if cfg.Network != "udp" {
		t.Errorf("Network=%q, want udp", cfg.Network)
	}
	if cfg.RemoteAddr != "vpn.example.test:1194" {
		t.Errorf("RemoteAddr=%q, want vpn.example.test:1194", cfg.RemoteAddr)
	}
	if cfg.Reneg != 3600*time.Second {
		t.Errorf("Reneg=%v, want 3600s", cfg.Reneg)
	}
	wantCiphers := []string{"AES-256-GCM", "CHACHA20-POLY1305", "AES-128-GCM"}
	if !slicesEqual(cfg.Ciphers, wantCiphers) {
		t.Errorf("Ciphers=%v, want %v", cfg.Ciphers, wantCiphers)
	}
	if cfg.TLSConfig == nil {
		t.Fatal("TLSConfig nil")
	}
	if cfg.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion=0x%x, want TLS 1.2", cfg.TLSConfig.MinVersion)
	}
	if cfg.TLSConfig.ServerName != "test-server" {
		t.Errorf("ServerName=%q, want test-server", cfg.TLSConfig.ServerName)
	}
	if cfg.TLSConfig.RootCAs == nil {
		t.Error("RootCAs nil — <ca> not loaded")
	}
	if len(cfg.TLSCryptV1) == 0 {
		t.Error("TLSCryptV1 empty — <tls-crypt> not loaded")
	}
	if cfg.TLSCryptV2 != nil {
		t.Error("TLSCryptV2 should be nil")
	}
	if !p.AuthUserPass {
		t.Error("AuthUserPass=false, want true")
	}
	if cfg.Username != "" || cfg.Password != "" {
		t.Error("Username/Password should be empty (caller fills)")
	}
	if len(p.Remotes) != 1 {
		t.Errorf("Remotes=%d, want 1", len(p.Remotes))
	}
}

func TestParseMultipleRemotes(t *testing.T) {
	t.Parallel()
	src := `client
dev tun
proto udp
remote a.example 1194
remote b.example 4569 udp
remote c.example 443 tcp
remote-random

<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`
	p, err := Parse(strings.NewReader(src), &ParseOptions{
		PickRemote: func(rs []Remote) Remote { return rs[1] }, // force b.example
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Remotes) != 3 {
		t.Fatalf("got %d remotes, want 3", len(p.Remotes))
	}
	if p.Config.RemoteAddr != "b.example:4569" {
		t.Errorf("RemoteAddr=%q, want b.example:4569", p.Config.RemoteAddr)
	}
	if p.Remotes[2].Proto != "tcp" {
		t.Errorf("Remotes[2].Proto=%q, want tcp", p.Remotes[2].Proto)
	}
}

func TestParseInlineCertKey(t *testing.T) {
	t.Parallel()
	src := `client
dev tun
proto udp
remote vpn.example 1194

<ca>` + caInline() + `</ca>

<cert>
` + certInline() + `</cert>

<key>
` + keyInline() + `</key>

<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`
	p, err := Parse(strings.NewReader(src), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Config.TLSConfig == nil || len(p.Config.TLSConfig.Certificates) == 0 {
		t.Fatal("client cert/key not loaded into TLSConfig.Certificates")
	}
}

func TestRejectsLegacy(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"comp-lzo": `client
dev tun
proto udp
remote vpn.example 1194
comp-lzo
<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`,
		"compress lz4-v2": `client
dev tun
proto udp
remote vpn.example 1194
compress lz4-v2
<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`,
		"dev tap": `client
dev tap
proto udp
remote vpn.example 1194
<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`,
		"non-AEAD cipher": `client
dev tun
proto udp
remote vpn.example 1194
cipher BF-CBC
<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`,
		"proto tcp-server": `client
dev tun
proto tcp-server
remote vpn.example 1194
<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(strings.NewReader(src), nil)
			if err == nil {
				t.Fatalf("%s: parse unexpectedly succeeded", name)
			}
		})
	}
}

func TestMissingControlChannelEncryption(t *testing.T) {
	t.Parallel()
	src := `client
dev tun
proto udp
remote vpn.example 1194
`
	_, err := Parse(strings.NewReader(src), nil)
	if err == nil {
		t.Fatal("expected error about missing tls-crypt")
	}
	if !strings.Contains(err.Error(), "tls-crypt") {
		t.Errorf("err=%v, want mention of tls-crypt", err)
	}
}

func TestNoRemote(t *testing.T) {
	t.Parallel()
	src := `client
dev tun
proto udp
<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`
	_, err := Parse(strings.NewReader(src), nil)
	if err == nil || !strings.Contains(err.Error(), "remote") {
		t.Fatalf("err=%v, want missing-remote", err)
	}
}

func TestTokenize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want []string
	}{
		{"a b c", []string{"a", "b", "c"}},
		{`remote "vpn host" 1194`, []string{"remote", "vpn host", "1194"}},
		{"   leading  spaces  ", []string{"leading", "spaces"}},
		{"", nil},
		// Single-quoted string (OpenVPN options.c::parse_line).
		{`push 'route 10.0.0.0'`, []string{"push", "route 10.0.0.0"}},
		// Backslash escapes a space outside quotes.
		{`path C:\\Program\ Files\\vpn`, []string{"path", `C:\Program Files\vpn`}},
		// Backslash inside double quotes escapes the quote.
		{`arg "a\"b"`, []string{"arg", `a"b`}},
		// Backslash is literal inside single quotes.
		{`arg 'a\b'`, []string{"arg", `a\b`}},
		// Empty quoted string is a real, distinct argument.
		{`push ""`, []string{"push", ""}},
	}
	for _, tc := range tests {
		got, err := tokenize(tc.in)
		if err != nil {
			t.Errorf("tokenize(%q): %v", tc.in, err)
			continue
		}
		if !slicesEqual(got, tc.want) {
			t.Errorf("tokenize(%q)=%v, want %v", tc.in, got, tc.want)
		}
	}
	if _, err := tokenize(`bad "unterminated`); err == nil {
		t.Error("expected error on unterminated double quote")
	}
	if _, err := tokenize(`bad 'unterminated`); err == nil {
		t.Error("expected error on unterminated single quote")
	}
	if _, err := tokenize(`trailing\`); err == nil {
		t.Error("expected error on trailing backslash escape")
	}
}

// TestParseBOM verifies a leading UTF-8 BOM (common from Windows editors) is
// stripped so the first directive still parses.
func TestParseBOM(t *testing.T) {
	t.Parallel()
	src := "\ufeff" + `client
dev tun
proto udp
remote vpn.example.test 1194
<ca>
` + caInline() + `</ca>
<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`
	p, err := Parse(strings.NewReader(src), nil)
	if err != nil {
		t.Fatalf("Parse with BOM: %v", err)
	}
	if p.Config.RemoteAddr != "vpn.example.test:1194" {
		t.Errorf("RemoteAddr=%q, want vpn.example.test:1194 (BOM not stripped?)", p.Config.RemoteAddr)
	}
}

// TestTLSCryptEmptyFile verifies an empty control-channel key file is rejected
// at parse time with a message naming the file, rather than passing the parser
// (non-nil, zero-length slice) and failing later inside Dial.
func TestTLSCryptEmptyFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, dir, "ca.pem", caInline())
	writeFile(t, dir, "empty.key", "")
	confPath := filepath.Join(dir, "client.ovpn")
	writeFile(t, dir, "client.ovpn", `client
dev tun
proto udp
remote vpn.example 1194
ca ca.pem
tls-crypt empty.key
`)
	_, err := ParseFile(confPath, nil)
	if err == nil {
		t.Fatal("expected error for empty tls-crypt key file")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error %q does not mention the empty key file", err)
	}
}

func TestStripComment(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in, want string
	}{
		{"key val # trailing", "key val "},
		{"key val ; semicolon", "key val "},
		{`name "has # inside"`, `name "has # inside"`},
		{"# pure comment", ""},
		{"", ""},
	} {
		if got := stripComment(tc.in); got != tc.want {
			t.Errorf("stripComment(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExternalFileRefs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, dir, "ca.pem", caInline())
	writeFile(t, dir, "ta.key", tlsCryptInline())
	writeFile(t, dir, "auth.txt", "alice\ns3cret\n")

	confPath := filepath.Join(dir, "client.ovpn")
	writeFile(t, dir, "client.ovpn", `client
dev tun
proto udp
remote vpn.example 1194
ca ca.pem
tls-crypt ta.key
auth-user-pass auth.txt
`)

	p, err := ParseFile(confPath, nil)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if p.Config.TLSConfig.RootCAs == nil {
		t.Error("RootCAs not loaded from ca.pem")
	}
	if len(p.Config.TLSCryptV1) == 0 {
		t.Error("TLSCryptV1 not loaded from ta.key")
	}
	if p.Config.Username != "alice" || p.Config.Password != "s3cret" {
		t.Errorf("creds=%q/%q, want alice/s3cret", p.Config.Username, p.Config.Password)
	}
	if !p.AuthUserPass {
		t.Error("AuthUserPass=false")
	}
}

func TestUnknownDirectiveWarns(t *testing.T) {
	t.Parallel()
	var warns []string
	src := `client
dev tun
proto udp
remote vpn.example 1194
some-unknown-directive arg1 arg2
<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`
	p, err := Parse(strings.NewReader(src), &ParseOptions{
		Warn: func(line int, dir, reason string) { warns = append(warns, dir+":"+reason) },
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Config.RemoteAddr != "vpn.example:1194" {
		t.Errorf("RemoteAddr=%q", p.Config.RemoteAddr)
	}
	if len(warns) == 0 {
		t.Error("expected warning for unknown directive")
	}
}

func TestServerNameOverride(t *testing.T) {
	t.Parallel()
	src := `client
dev tun
proto udp
remote 192.0.2.1 1194
<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`
	p, err := Parse(strings.NewReader(src), &ParseOptions{
		ServerNameOverride: "vpn-name",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Config.TLSConfig.ServerName != "vpn-name" {
		t.Errorf("ServerName=%q, want vpn-name", p.Config.TLSConfig.ServerName)
	}
}

// slicesEqual compares two []string slices for exact equality (order matters).
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// --- fixture helpers — kept small to keep test code readable ---

// pkiMu protects lazy generation of caPEM/certPEM/keyPEM below.
var (
	pkiMu     sync.Mutex
	cachedCA  string
	cachedCrt string
	cachedKey string
)

// generatePKI lazily mints a CA + leaf ECDSA cert/key pair for tests. Real
// PEM so crypto/tls.X509KeyPair and crypto/x509.AppendCertsFromPEM accept it.
func generatePKI() (caPEM, certPEM, keyPEM string) {
	pkiMu.Lock()
	defer pkiMu.Unlock()
	if cachedCA != "" {
		return cachedCA, cachedCrt, cachedKey
	}

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	cachedCA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "fake-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	cachedCrt = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	leafKeyDER, _ := x509.MarshalECPrivateKey(leafKey)
	cachedKey = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}))
	return cachedCA, cachedCrt, cachedKey
}

func caInline() string {
	ca, _, _ := generatePKI()
	return ca
}

func certInline() string {
	_, crt, _ := generatePKI()
	return crt
}

func keyInline() string {
	_, _, key := generatePKI()
	return key
}

// tlsCryptInline returns a valid OpenVPN tls-crypt static key body, 256 hex
// bytes wrapped between BEGIN/END markers.
func tlsCryptInline() string {
	return `
-----BEGIN OpenVPN Static key V1-----
6acef03f62675b4b1bbd03e53b187727
423cea742242106cb2916a8a4c829756
3d22c7e5cef430b1103c6f66eb1fc5b3
75a672f158e2e2e936c3faa48b035a6d
e17beaac23b5f03b10b868d53d03521d
8ba115059da777a60cbfd7b2c9c57472
78a15b8f6e68a3ef7fd583ec9f398c8b
d4735dab40cbd1e3c62a822e97489186
c30a0b48c7c38ea32ceb056d3fa5a710
e10ccc7a0ddb363b08c3d2777a3395e1
0c0b6080f56309192ab5aacd4b45f55d
a61fc77af39bd81a19218a79762c3386
2df55785075f37d8c71dc8a42097ee43
344739a0dd48d03025b0450cf1fb5e8c
aeb893d9a96d1f15519bb3c4dcb40ee3
16672ea16c012664f8a9f11255518deb
-----END OpenVPN Static key V1-----
`
}

// Ensure compile-time access (currently unused but useful for future tests).
var _ = errors.New

// scrambleConfigSrc builds a minimal-but-valid .ovpn config that adds
// the supplied `scramble` directive line. The other directives are kept
// to the bare minimum the parser accepts.
func scrambleConfigSrc(scrambleLine string) string {
	return `client
dev tun
proto udp
remote vpn.example 1194
verify-x509-name test-server name
` + scrambleLine + `
<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`
}

func TestParseScrambleObfuscate(t *testing.T) {
	t.Parallel()
	p, err := Parse(strings.NewReader(scrambleConfigSrc("scramble obfuscate mysecret")), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Config.Scramble == nil {
		t.Fatal("Scramble nil, want populated")
	}
	if p.Config.Scramble.Mode != openvpn.ScrambleObfuscate {
		t.Errorf("Mode=%v, want ScrambleObfuscate", p.Config.Scramble.Mode)
	}
	if !bytes.Equal(p.Config.Scramble.Key, []byte("mysecret")) {
		t.Errorf("Key=%q, want %q", p.Config.Scramble.Key, "mysecret")
	}
}

func TestParseScrambleXormask(t *testing.T) {
	t.Parallel()
	p, err := Parse(strings.NewReader(scrambleConfigSrc("scramble xormask hunter2")), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Config.Scramble == nil {
		t.Fatal("Scramble nil, want populated")
	}
	if p.Config.Scramble.Mode != openvpn.ScrambleXorMask {
		t.Errorf("Mode=%v, want ScrambleXorMask", p.Config.Scramble.Mode)
	}
	if !bytes.Equal(p.Config.Scramble.Key, []byte("hunter2")) {
		t.Errorf("Key=%q, want %q", p.Config.Scramble.Key, "hunter2")
	}
}

func TestParseScrambleXorPtrPos(t *testing.T) {
	t.Parallel()
	p, err := Parse(strings.NewReader(scrambleConfigSrc("scramble xorptrpos")), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Config.Scramble == nil {
		t.Fatal("Scramble nil, want populated")
	}
	if p.Config.Scramble.Mode != openvpn.ScrambleXorPtrPos {
		t.Errorf("Mode=%v, want ScrambleXorPtrPos", p.Config.Scramble.Mode)
	}
	if len(p.Config.Scramble.Key) != 0 {
		t.Errorf("Key=%q, want empty for xorptrpos", p.Config.Scramble.Key)
	}
}

func TestParseScrambleReverse(t *testing.T) {
	t.Parallel()
	p, err := Parse(strings.NewReader(scrambleConfigSrc("scramble reverse")), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Config.Scramble == nil {
		t.Fatal("Scramble nil, want populated")
	}
	if p.Config.Scramble.Mode != openvpn.ScrambleReverse {
		t.Errorf("Mode=%v, want ScrambleReverse", p.Config.Scramble.Mode)
	}
	if len(p.Config.Scramble.Key) != 0 {
		t.Errorf("Key=%q, want empty for reverse", p.Config.Scramble.Key)
	}
}

func TestParseScrambleErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		directive   string
		wantContain string
	}{
		{"missing mode", "scramble", "mode required"},
		{"obfuscate without secret", "scramble obfuscate", "secret required"},
		{"xormask without secret", "scramble xormask", "secret required"},
		{"unknown mode", "scramble bogus mysecret", "unknown mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(strings.NewReader(scrambleConfigSrc(tc.directive)), nil)
			if err == nil {
				t.Fatalf("Parse: nil error, want error containing %q", tc.wantContain)
			}
			if !strings.Contains(err.Error(), tc.wantContain) {
				t.Fatalf("err=%q, want substring %q", err, tc.wantContain)
			}
		})
	}
}

func TestParseScrambleAbsent(t *testing.T) {
	t.Parallel()
	// scrambleConfigSrc with an empty extra line — no scramble directive.
	p, err := Parse(strings.NewReader(scrambleConfigSrc("")), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Config.Scramble != nil {
		t.Errorf("Scramble=%+v, want nil", p.Config.Scramble)
	}
}

// tlsAuthConfigSrc builds a minimal-but-valid tls-auth profile, splicing in
// the supplied extra directive lines (e.g. `key-direction 1`, `auth SHA256`).
func tlsAuthConfigSrc(extraLines string) string {
	return `client
dev tun
proto udp
remote vpn.example 1194
verify-x509-name test-server name
` + extraLines + `
<tls-auth>` + tlsCryptInline() + `</tls-auth>
`
}

func TestParseTLSAuthInline(t *testing.T) {
	t.Parallel()
	p, err := Parse(strings.NewReader(tlsAuthConfigSrc("key-direction 1")), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Config.TLSAuth) == 0 {
		t.Fatal("TLSAuth not populated from inline <tls-auth>")
	}
	if len(p.Config.TLSCryptV1) != 0 || len(p.Config.TLSCryptV2) != 0 {
		t.Error("tls-crypt fields unexpectedly set for a tls-auth profile")
	}
	if p.Config.KeyDirection != 1 {
		t.Errorf("KeyDirection=%d, want 1", p.Config.KeyDirection)
	}
}

func TestParseKeyDirectionValues(t *testing.T) {
	t.Parallel()
	for _, kd := range []int{0, 1} {
		p, err := Parse(strings.NewReader(tlsAuthConfigSrc("key-direction "+strconv.Itoa(kd))), nil)
		if err != nil {
			t.Fatalf("key-direction %d: Parse: %v", kd, err)
		}
		if p.Config.KeyDirection != kd {
			t.Errorf("KeyDirection=%d, want %d", p.Config.KeyDirection, kd)
		}
	}
	// Absent key-direction in a tls-auth profile defaults to 1.
	p, err := Parse(strings.NewReader(tlsAuthConfigSrc("auth SHA256")), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Config.KeyDirection != 1 {
		t.Errorf("default KeyDirection=%d, want 1", p.Config.KeyDirection)
	}
	if p.Config.Auth != "SHA256" {
		t.Errorf("Auth=%q, want SHA256", p.Config.Auth)
	}
	// Invalid key-direction is rejected.
	if _, err := Parse(strings.NewReader(tlsAuthConfigSrc("key-direction 2")), nil); err == nil {
		t.Error("expected error on key-direction 2")
	}
}

func TestParseTLSAuthFileForm(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, dir, "ta.key", tlsCryptInline())
	writeFile(t, dir, "client.ovpn", `client
dev tun
proto udp
remote vpn.example 1194
verify-x509-name test-server name
tls-auth ta.key 1
`)
	p, err := ParseFile(filepath.Join(dir, "client.ovpn"), nil)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(p.Config.TLSAuth) == 0 {
		t.Fatal("TLSAuth not loaded from ta.key")
	}
	if p.Config.KeyDirection != 1 {
		t.Errorf("KeyDirection=%d, want 1 (from `tls-auth ta.key 1`)", p.Config.KeyDirection)
	}
}

func TestParseCipherNoneTolerated(t *testing.T) {
	t.Parallel()
	p, err := Parse(strings.NewReader(tlsAuthConfigSrc("cipher none")), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Config.Ciphers) != 0 {
		t.Errorf("Ciphers=%v, want empty (NCP defaults)", p.Config.Ciphers)
	}
	// `none` mixed into data-ciphers is dropped, keeping the rest.
	p2, err := Parse(strings.NewReader(tlsAuthConfigSrc("data-ciphers AES-256-GCM:none")), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p2.Config.Ciphers) != 1 || p2.Config.Ciphers[0] != "AES-256-GCM" {
		t.Errorf("Ciphers=%v, want [AES-256-GCM]", p2.Config.Ciphers)
	}
}

func TestParseSetenvUV(t *testing.T) {
	t.Parallel()
	p, err := Parse(strings.NewReader(tlsAuthConfigSrc(
		"setenv UV_LOCAL_ID_0 token-xyz\nsetenv FORWARD_COMPATIBLE 1")), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := p.Config.PeerInfoExtra["UV_LOCAL_ID_0"]; got != "token-xyz" {
		t.Errorf("UV_LOCAL_ID_0=%q, want token-xyz", got)
	}
	if _, ok := p.Config.PeerInfoExtra["FORWARD_COMPATIBLE"]; ok {
		t.Error("non-UV setenv leaked into PeerInfoExtra")
	}
}

func TestParseTLSAuthCryptMutualExclusion(t *testing.T) {
	t.Parallel()
	src := `client
dev tun
proto udp
remote vpn.example 1194
verify-x509-name test-server name
<tls-auth>` + tlsCryptInline() + `</tls-auth>
<tls-crypt>` + tlsCryptInline() + `</tls-crypt>
`
	if _, err := Parse(strings.NewReader(src), nil); err == nil {
		t.Fatal("expected mutual-exclusion error for tls-auth + tls-crypt")
	}
}

// TestParseObfuscatedTLSAuthProfile is a smoke test over a profile that
// combines every obfuscated-provider trait at once: scramble obfuscate +
// tls-auth + key-direction + cipher none + setenv UV_*. It proves they all
// coexist and map onto Config correctly.
func TestParseObfuscatedTLSAuthProfile(t *testing.T) {
	t.Parallel()
	src := `client
dev tun
proto udp
remote vpn.example 110
verify-x509-name test-server name
remote-cert-tls server
auth-user-pass
cipher none
scramble obfuscate 831066042faf541ac9f25c7b5914d8ff
setenv UV_LOCAL_ID_0 device-token-abc
<tls-auth>` + tlsCryptInline() + `</tls-auth>
key-direction 1
`
	p, err := Parse(strings.NewReader(src), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Config.TLSAuth) == 0 {
		t.Error("TLSAuth empty")
	}
	if p.Config.KeyDirection != 1 {
		t.Errorf("KeyDirection=%d, want 1", p.Config.KeyDirection)
	}
	if p.Config.Scramble == nil || p.Config.Scramble.Mode != openvpn.ScrambleObfuscate {
		t.Error("scramble obfuscate not parsed")
	}
	if len(p.Config.Ciphers) != 0 {
		t.Errorf("Ciphers=%v, want empty (cipher none dropped)", p.Config.Ciphers)
	}
	if got := p.Config.PeerInfoExtra["UV_LOCAL_ID_0"]; got != "device-token-abc" {
		t.Errorf("UV_LOCAL_ID_0=%q, want device-token-abc", got)
	}
}
