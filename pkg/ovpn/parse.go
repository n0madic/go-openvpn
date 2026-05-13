// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ovpn parses OpenVPN .ovpn configuration files into a ready-to-use
// openvpn.Config for the go-openvpn client library.
//
// Coverage focuses on the modern 2.6+ profile that this library actually
// supports: TLS+NCP, AEAD ciphers, tls-crypt v1/v2. Legacy directives
// (compression, tls-auth, BF-CBC, dev tap, static-key-only) are rejected.
// Comfort directives (persist-key, nobind, etc.) are silently accepted.
package ovpn

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/n0madic/go-openvpn"
)

// Remote is one `remote HOST PORT [proto]` line.
type Remote struct {
	Host string
	Port string
	// Proto is the per-remote protocol override ("udp", "tcp", "tcp-client",
	// or "" if not specified — caller should fall back to the global Proto).
	Proto string
}

// Addr returns the host:port form. Uses net.JoinHostPort so unbracketed
// IPv6 literals are correctly wrapped (e.g. "2001:db8::1" → "[2001:db8::1]:1194")
// and any existing brackets on the host are normalized away first.
func (r Remote) Addr() string {
	h := r.Host
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	return net.JoinHostPort(h, r.Port)
}

// normalizeProto maps OpenVPN's proto keywords ("tcp", "tcp-client",
// "tcp4-client", "udp6", ...) to the values openvpn.Config.Network expects
// ("tcp" or "udp"). Returns "" for unknown values so callers can fall back.
func normalizeProto(p string) string {
	switch p {
	case "udp", "udp4", "udp6":
		return "udp"
	case "tcp", "tcp-client", "tcp4-client", "tcp6-client", "tcp4", "tcp6":
		return "tcp"
	}
	return ""
}

// Parsed bundles a ready-to-use openvpn.Config with the metadata that didn't
// fit into the Config (e.g. the full list of `remote` lines).
type Parsed struct {
	// Config is ready to hand to openvpn.Dial. If the source file had
	// `auth-user-pass` without a file argument, Config.Username and
	// Config.Password are empty — the caller is expected to populate them
	// before dialing.
	Config *openvpn.Config

	// Remotes is the complete list of remotes from the file. Config.RemoteAddr
	// points at one of them (the first one, unless `remote-random` set or
	// ParseOptions.PickRemote returned a different one).
	Remotes []Remote

	// AuthUserPass is true iff the file declared `auth-user-pass`. When the
	// directive had a file argument, the parser read it and set
	// Config.Username / Config.Password; otherwise the caller must.
	AuthUserPass bool

	// Path of the source file (when ParseFile was used), empty otherwise.
	SourcePath string
}

// ParseOptions tweaks parser behavior.
type ParseOptions struct {
	// BaseDir is the directory to resolve relative file references against
	// (`ca myCa.pem`, `tls-crypt ta.key`, etc.). Defaults to the directory
	// containing the source file when ParseFile is used; "." otherwise.
	BaseDir string

	// Username / Password populate Config.Username/Password when the file
	// declares `auth-user-pass`. Optional — caller can also set them on
	// the returned Config after parsing.
	Username string
	Password string

	// ServerNameOverride sets TLSConfig.ServerName explicitly, overriding
	// any `verify-x509-name`. Useful when the OVPN file has no SNI hint
	// and the dial target is an IP.
	ServerNameOverride string

	// PickRemote chooses one of the parsed remotes. nil = pick the first
	// (or a random one if the file declares `remote-random`).
	PickRemote func([]Remote) Remote

	// Logger optionally receives diagnostic warnings about ignored
	// directives. nil = silent. Not propagated into Config.Logger — that
	// remains the caller's responsibility.
	Warn func(line int, directive, reason string)
}

// Parse reads an OpenVPN config from r.
func Parse(r io.Reader, opt *ParseOptions) (*Parsed, error) {
	if opt == nil {
		opt = &ParseOptions{}
	}
	if opt.BaseDir == "" {
		opt.BaseDir = "."
	}
	st := newState(opt)
	if err := st.run(r); err != nil {
		return nil, err
	}
	return st.finalize()
}

// ParseFile is a convenience wrapper that resolves relative file references
// against the directory of path.
func ParseFile(path string, opt *ParseOptions) (*Parsed, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	if opt == nil {
		opt = &ParseOptions{}
	}
	if opt.BaseDir == "" {
		opt.BaseDir = filepath.Dir(path)
	}
	p, err := Parse(f, opt)
	if err != nil {
		return nil, err
	}
	p.SourcePath = path
	return p, nil
}

// MaxInlineBytesTotal caps the cumulative byte-size of all inline blocks
// in a single .ovpn file. Prevents a hostile config from exhausting memory
// by stacking many large <ca>/<cert>/<key> blocks (each up to 8MB on its
// own via the scanner buffer).
const MaxInlineBytesTotal = 16 * 1024 * 1024

// parseState carries everything the dispatch table accumulates.
type parseState struct {
	opt *ParseOptions

	proto        string // udp / tcp
	remotes      []Remote
	remoteRand   bool
	cipher       string
	dataCiphers  []string
	reneg        time.Duration
	tlsMinVer    uint16
	tlsMaxVer    uint16
	serverName   string
	authUserPass bool

	caPEMs   [][]byte
	certPEM  []byte
	keyPEM   []byte
	tlsCrypt []byte
	tlsCV2   []byte

	// inlineBytesTotal tracks cumulative bytes consumed by inline blocks
	// across the whole file (bounded by MaxInlineBytesTotal).
	inlineBytesTotal int
}

func newState(opt *ParseOptions) *parseState {
	return &parseState{opt: opt}
}

// run iterates over the input and dispatches each directive.
func (s *parseState) run(r io.Reader) error {
	sc := bufio.NewScanner(r)
	// Allow large inline cert/key blocks (8MB upper bound).
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)

	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		line := stripComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Inline block start? `<tag>` (possibly with whitespace after).
		if name, ok := openTag(line); ok {
			content, endLine, err := readInlineBlock(sc, name, lineNo)
			if err != nil {
				return fmt.Errorf("line %d: %w", lineNo, err)
			}
			s.inlineBytesTotal += len(content)
			if s.inlineBytesTotal > MaxInlineBytesTotal {
				return fmt.Errorf("line %d: cumulative inline-block size exceeds %d bytes (hostile or malformed config?)", lineNo, MaxInlineBytesTotal)
			}
			if err := s.handleInline(name, content, lineNo); err != nil {
				return fmt.Errorf("line %d: %w", lineNo, err)
			}
			lineNo = endLine
			continue
		}

		tokens, err := tokenize(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		if len(tokens) == 0 {
			continue
		}
		name, args := tokens[0], tokens[1:]
		if err := s.handleDirective(name, args, lineNo); err != nil {
			return fmt.Errorf("line %d (%s): %w", lineNo, name, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	return nil
}

// stripComment removes anything after the first unquoted # or ; that starts
// a comment. OpenVPN treats both `;` and `#` as comment leaders.
func stripComment(s string) string {
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		if c == '#' || c == ';' {
			return s[:i]
		}
	}
	return s
}

// openTag matches `<name>` at the start of a line. Returns the bare tag
// name (no angle brackets) and whether the line is exclusively that tag.
func openTag(line string) (string, bool) {
	if len(line) < 3 || line[0] != '<' {
		return "", false
	}
	if line[1] == '/' {
		return "", false
	}
	end := strings.IndexByte(line, '>')
	if end < 0 {
		return "", false
	}
	// The tag must be the entire trimmed line.
	if end+1 != len(line) {
		return "", false
	}
	name := line[1:end]
	if name == "" {
		return "", false
	}
	return name, true
}

// readInlineBlock consumes lines until it sees the matching `</tag>`. The
// returned content is the verbatim text between the opening and closing tag,
// with one trailing newline appended to each line (so it works for both PEM
// and hex-encoded keys). endLine is the line number of the closing tag.
func readInlineBlock(sc *bufio.Scanner, name string, startLine int) ([]byte, int, error) {
	closing := "</" + name + ">"
	var out []byte
	line := startLine
	for sc.Scan() {
		line++
		raw := sc.Text()
		if strings.TrimSpace(raw) == closing {
			return out, line, nil
		}
		out = append(out, raw...)
		out = append(out, '\n')
	}
	if err := sc.Err(); err != nil {
		return nil, line, fmt.Errorf("scan inside <%s>: %w", name, err)
	}
	return nil, line, fmt.Errorf("unterminated <%s> block (started at line %d)", name, startLine)
}

// tokenize splits a line into whitespace-separated tokens, with support for
// double-quoted strings.
func tokenize(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case !inQuote && (c == ' ' || c == '\t'):
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if inQuote {
		return nil, errors.New("unterminated quoted string")
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out, nil
}

// warn is a small helper to surface a non-fatal diagnostic via the option's
// Warn callback (if set).
func (s *parseState) warn(line int, directive, reason string) {
	if s.opt.Warn != nil {
		s.opt.Warn(line, directive, reason)
	}
}

// handleInline processes a `<name>...</name>` block.
func (s *parseState) handleInline(name string, content []byte, line int) error {
	switch name {
	case "ca":
		s.caPEMs = append(s.caPEMs, content)
	case "cert":
		s.certPEM = content
	case "key":
		s.keyPEM = content
	case "tls-crypt":
		s.tlsCrypt = content
	case "tls-crypt-v2":
		s.tlsCV2 = content
	case "tls-auth":
		return errors.New("tls-auth is not supported (use tls-crypt or tls-crypt-v2)")
	case "secret":
		return errors.New("static-key mode is not supported (TLS+NCP only)")
	case "connection":
		// `<connection>` blocks describe alternative endpoints; we treat
		// them as inert and rely on `remote` directives in the outer scope.
		s.warn(line, name, "ignored inline <connection> block")
	default:
		s.warn(line, name, "ignored unknown inline block")
	}
	return nil
}

// handleDirective dispatches a single keyword line.
func (s *parseState) handleDirective(name string, args []string, line int) error {
	switch name {
	// ---- transport / endpoint ----
	case "proto":
		return s.setProto(args)
	case "remote":
		return s.addRemote(args)
	case "remote-random":
		s.remoteRand = true
	case "rport", "lport", "local", "nobind":
		// rport/lport could matter for future use; nobind is a no-op for us.

	// ---- ciphers / negotiation ----
	case "cipher":
		if len(args) != 1 {
			return errors.New("cipher: expected one argument")
		}
		s.cipher = args[0]
	case "data-ciphers", "ncp-ciphers":
		if len(args) != 1 {
			return fmt.Errorf("%s: expected one argument", name)
		}
		for c := range strings.SplitSeq(args[0], ":") {
			c = strings.TrimSpace(c)
			if c != "" {
				s.dataCiphers = append(s.dataCiphers, c)
			}
		}
	case "auth":
		// We don't validate or apply auth — modern AEAD has its own MAC,
		// and tls-crypt has its own HMAC. Accepted silently.
		_ = args

	// ---- TLS / cert ----
	case "ca":
		return s.loadCAFile(args)
	case "cert":
		return s.loadCertFile(args)
	case "key":
		return s.loadKeyFile(args)
	case "tls-crypt":
		return s.loadTLSCryptFile(args, false)
	case "tls-crypt-v2":
		return s.loadTLSCryptFile(args, true)
	case "tls-auth":
		return errors.New("tls-auth is not supported (use tls-crypt or tls-crypt-v2)")
	case "tls-version-min":
		return s.setTLSMin(args)
	case "tls-version-max":
		return s.setTLSMax(args)
	case "verify-x509-name":
		return s.setVerifyName(args)
	case "remote-cert-tls":
		// Equivalent to `--remote-cert-eku "TLS Web Server Authentication"`;
		// Go's TLS verification already requires server EKU on the server
		// cert when ServerName is set. Treat as enforced default.

	// ---- timing / rekey ----
	case "reneg-sec", "reneg-bytes", "reneg-pkts":
		if name == "reneg-sec" {
			return s.setRenegSec(args)
		}
		s.warn(line, name, "ignored (use --reneg-sec)")
	case "keepalive", "ping", "ping-restart", "ping-exit", "hand-window",
		"tran-window", "explicit-exit-notify":
		// All accepted silently — explicit-exit-notify is always on; the
		// rest are handshake-only/keep-alive overrides that the server's
		// PUSH_REPLY ultimately drives.

	// ---- auth ----
	case "auth-user-pass":
		s.authUserPass = true
		if len(args) == 1 {
			if err := s.readAuthFile(args[0]); err != nil {
				return err
			}
		} else if len(args) > 1 {
			return errors.New("auth-user-pass: expected 0 or 1 argument")
		}
	case "auth-retry":
		// Modes nointeract|interact|none — not relevant to a non-interactive
		// library. Accept silently.

	// ---- compression (rejected, modern policy) ----
	case "comp-lzo":
		if len(args) == 1 && (args[0] == "no" || args[0] == "off") {
			return nil
		}
		return errors.New("comp-lzo is not supported (compression is disabled)")
	case "compress":
		if len(args) == 0 || args[0] == "stub-v2" || args[0] == "" {
			// `compress` without args, or `compress stub-v2`, is what
			// modern ProtonVPN-style configs use to disable comp. OK.
			return nil
		}
		return fmt.Errorf("compress %s is not supported", args[0])

	// ---- topology hints ----
	case "dev":
		if len(args) == 1 && strings.HasPrefix(args[0], "tap") {
			return errors.New("dev tap is not supported (tun mode only)")
		}
		// dev tun / dev tunN → accepted
	case "dev-type":
		if len(args) == 1 && args[0] == "tap" {
			return errors.New("dev-type tap is not supported (tun mode only)")
		}
	case "topology":
		// Accepted silently — server's PUSH_REPLY topology is authoritative.

	// ---- noise (silently ignored) ----
	case "client", "tls-client", "pull", "nopull",
		"persist-key", "persist-tun", "resolv-retry",
		"setenv", "script-security", "mute", "mute-replay-warnings",
		"verb", "auth-nocache", "key-direction",
		"tun-mtu", "tun-mtu-extra", "link-mtu", "fragment", "mssfix",
		"route", "route-gateway", "route-metric", "route-delay",
		"route-noexec", "redirect-gateway", "redirect-private",
		"dhcp-option", "register-dns",
		"sndbuf", "rcvbuf", "fast-io",
		"connect-retry", "connect-retry-max", "connect-timeout",
		"replay-window", "key-method", "tls-cipher", "tls-ciphersuites":
		// no-op — these are either client convenience flags, kernel-tun
		// concerns, or duplicates of options the server pushes anyway.

	default:
		s.warn(line, name, "ignored unknown directive")
	}
	return nil
}

// setProto maps OpenVPN's proto keyword onto our Network field.
func (s *parseState) setProto(args []string) error {
	if len(args) != 1 {
		return errors.New("proto: expected one argument")
	}
	if args[0] == "tcp-server" {
		return errors.New("proto tcp-server is not supported (client mode only)")
	}
	n := normalizeProto(args[0])
	if n == "" {
		return fmt.Errorf("proto: unsupported value %q", args[0])
	}
	s.proto = n
	return nil
}

// addRemote handles `remote HOST [PORT [PROTO]]`. Default port is 1194.
func (s *parseState) addRemote(args []string) error {
	if len(args) == 0 {
		return errors.New("remote: expected at least HOST")
	}
	r := Remote{Host: args[0], Port: "1194"}
	if len(args) >= 2 {
		// Validate port number.
		if _, err := strconv.Atoi(args[1]); err != nil {
			return fmt.Errorf("remote: invalid port %q", args[1])
		}
		r.Port = args[1]
	}
	if len(args) >= 3 {
		r.Proto = args[2]
	}
	s.remotes = append(s.remotes, r)
	return nil
}

func (s *parseState) setRenegSec(args []string) error {
	if len(args) != 1 {
		return errors.New("reneg-sec: expected one argument")
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("reneg-sec: invalid number %q", args[0])
	}
	if n < 0 {
		return fmt.Errorf("reneg-sec: negative value %d", n)
	}
	s.reneg = time.Duration(n) * time.Second
	return nil
}

func (s *parseState) setTLSMin(args []string) error {
	if len(args) == 0 {
		return errors.New("tls-version-min: expected version")
	}
	v, err := tlsVersionFromString(args[0])
	if err != nil {
		return err
	}
	s.tlsMinVer = v
	return nil
}

func (s *parseState) setTLSMax(args []string) error {
	if len(args) == 0 {
		return errors.New("tls-version-max: expected version")
	}
	v, err := tlsVersionFromString(args[0])
	if err != nil {
		return err
	}
	s.tlsMaxVer = v
	return nil
}

func tlsVersionFromString(s string) (uint16, error) {
	switch s {
	case "1.0", "1.1":
		return 0, fmt.Errorf("TLS %s is no longer supported (minimum is TLS 1.2)", s)
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version %q", s)
	}
}

// setVerifyName handles `verify-x509-name NAME [type]`.
// We only support type == "name" (or no type) — modeling it as
// TLSConfig.ServerName, which Go matches against SAN/CN.
func (s *parseState) setVerifyName(args []string) error {
	if len(args) == 0 {
		return errors.New("verify-x509-name: expected NAME")
	}
	if len(args) >= 2 && args[1] != "name" {
		return fmt.Errorf("verify-x509-name type %q is not supported (only \"name\")", args[1])
	}
	s.serverName = args[0]
	return nil
}

// readAuthFile reads a 2-line username/password file.
func (s *parseState) readAuthFile(rel string) error {
	path := s.resolvePath(rel)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("auth-user-pass: %w", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	var user, pass string
	if sc.Scan() {
		user = sc.Text()
	}
	if sc.Scan() {
		pass = sc.Text()
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("auth-user-pass: %w", err)
	}
	if user == "" || pass == "" {
		return errors.New("auth-user-pass file must have two non-empty lines")
	}
	s.opt.Username = user
	s.opt.Password = pass
	return nil
}

// loadCAFile loads `ca FILE` or accepts inline marker (already handled).
func (s *parseState) loadCAFile(args []string) error {
	if len(args) != 1 {
		return errors.New("ca: expected one argument (file path)")
	}
	b, err := os.ReadFile(s.resolvePath(args[0]))
	if err != nil {
		return fmt.Errorf("ca: %w", err)
	}
	s.caPEMs = append(s.caPEMs, b)
	return nil
}

func (s *parseState) loadCertFile(args []string) error {
	if len(args) != 1 {
		return errors.New("cert: expected one argument (file path)")
	}
	b, err := os.ReadFile(s.resolvePath(args[0]))
	if err != nil {
		return fmt.Errorf("cert: %w", err)
	}
	s.certPEM = b
	return nil
}

func (s *parseState) loadKeyFile(args []string) error {
	if len(args) != 1 {
		return errors.New("key: expected one argument (file path)")
	}
	b, err := os.ReadFile(s.resolvePath(args[0]))
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	s.keyPEM = b
	return nil
}

func (s *parseState) loadTLSCryptFile(args []string, v2 bool) error {
	if len(args) < 1 {
		return errors.New("tls-crypt: expected one argument (file path)")
	}
	b, err := os.ReadFile(s.resolvePath(args[0]))
	if err != nil {
		return fmt.Errorf("tls-crypt: %w", err)
	}
	if v2 {
		s.tlsCV2 = b
	} else {
		s.tlsCrypt = b
	}
	return nil
}

func (s *parseState) resolvePath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.opt.BaseDir, p)
}

// finalize turns the accumulated state into an openvpn.Config + metadata.
func (s *parseState) finalize() (*Parsed, error) {
	if len(s.remotes) == 0 {
		return nil, errors.New("no `remote` directive in file")
	}
	if s.proto == "" {
		s.proto = "udp"
	}
	if s.tlsCrypt == nil && s.tlsCV2 == nil {
		return nil, errors.New("missing tls-crypt or tls-crypt-v2 (this library requires modern control-channel encryption)")
	}
	if s.tlsCrypt != nil && s.tlsCV2 != nil {
		return nil, errors.New("both tls-crypt and tls-crypt-v2 set; only one may be active")
	}

	picked := s.pickRemote()

	tlsCfg := &tls.Config{}
	if s.tlsMinVer != 0 {
		tlsCfg.MinVersion = s.tlsMinVer
	} else {
		tlsCfg.MinVersion = tls.VersionTLS12
	}
	if s.tlsMaxVer != 0 {
		tlsCfg.MaxVersion = s.tlsMaxVer
	}
	var serverNameForCheck string
	switch {
	case s.opt.ServerNameOverride != "":
		tlsCfg.ServerName = s.opt.ServerNameOverride
		serverNameForCheck = s.opt.ServerNameOverride
	case s.serverName != "":
		tlsCfg.ServerName = s.serverName
		serverNameForCheck = s.serverName
	case isHostname(picked.Host):
		// Use the picked host as SNI / verification target.
		tlsCfg.ServerName = picked.Host
		serverNameForCheck = picked.Host
	}

	if len(s.caPEMs) > 0 {
		pool := x509.NewCertPool()
		for i, pemBytes := range s.caPEMs {
			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, fmt.Errorf("ca[%d]: no certificates parsed (PEM malformed?)", i)
			}
		}
		tlsCfg.RootCAs = pool
	}

	// When neither verify-x509-name nor a hostname-style remote nor an
	// explicit ServerNameOverride is available, replicate OpenVPN's default
	// behavior: verify the certificate chain (against RootCAs), require the
	// server TLS Web Server EKU (matching `remote-cert-tls server`), but
	// skip CN/SAN hostname matching. crypto/tls forces an explicit policy
	// in this case — InsecureSkipVerify alone would also drop chain
	// verification, so we install a VerifyConnection callback that does the
	// chain check ourselves.
	if serverNameForCheck == "" {
		// Surface a warning when the user has no <ca> AND no
		// verify-x509-name / hostname remote: with roots==nil, x509.Verify
		// falls back to the system trust store, which may or may not be
		// what the operator intended. Loud, single warning.
		if len(s.caPEMs) == 0 && tlsCfg.RootCAs == nil {
			s.warn(0, "ca", "no <ca> in config and no verify-x509-name; server cert will be verified against the system CA pool (set verify-x509-name or provide a <ca> block to be explicit)")
		}
		tlsCfg.InsecureSkipVerify = true
		roots := tlsCfg.RootCAs
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("ovpn: no peer certificate presented")
			}
			opts := x509.VerifyOptions{
				Roots:         roots,
				Intermediates: x509.NewCertPool(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			for _, c := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}
			if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
				return fmt.Errorf("ovpn: server cert verify: %w", err)
			}
			return nil
		}
	}
	if s.certPEM != nil || s.keyPEM != nil {
		if s.certPEM == nil || s.keyPEM == nil {
			return nil, errors.New("client cert/key pair incomplete (one of <cert>/<key> missing)")
		}
		pair, err := tls.X509KeyPair(s.certPEM, s.keyPEM)
		if err != nil {
			return nil, fmt.Errorf("client cert/key pair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}

	// Cipher list: prefer data-ciphers; fall back to cipher singleton.
	ciphers := s.dataCiphers
	if len(ciphers) == 0 && s.cipher != "" {
		ciphers = []string{s.cipher}
	}
	if err := validateCiphers(ciphers); err != nil {
		return nil, err
	}

	// Per-remote proto wins over the global `proto` line — e.g. `remote
	// vpn.example 443 tcp` must dial TCP even if the file opens with
	// `proto udp`. Normalize OpenVPN's aliases to "tcp"/"udp"; fall back to
	// the global proto when picked.Proto is empty or unrecognized.
	network := s.proto
	if n := normalizeProto(picked.Proto); n != "" {
		network = n
	}

	cfg := &openvpn.Config{
		Network:    network,
		RemoteAddr: picked.Addr(),
		TLSConfig:  tlsCfg,
		TLSCryptV1: s.tlsCrypt,
		TLSCryptV2: s.tlsCV2,
		Ciphers:    ciphers,
		Reneg:      s.reneg,
		Username:   s.opt.Username,
		Password:   s.opt.Password,
	}

	return &Parsed{
		Config:       cfg,
		Remotes:      append([]Remote(nil), s.remotes...),
		AuthUserPass: s.authUserPass,
	}, nil
}

// pickRemote returns the configured Remote, honoring PickRemote if set and
// `remote-random` otherwise.
func (s *parseState) pickRemote() Remote {
	if s.opt.PickRemote != nil {
		return s.opt.PickRemote(s.remotes)
	}
	if s.remoteRand && len(s.remotes) > 1 {
		return s.remotes[rand.IntN(len(s.remotes))]
	}
	return s.remotes[0]
}

// isHostname returns true if h is a DNS name (not an IPv4/IPv6 literal).
// Bracketed IPv6 literals like "[2001:db8::1]" are stripped before parsing.
func isHostname(h string) bool {
	if h == "" {
		return false
	}
	probe := h
	if len(probe) >= 2 && probe[0] == '[' && probe[len(probe)-1] == ']' {
		probe = probe[1 : len(probe)-1]
	}
	_, err := netip.ParseAddr(probe)
	return err != nil
}

// validateCiphers checks that we recognise every cipher in the list as one
// our library can actually use (AEAD only).
func validateCiphers(cs []string) error {
	if len(cs) == 0 {
		return nil // empty = use library defaults
	}
	for _, c := range cs {
		switch c {
		case "AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305":
		default:
			return fmt.Errorf("cipher %q is not supported (AEAD only: AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305)", c)
		}
	}
	return nil
}
