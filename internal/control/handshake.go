// SPDX-License-Identifier: AGPL-3.0-or-later

package control

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/n0madic/go-openvpn/internal/proto"
	"github.com/n0madic/go-openvpn/internal/reliable"
	"github.com/n0madic/go-openvpn/internal/trace"
)

// ErrAuthFailed is returned when the server responds AUTH_FAILED to our
// PUSH_REQUEST (typically wrong username/password).
var ErrAuthFailed = errors.New("control: server replied AUTH_FAILED")

// Config configures Run.
type Config struct {
	// TLSConfig is used for the inner TLS 1.2/1.3 session. Must have
	// RootCAs, ServerName and (for mTLS — which OpenVPN always uses) at
	// least one client Certificate set.
	TLSConfig *tls.Config

	// Username/Password — only sent if either is non-empty, matching
	// OpenVPN's --auth-user-pass behaviour.
	Username, Password string

	// Ciphers is the colon-comma list we advertise in IV_CIPHERS, in
	// priority order. Defaults to AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM.
	Ciphers []string

	// PeerInfoExtra is merged into the peer-info field.
	PeerInfoExtra map[string]string

	// Proto is the wire transport name to advertise in the options-string
	// ("UDPv4", "UDPv6", "TCPv4_CLIENT", "TCPv6_CLIENT"). Defaults to UDPv4.
	Proto string

	// HardResetOpcode is the opcode used for the initial client packet —
	// PControlHardResetClientV2 for plain tls-crypt, V3 for tls-crypt-v2.
	HardResetOpcode proto.Opcode

	// PeerInfoVersion overrides IV_VER. Empty ⇒ proto.DefaultPeerInfo default.
	PeerInfoVersion string

	// Tracer, when non-nil, receives one HandshakeEvent at the start of
	// each handshake stage (nil Err) and one extra event with err!=nil
	// if the stage fails. A final StageComplete is emitted on success.
	// nil treated as a NoopTracer (zero overhead).
	Tracer trace.HandshakeTracer
}

// Result is what a successful Run returns.
type Result struct {
	TLSConn     *tls.Conn
	KeyMaterial DataKeyMaterial
	PushReply   proto.PushReply
	Cipher      string // negotiated AEAD cipher from PUSH_REPLY
	PeerID      uint32
	RemoteSID   uint64
	ServerKM2   proto.KeyMethod2 // diagnostic
}

// Run executes the full client-side OpenVPN 2.6+ handshake. layer must
// already be running (pumper attached) so packets actually flow.
//
// On success the returned TLSConn is open and ready for soft-reset
// renegotiation later in the session's lifetime; the caller owns its Close.
func Run(ctx context.Context, layer *reliable.Layer, localAddr, remoteAddr net.Addr, cfg Config) (*Result, error) {
	if cfg.TLSConfig == nil {
		return nil, errors.New("control: TLSConfig required")
	}
	if cfg.HardResetOpcode == 0 {
		cfg.HardResetOpcode = proto.PControlHardResetClientV2
	}
	if len(cfg.Ciphers) == 0 {
		cfg.Ciphers = []string{"AES-256-GCM", "CHACHA20-POLY1305", "AES-128-GCM"}
	}
	if cfg.Proto == "" {
		cfg.Proto = "UDPv4"
	}
	tracer := cfg.Tracer
	if tracer == nil {
		tracer = trace.NoopTracer{}
	}
	emit := func(stage trace.HandshakeStage, err error) {
		tracer.OnHandshakeEvent(trace.HandshakeEvent{
			Stage: stage,
			Time:  time.Now(),
			Err:   err,
		})
	}

	// 1. Send P_CONTROL_HARD_RESET_CLIENT_V2/V3.
	emit(trace.StageHardReset, nil)
	if err := layer.SendHardReset(cfg.HardResetOpcode); err != nil {
		err = fmt.Errorf("control: send hard reset: %w", err)
		emit(trace.StageHardReset, err)
		return nil, err
	}

	// 2. Run TLS handshake over the reliable layer.
	emit(trace.StageTLSHandshake, nil)
	adapter := reliable.NewAdapter(layer, localAddr, remoteAddr)
	tlsConn := tls.Client(adapter, cfg.TLSConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		err = fmt.Errorf("control: TLS handshake: %w", err)
		emit(trace.StageTLSHandshake, err)
		return nil, err
	}

	// 3. Build & send client KEY_METHOD 2.
	emit(trace.StageKeyMethod2Send, nil)
	authUserPass := cfg.Username != "" || cfg.Password != ""
	ciphersStr := strings.Join(cfg.Ciphers, ":")

	clientKM := proto.KeyMethod2{
		IsServer:     false,
		Options:      buildOptionsString(ciphersStr, cfg.Proto),
		AuthUserPass: authUserPass,
		Username:     cfg.Username,
		Password:     cfg.Password,
		PeerInfo:     buildPeerInfo(ciphersStr, cfg.PeerInfoVersion, cfg.PeerInfoExtra),
	}
	if _, err := rand.Read(clientKM.PreMaster[:]); err != nil {
		err = fmt.Errorf("control: gen pre_master: %w", err)
		emit(trace.StageKeyMethod2Send, err)
		return nil, err
	}
	if _, err := rand.Read(clientKM.Random1[:]); err != nil {
		err = fmt.Errorf("control: gen random1: %w", err)
		emit(trace.StageKeyMethod2Send, err)
		return nil, err
	}
	if _, err := rand.Read(clientKM.Random2[:]); err != nil {
		err = fmt.Errorf("control: gen random2: %w", err)
		emit(trace.StageKeyMethod2Send, err)
		return nil, err
	}
	clientKMBytes, err := proto.MarshalKeyMethod2(clientKM)
	if err != nil {
		err = fmt.Errorf("control: marshal client KEY_METHOD 2: %w", err)
		emit(trace.StageKeyMethod2Send, err)
		return nil, err
	}
	if _, err := tlsConn.Write(clientKMBytes); err != nil {
		err = fmt.Errorf("control: send client KEY_METHOD 2: %w", err)
		emit(trace.StageKeyMethod2Send, err)
		return nil, err
	}
	// pre_master is now embedded in the marshalled buffer (which crypto/tls
	// owns) and the struct copy in the goroutine stack. Zero both so a heap
	// dump or core file doesn't expose the secret long after the handshake.
	clear(clientKM.PreMaster[:])
	clear(clientKMBytes)

	// 4. Receive server's KEY_METHOD 2.
	emit(trace.StageKeyMethod2Recv, nil)
	serverKM, err := ReadKeyMethod2(tlsConn, true, false)
	if err != nil {
		err = fmt.Errorf("control: read server KEY_METHOD 2: %w", err)
		emit(trace.StageKeyMethod2Recv, err)
		return nil, err
	}

	// 5. Send PUSH_REQUEST.
	emit(trace.StagePushRequest, nil)
	if err := WriteControlMessage(tlsConn, "PUSH_REQUEST"); err != nil {
		err = fmt.Errorf("control: send PUSH_REQUEST: %w", err)
		emit(trace.StagePushRequest, err)
		return nil, err
	}

	// 6. Read response — PUSH_REPLY or AUTH_FAILED.
	emit(trace.StagePushReply, nil)
	msg, err := ReadControlMessage(tlsConn)
	if err != nil {
		err = fmt.Errorf("control: read response: %w", err)
		emit(trace.StagePushReply, err)
		return nil, err
	}
	if strings.HasPrefix(msg, "AUTH_FAILED") {
		err = fmt.Errorf("%w: %s", ErrAuthFailed, msg)
		emit(trace.StagePushReply, err)
		return nil, err
	}
	pushReply, err := proto.ParsePushReply(msg)
	if err != nil {
		err = fmt.Errorf("control: parse PUSH_REPLY: %w", err)
		emit(trace.StagePushReply, err)
		return nil, err
	}
	if pushReply.Cipher == "" {
		err = errors.New("control: PUSH_REPLY missing cipher")
		emit(trace.StagePushReply, err)
		return nil, err
	}
	if _, err := AEADKeyLen(pushReply.Cipher); err != nil {
		emit(trace.StagePushReply, err)
		return nil, err
	}

	// 7. Derive data-channel keys via TLS-EKM.
	emit(trace.StageDataKeys, nil)
	cs := tlsConn.ConnectionState()
	keys, err := DeriveDataKeys(cs)
	if err != nil {
		emit(trace.StageDataKeys, err)
		return nil, err
	}

	emit(trace.StageComplete, nil)
	remoteSID, _ := layer.RemoteSessionID()
	return &Result{
		TLSConn:     tlsConn,
		KeyMaterial: keys,
		PushReply:   pushReply,
		Cipher:      pushReply.Cipher,
		PeerID:      pushReply.PeerID,
		RemoteSID:   remoteSID,
		ServerKM2:   serverKM,
	}, nil
}

// buildOptionsString assembles the options field server-side parses for the
// (mostly cosmetic) OCC consistency check. Most directives are overridden by
// NCP+PUSH_REPLY anyway; the server logs but doesn't reject on mismatch.
func buildOptionsString(ciphers, proto string) string {
	return strings.Join([]string{
		"V4",
		"dev-type tun",
		"link-mtu 1559",
		"tun-mtu 1500",
		"proto " + proto,
		// "cipher" must name one of the IV_CIPHERS list; the server
		// updates it via PUSH_REPLY anyway.
		"cipher " + firstCipher(ciphers),
		"auth SHA256",
		"keysize 256",
		"key-method 2",
		"tls-client",
	}, ",")
}

// buildPeerInfo combines the default IV_* fields with caller-supplied extras
// and returns the NUL-terminated string for the peer_info field. version
// overrides IV_VER (empty ⇒ proto default).
func buildPeerInfo(ciphers, version string, extra map[string]string) string {
	pi := proto.DefaultPeerInfo(ciphers)
	if version != "" {
		pi.Set("IV_VER", version)
	}
	for k, v := range extra {
		pi.Set(k, v)
	}
	return pi.Encode()
}

// firstCipher returns the first cipher in a colon-separated list.
func firstCipher(s string) string {
	head, _, _ := strings.Cut(s, ":")
	return head
}
