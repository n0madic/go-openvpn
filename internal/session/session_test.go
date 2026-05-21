// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn/internal/control"
	"github.com/n0madic/go-openvpn/internal/data"
	"github.com/n0madic/go-openvpn/internal/proto"
	"github.com/n0madic/go-openvpn/internal/reliable"
	"github.com/n0madic/go-openvpn/internal/session"
	"github.com/n0madic/go-openvpn/internal/tlscrypt"
	"github.com/n0madic/go-openvpn/internal/transport"
)

// TestFirstPingAES256GCM verifies that a client opens a session
// against a self-built server simulator, sends an IP packet through Tunnel,
// and reads back the echoed packet — exercising every layer end-to-end.
func TestFirstPingAES256GCM(t *testing.T) { runPingWithCipher(t, "AES-256-GCM") }

// TestFirstPingChaCha20 verifies that the server forces a
// non-default cipher via PUSH_REPLY (after the client has advertised it in
// IV_CIPHERS) and the same echo round-trip succeeds — proving NCP works.
func TestFirstPingChaCha20(t *testing.T) { runPingWithCipher(t, "CHACHA20-POLY1305") }

// TestFirstPingAES128GCM exercises the smaller-key AEAD variant.
func TestFirstPingAES128GCM(t *testing.T) { runPingWithCipher(t, "AES-128-GCM") }

// TestDialWithTransportNoNetworkHint verifies that DialWithTransport works
// when Network and RemoteAddr are empty. That is the injected-transport
// case: those fields are only hints to a caller-supplied TransportDialer and
// the session never dials a socket itself, so validateConfig must not
// require them.
func TestDialWithTransportNoNetworkHint(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	if _, err := rand.Read(staticKey[:]); err != nil {
		t.Fatal(err)
	}
	serverWrap, err := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)
	if err != nil {
		t.Fatal(err)
	}

	cTr, sTr := transport.MemoryPair()
	cert, pool := genSelfSignedCert(t)

	const peerID = uint32(7)
	go func() {
		_ = runServerWithDataEcho(ctx, sTr, serverWrap, cert, peerID, "AES-256-GCM", t)
	}()

	// Network and RemoteAddr deliberately left empty.
	sess, err := session.DialWithTransport(ctx, session.Config{
		TLSConfig:  &tls.Config{ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13},
		TLSCryptV1: staticKey[:],
		Ciphers:    []string{"AES-256-GCM"},
	}, cTr)
	if err != nil {
		t.Fatalf("DialWithTransport with empty Network/RemoteAddr: %v", err)
	}
	defer func() { _ = sess.Close() }()

	payload := []byte("ping over injected transport")
	if _, err := sess.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 1500)
	done := make(chan error, 1)
	go func() {
		n, err := sess.Read(buf)
		if err == nil && !bytes.Equal(buf[:n], payload) {
			err = fmt.Errorf("echo mismatch: got %q", buf[:n])
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("read timed out")
	}
}

// TestServerRESTART verifies that when the server sends a RESTART control
// message after handshake, the client surfaces it as openvpn.RestartError
// from Read/Write.
func TestServerRESTART(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	serverWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)

	cTr, sTr := transport.MemoryPair()
	cert, pool := genSelfSignedCert(t)

	go func() {
		_ = runServerWithRESTART(ctx, sTr, serverWrap, cert, t)
	}()

	sess, err := session.DialWithTransport(ctx, session.Config{
		Network:    "memory",
		RemoteAddr: "memB",
		TLSConfig:  &tls.Config{ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13},
		TLSCryptV1: staticKey[:],
		Ciphers:    []string{"AES-256-GCM"},
	}, cTr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	// Wait for the simulator to send RESTART; Read should unblock with
	// the typed error.
	buf := make([]byte, 1500)
	rch := make(chan error, 1)
	go func() {
		_, err := sess.Read(buf)
		rch <- err
	}()

	select {
	case err := <-rch:
		var re *session.RestartError
		if !errors.As(err, &re) {
			t.Fatalf("got %v, want *RestartError", err)
		}
		if re.Reason != "server-initiated reboot" {
			t.Errorf("Reason = %q, want %q", re.Reason, "server-initiated reboot")
		}
		if re.Delay != 30*time.Second {
			t.Errorf("Delay = %s, want 30s", re.Delay)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Read did not return RestartError within 10s")
	}
}

// TestExitNotifySent verifies that Client.Close() sends "EXIT\0" over the
// TLS control channel.
func TestExitNotifySent(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	serverWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)

	cTr, sTr := transport.MemoryPair()
	cert, pool := genSelfSignedCert(t)

	gotExit := make(chan string, 1)
	go func() {
		_ = runServerCapturingExit(ctx, sTr, serverWrap, cert, gotExit, t)
	}()

	sess, err := session.DialWithTransport(ctx, session.Config{
		Network:    "memory",
		RemoteAddr: "memB",
		TLSConfig:  &tls.Config{ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13},
		TLSCryptV1: staticKey[:],
		Ciphers:    []string{"AES-256-GCM"},
	}, cTr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Brief wait for the server simulator to be ready post-handshake.
	time.Sleep(100 * time.Millisecond)

	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case got := <-gotExit:
		if got != "EXIT" {
			t.Errorf("server saw %q, want EXIT", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive EXIT within 5s")
	}
}

// TestFirstPingTLSCryptV2 verifies that a client uses a
// tls-crypt-v2 client bundle (Kc + WKc) instead of a raw static key.
// The server unwraps WKc with its master key to recover Kc, then proceeds
// with normal v1-style wrap/unwrap using Kc.
func TestFirstPingTLSCryptV2(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	// Server master keys + a fresh Kc + minimal metadata (timestamp type).
	var ka, ke [32]byte
	rand.Read(ka[:])
	rand.Read(ke[:])
	var kc [tlscrypt.StaticKeyLen]byte
	rand.Read(kc[:])
	wkc, err := tlscrypt.WrapWKc(kc, []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 1}, ka, ke)
	if err != nil {
		t.Fatal(err)
	}
	bundle := tlscrypt.EncodeClientBundleV2(kc, wkc)

	cTr, sTr := transport.MemoryPair()
	cert, pool := genSelfSignedCert(t)
	const peerID = uint32(7)
	const cipher = "AES-256-GCM"

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- runServerWithTLSCryptV2(ctx, sTr, ka, ke, cert, peerID, cipher, t)
	}()

	cfg := session.Config{
		Network:    "memory",
		RemoteAddr: "memB",
		TLSConfig: &tls.Config{
			ServerName: "localhost",
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		},
		TLSCryptV2: bundle,
		Ciphers:    []string{cipher},
	}
	sess, err := session.DialWithTransport(ctx, cfg, cTr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	payload := []byte("v2 echo!")
	if _, err := sess.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	rch := make(chan []byte, 1)
	go func() {
		n, _ := sess.Read(buf)
		rch <- buf[:n]
	}()
	select {
	case got := <-rch:
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch: %q vs %q", got, payload)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("echo timeout")
	}
	_ = sess.Close()
	select {
	case <-serverErrCh:
	case <-time.After(2 * time.Second):
	}
}

func runPingWithCipher(t *testing.T, cipher string) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	// Shared tls-crypt key (raw 256B for simplicity).
	var staticKey [tlscrypt.StaticKeyLen]byte
	if _, err := rand.Read(staticKey[:]); err != nil {
		t.Fatal(err)
	}
	serverWrap, err := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)
	if err != nil {
		t.Fatal(err)
	}

	// Memory transport pair. Client takes cTr; server simulator takes sTr.
	cTr, sTr := transport.MemoryPair()

	cert, pool := genSelfSignedCert(t)

	// Server simulator: full handshake + AEAD echo loop.
	const peerID = uint32(42)
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- runServerWithDataEcho(ctx, sTr, serverWrap, cert, peerID, cipher, t)
	}()

	// Client session — advertise all three ciphers in priority order; server
	// picks the one we asked it to test.
	cfg := session.Config{
		Network:    "memory", // ignored when using DialWithTransport
		RemoteAddr: "memB",
		TLSConfig: &tls.Config{
			ServerName: "localhost",
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		},
		TLSCryptV1: staticKey[:],
		Ciphers:    []string{"AES-256-GCM", "CHACHA20-POLY1305", "AES-128-GCM"},
	}
	sess, err := session.DialWithTransport(ctx, cfg, cTr)
	if err != nil {
		t.Fatalf("client Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	// Send an "IP packet" (test payload).
	payload := []byte("ICMP echo request")
	if _, err := sess.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Receive the echoed packet.
	buf := make([]byte, 1500)
	readDone := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := sess.Read(buf)
		readDone <- struct {
			n   int
			err error
		}{n, err}
	}()

	select {
	case r := <-readDone:
		if r.err != nil {
			t.Fatalf("Read: %v", r.err)
		}
		if !bytes.Equal(buf[:r.n], payload) {
			t.Fatalf("got %q, want %q", buf[:r.n], payload)
		}
	case <-ctx.Done():
		t.Fatal("read timed out")
	}

	// Verify PushReply was parsed.
	pr := sess.PushReply()
	if pr.PeerID != peerID {
		t.Errorf("PeerID = %d, want %d", pr.PeerID, peerID)
	}
	if pr.Cipher != cipher {
		t.Errorf("Cipher = %q, want %q", pr.Cipher, cipher)
	}

	_ = sess.Close()

	// Give server a moment to wrap up.
	select {
	case err := <-serverErrCh:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, transport.ErrClosed) {
			t.Logf("server returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Log("server goroutine still running on test exit")
	}
}

// runServerWithDataEcho runs a one-shot server that completes the handshake
// then echoes back every P_DATA_V2 packet (after AEAD round-trip). A single
// reader goroutine owns the transport and demuxes control/data; outbound
// control goes through a writer goroutine; data outbound is synchronous from
// the echo path.
func runServerWithDataEcho(
	ctx context.Context,
	tr transport.PacketConn,
	wrap *tlscrypt.Wrapper,
	cert tls.Certificate,
	peerID uint32,
	cipher string,
	t *testing.T,
) error {
	t.Helper()

	layer := reliable.New(reliable.Config{LocalSessionID: 0x5E5E5E5E5E5E5E5E})

	// Active data slot is set after handshake; until then data packets are
	// dropped (they shouldn't arrive that early anyway).
	var slotMu sync.Mutex
	var activeSlot *data.Slot
	getSlot := func() *data.Slot {
		slotMu.Lock()
		defer slotMu.Unlock()
		return activeSlot
	}

	pumpCtx, pumpCancel := context.WithCancel(ctx)
	defer pumpCancel()

	// Reader: demuxes control vs data.
	go func() {
		for {
			pkt, err := tr.ReadPacket(pumpCtx)
			if err != nil {
				return
			}
			if len(pkt) < 1 {
				continue
			}
			opcode, _ := proto.UnpackOpcodeKID(pkt[0])
			if opcode.IsData() {
				slot := getSlot()
				if slot == nil {
					continue
				}
				plain, err := slot.Open(pkt)
				if err != nil {
					t.Logf("server open: %v", err)
					continue
				}
				echo, err := slot.Seal(plain)
				if err != nil {
					t.Logf("server seal: %v", err)
					continue
				}
				if err := tr.WritePacket(pumpCtx, echo); err != nil {
					return
				}
				continue
			}
			// Control: unwrap, parse, feed reliability.
			opcodeKID, sid, _, plain, err := wrap.Unwrap(pkt)
			if err != nil {
				continue
			}
			_, kid := proto.UnpackOpcodeKID(opcodeKID)
			in := reliable.InPacket{Opcode: opcode, KeyID: kid, SessionID: sid}
			if opcode == proto.PAckV1 {
				ap, err := proto.ParseAckPayload(plain)
				if err != nil {
					continue
				}
				in.Ack = ap
			} else {
				cp, err := proto.ParseControlPayload(plain)
				if err != nil {
					continue
				}
				in.Payload = cp
			}
			_ = layer.HandleInbound(in)
		}
	}()

	// Writer: drains reliable.Outbound → wrap → transport.
	go func() {
		for {
			select {
			case <-pumpCtx.Done():
				return
			case out, ok := <-layer.Outbound():
				if !ok {
					return
				}
				var body []byte
				var err error
				if out.IsAck() {
					body, err = proto.MarshalAckPayload(out.Ack)
				} else {
					body, err = proto.MarshalControlPayload(out.Payload)
				}
				if err != nil {
					return
				}
				opcodeKID := proto.PackOpcodeKID(out.Opcode, out.KeyID)
				wrapped := wrap.Wrap(opcodeKID, out.SessionID, body)
				if err := tr.WritePacket(pumpCtx, wrapped); err != nil {
					return
				}
			}
		}
	}()

	// Ticker.
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-pumpCtx.Done():
				return
			case <-ticker.C:
				if err := layer.Tick(); err != nil {
					return
				}
			}
		}
	}()

	if err := layer.SendHardReset(proto.PControlHardResetServerV2); err != nil {
		return err
	}

	adapter := reliable.NewAdapter(layer, tr.LocalAddr(), tr.RemoteAddr())
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	tlsConn := tls.Server(adapter, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	defer func() { _ = tlsConn.Close() }()

	if _, err := control.ReadKeyMethod2(tlsConn, false, false); err != nil {
		return err
	}

	serverKM := proto.KeyMethod2{
		IsServer: true,
		Options:  "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto UDPv4,cipher " + cipher + ",auth SHA256,keysize 256,key-method 2,tls-server",
		PeerInfo: "IV_VER=2.6.0\n",
	}
	rand.Read(serverKM.Random1[:])
	rand.Read(serverKM.Random2[:])
	serverKMBytes, _ := proto.MarshalKeyMethod2(serverKM)
	if _, err := tlsConn.Write(serverKMBytes); err != nil {
		return err
	}

	msg, err := control.ReadControlMessage(tlsConn)
	if err != nil {
		return err
	}
	if msg != "PUSH_REQUEST" {
		return errors.New("expected PUSH_REQUEST, got: " + msg)
	}
	pushReply := "PUSH_REPLY,ifconfig 10.8.0.6 255.255.255.0,topology subnet,peer-id " + itoa(peerID) +
		",cipher " + cipher + ",tun-mtu 1500,ping 10,ping-restart 60"
	if err := control.WriteControlMessage(tlsConn, pushReply); err != nil {
		return err
	}

	// Derive EKM keys and build server-side data slot (mirror of client).
	cs := tlsConn.ConnectionState()
	mat, err := cs.ExportKeyingMaterial(control.ExportLabel, nil, control.DataKeyMaterialLen)
	if err != nil {
		return err
	}
	keyLen := 32 // AES-256-GCM
	if cipher == "AES-128-GCM" {
		keyLen = 16
	}
	// Client uses: Send=c2s, Recv=s2c. Server uses opposite.
	serverSlot, err := data.NewSlot(data.SlotConfig{
		KeyID:   0,
		PeerID:  peerID,
		Cipher:  cipher,
		SendKey: mat[128 : 128+keyLen], // s2c (server outbound)
		SendIV:  [data.ImplicitIVLen]byte(mat[192 : 192+data.ImplicitIVLen]),
		RecvKey: mat[0:keyLen], // c2s (server inbound)
		RecvIV:  [data.ImplicitIVLen]byte(mat[64 : 64+data.ImplicitIVLen]),
	})
	if err != nil {
		return err
	}
	// Install the slot — the reader goroutine starts echoing data packets.
	slotMu.Lock()
	activeSlot = serverSlot
	slotMu.Unlock()

	// Block until ctx is done; reader/writer/ticker goroutines do all work.
	<-ctx.Done()
	return ctx.Err()
}

// itoa is the minimal stand-in for strconv.Itoa, kept inline to avoid an
// extra import for the single use.
func itoa(u uint32) string {
	if u == 0 {
		return "0"
	}
	var b [11]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}

// runServerWithTLSCryptV2 is the v2 variant: the first packet is
// HARD_RESET_CLIENT_V3 with a WKc trailer; we unwrap it with master keys to
// recover Kc, build a v1-style wrapper, then proceed exactly like
// runServerWithDataEcho.
func runServerWithTLSCryptV2(
	ctx context.Context,
	tr transport.PacketConn,
	ka, ke [32]byte,
	cert tls.Certificate,
	peerID uint32,
	cipher string,
	t *testing.T,
) error {
	t.Helper()

	// Block on the first packet — it must be HARD_RESET_CLIENT_V3 with WKc.
	first, err := tr.ReadPacket(ctx)
	if err != nil {
		return err
	}
	if len(first) < 2 {
		return errors.New("server v2: first packet too short")
	}
	op, _ := proto.UnpackOpcodeKID(first[0])
	if op != proto.PControlHardResetClientV3 {
		return fmt.Errorf("server v2: expected HARD_RESET_CLIENT_V3, got %s", op)
	}
	wkcLen := int(uint16(first[len(first)-2])<<8 | uint16(first[len(first)-1]))
	if wkcLen > len(first) || wkcLen < tlscrypt.V2MinWKcLen {
		return fmt.Errorf("server v2: bad WKc length %d in packet of %d bytes", wkcLen, len(first))
	}
	wkc := first[len(first)-wkcLen:]
	innerPkt := first[:len(first)-wkcLen]

	kc, _, err := tlscrypt.UnwrapWKc(wkc, ka, ke)
	if err != nil {
		return fmt.Errorf("server v2: unwrap WKc: %w", err)
	}
	wrap, err := tlscrypt.New(kc, tlscrypt.DirectionNormal)
	if err != nil {
		return err
	}

	// Unwrap the inner packet and stash it for the reader goroutine to
	// process — we synthesise it back into the read pipeline below.
	opcodeKID, sid, _, plain, err := wrap.Unwrap(innerPkt)
	if err != nil {
		return fmt.Errorf("server v2: unwrap inner: %w", err)
	}

	layer := reliable.New(reliable.Config{LocalSessionID: 0xABCDEF0123456789})

	// Feed the bootstrap packet to the reliability layer manually before
	// starting the goroutines (so subsequent acks/handshake can flow).
	op2, kid := proto.UnpackOpcodeKID(opcodeKID)
	cp, err := proto.ParseControlPayload(plain)
	if err != nil {
		return fmt.Errorf("server v2: parse bootstrap payload: %w", err)
	}
	_ = layer.HandleInbound(reliable.InPacket{
		Opcode: op2, KeyID: kid, SessionID: sid, Payload: cp,
	})

	// Now identical to v1 path.
	return continueServerSim(ctx, layer, tr, wrap, cert, peerID, cipher, t)
}

// continueServerSim factors the post-bootstrap server logic shared between
// the v1 and v2 paths. It owns the transport from this point forward.
func continueServerSim(
	ctx context.Context,
	layer *reliable.Layer,
	tr transport.PacketConn,
	wrap *tlscrypt.Wrapper,
	cert tls.Certificate,
	peerID uint32,
	cipher string,
	t *testing.T,
) error {
	t.Helper()
	var slotMu sync.Mutex
	var activeSlot *data.Slot
	getSlot := func() *data.Slot { slotMu.Lock(); defer slotMu.Unlock(); return activeSlot }

	pumpCtx, pumpCancel := context.WithCancel(ctx)
	defer pumpCancel()

	go func() {
		for {
			pkt, err := tr.ReadPacket(pumpCtx)
			if err != nil {
				return
			}
			if len(pkt) < 1 {
				continue
			}
			opcode, _ := proto.UnpackOpcodeKID(pkt[0])
			if opcode.IsData() {
				slot := getSlot()
				if slot == nil {
					continue
				}
				plain, err := slot.Open(pkt)
				if err != nil {
					continue
				}
				echo, err := slot.Seal(plain)
				if err != nil {
					return
				}
				_ = tr.WritePacket(pumpCtx, echo)
				continue
			}
			opcodeKID, sid, _, plain, err := wrap.Unwrap(pkt)
			if err != nil {
				continue
			}
			_, kid := proto.UnpackOpcodeKID(opcodeKID)
			in := reliable.InPacket{Opcode: opcode, KeyID: kid, SessionID: sid}
			if opcode == proto.PAckV1 {
				ap, err := proto.ParseAckPayload(plain)
				if err != nil {
					continue
				}
				in.Ack = ap
			} else {
				cp, err := proto.ParseControlPayload(plain)
				if err != nil {
					continue
				}
				in.Payload = cp
			}
			_ = layer.HandleInbound(in)
		}
	}()

	go func() {
		for {
			select {
			case <-pumpCtx.Done():
				return
			case out, ok := <-layer.Outbound():
				if !ok {
					return
				}
				var body []byte
				var err error
				if out.IsAck() {
					body, err = proto.MarshalAckPayload(out.Ack)
				} else {
					body, err = proto.MarshalControlPayload(out.Payload)
				}
				if err != nil {
					return
				}
				opcodeKID := proto.PackOpcodeKID(out.Opcode, out.KeyID)
				wrapped := wrap.Wrap(opcodeKID, out.SessionID, body)
				if err := tr.WritePacket(pumpCtx, wrapped); err != nil {
					return
				}
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-pumpCtx.Done():
				return
			case <-ticker.C:
				if err := layer.Tick(); err != nil {
					return
				}
			}
		}
	}()

	if err := layer.SendHardReset(proto.PControlHardResetServerV2); err != nil {
		return err
	}

	adapter := reliable.NewAdapter(layer, tr.LocalAddr(), tr.RemoteAddr())
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	tlsConn := tls.Server(adapter, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	defer func() { _ = tlsConn.Close() }()

	if _, err := control.ReadKeyMethod2(tlsConn, false, false); err != nil {
		return err
	}
	serverKM := proto.KeyMethod2{
		IsServer: true,
		Options:  "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto UDPv4,cipher " + cipher + ",auth SHA256,keysize 256,key-method 2,tls-server",
		PeerInfo: "IV_VER=2.6.0\n",
	}
	rand.Read(serverKM.Random1[:])
	rand.Read(serverKM.Random2[:])
	skBytes, _ := proto.MarshalKeyMethod2(serverKM)
	if _, err := tlsConn.Write(skBytes); err != nil {
		return err
	}
	msg, err := control.ReadControlMessage(tlsConn)
	if err != nil {
		return err
	}
	if msg != "PUSH_REQUEST" {
		return errors.New("expected PUSH_REQUEST")
	}
	pushReply := "PUSH_REPLY,ifconfig 10.8.0.6 255.255.255.0,topology subnet,peer-id " + itoa(peerID) +
		",cipher " + cipher + ",tun-mtu 1500,ping 10,ping-restart 60"
	if err := control.WriteControlMessage(tlsConn, pushReply); err != nil {
		return err
	}

	cs := tlsConn.ConnectionState()
	mat, err := cs.ExportKeyingMaterial(control.ExportLabel, nil, control.DataKeyMaterialLen)
	if err != nil {
		return err
	}
	keyLen := 32
	if cipher == "AES-128-GCM" {
		keyLen = 16
	}
	serverSlot, err := data.NewSlot(data.SlotConfig{
		KeyID:   0,
		PeerID:  peerID,
		Cipher:  cipher,
		SendKey: mat[128 : 128+keyLen],
		SendIV:  [data.ImplicitIVLen]byte(mat[192 : 192+data.ImplicitIVLen]),
		RecvKey: mat[0:keyLen],
		RecvIV:  [data.ImplicitIVLen]byte(mat[64 : 64+data.ImplicitIVLen]),
	})
	if err != nil {
		return err
	}
	slotMu.Lock()
	activeSlot = serverSlot
	slotMu.Unlock()

	<-ctx.Done()
	return ctx.Err()
}

// TestRekeyMultipleCycles validates that the key-id rotation handles
// multiple rekeys: 0 → 1 → 2 → 3, with continuous data flow.
func TestRekeyMultipleCycles(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	serverWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)

	cTr, sTr := transport.MemoryPair()
	cert, pool := genSelfSignedCert(t)
	const peerID = uint32(22)
	const cipher = "CHACHA20-POLY1305"

	srvDone := make(chan error, 1)
	go func() {
		srvDone <- runRekeyAwareServer(ctx, sTr, serverWrap, cert, peerID, cipher, t)
	}()

	sess, err := session.DialWithTransport(ctx, session.Config{
		Network:    "memory",
		RemoteAddr: "memB",
		TLSConfig: &tls.Config{
			ServerName: "localhost",
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		},
		TLSCryptV1:       staticKey[:],
		Ciphers:          []string{cipher},
		TransitionWindow: 500 * time.Millisecond, // fast retirement for the test
	}, cTr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	for i := range 4 {
		echoCheck(t, sess, fmt.Appendf(nil, "gen-%d-before", i))
		if i == 3 {
			break
		}
		rkCtx, rkCancel := context.WithTimeout(ctx, 10*time.Second)
		err := sess.Rekey(rkCtx)
		rkCancel()
		if err != nil {
			t.Fatalf("rekey %d: %v", i, err)
		}
	}

	_ = sess.Close()
	cancel()
	select {
	case <-srvDone:
	case <-time.After(2 * time.Second):
	}
}

// TestRekeySoftReset verifies that an established session goes
// through one full soft-reset rekey cycle. After the rekey, data continues
// to flow encrypted under the new key-id with no packet loss.
func TestRekeySoftReset(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	serverWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)

	cTr, sTr := transport.MemoryPair()
	cert, pool := genSelfSignedCert(t)
	const peerID = uint32(11)
	const cipher = "AES-256-GCM"

	srvDone := make(chan error, 1)
	go func() {
		srvDone <- runRekeyAwareServer(ctx, sTr, serverWrap, cert, peerID, cipher, t)
	}()

	sess, err := session.DialWithTransport(ctx, session.Config{
		Network:    "memory",
		RemoteAddr: "memB",
		TLSConfig: &tls.Config{
			ServerName: "localhost",
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		},
		TLSCryptV1:       staticKey[:],
		Ciphers:          []string{cipher},
		TransitionWindow: 2 * time.Second,
	}, cTr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	// Pre-rekey echo round-trip on key-id 0.
	echoCheck(t, sess, []byte("before-rekey"))

	// Trigger rekey explicitly.
	rkCtx, rkCancel := context.WithTimeout(ctx, 15*time.Second)
	defer rkCancel()
	if err := sess.Rekey(rkCtx); err != nil {
		t.Fatalf("Rekey: %v", err)
	}

	// Post-rekey echo: must succeed on the new (key-id 1) slot.
	echoCheck(t, sess, []byte("after-rekey-1"))
	echoCheck(t, sess, []byte("after-rekey-2"))

	_ = sess.Close()
	select {
	case err := <-srvDone:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, transport.ErrClosed) {
			t.Logf("server returned: %v", err)
		}
	case <-time.After(2 * time.Second):
	}
}

func echoCheck(t *testing.T, sess *session.Session, payload []byte) {
	t.Helper()
	if _, err := sess.Write(payload); err != nil {
		t.Fatalf("Write %q: %v", payload, err)
	}
	buf := make([]byte, 1500)
	rch := make(chan []byte, 1)
	go func() {
		n, _ := sess.Read(buf)
		rch <- buf[:n]
	}()
	select {
	case got := <-rch:
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch: got %q want %q", got, payload)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("echo timeout for %q", payload)
	}
}

// runRekeyAwareServer is a server simulator that maintains its own per-key-id
// slot/layer tables and handles soft-reset rekey from the client.
func runRekeyAwareServer(
	ctx context.Context,
	tr transport.PacketConn,
	wrap *tlscrypt.Wrapper,
	cert tls.Certificate,
	peerID uint32,
	cipher string,
	t *testing.T,
) error {
	t.Helper()

	type serverState struct {
		mu     sync.Mutex
		layers map[uint8]*reliable.Layer
		slots  map[uint8]*data.Slot
		active uint8
	}
	state := &serverState{
		layers: make(map[uint8]*reliable.Layer),
		slots:  make(map[uint8]*data.Slot),
	}

	pumpCtx, pumpCancel := context.WithCancel(ctx)
	defer pumpCancel()

	// Active outbound slot accessor.
	activeSlot := func() *data.Slot {
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.slots[state.active]
	}
	getSlot := func(kid uint8) *data.Slot {
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.slots[kid]
	}
	getLayer := func(kid uint8) *reliable.Layer {
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.layers[kid]
	}
	installLayer := func(kid uint8, l *reliable.Layer) {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.layers[kid] = l
	}
	installSlot := func(s *data.Slot) {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.slots[s.KeyID] = s
		state.active = s.KeyID
	}

	startWriter := func(layer *reliable.Layer) {
		go func() {
			for {
				select {
				case <-pumpCtx.Done():
					return
				case out, ok := <-layer.Outbound():
					if !ok {
						return
					}
					var body []byte
					var err error
					if out.IsAck() {
						body, err = proto.MarshalAckPayload(out.Ack)
					} else {
						body, err = proto.MarshalControlPayload(out.Payload)
					}
					if err != nil {
						return
					}
					opcodeKID := proto.PackOpcodeKID(out.Opcode, out.KeyID)
					wrapped := wrap.Wrap(opcodeKID, out.SessionID, body)
					if err := tr.WritePacket(pumpCtx, wrapped); err != nil {
						return
					}
				}
			}
		}()
		go func() {
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-pumpCtx.Done():
					return
				case <-ticker.C:
					if err := layer.Tick(); err != nil {
						return
					}
				}
			}
		}()
	}

	// runServerHandshake performs the server-side TLS+KEY_METHOD 2 sequence
	// on a layer. For the initial handshake (initial=true) it also sends a
	// PUSH_REPLY; for a rekey it does not.
	runServerHandshake := func(layer *reliable.Layer, kid uint8, initial bool) error {
		adapter := reliable.NewAdapter(layer, tr.LocalAddr(), tr.RemoteAddr())
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
		tlsConn := tls.Server(adapter, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return err
		}
		// Server doesn't close tlsConn — used later for keying material.
		if _, err := control.ReadKeyMethod2(tlsConn, false, false); err != nil {
			return err
		}
		serverKM := proto.KeyMethod2{
			IsServer: true,
			Options:  "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto UDPv4,cipher " + cipher + ",auth SHA256,keysize 256,key-method 2,tls-server",
			PeerInfo: "IV_VER=2.6.0\n",
		}
		rand.Read(serverKM.Random1[:])
		rand.Read(serverKM.Random2[:])
		skBytes, _ := proto.MarshalKeyMethod2(serverKM)
		if _, err := tlsConn.Write(skBytes); err != nil {
			return err
		}
		if initial {
			msg, err := control.ReadControlMessage(tlsConn)
			if err != nil {
				return err
			}
			if msg != "PUSH_REQUEST" {
				return errors.New("expected PUSH_REQUEST")
			}
			pushReply := "PUSH_REPLY,ifconfig 10.8.0.6 255.255.255.0,topology subnet,peer-id " + itoa(peerID) +
				",cipher " + cipher + ",tun-mtu 1500,ping 10,ping-restart 60"
			if err := control.WriteControlMessage(tlsConn, pushReply); err != nil {
				return err
			}
		}
		cs := tlsConn.ConnectionState()
		mat, err := cs.ExportKeyingMaterial(control.ExportLabel, nil, control.DataKeyMaterialLen)
		if err != nil {
			return err
		}
		keyLen := 32
		if cipher == "AES-128-GCM" {
			keyLen = 16
		}
		slot, err := data.NewSlot(data.SlotConfig{
			KeyID:   kid,
			PeerID:  peerID,
			Cipher:  cipher,
			SendKey: mat[128 : 128+keyLen],
			SendIV:  [data.ImplicitIVLen]byte(mat[192 : 192+data.ImplicitIVLen]),
			RecvKey: mat[0:keyLen],
			RecvIV:  [data.ImplicitIVLen]byte(mat[64 : 64+data.ImplicitIVLen]),
		})
		if err != nil {
			return err
		}
		installSlot(slot)
		return nil
	}

	// Initial server layer (key-id 0).
	initialLayer := reliable.New(reliable.Config{LocalSessionID: 0x5E5E5E5E5E5E5E5E, InitialKeyID: 0})
	installLayer(0, initialLayer)
	startWriter(initialLayer)
	if err := initialLayer.SendHardReset(proto.PControlHardResetServerV2); err != nil {
		return err
	}

	// Reader goroutine: demuxes by key-id, spawns rekey handshakes.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			pkt, err := tr.ReadPacket(pumpCtx)
			if err != nil {
				return
			}
			if len(pkt) < 1 {
				continue
			}
			opcode, kid := proto.UnpackOpcodeKID(pkt[0])
			if opcode.IsData() {
				slot := getSlot(kid)
				if slot == nil {
					continue
				}
				plain, err := slot.Open(pkt)
				if err != nil {
					continue
				}
				echo, err := activeSlot().Seal(plain)
				if err != nil {
					return
				}
				_ = tr.WritePacket(pumpCtx, echo)
				continue
			}
			// Control packet — route to layer; create one on a new kid.
			layer := getLayer(kid)
			if layer == nil {
				newLayer := reliable.New(reliable.Config{
					LocalSessionID: 0x5E5E5E5E5E5E5E5E,
					InitialKeyID:   kid,
				})
				if sid, ok := initialLayer.RemoteSessionID(); ok {
					newLayer.SetRemoteSessionID(sid)
				}
				installLayer(kid, newLayer)
				startWriter(newLayer)
				// Spawn a server-side rekey handshake.
				go func(l *reliable.Layer, k uint8) {
					if err := runServerHandshake(l, k, false); err != nil {
						t.Logf("server rekey handshake (kid=%d): %v", k, err)
					}
				}(newLayer, kid)
				layer = newLayer
			}
			opcodeKID, sid, _, plain, err := wrap.Unwrap(pkt)
			if err != nil {
				continue
			}
			_, kid2 := proto.UnpackOpcodeKID(opcodeKID)
			in := reliable.InPacket{Opcode: opcode, KeyID: kid2, SessionID: sid}
			if opcode == proto.PAckV1 {
				ap, err := proto.ParseAckPayload(plain)
				if err != nil {
					continue
				}
				in.Ack = ap
			} else {
				cp, err := proto.ParseControlPayload(plain)
				if err != nil {
					continue
				}
				in.Payload = cp
			}
			_ = layer.HandleInbound(in)
		}
	}()

	// Initial server-side handshake.
	if err := runServerHandshake(initialLayer, 0, true); err != nil {
		return err
	}

	<-ctx.Done()
	<-readerDone
	return ctx.Err()
}

// runServerWithRESTART completes a handshake and then immediately writes a
// RESTART,30,server-initiated reboot control message to the client.
func runServerWithRESTART(
	ctx context.Context,
	tr transport.PacketConn,
	wrap *tlscrypt.Wrapper,
	cert tls.Certificate,
	t *testing.T,
) error {
	t.Helper()
	tlsConn, err := minimalServerHandshake(ctx, tr, wrap, cert, t)
	if err != nil {
		return err
	}
	defer func() { _ = tlsConn.Close() }()
	// After PUSH_REPLY, send RESTART to trigger client-side disconnect.
	return control.WriteControlMessage(tlsConn, "RESTART,30,server-initiated reboot")
}

// runServerCapturingExit completes a handshake and then reads the next
// control message, which should be "EXIT" emitted by the client on its
// Close().
func runServerCapturingExit(
	ctx context.Context,
	tr transport.PacketConn,
	wrap *tlscrypt.Wrapper,
	cert tls.Certificate,
	gotExit chan<- string,
	t *testing.T,
) error {
	t.Helper()
	tlsConn, err := minimalServerHandshake(ctx, tr, wrap, cert, t)
	if err != nil {
		return err
	}
	defer func() { _ = tlsConn.Close() }()
	msg, err := control.ReadControlMessage(tlsConn)
	if err != nil {
		return err
	}
	gotExit <- msg
	return nil
}

// minimalServerHandshake runs the server-side initial handshake (hard reset
// → TLS → KEY_METHOD 2 → PUSH_REPLY) and returns the open TLS conn for
// further control-channel reads/writes. Shared scaffolding for tests that
// exercise post-handshake server behaviour.
func minimalServerHandshake(
	ctx context.Context,
	tr transport.PacketConn,
	wrap *tlscrypt.Wrapper,
	cert tls.Certificate,
	t *testing.T,
) (*tls.Conn, error) {
	t.Helper()
	layer := reliable.New(reliable.Config{LocalSessionID: 0xDEADBEEFCAFE})

	pumpCtx, pumpCancel := context.WithCancel(ctx)
	go func() {
		<-pumpCtx.Done()
	}()
	_ = pumpCancel // released by ctx cascade

	// Reader: control packets only — this server doesn't echo data.
	go func() {
		for {
			pkt, err := tr.ReadPacket(pumpCtx)
			if err != nil {
				return
			}
			if len(pkt) < 1 {
				continue
			}
			opcode, kid := proto.UnpackOpcodeKID(pkt[0])
			if opcode.IsData() {
				continue
			}
			opcodeKID, sid, _, plain, err := wrap.Unwrap(pkt)
			if err != nil {
				continue
			}
			_ = opcodeKID
			in := reliable.InPacket{Opcode: opcode, KeyID: kid, SessionID: sid}
			if opcode == proto.PAckV1 {
				ap, err := proto.ParseAckPayload(plain)
				if err != nil {
					continue
				}
				in.Ack = ap
			} else {
				cp, err := proto.ParseControlPayload(plain)
				if err != nil {
					continue
				}
				in.Payload = cp
			}
			_ = layer.HandleInbound(in)
		}
	}()

	// Writer.
	go func() {
		for {
			select {
			case <-pumpCtx.Done():
				return
			case out, ok := <-layer.Outbound():
				if !ok {
					return
				}
				var body []byte
				var err error
				if out.IsAck() {
					body, err = proto.MarshalAckPayload(out.Ack)
				} else {
					body, err = proto.MarshalControlPayload(out.Payload)
				}
				if err != nil {
					return
				}
				wrapped := wrap.Wrap(proto.PackOpcodeKID(out.Opcode, out.KeyID), out.SessionID, body)
				if err := tr.WritePacket(pumpCtx, wrapped); err != nil {
					return
				}
			}
		}
	}()

	// Ticker.
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-pumpCtx.Done():
				return
			case <-ticker.C:
				if err := layer.Tick(); err != nil {
					return
				}
			}
		}
	}()

	if err := layer.SendHardReset(proto.PControlHardResetServerV2); err != nil {
		return nil, err
	}

	adapter := reliable.NewAdapter(layer, tr.LocalAddr(), tr.RemoteAddr())
	tlsConn := tls.Server(adapter, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if _, err := control.ReadKeyMethod2(tlsConn, false, false); err != nil {
		return nil, err
	}
	serverKM := proto.KeyMethod2{
		IsServer: true,
		Options:  "V4,dev-type tun,cipher AES-256-GCM,auth SHA256,key-method 2,tls-server",
		PeerInfo: "IV_VER=2.6.0\n",
	}
	rand.Read(serverKM.Random1[:])
	rand.Read(serverKM.Random2[:])
	b, _ := proto.MarshalKeyMethod2(serverKM)
	if _, err := tlsConn.Write(b); err != nil {
		return nil, err
	}
	if _, err := control.ReadControlMessage(tlsConn); err != nil {
		return nil, err
	}
	pushReply := "PUSH_REPLY,ifconfig 10.8.0.6 255.255.255.0,topology subnet,peer-id 1,cipher AES-256-GCM,tun-mtu 1500,ping 10,ping-restart 60"
	if err := control.WriteControlMessage(tlsConn, pushReply); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func genSelfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ovpn-server"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return cert, pool
}
