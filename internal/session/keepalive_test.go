// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
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

// keepaliveServer is a configurable test server simulator for keepalive
// behaviour: it can be told what `ping`/`ping-restart` directives to push,
// whether to echo client data, and exposes channels to observe inbound
// PINGs/data and to inject server→client data packets.
type keepaliveServer struct {
	pingInterval int  // seconds; 0 = don't push
	pingRestart  int  // seconds; 0 = don't push
	echoData     bool // echo non-PING data back

	recvPing chan struct{}
	recvData chan []byte
	inject   chan []byte
}

func newKeepaliveServer() *keepaliveServer {
	return &keepaliveServer{
		recvPing: make(chan struct{}, 64),
		recvData: make(chan []byte, 64),
		inject:   make(chan []byte, 8),
	}
}

func (ks *keepaliveServer) run(
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

	var slotMu sync.Mutex
	var activeSlot *data.Slot
	getSlot := func() *data.Slot { slotMu.Lock(); defer slotMu.Unlock(); return activeSlot }

	pumpCtx, pumpCancel := context.WithCancel(ctx)
	defer pumpCancel()

	// Reader: control vs data.
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
				if proto.IsPing(plain) {
					select {
					case ks.recvPing <- struct{}{}:
					default:
					}
					continue
				}
				buf := append([]byte(nil), plain...)
				select {
				case ks.recvData <- buf:
				default:
				}
				if ks.echoData {
					if echo, err := slot.Seal(buf); err == nil {
						_ = tr.WritePacket(pumpCtx, echo)
					}
				}
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
					continue
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
	if _, err := control.ReadControlMessage(tlsConn); err != nil {
		return err
	}
	pushReply := "PUSH_REPLY,ifconfig 10.8.0.6 255.255.255.0,topology subnet,peer-id " +
		itoa(peerID) + ",cipher " + cipher + ",tun-mtu 1500"
	if ks.pingInterval > 0 {
		pushReply += ",ping " + itoa(uint32(ks.pingInterval))
	}
	if ks.pingRestart > 0 {
		pushReply += ",ping-restart " + itoa(uint32(ks.pingRestart))
	}
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

	// Inject pump: feed plaintext from ks.inject as sealed data packets.
	go func() {
		for {
			select {
			case <-pumpCtx.Done():
				return
			case payload, ok := <-ks.inject:
				if !ok {
					return
				}
				sealed, err := serverSlot.Seal(payload)
				if err != nil {
					continue
				}
				_ = tr.WritePacket(pumpCtx, sealed)
			}
		}
	}()

	<-ctx.Done()
	return ctx.Err()
}

// TestKeepalivePingSent verifies that the client periodically transmits the
// OpenVPN PING magic on the data channel when the server pushes `ping N`.
func TestKeepalivePingSent(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	serverWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)
	cert, pool := genSelfSignedCert(t)
	cTr, sTr := transport.MemoryPair()

	ks := newKeepaliveServer()
	ks.pingInterval = 1
	ks.pingRestart = 60
	ks.echoData = false

	srvDone := make(chan error, 1)
	go func() { srvDone <- ks.run(ctx, sTr, serverWrap, cert, 11, "AES-256-GCM", t) }()

	sess, err := session.DialWithTransport(ctx, session.Config{
		Network:    "memory",
		RemoteAddr: "memB",
		TLSConfig: &tls.Config{
			ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13,
		},
		TLSCryptV1: staticKey[:],
		Ciphers:    []string{"AES-256-GCM"},
	}, cTr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	// Expect at least 2 pings within ~3.5s (ping=1s).
	deadline := time.After(3500 * time.Millisecond)
	pings := 0
loop:
	for pings < 2 {
		select {
		case <-ks.recvPing:
			pings++
		case <-deadline:
			break loop
		}
	}
	if pings < 2 {
		t.Fatalf("got %d PINGs in 3.5s, want >=2", pings)
	}
}

// TestKeepaliveIncomingFiltered verifies that incoming PING packets are
// consumed by the session and never surfaced through Read.
func TestKeepaliveIncomingFiltered(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	serverWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)
	cert, pool := genSelfSignedCert(t)
	cTr, sTr := transport.MemoryPair()

	ks := newKeepaliveServer()
	// Both zero: client neither sends pings nor runs the restart watchdog.
	ks.pingInterval = 0
	ks.pingRestart = 0
	ks.echoData = false

	srvDone := make(chan error, 1)
	go func() { srvDone <- ks.run(ctx, sTr, serverWrap, cert, 12, "AES-256-GCM", t) }()

	sess, err := session.DialWithTransport(ctx, session.Config{
		Network:    "memory",
		RemoteAddr: "memB",
		TLSConfig: &tls.Config{
			ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13,
		},
		TLSCryptV1: staticKey[:],
		Ciphers:    []string{"AES-256-GCM"},
	}, cTr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	// Let the server's inject pump spin up.
	time.Sleep(100 * time.Millisecond)

	// Push a PING first; if not filtered it will be the first thing Read
	// returns, masking the real IP packet that follows.
	ks.inject <- append([]byte(nil), proto.PingMagic[:]...)
	payload := []byte("real packet")
	ks.inject <- payload

	buf := make([]byte, 1500)
	readCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		n, err := sess.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		readCh <- buf[:n]
	}()
	select {
	case got := <-readCh:
		if bytes.Equal(got, proto.PingMagic[:]) {
			t.Fatal("PING leaked through Read — filter missing")
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("Read returned %q, want %q", got, payload)
		}
	case err := <-errCh:
		t.Fatalf("Read error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Read timed out — IP packet didn't surface")
	}
}

// TestKeepaliveDefaultsApplied verifies that when the server omits both
// `ping` and `ping-restart` from PUSH_REPLY (typical of e.g. ProtonVPN), the
// session falls back to non-zero defaults so the keepalive layer actually
// runs in production.
func TestKeepaliveDefaultsApplied(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	serverWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)
	cert, pool := genSelfSignedCert(t)
	cTr, sTr := transport.MemoryPair()

	ks := newKeepaliveServer()
	// Server pushes neither — mimics ProtonVPN.
	ks.pingInterval = 0
	ks.pingRestart = 0
	ks.echoData = false

	srvDone := make(chan error, 1)
	go func() { srvDone <- ks.run(ctx, sTr, serverWrap, cert, 14, "AES-256-GCM", t) }()

	sess, err := session.DialWithTransport(ctx, session.Config{
		Network:    "memory",
		RemoteAddr: "memB",
		TLSConfig: &tls.Config{
			ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13,
		},
		TLSCryptV1: staticKey[:],
		Ciphers:    []string{"AES-256-GCM"},
	}, cTr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	pr := sess.PushReply()
	if pr.PingInterval <= 0 {
		t.Errorf("PingInterval = %v, want >0 (default applied)", pr.PingInterval)
	}
	if pr.PingRestart <= 0 {
		t.Errorf("PingRestart = %v, want >0 (default applied)", pr.PingRestart)
	}
}

// TestRequestRestartTriggersRestartError verifies that an external caller
// can request a session restart via Session.RequestRestart — Read surfaces
// the typed *RestartError so the surrounding openvpn.Client can drive
// AutoReconnect.
func TestRequestRestartTriggersRestartError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	serverWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)
	cert, pool := genSelfSignedCert(t)
	cTr, sTr := transport.MemoryPair()

	ks := newKeepaliveServer()
	ks.pingInterval = 0
	ks.pingRestart = 0 // disable watchdog so only RequestRestart can fire
	ks.echoData = false

	srvDone := make(chan error, 1)
	go func() { srvDone <- ks.run(ctx, sTr, serverWrap, cert, 16, "AES-256-GCM", t) }()

	sess, err := session.DialWithTransport(ctx, session.Config{
		Network:    "memory",
		RemoteAddr: "memB",
		TLSConfig: &tls.Config{
			ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13,
		},
		TLSCryptV1: staticKey[:],
		Ciphers:    []string{"AES-256-GCM"},
	}, cTr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	buf := make([]byte, 1500)
	errCh := make(chan error, 1)
	go func() {
		_, err := sess.Read(buf)
		errCh <- err
	}()

	// Give Read a moment to block on ingressCh, then trigger.
	time.Sleep(50 * time.Millisecond)
	sess.RequestRestart("test-requested")

	select {
	case err := <-errCh:
		var re *session.RestartError
		if !errors.As(err, &re) {
			t.Fatalf("got %T (%v), want *RestartError", err, err)
		}
		if re.Reason != "test-requested" {
			t.Errorf("Reason = %q, want %q", re.Reason, "test-requested")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not surface RestartError within 2s")
	}
}

// TestPingRestartTriggersRestart verifies that prolonged silence on the data
// channel (exceeding ping-restart) surfaces as *RestartError from Read so the
// upper layer (openvpn.Client) can drive AutoReconnect.
func TestPingRestartTriggersRestart(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	serverWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)
	cert, pool := genSelfSignedCert(t)
	cTr, sTr := transport.MemoryPair()

	ks := newKeepaliveServer()
	// Client must not generate its own pings — otherwise the server's echo
	// (which is off here anyway) is moot; the absence of inbound traffic is
	// what should trigger the watchdog.
	ks.pingInterval = 0
	ks.pingRestart = 1
	ks.echoData = false

	srvDone := make(chan error, 1)
	go func() { srvDone <- ks.run(ctx, sTr, serverWrap, cert, 13, "AES-256-GCM", t) }()

	sess, err := session.DialWithTransport(ctx, session.Config{
		Network:    "memory",
		RemoteAddr: "memB",
		TLSConfig: &tls.Config{
			ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13,
		},
		TLSCryptV1: staticKey[:],
		Ciphers:    []string{"AES-256-GCM"},
	}, cTr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = sess.Close() }()

	buf := make([]byte, 1500)
	errCh := make(chan error, 1)
	go func() {
		_, err := sess.Read(buf)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		var re *session.RestartError
		if !errors.As(err, &re) {
			t.Fatalf("got %T (%v), want *RestartError", err, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not return RestartError within 5s")
	}
}
