// SPDX-License-Identifier: AGPL-3.0-or-later

package openvpn_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn"
	"github.com/n0madic/go-openvpn/internal/control"
	"github.com/n0madic/go-openvpn/internal/data"
	"github.com/n0madic/go-openvpn/internal/proto"
	"github.com/n0madic/go-openvpn/internal/reliable"
	"github.com/n0madic/go-openvpn/internal/tlscrypt"
)

// TestAutoReconnectRESTART verifies that with Config.AutoReconnect=true the
// Tunnel survives a server-sent RESTART transparently — Read returns the
// echo from the SECOND session without surfacing RestartError to the caller.
func TestAutoReconnectRESTART(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	cert, pool := genSelfSignedCert(t)

	// Listen on a real UDP socket so the client can reconnect to the same
	// address. The server spawns a goroutine per accepted "session".
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	serverAddr := udp.LocalAddr().String()

	var attempt atomic.Uint32
	go runMultiSessionServer(ctx, udp, staticKey, cert, &attempt, t)

	cli, err := openvpn.Dial(ctx, &openvpn.Config{
		Network:              "udp",
		RemoteAddr:           serverAddr,
		TLSConfig:            &tls.Config{ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13},
		TLSCryptV1:           staticKey[:],
		Ciphers:              []string{"AES-256-GCM"},
		AutoReconnect:        true,
		ReconnectMaxAttempts: 3,
		ReconnectMaxInterval: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = cli.Close() }()

	conn := cli.Tunnel()

	// Background sender: keep pinging until the test reader observes the
	// session-2 echo. VPN data is fire-and-forget so any single Write
	// during the RESTART window may be lost; the reader is the source of
	// truth.
	stopSend := make(chan struct{})
	defer close(stopSend)
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopSend:
				return
			case <-ticker.C:
				_, _ = conn.Write([]byte("ping-for-restart"))
			}
		}
	}()

	// Read loop drains echo replies until we see the session-2 prefix,
	// which proves the auto-reconnect actually happened and data flows
	// on the new session.
	buf := make([]byte, 1500)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read after auto-reconnect: %v", err)
		}
		got := string(buf[:n])
		t.Logf("got %q", got)
		if got == "echo2:ping-for-restart" {
			if attempt.Load() < 2 {
				t.Errorf("server saw only %d sessions, expected ≥2", attempt.Load())
			}
			return
		}
	}
	t.Fatalf("never received session-2 echo within 15s")
}

// TestRestartErrorPropagatedWithoutAutoReconnect verifies the default
// (AutoReconnect=false) behaviour: RestartError reaches the caller.
func TestRestartErrorPropagatedWithoutAutoReconnect(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	cert, pool := genSelfSignedCert(t)

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()

	var attempt atomic.Uint32
	go runMultiSessionServer(ctx, udp, staticKey, cert, &attempt, t)

	cli, err := openvpn.Dial(ctx, &openvpn.Config{
		Network:    "udp",
		RemoteAddr: udp.LocalAddr().String(),
		TLSConfig:  &tls.Config{ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13},
		TLSCryptV1: staticKey[:],
		Ciphers:    []string{"AES-256-GCM"},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = cli.Close() }()

	conn := cli.Tunnel()
	buf := make([]byte, 1500)

	rch := make(chan error, 1)
	go func() {
		_, err := conn.Read(buf)
		rch <- err
	}()
	select {
	case err := <-rch:
		var re *openvpn.RestartError
		if !errors.As(err, &re) {
			t.Fatalf("got %v, want *RestartError", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Read did not return within 10s")
	}
}

// runMultiSessionServer is a tiny test "server" that:
//  1. Accepts the first UDP packet, runs a full handshake with the client.
//  2. Sends a RESTART control message to the client.
//  3. Waits for the second handshake (after client reconnect).
//  4. Echoes a single ping back with "echo2:" prefix.
//
// It DOES NOT implement TUN — it processes only the AEAD echo loop. attempt
// counts how many sessions have been established (1 = first handshake done,
// 2 = reconnect handshake done).
func runMultiSessionServer(
	ctx context.Context,
	udp net.PacketConn,
	staticKey [tlscrypt.StaticKeyLen]byte,
	cert tls.Certificate,
	attempt *atomic.Uint32,
	t *testing.T,
) {
	t.Helper()

	for {
		// Each "session" gets a dedicated tlscrypt wrapper + pumpCtx.
		sessCtx, sessCancel := context.WithCancel(ctx)

		wrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)
		tr := newSrvPacketConn(udp)
		go func() {
			<-sessCtx.Done()
			_ = tr.Close()
		}()

		idx := attempt.Add(1)
		err := runOneSession(sessCtx, tr, wrap, cert, idx, t)
		sessCancel()
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			t.Logf("server session %d ended: %v", idx, err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// runOneSession performs server-side handshake on tr. If sessionIdx == 1 the
// session sends RESTART after the handshake. If >= 2 it sets up the AEAD
// echo loop and prefixes echoes with "echo2:" so the test can distinguish
// generations.
func runOneSession(
	ctx context.Context,
	tr *srvPacketConn,
	wrap *tlscrypt.Wrapper,
	cert tls.Certificate,
	sessionIdx uint32,
	t *testing.T,
) error {
	t.Helper()
	layer := reliable.New(reliable.Config{LocalSessionID: 0xA000 + uint64(sessionIdx)})

	pumpCtx, pumpCancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		pumpCancel()
		// Synchronously wait for goroutines to drain so the next session's
		// reader doesn't race for residual packets in the shared UDP buffer.
		_ = tr.Close()
		wg.Wait()
	}()

	const peerID = uint32(0)
	const cipher = "AES-256-GCM"

	var slotMu sync.Mutex
	var activeSlot *data.Slot

	// reader: demuxes data vs control. The first packet of a new session
	// must be a HARD_RESET_CLIENT_V2/V3 from a fresh client source port;
	// stale packets left over from a previous session in the kernel UDP
	// buffer are discarded until we see one.
	clientLocked := false
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			pkt, err := tr.ReadPacket(pumpCtx)
			if err != nil {
				return
			}
			if len(pkt) < 1 {
				continue
			}
			opcode, kid := proto.UnpackOpcodeKID(pkt[0])
			if !clientLocked {
				if opcode != proto.PControlHardResetClientV2 && opcode != proto.PControlHardResetClientV3 {
					continue
				}
				clientLocked = true
				tr.LockPeer()
			}
			if opcode.IsData() {
				slotMu.Lock()
				slot := activeSlot
				slotMu.Unlock()
				if slot == nil {
					continue
				}
				plain, err := slot.Open(pkt)
				if err != nil {
					continue
				}
				// Prefix with "echoN:" to identify the session generation.
				resp := []byte{}
				if sessionIdx >= 2 {
					resp = append(resp, []byte("echo2:")...)
				} else {
					resp = append(resp, []byte("echo1:")...)
				}
				resp = append(resp, plain...)
				echo, err := slot.Seal(resp)
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

	// writer
	wg.Add(1)
	go func() {
		defer wg.Done()
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
	wg.Add(1)
	go func() {
		defer wg.Done()
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
	tlsConn := tls.Server(adapter, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	defer func() { _ = tlsConn.Close() }()

	if _, err := control.ReadKeyMethod2(tlsConn, false, false); err != nil {
		return err
	}
	serverKM := proto.KeyMethod2{
		IsServer: true,
		Options:  "V4,cipher AES-256-GCM,tls-server",
		PeerInfo: "IV_VER=2.6.0\n",
	}
	rand.Read(serverKM.Random1[:])
	rand.Read(serverKM.Random2[:])
	b, _ := proto.MarshalKeyMethod2(serverKM)
	if _, err := tlsConn.Write(b); err != nil {
		return err
	}
	if _, err := control.ReadControlMessage(tlsConn); err != nil {
		return err
	}
	pushReply := "PUSH_REPLY,ifconfig 10.8.0.6 255.255.255.0,topology subnet,peer-id 0,cipher AES-256-GCM,tun-mtu 1500,ping 10,ping-restart 60"
	if err := control.WriteControlMessage(tlsConn, pushReply); err != nil {
		return err
	}

	// Build server-side data slot.
	cs := tlsConn.ConnectionState()
	mat, err := cs.ExportKeyingMaterial(control.ExportLabel, nil, control.DataKeyMaterialLen)
	if err != nil {
		return err
	}
	slot, err := data.NewSlot(data.SlotConfig{
		KeyID:   0,
		PeerID:  peerID,
		Cipher:  cipher,
		SendKey: mat[128:160],
		SendIV:  [data.ImplicitIVLen]byte(mat[192:200]),
		RecvKey: mat[0:32],
		RecvIV:  [data.ImplicitIVLen]byte(mat[64:72]),
	})
	if err != nil {
		return err
	}
	slotMu.Lock()
	activeSlot = slot
	slotMu.Unlock()

	if sessionIdx == 1 {
		// Send RESTART after a brief delay so the client has a chance to
		// finalise its data-slot install.
		time.Sleep(200 * time.Millisecond)
		_ = control.WriteControlMessage(tlsConn, "RESTART,0,server-triggered")
		// Wait briefly for the message to flush, then close so the client's
		// reconnect dials anew.
		time.Sleep(200 * time.Millisecond)
		return nil
	}
	// For session 2+, hold the connection open so the echo loop can run.
	<-ctx.Done()
	return ctx.Err()
}

// --- Test helpers ---

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
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return cert, pool
}

// srvPacketConn adapts a connectionless net.PacketConn for our session to
// see a single-peer transport. The server tracks the most recent client
// address (since UDP is connectionless) and uses it for all writes.
// WritePacket blocks until at least one inbound packet has identified the
// peer; otherwise the server-initiated hard reset would have nowhere to go.
//
// LockPeer freezes the peer to the current value — used after the reader
// identifies a fresh HARD_RESET_CLIENT_V2 so subsequent stray packets from
// the previous session (queued in the kernel UDP buffer) don't reassign
// peer to the old port.
type srvPacketConn struct {
	udp     net.PacketConn
	mu      sync.Mutex
	peer    net.Addr
	locked  bool
	peerSet *sync.Cond
	closed  atomic.Bool
	readBuf []byte
}

func newSrvPacketConn(udp net.PacketConn) *srvPacketConn {
	s := &srvPacketConn{udp: udp, readBuf: make([]byte, 65535)}
	s.peerSet = sync.NewCond(&s.mu)
	return s
}

func (s *srvPacketConn) ReadPacket(ctx context.Context) ([]byte, error) {
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	_ = s.udp.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	for {
		if s.closed.Load() {
			return nil, net.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, addr, err := s.udp.ReadFrom(s.readBuf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				_ = s.udp.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				continue
			}
			return nil, err
		}
		s.mu.Lock()
		if s.locked {
			// Drop packets from other source addresses (stale session traffic).
			if s.peer == nil || addr.String() != s.peer.String() {
				s.mu.Unlock()
				continue
			}
		} else {
			first := s.peer == nil
			s.peer = addr
			if first {
				s.peerSet.Broadcast()
			}
		}
		s.mu.Unlock()
		out := make([]byte, n)
		copy(out, s.readBuf[:n])
		return out, nil
	}
}

// LockPeer pins the current peer addr; subsequent ReadPacket calls discard
// datagrams from any other addr.
func (s *srvPacketConn) LockPeer() {
	s.mu.Lock()
	s.locked = true
	s.mu.Unlock()
}

func (s *srvPacketConn) WritePacket(ctx context.Context, p []byte) error {
	// Wait for the reader to identify and LOCK onto a fresh client
	// (HARD_RESET_CLIENT_V2/V3). Until then, sending would risk going to a
	// stale source from a previous session.
	for {
		s.mu.Lock()
		ready := s.locked && s.peer != nil
		peer := s.peer
		s.mu.Unlock()
		if s.closed.Load() {
			return net.ErrClosed
		}
		if ready {
			_, err := s.udp.WriteTo(p, peer)
			return err
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *srvPacketConn) LocalAddr() net.Addr  { return s.udp.LocalAddr() }
func (s *srvPacketConn) RemoteAddr() net.Addr { s.mu.Lock(); defer s.mu.Unlock(); return s.peer }
func (s *srvPacketConn) Close() error {
	s.closed.Store(true)
	s.mu.Lock()
	s.peerSet.Broadcast()
	s.mu.Unlock()
	return nil
}
