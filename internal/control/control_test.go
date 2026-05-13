// SPDX-License-Identifier: AGPL-3.0-or-later

package control_test

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
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn/internal/control"
	"github.com/n0madic/go-openvpn/internal/proto"
	"github.com/n0madic/go-openvpn/internal/reliable"
	"github.com/n0madic/go-openvpn/internal/tlscrypt"
	"github.com/n0madic/go-openvpn/internal/transport"
)

// --- Unit tests for pure helpers ---

func TestReadKeyMethod2RoundTrip(t *testing.T) {
	t.Parallel()
	src := proto.KeyMethod2{
		IsServer:     false,
		Options:      "V4,cipher AES-256-GCM",
		AuthUserPass: true,
		Username:     "alice",
		Password:     "s3cret",
		PeerInfo:     "IV_VER=2.6.0\nIV_PROTO=8\n",
	}
	for i := range src.PreMaster {
		src.PreMaster[i] = byte(i)
	}
	for i := range src.Random1 {
		src.Random1[i] = byte(0x40 + i)
		src.Random2[i] = byte(0x80 + i)
	}
	enc, err := proto.MarshalKeyMethod2(src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := control.ReadKeyMethod2(bytes.NewReader(enc), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Options != src.Options || got.Username != src.Username ||
		got.Password != src.Password || got.PeerInfo != src.PeerInfo ||
		got.PreMaster != src.PreMaster || got.Random1 != src.Random1 || got.Random2 != src.Random2 {
		t.Fatal("round-trip diverged")
	}
}

func TestReadControlMessageNULTerminated(t *testing.T) {
	t.Parallel()
	r := bytes.NewReader([]byte("PUSH_REPLY,foo,bar\x00"))
	got, err := control.ReadControlMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	if got != "PUSH_REPLY,foo,bar" {
		t.Errorf("got %q", got)
	}
}

func TestAEADKeyLen(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cipher string
		want   int
	}{
		{"AES-256-GCM", 32},
		{"AES-128-GCM", 16},
		{"CHACHA20-POLY1305", 32},
	}
	for _, c := range cases {
		if got, err := control.AEADKeyLen(c.cipher); err != nil || got != c.want {
			t.Errorf("%s: got %d err=%v, want %d", c.cipher, got, err, c.want)
		}
	}
	if _, err := control.AEADKeyLen("BF-CBC"); err == nil {
		t.Error("expected error on unsupported cipher")
	}
}

// --- Full handshake integration test ---

func TestRunFullHandshake(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	// Shared tls-crypt v1 key.
	var staticKey [tlscrypt.StaticKeyLen]byte
	if _, err := rand.Read(staticKey[:]); err != nil {
		t.Fatal(err)
	}
	clientWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionInverse)
	serverWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)

	cTr, sTr := transport.MemoryPair()
	clientLayer := reliable.New(reliable.Config{LocalSessionID: 0xC1C1C1C1})
	serverLayer := reliable.New(reliable.Config{LocalSessionID: 0x5E5E5E5E})

	(&pumper{layer: clientLayer, tr: cTr, wrap: clientWrap}).run(ctx, t)
	(&pumper{layer: serverLayer, tr: sTr, wrap: serverWrap}).run(ctx, t)

	cert, pool := genSelfSignedCert(t)

	// Server simulator in a goroutine.
	const pushReply = "PUSH_REPLY,ifconfig 10.8.0.6 255.255.255.0,topology subnet,peer-id 42,cipher AES-256-GCM,tun-mtu 1500,ping 10,ping-restart 60,route-gateway 10.8.0.1"

	var serverErr error
	var serverEKM [256]byte
	var wg sync.WaitGroup
	wg.Go(func() {
		serverErr = runServerSim(ctx, serverLayer, sTr, cert, pushReply, &serverEKM)
	})

	cfg := control.Config{
		TLSConfig: &tls.Config{
			ServerName: "localhost",
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		},
		Ciphers: []string{"AES-256-GCM", "CHACHA20-POLY1305", "AES-128-GCM"},
	}
	result, err := control.Run(ctx, clientLayer, cTr.LocalAddr(), cTr.RemoteAddr(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer func() { _ = result.TLSConn.Close() }()

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server sim: %v", serverErr)
	}

	if result.Cipher != "AES-256-GCM" {
		t.Errorf("Cipher = %q, want AES-256-GCM", result.Cipher)
	}
	if result.PeerID != 42 {
		t.Errorf("PeerID = %d, want 42", result.PeerID)
	}
	if result.PushReply.LocalIP.String() != "10.8.0.6" {
		t.Errorf("LocalIP = %s, want 10.8.0.6", result.PushReply.LocalIP)
	}
	if result.RemoteSID != 0x5E5E5E5E {
		t.Errorf("RemoteSID = %x, want 5E5E5E5E", result.RemoteSID)
	}
	var zero [256]byte
	if result.KeyMaterial == zero {
		t.Error("key material is all zeros")
	}
	// Both sides must derive identical key material via TLS-EKM.
	if !bytes.Equal(result.KeyMaterial[:], serverEKM[:]) {
		t.Error("client/server EKM mismatch")
	}
}

func TestRunRejectsAuthFailed(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	clientWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionInverse)
	serverWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)

	cTr, sTr := transport.MemoryPair()
	clientLayer := reliable.New(reliable.Config{LocalSessionID: 1})
	serverLayer := reliable.New(reliable.Config{LocalSessionID: 2})

	(&pumper{layer: clientLayer, tr: cTr, wrap: clientWrap}).run(ctx, t)
	(&pumper{layer: serverLayer, tr: sTr, wrap: serverWrap}).run(ctx, t)

	cert, pool := genSelfSignedCert(t)

	var wg sync.WaitGroup
	wg.Go(func() {
		_ = runServerSim(ctx, serverLayer, sTr, cert, "AUTH_FAILED,bad credentials", nil)
	})

	cfg := control.Config{
		TLSConfig: &tls.Config{ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13},
		Username:  "alice",
		Password:  "wrong",
	}
	_, err := control.Run(ctx, clientLayer, cTr.LocalAddr(), cTr.RemoteAddr(), cfg)
	if !errors.Is(err, control.ErrAuthFailed) {
		t.Fatalf("got %v, want ErrAuthFailed", err)
	}
	wg.Wait()
}

// --- Helpers ---

// runServerSim implements just enough of the OpenVPN server protocol to drive
// our client through a full handshake. It writes pushReply (raw, NUL is
// appended internally) and stores the server-side EKM in eOut if non-nil.
func runServerSim(ctx context.Context, layer *reliable.Layer, tr transport.PacketConn, cert tls.Certificate, pushReply string, eOut *[256]byte) error {
	if err := layer.SendHardReset(proto.PControlHardResetServerV2); err != nil {
		return err
	}
	adapter := reliable.NewAdapter(layer, tr.LocalAddr(), tr.RemoteAddr())
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.NoClientCert, // accept anonymous client (our test cert is on server only)
	}
	tlsConn := tls.Server(adapter, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	defer func() { _ = tlsConn.Close() }()

	authUserPass := !isPushReply(pushReply) // if we're going to reply AUTH_FAILED the client probably sent user/pass
	clientKM, err := control.ReadKeyMethod2(tlsConn, false, authUserPass)
	if err != nil {
		return err
	}
	_ = clientKM

	// Server's KEY_METHOD 2.
	serverKM := proto.KeyMethod2{
		IsServer: true,
		Options:  "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth SHA256,keysize 256,key-method 2,tls-server",
		PeerInfo: "IV_VER=2.6.0\nIV_PLAT=test\n",
	}
	if _, err := rand.Read(serverKM.Random1[:]); err != nil {
		return err
	}
	if _, err := rand.Read(serverKM.Random2[:]); err != nil {
		return err
	}
	serverKMBytes, err := proto.MarshalKeyMethod2(serverKM)
	if err != nil {
		return err
	}
	if _, err := tlsConn.Write(serverKMBytes); err != nil {
		return err
	}

	// PUSH_REQUEST or short-circuit AUTH_FAILED.
	msg, err := control.ReadControlMessage(tlsConn)
	if err != nil {
		return err
	}
	if msg != "PUSH_REQUEST" {
		return errors.New("expected PUSH_REQUEST, got " + msg)
	}
	if err := control.WriteControlMessage(tlsConn, pushReply); err != nil {
		return err
	}

	if eOut != nil {
		cs := tlsConn.ConnectionState()
		mat, err := cs.ExportKeyingMaterial(control.ExportLabel, nil, control.DataKeyMaterialLen)
		if err != nil {
			return err
		}
		copy(eOut[:], mat)
	}
	return nil
}

func isPushReply(s string) bool {
	return len(s) > 11 && s[:11] == "PUSH_REPLY,"
}

// --- Pumper (duplicated from reliable integration test) ---

type pumper struct {
	layer *reliable.Layer
	tr    transport.PacketConn
	wrap  *tlscrypt.Wrapper
}

func (p *pumper) run(ctx context.Context, t *testing.T) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Go(func() { p.runOutbound(ctx, t) })
	wg.Go(func() { p.runInbound(ctx, t) })
	wg.Go(func() { p.runTicker(ctx) })
	go func() { wg.Wait() }()
}

func (p *pumper) runOutbound(ctx context.Context, t *testing.T) {
	t.Helper()
	for {
		select {
		case <-ctx.Done():
			return
		case out, ok := <-p.layer.Outbound():
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
				t.Errorf("marshal: %v", err)
				return
			}
			opcodeKID := proto.PackOpcodeKID(out.Opcode, out.KeyID)
			wrapped := p.wrap.Wrap(opcodeKID, out.SessionID, body)
			if err := p.tr.WritePacket(ctx, wrapped); err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, transport.ErrClosed) {
					t.Errorf("transport write: %v", err)
				}
				return
			}
		}
	}
}

func (p *pumper) runInbound(ctx context.Context, t *testing.T) {
	t.Helper()
	for {
		pkt, err := p.tr.ReadPacket(ctx)
		if err != nil {
			return
		}
		opcodeKID, sid, _, plain, err := p.wrap.Unwrap(pkt)
		if err != nil {
			t.Logf("tlscrypt unwrap: %v", err)
			continue
		}
		opcode, kid := proto.UnpackOpcodeKID(opcodeKID)
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
		if err := p.layer.HandleInbound(in); err != nil && !errors.Is(err, reliable.ErrClosed) {
			t.Logf("handle inbound: %v", err)
		}
	}
}

func (p *pumper) runTicker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.layer.Tick(); err != nil {
				return
			}
		}
	}
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
