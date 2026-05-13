// SPDX-License-Identifier: AGPL-3.0-or-later

package reliable_test

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
	"io"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn/internal/proto"
	"github.com/n0madic/go-openvpn/internal/reliable"
	"github.com/n0madic/go-openvpn/internal/tlscrypt"
	"github.com/n0madic/go-openvpn/internal/transport"
)

// pumper plumbs a reliable.Layer to a transport.PacketConn through a
// tlscrypt.Wrapper. It mirrors what session.go will do in production.
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
			body, err := marshalOut(out)
			if err != nil {
				t.Errorf("marshalOut: %v", err)
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
				t.Logf("parse ack: %v", err)
				continue
			}
			in.Ack = ap
		} else {
			cp, err := proto.ParseControlPayload(plain)
			if err != nil {
				t.Logf("parse control payload: %v", err)
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

func marshalOut(o reliable.OutPacket) ([]byte, error) {
	if o.IsAck() {
		return proto.MarshalAckPayload(o.Ack)
	}
	return proto.MarshalControlPayload(o.Payload)
}

// genSelfSignedCert produces an ECDSA P-256 self-signed cert + its key for
// testing. The cert is valid for "localhost" and lasts an hour.
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

// TestTLSHandshakeOverReliableStack runs a full TLS 1.3 handshake between two
// reliable.Layers connected through transport.MemoryPair + tls-crypt wrap.
// Exercises every layer below TLS end-to-end.
func TestTLSHandshakeOverReliableStack(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	// Shared tls-crypt static key.
	var staticKey [tlscrypt.StaticKeyLen]byte
	if _, err := rand.Read(staticKey[:]); err != nil {
		t.Fatal(err)
	}
	clientWrap, err := tlscrypt.New(staticKey, tlscrypt.DirectionInverse)
	if err != nil {
		t.Fatal(err)
	}
	serverWrap, err := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)
	if err != nil {
		t.Fatal(err)
	}

	// Memory transport pair.
	cTr, sTr := transport.MemoryPair()

	// Reliable layers.
	clientLayer := reliable.New(reliable.Config{LocalSessionID: 0x1111})
	serverLayer := reliable.New(reliable.Config{LocalSessionID: 0x2222})

	// Pumps connect each layer to its transport endpoint.
	(&pumper{layer: clientLayer, tr: cTr, wrap: clientWrap}).run(ctx, t)
	(&pumper{layer: serverLayer, tr: sTr, wrap: serverWrap}).run(ctx, t)

	// Hard reset both sides so session-ids are exchanged. This is normally
	// driven by the control state machine; here we just kick it off manually.
	if err := clientLayer.SendHardReset(proto.PControlHardResetClientV2); err != nil {
		t.Fatal(err)
	}
	if err := serverLayer.SendHardReset(proto.PControlHardResetServerV2); err != nil {
		t.Fatal(err)
	}

	// TLS config: self-signed cert as both server identity and client trust.
	cert, pool := genSelfSignedCert(t)
	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	clientTLSCfg := &tls.Config{
		ServerName: "localhost",
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}

	// Adapt layers to net.Conn for crypto/tls.
	clientConn := tls.Client(reliable.NewAdapter(clientLayer, cTr.LocalAddr(), cTr.RemoteAddr()), clientTLSCfg)
	serverConn := tls.Server(reliable.NewAdapter(serverLayer, sTr.LocalAddr(), sTr.RemoteAddr()), serverTLSCfg)

	var wg sync.WaitGroup
	var clientErr, serverErr error
	wg.Go(func() { clientErr = clientConn.Handshake() })
	wg.Go(func() { serverErr = serverConn.Handshake() })
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client handshake: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}

	// Sanity: negotiated TLS 1.2 or 1.3.
	cs := clientConn.ConnectionState()
	if cs.Version < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version %x is below 1.2", cs.Version)
	}

	// Bidirectional app data over the TLS tunnel.
	wg = sync.WaitGroup{}
	wg.Go(func() {
		if _, err := clientConn.Write([]byte("hello tls")); err != nil {
			t.Errorf("client write: %v", err)
		}
	})
	wg.Go(func() {
		buf := make([]byte, 32)
		n, err := io.ReadAtLeast(serverConn, buf, len("hello tls"))
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if string(buf[:n]) != "hello tls" {
			t.Errorf("server got %q, want %q", buf[:n], "hello tls")
		}
	})
	wg.Wait()
}

// TestTLSKeyMaterialExport verifies that crypto/tls.ExportKeyingMaterial
// works on a TLS connection running over our stack — this is the foundation
// of OpenVPN's TLS-EKM data-channel key derivation.
func TestTLSKeyMaterialExport(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var staticKey [tlscrypt.StaticKeyLen]byte
	rand.Read(staticKey[:])
	clientWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionInverse)
	serverWrap, _ := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)

	cTr, sTr := transport.MemoryPair()
	clientLayer := reliable.New(reliable.Config{LocalSessionID: 0xAAAA})
	serverLayer := reliable.New(reliable.Config{LocalSessionID: 0xBBBB})

	(&pumper{layer: clientLayer, tr: cTr, wrap: clientWrap}).run(ctx, t)
	(&pumper{layer: serverLayer, tr: sTr, wrap: serverWrap}).run(ctx, t)

	if err := clientLayer.SendHardReset(proto.PControlHardResetClientV2); err != nil {
		t.Fatalf("client SendHardReset: %v", err)
	}
	if err := serverLayer.SendHardReset(proto.PControlHardResetServerV2); err != nil {
		t.Fatalf("server SendHardReset: %v", err)
	}

	cert, pool := genSelfSignedCert(t)
	clientCfg := &tls.Config{ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13}
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

	clientConn := tls.Client(reliable.NewAdapter(clientLayer, cTr.LocalAddr(), cTr.RemoteAddr()), clientCfg)
	serverConn := tls.Server(reliable.NewAdapter(serverLayer, sTr.LocalAddr(), sTr.RemoteAddr()), serverCfg)

	var wg sync.WaitGroup
	wg.Go(func() {
		if err := clientConn.Handshake(); err != nil {
			t.Errorf("client handshake: %v", err)
		}
	})
	wg.Go(func() {
		if err := serverConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
		}
	})
	wg.Wait()

	// Both sides export the same key material via RFC 5705. This is what
	// OpenVPN 2.6 uses for data-channel keys when --key-derivation tls-ekm
	// is negotiated.
	const label = "EXPORTER-OpenVPN-datakeys"
	const length = 256

	clientCS := clientConn.ConnectionState()
	cMat, err := clientCS.ExportKeyingMaterial(label, nil, length)
	if err != nil {
		t.Fatalf("client EKM: %v", err)
	}
	serverCS := serverConn.ConnectionState()
	sMat, err := serverCS.ExportKeyingMaterial(label, nil, length)
	if err != nil {
		t.Fatalf("server EKM: %v", err)
	}
	if string(cMat) != string(sMat) {
		t.Fatal("client and server derived different key material")
	}
	if len(cMat) != length {
		t.Fatalf("got %d bytes, want %d", len(cMat), length)
	}
}
