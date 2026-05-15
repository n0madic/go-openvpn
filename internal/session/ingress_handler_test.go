// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn/internal/proto"
	"github.com/n0madic/go-openvpn/internal/session"
	"github.com/n0madic/go-openvpn/internal/tlscrypt"
	"github.com/n0madic/go-openvpn/internal/transport"
)

// dialSessionWithEchoServer brings up a one-shot session against the
// runServerWithDataEcho simulator and returns the live client session
// plus a cleanup func. Shared by the IngressHandler tests below.
func dialSessionWithEchoServer(t *testing.T) (*session.Session, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)

	var staticKey [tlscrypt.StaticKeyLen]byte
	if _, err := rand.Read(staticKey[:]); err != nil {
		cancel()
		t.Fatal(err)
	}
	serverWrap, err := tlscrypt.New(staticKey, tlscrypt.DirectionNormal)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cTr, sTr := transport.MemoryPair()
	cert, pool := genSelfSignedCert(t)

	const peerID = uint32(0x1337)
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- runServerWithDataEcho(ctx, sTr, serverWrap, cert, peerID, "AES-256-GCM", t)
	}()

	cfg := session.Config{
		Network:    "memory",
		RemoteAddr: "memB",
		TLSConfig: &tls.Config{
			ServerName: "localhost",
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		},
		TLSCryptV1: staticKey[:],
		Ciphers:    []string{"AES-256-GCM"},
	}
	sess, err := session.DialWithTransport(ctx, cfg, cTr)
	if err != nil {
		cancel()
		t.Fatalf("Dial: %v", err)
	}

	cleanup := func() {
		_ = sess.Close()
		cancel()
		select {
		case err := <-serverErr:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, transport.ErrClosed) {
				t.Logf("server returned: %v", err)
			}
		case <-time.After(2 * time.Second):
		}
	}
	return sess, cleanup
}

// TestIngressHandlerReceivesDecryptedPacket sends one IP packet over the
// tunnel and asserts the registered handler receives the exact bytes
// echoed back by the simulator, instead of the channel-based Read path.
func TestIngressHandlerReceivesDecryptedPacket(t *testing.T) {
	t.Parallel()
	sess, cleanup := dialSessionWithEchoServer(t)
	defer cleanup()

	got := make(chan []byte, 1)
	sess.SetIngressHandler(func(ip []byte) {
		// Copy because the contract allows the buffer to be reused.
		dup := make([]byte, len(ip))
		copy(dup, ip)
		select {
		case got <- dup:
		default:
		}
	})

	want := []byte("ingress-handler-payload")
	if _, err := sess.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case b := <-got:
		if !bytes.Equal(b, want) {
			t.Fatalf("handler got %q, want %q", b, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler never fired within 5s")
	}
}

// TestIngressHandlerSkipsPingMagic exercises the PING filter: the
// handler must NOT see proto.PingMagic — those are filtered before the
// handler dispatch (same contract as the channel path).
func TestIngressHandlerSkipsPingMagic(t *testing.T) {
	t.Parallel()
	sess, cleanup := dialSessionWithEchoServer(t)
	defer cleanup()

	var pingCount, otherCount atomic.Int32
	sess.SetIngressHandler(func(ip []byte) {
		if proto.IsPing(ip) {
			pingCount.Add(1)
		} else {
			otherCount.Add(1)
		}
	})

	// The echo server bounces whatever we Write back. Sending PingMagic
	// makes the server reply with the same bytes — but on the receive
	// side handleDataIn's IsPing filter must strip it BEFORE the handler
	// runs, so pingCount stays at 0.
	if _, err := sess.Write(proto.PingMagic[:]); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Send something real after to give the test a positive signal that
	// inbound is flowing — otherwise a stuck pipeline would look like
	// the test passing.
	if _, err := sess.Write([]byte("after-ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	deadline := time.After(5 * time.Second)
	for otherCount.Load() == 0 {
		select {
		case <-deadline:
			t.Fatalf("never saw real inbound; ping=%d other=%d", pingCount.Load(), otherCount.Load())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if got := pingCount.Load(); got != 0 {
		t.Fatalf("handler saw %d PING(s) — must be filtered before dispatch", got)
	}
}

// TestSetIngressHandlerNilFallsBackToChannel: with a handler set, Read
// would block forever; clearing the handler must restore the channel
// path so Read picks up the next echoed packet.
func TestSetIngressHandlerNilFallsBackToChannel(t *testing.T) {
	t.Parallel()
	sess, cleanup := dialSessionWithEchoServer(t)
	defer cleanup()

	handled := make(chan []byte, 1)
	sess.SetIngressHandler(func(ip []byte) {
		dup := make([]byte, len(ip))
		copy(dup, ip)
		select {
		case handled <- dup:
		default:
		}
	})

	// First round: handler path.
	if _, err := sess.Write([]byte("phase-1")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case <-handled:
	case <-time.After(3 * time.Second):
		t.Fatal("handler never fired in phase 1")
	}

	// Detach. SetIngressHandler(nil) returns after draining any in-flight
	// invocation — there shouldn't be one in this synchronous test, but
	// the contract holds either way.
	sess.SetIngressHandler(nil)

	// Second round: channel path. Read should now receive the echo.
	if _, err := sess.Write([]byte("phase-2")); err != nil {
		t.Fatalf("Write: %v", err)
	}
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
			t.Fatalf("Read after detach: %v", r.err)
		}
		if got := string(buf[:r.n]); got != "phase-2" {
			t.Fatalf("Read got %q, want %q", got, "phase-2")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read never returned in phase 2 (channel path)")
	}
}

// TestIngressHandlerReplacePropagates ensures a second SetIngressHandler
// call replaces the first handler — the session must dispatch to the
// LATEST registered handler, not the original. Mirrors what
// openvpn.Client.SetIngressHandler does on every reconnect.
func TestIngressHandlerReplacePropagates(t *testing.T) {
	t.Parallel()
	sess, cleanup := dialSessionWithEchoServer(t)
	defer cleanup()

	var firstFired, secondFired atomic.Int32
	sess.SetIngressHandler(func(ip []byte) { firstFired.Add(1) })
	// Replace before any traffic flows.
	hit := make(chan struct{}, 1)
	sess.SetIngressHandler(func(ip []byte) {
		secondFired.Add(1)
		select {
		case hit <- struct{}{}:
		default:
		}
	})

	if _, err := sess.Write([]byte("after-replace")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case <-hit:
	case <-time.After(3 * time.Second):
		t.Fatal("replaced handler never fired")
	}
	if firstFired.Load() != 0 {
		t.Fatalf("first handler should never have fired, got %d", firstFired.Load())
	}
	if secondFired.Load() == 0 {
		t.Fatal("second handler did not fire")
	}
}

// TestSetIngressHandlerDrainsInFlight covers the RWMutex contract: a
// slow handler in progress must hold up SetIngressHandler(nil) until
// the handler call returns. This is what makes Net.Close → stack.Close
// race-free against DeliverNetworkPacket from a straggler handler call.
func TestSetIngressHandlerDrainsInFlight(t *testing.T) {
	t.Parallel()
	sess, cleanup := dialSessionWithEchoServer(t)
	defer cleanup()

	const dwell = 200 * time.Millisecond
	inHandler := make(chan struct{})
	releaseHandler := make(chan struct{})
	var handlerFinished atomic.Bool

	sess.SetIngressHandler(func(ip []byte) {
		close(inHandler)
		<-releaseHandler
		handlerFinished.Store(true)
	})

	// Trigger the slow handler.
	if _, err := sess.Write([]byte("slow")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case <-inHandler:
	case <-time.After(3 * time.Second):
		t.Fatal("handler never started")
	}

	// SetIngressHandler(nil) must block until the in-flight handler
	// returns. Run it in a goroutine; assert it does NOT return until we
	// release the handler.
	var wg sync.WaitGroup
	wg.Add(1)
	setDone := make(chan struct{})
	go func() {
		defer wg.Done()
		sess.SetIngressHandler(nil)
		close(setDone)
	}()

	select {
	case <-setDone:
		t.Fatal("SetIngressHandler(nil) returned before handler finished — drain broken")
	case <-time.After(dwell):
		// expected: handler still holding the RLock
	}

	if handlerFinished.Load() {
		t.Fatal("handler reported finished before we released it")
	}

	// Release the handler; SetIngressHandler(nil) must now complete
	// promptly.
	close(releaseHandler)

	select {
	case <-setDone:
	case <-time.After(3 * time.Second):
		t.Fatal("SetIngressHandler(nil) did not return after handler released")
	}
	if !handlerFinished.Load() {
		t.Fatal("handler did not run to completion")
	}
	wg.Wait()
}
