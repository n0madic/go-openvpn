// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-openvpn/internal/control"
	"github.com/n0madic/go-openvpn/internal/data"
	"github.com/n0madic/go-openvpn/internal/proto"
	"github.com/n0madic/go-openvpn/internal/reliable"
)

// ErrRekeyRequired signals that the active data slot's packet-id counter has
// crossed the rekey threshold (or the renegotiation deadline has elapsed).
// Returned by the rekey watchdog when auto-rekey is not configured.
var ErrRekeyRequired = errors.New("session: rekey required")

// ErrRekeyInProgress is returned by Rekey when another rekey is already
// running.
var ErrRekeyInProgress = errors.New("session: rekey already in progress")

// rekeyState tracks the conditions under which a rekey must fire.
type rekeyState struct {
	startTime time.Time
	reneg     time.Duration // 0 disables time-based trigger
	triggered atomic.Bool
}

func newRekeyState(reneg time.Duration, clock func() time.Time) *rekeyState {
	if clock == nil {
		clock = time.Now
	}
	return &rekeyState{startTime: clock(), reneg: reneg}
}

// Check reports whether a rekey condition has been reached. Once true, it
// stays true (the atomic flag latches).
func (r *rekeyState) Check(slot *data.Slot, now time.Time) bool {
	if r.triggered.Load() {
		return true
	}
	if r.reneg > 0 && now.Sub(r.startTime) >= r.reneg {
		r.triggered.Store(true)
		return true
	}
	if slot != nil && slot.SendPID() >= data.PacketIDRekeyThreshold {
		r.triggered.Store(true)
		return true
	}
	return false
}

// Trigger forces the rekey flag to true.
func (r *rekeyState) Trigger() { r.triggered.Store(true) }

// Reset clears the trigger so the watchdog can wait for the next interval.
// Called after a successful rekey.
func (r *rekeyState) Reset(now time.Time) {
	r.triggered.Store(false)
	r.startTime = now
}

// rekeyWatch fires PerformSoftReset when a rekey condition is reached. If
// the rekey fails, the session is closed.
func (s *Session) rekeyWatch(ctx context.Context, state *rekeyState) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !state.Check(s.slots.Active(), time.Now()) {
				continue
			}
			rekeyCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			err := s.rekeyMgr.PerformSoftReset(rekeyCtx)
			cancel()
			if err != nil {
				s.log.Error("auto-rekey failed, closing session", "err", err)
				_ = s.Close()
				return
			}
			state.Reset(time.Now())
		}
	}
}

// rekeyManager serialises rekey operations on a Session.
type rekeyManager struct {
	s                *Session
	mu               sync.Mutex
	inProgress       bool
	transitionWindow time.Duration
}

func newRekeyManager(s *Session, transitionWindow time.Duration) *rekeyManager {
	if transitionWindow <= 0 {
		transitionWindow = 60 * time.Second
	}
	return &rekeyManager{s: s, transitionWindow: transitionWindow}
}

// PerformSoftReset executes a single soft-reset rekey cycle: creates a new
// reliable.Layer for the next key-id, runs P_CONTROL_SOFT_RESET_V1 + a fresh
// TLS handshake + KEY_METHOD 2 + TLS-EKM, installs the new data slot, and
// schedules retirement of the old slot/layer after the transition window.
//
// Both client- and server-initiated rekeys converge on the same shared
// secret since both sides drive the same TLS handshake and EKM export.
// PUSH_REPLY is NOT re-sent — pushed options remain session-scoped.
func (m *rekeyManager) PerformSoftReset(ctx context.Context) error {
	// Reject on already-closing sessions before doing any work. Without this
	// check, an externally-triggered rekey (Client.Rekey / Write-driven
	// forced rekey) that races with Close could lose the new layer's pumps
	// after s.workers has begun shutdown. Belt-and-suspenders: the retire
	// goroutine is also spawned outside s.workers, but this short-circuits
	// earlier.
	if m.s.closed.Load() {
		return ErrClosed
	}
	m.mu.Lock()
	if m.inProgress {
		m.mu.Unlock()
		return ErrRekeyInProgress
	}
	m.inProgress = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.inProgress = false
		m.mu.Unlock()
	}()

	s := m.s
	oldKID := s.slots.ActiveKID()
	newKID := nextKeyID(oldKID)
	s.log.Info("rekey starting", "old_kid", oldKID, "new_kid", newKID)

	// 1. Create new reliable.Layer for the new key-id.
	newLayer := reliable.New(reliable.Config{
		LocalSessionID: s.localSID,
		InitialKeyID:   newKID,
	})
	if oldLayer := s.layers.Get(oldKID); oldLayer != nil {
		if sid, ok := oldLayer.RemoteSessionID(); ok {
			// Pre-seed remote SID so ACKs from the start are valid.
			newLayer.SetRemoteSessionID(sid)
		}
	}
	s.layers.Install(newKID, newLayer)
	s.startLayerPumps(newLayer)

	// 2. Send the initial packet on the new layer: P_CONTROL_SOFT_RESET_V1.
	// This carries msg_pid 0 of the new reliable channel and signals the
	// server to start its own rekey handshake.
	if err := newLayer.SendHardReset(proto.PControlSoftResetV1); err != nil {
		s.retireLayer(newKID)
		return fmt.Errorf("rekey: send soft reset: %w", err)
	}

	// 3. Run a fresh TLS client handshake over the new layer.
	newAdapter := reliable.NewAdapter(newLayer, s.transport.LocalAddr(), s.transport.RemoteAddr())
	newTLS := tls.Client(newAdapter, s.tlsConfig)
	if err := newTLS.HandshakeContext(ctx); err != nil {
		s.retireLayer(newKID)
		return fmt.Errorf("rekey: TLS handshake: %w", err)
	}

	// 4. Exchange KEY_METHOD 2. No PUSH_REQUEST on rekey — server keeps
	// the previously pushed options.
	clientKM, err := buildRekeyClientKM(s)
	if err != nil {
		_ = newTLS.Close()
		s.retireLayer(newKID)
		return err
	}
	cmBytes, err := proto.MarshalKeyMethod2(clientKM)
	if err != nil {
		_ = newTLS.Close()
		s.retireLayer(newKID)
		return fmt.Errorf("rekey: marshal KEY_METHOD 2: %w", err)
	}
	if _, err := newTLS.Write(cmBytes); err != nil {
		_ = newTLS.Close()
		s.retireLayer(newKID)
		return fmt.Errorf("rekey: write KEY_METHOD 2: %w", err)
	}
	// Erase the pre_master copies (struct + marshalled wire buffer) — see
	// the same pattern in control.Run().
	clear(clientKM.PreMaster[:])
	clear(cmBytes)
	if _, err := control.ReadKeyMethod2(newTLS, true, false); err != nil {
		_ = newTLS.Close()
		s.retireLayer(newKID)
		return fmt.Errorf("rekey: read server KEY_METHOD 2: %w", err)
	}

	// 5. Derive new data-channel keys via TLS-EKM on the new TLS session.
	cs := newTLS.ConnectionState()
	mat, err := cs.ExportKeyingMaterial(control.ExportLabel, nil, control.DataKeyMaterialLen)
	if err != nil {
		_ = newTLS.Close()
		s.retireLayer(newKID)
		return fmt.Errorf("rekey: TLS-EKM: %w", err)
	}
	defer clear(mat)
	keyLen, err := control.AEADKeyLen(s.cipher)
	if err != nil {
		_ = newTLS.Close()
		s.retireLayer(newKID)
		return err
	}

	// 6. Build the new data slot.
	newSlot, err := data.NewSlot(data.SlotConfig{
		KeyID:   newKID,
		PeerID:  s.peerID,
		Cipher:  s.cipher,
		SendKey: mat[0:keyLen],
		SendIV:  [data.ImplicitIVLen]byte(mat[64 : 64+data.ImplicitIVLen]),
		RecvKey: mat[128 : 128+keyLen],
		RecvIV:  [data.ImplicitIVLen]byte(mat[192 : 192+data.ImplicitIVLen]),
	})
	if err != nil {
		_ = newTLS.Close()
		s.retireLayer(newKID)
		return fmt.Errorf("rekey: build slot: %w", err)
	}

	// 7. Atomic switch — new slot becomes active outbound, and the new TLS
	// conn becomes the control channel for post-handshake server messages
	// (RESTART, INFO, EXIT). installTLSConn closes the previous conn which
	// shuts down its reader goroutine.
	s.slots.Install(newSlot, true)
	s.installTLSConn(newTLS)
	s.log.Info("rekey complete, switched outbound", "kid", newKID)

	// 8. Schedule retirement of the old slot + layer after the transition
	// window. We keep the old slot accepting inbound for the duration to
	// avoid drops on in-flight packets the server hasn't yet rotated.
	//
	// Deliberately NOT in s.workers: PerformSoftReset can be called from
	// user goroutines (Client.Rekey, Write-driven forced rekey) that are
	// not part of s.workers, so registering this here could race with
	// shutdown's Wait. retireAfter self-terminates on s.ctx.Done().
	go m.retireAfter(oldKID)
	return nil
}

func (m *rekeyManager) retireAfter(kid uint8) {
	timer := time.NewTimer(m.transitionWindow)
	defer timer.Stop()
	select {
	case <-m.s.ctx.Done():
		return
	case <-timer.C:
	}
	m.s.slots.Retire(kid)
	m.s.retireLayer(kid)
}

// retireLayer closes and removes a layer (no-op if absent).
func (s *Session) retireLayer(kid uint8) {
	if l := s.layers.Retire(kid); l != nil {
		_ = l.Close()
	}
}

// buildRekeyClientKM constructs the client-side KEY_METHOD 2 for a rekey.
// Identical to the initial one minus the peer-info (server already has it).
func buildRekeyClientKM(s *Session) (proto.KeyMethod2, error) {
	var km proto.KeyMethod2
	if _, err := rand.Read(km.PreMaster[:]); err != nil {
		return km, err
	}
	if _, err := rand.Read(km.Random1[:]); err != nil {
		return km, err
	}
	if _, err := rand.Read(km.Random2[:]); err != nil {
		return km, err
	}
	ciphersStr := strings.Join(s.cfg.Ciphers, ":")
	if ciphersStr == "" {
		ciphersStr = "AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM"
	}
	km.Options = strings.Join([]string{
		"V4",
		"dev-type tun",
		"link-mtu 1559",
		"tun-mtu 1500",
		"proto UDPv4",
		"cipher " + firstColonField(ciphersStr),
		"auth SHA256",
		"keysize 256",
		"key-method 2",
		"tls-client",
	}, ",")
	authUserPass := s.cfg.Username != "" || s.cfg.Password != ""
	km.AuthUserPass = authUserPass
	km.Username = s.cfg.Username
	km.Password = s.cfg.Password
	pi := proto.DefaultPeerInfo(ciphersStr)
	if s.cfg.PeerInfoVersion != "" {
		pi.Set("IV_VER", s.cfg.PeerInfoVersion)
	}
	// Carry the same peer-info extras (e.g. UV_* tokens) the initial
	// handshake advertised — some providers key per-session state on them.
	for k, v := range s.cfg.PeerInfoExtra {
		pi.Set(k, v)
	}
	km.PeerInfo = pi.Encode()
	return km, nil
}

func firstColonField(s string) string {
	head, _, _ := strings.Cut(s, ":")
	return head
}
