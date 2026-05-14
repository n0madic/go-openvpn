// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reliable implements the OpenVPN control-channel reliability shim
// between the raw transport (UDP/TCP after tls-crypt unwrap) and crypto/tls.
//
// Layer is the central type: it accepts inbound ControlPayloads, deduplicates
// them, delivers their bodies in msg_pid order to a TLS reader, chunks TLS
// writes into <=TLSChunkSize P_CONTROL_V1 packets, retransmits unacked ones,
// and emits standalone P_ACK_V1 packets when piggyback is unavailable.
//
// Layer is safe for concurrent use: the TLS goroutine calls Read/Write while
// the orchestrator goroutine calls HandleInbound/Tick.
package reliable

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/n0madic/go-openvpn/internal/proto"
)

// Wire and behavioural constants mirror OpenVPN 2.6 (src/openvpn/reliable.h
// and openvpn.h).
const (
	// MaxAcksPerPacket caps the per-packet ack array (RELIABLE_ACK_SIZE).
	MaxAcksPerPacket = 8
	// MaxQueueSize caps the outbound unacked queue (RELIABLE_CAPACITY).
	MaxQueueSize = 12
	// MaxRetransmits limits how many times we retransmit before giving up.
	MaxRetransmits = 8
	// InitialRetransmit is the base backoff for retransmits.
	InitialRetransmit = time.Second
	// MaxRetransmit caps the per-retransmit backoff.
	MaxRetransmit = 16 * time.Second
	// AckFlushDelay is the grace period before sending a standalone P_ACK_V1
	// when no piggyback opportunity arrived. Short enough that perceived
	// handshake latency doesn't suffer; long enough that any imminent
	// outbound P_CONTROL_V1 can piggyback the ack and avoid a separate
	// packet on the wire. 20ms matches ooni/minivpn's tuning.
	AckFlushDelay = 20 * time.Millisecond
	// FastRetransmitThreshold is the number of ACKs we must observe for
	// packets with strictly higher msgPIDs before we treat a still-pending
	// packet as lost and retransmit it without waiting for its backoff
	// timer. Mirrors TCP's three-duplicate-ACK heuristic — in lossy
	// uplinks (mobile, Wi-Fi) it cuts handshake/rekey latency by avoiding
	// the 1-second initial backoff. Idea borrowed from ooni/minivpn.
	FastRetransmitThreshold = 3
	// TLSChunkSize caps the body bytes per outbound P_CONTROL_V1. Adds
	// tls-crypt prefix (~45 bytes) + ack/sid overhead → fits in <1300 bytes
	// on-wire which is below typical 1500-byte MTU.
	TLSChunkSize = 1200
)

// Errors emitted by Layer.
var (
	ErrClosed             = errors.New("reliable: closed")
	ErrTooManyRetransmits = errors.New("reliable: peer unreachable (max retransmits exceeded)")
	ErrQueueFull          = errors.New("reliable: outbound queue full")
	ErrSessionIDMismatch  = errors.New("reliable: remote session-id changed")
)

// OutPacket is what Layer emits on its Outbound channel: a fully assembled
// control-channel packet ready to be tls-crypt-wrapped and transmitted.
type OutPacket struct {
	Opcode    proto.Opcode
	KeyID     uint8
	SessionID uint64

	// Payload is used for any opcode except PAckV1.
	Payload proto.ControlPayload
	// Ack is used for PAckV1 only.
	Ack proto.AckPayload
}

// IsAck reports whether this packet is a standalone P_ACK_V1.
func (o OutPacket) IsAck() bool { return o.Opcode == proto.PAckV1 }

// InPacket is the input to HandleInbound: an already-tls-crypt-unwrapped and
// proto-parsed packet.
type InPacket struct {
	Opcode    proto.Opcode
	KeyID     uint8
	SessionID uint64 // remote session-id from the wire

	Payload proto.ControlPayload // used for any opcode except PAckV1
	Ack     proto.AckPayload     // used for PAckV1 only
}

// Config configures a Layer.
type Config struct {
	// LocalSessionID is this client's 64-bit session-id, fixed for the life
	// of the TLS session.
	LocalSessionID uint64
	// InitialKeyID is the key-id used in outbound packets. 0 for hard-reset
	// start; bumped by the rekey logic on soft reset.
	InitialKeyID uint8
	// OutboundBuffer is the capacity of the outbound channel. 64 is plenty
	// since control traffic is bursty but low-volume.
	OutboundBuffer int
	// Clock overrides time.Now (for tests).
	Clock func() time.Time
}

// Layer is the reliability layer instance.
type Layer struct {
	cfg Config

	mu              sync.Mutex
	keyID           uint8
	remoteSessionID uint64
	remoteKnown     bool

	// outbound state
	nextTxPID uint32
	txQueue   map[uint32]*pendingPkt

	// inbound state
	nextRxPID uint32
	rxBuffer  map[uint32][]byte

	// ack state — pendingAcks is the ordered FIFO emitted on the wire;
	// pendingAckSet mirrors it for O(1) dedupe in addPendingAckLocked.
	// Always kept in sync: every slice push adds to the set, every slice
	// removal deletes from the set.
	pendingAcks     []uint32
	pendingAckSet   map[uint32]struct{}
	ackPendingSince time.Time

	// TLS-side read buffer
	readBuf    []byte
	readClosed bool
	readErr    error
	readCond   *sync.Cond

	// Signalled when txQueue has space (after acks remove entries) so a
	// blocked Write can resume. Bound to l.mu.
	queueCond *sync.Cond

	// Signalled when remoteKnown transitions to true so a Write waiting
	// for the peer's hard-reset can proceed. Bound to l.mu.
	remoteCond *sync.Cond

	outbound chan OutPacket
	closed   bool
}

type pendingPkt struct {
	msgPID   uint32
	opcode   proto.Opcode
	body     []byte
	sentAt   time.Time
	attempts int
	// higherACKs counts how many times we have observed an inbound ACK
	// for some packet with msgPID > this one's. Once it reaches
	// FastRetransmitThreshold, Tick will resend without waiting for the
	// backoff timer — TCP-style fast retransmit. Reset to zero after
	// each retransmit so the counter restarts from the new send.
	higherACKs int
}

// New constructs a Layer.
func New(cfg Config) *Layer {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.OutboundBuffer <= 0 {
		cfg.OutboundBuffer = 64
	}
	l := &Layer{
		cfg:           cfg,
		keyID:         cfg.InitialKeyID,
		txQueue:       make(map[uint32]*pendingPkt),
		rxBuffer:      make(map[uint32][]byte),
		outbound:      make(chan OutPacket, cfg.OutboundBuffer),
		pendingAckSet: make(map[uint32]struct{}),
	}
	l.readCond = sync.NewCond(&l.mu)
	l.queueCond = sync.NewCond(&l.mu)
	l.remoteCond = sync.NewCond(&l.mu)
	return l
}

// Outbound returns the channel of packets to wrap with tls-crypt and send.
// The orchestrator drains this channel.
func (l *Layer) Outbound() <-chan OutPacket { return l.outbound }

// SetKeyID changes the key-id for subsequent outbound packets (used by rekey).
func (l *Layer) SetKeyID(k uint8) {
	l.mu.Lock()
	l.keyID = k
	l.mu.Unlock()
}

// KeyID returns the key-id used in outbound packets.
func (l *Layer) KeyID() uint8 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.keyID
}

// RemoteSessionID returns the peer's session-id if known.
func (l *Layer) RemoteSessionID() (uint64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.remoteSessionID, l.remoteKnown
}

// SetRemoteSessionID pre-seeds the peer's session-id. Used by rekey to
// inherit the SID from the previous-generation layer so ACKs are valid from
// the very first outbound packet on the new channel.
func (l *Layer) SetRemoteSessionID(sid uint64) {
	l.mu.Lock()
	l.remoteSessionID = sid
	l.remoteKnown = true
	l.remoteCond.Broadcast()
	l.mu.Unlock()
}

// SendHardReset queues the initial P_CONTROL_HARD_RESET_CLIENT_V2 or V3
// packet (opcode chosen by caller). Body is empty.
func (l *Layer) SendHardReset(opcode proto.Opcode) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if !opcode.IsControl() {
		return errors.New("reliable: hard reset opcode must be a control opcode")
	}
	return l.enqueueAndEmitLocked(opcode, nil)
}

// SendSoftReset queues a P_CONTROL_SOFT_RESET_V1 packet on the supplied
// (new) key-id. Body is empty. Caller is responsible for then calling
// SetKeyID to switch outbound to the new key-id.
func (l *Layer) SendSoftReset(newKeyID uint8) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	// The soft-reset packet itself goes out under the *new* key-id; we leave
	// the layer's keyID unchanged so subsequent retransmits use whichever
	// the caller has set.
	prev := l.keyID
	l.keyID = newKeyID
	err := l.enqueueAndEmitLocked(proto.PControlSoftResetV1, nil)
	l.keyID = prev
	return err
}

// enqueueAndEmitLocked records a new outbound packet in txQueue and emits it
// once. Caller must hold mu.
func (l *Layer) enqueueAndEmitLocked(opcode proto.Opcode, body []byte) error {
	if len(l.txQueue) >= MaxQueueSize {
		return ErrQueueFull
	}
	pid := l.nextTxPID
	l.nextTxPID++
	now := l.cfg.Clock()
	bodyCopy := append([]byte(nil), body...)
	l.txQueue[pid] = &pendingPkt{
		msgPID:   pid,
		opcode:   opcode,
		body:     bodyCopy,
		sentAt:   now,
		attempts: 1,
	}
	return l.emitLocked(opcode, pid, bodyCopy)
}

// emitLocked builds an OutPacket and pushes it onto the outbound channel.
// Drains up to MaxAcksPerPacket pending acks to piggyback. Caller must hold
// mu.
//
// On a full outbound channel the call returns nil — the packet remains in
// txQueue and will be re-emitted by the next Tick. The previous semantics
// returned ErrQueueFull, which made callers surface a "queue full" error
// to user code even though the data was successfully queued for retransmit.
func (l *Layer) emitLocked(opcode proto.Opcode, msgPID uint32, body []byte) error {
	acks := l.drainAcksLocked(MaxAcksPerPacket)
	payload := proto.ControlPayload{
		Acks:            acks,
		RemoteSessionID: l.remoteSessionID,
		MessagePID:      msgPID,
		Body:            body,
	}
	out := OutPacket{
		Opcode:    opcode,
		KeyID:     l.keyID,
		SessionID: l.cfg.LocalSessionID,
		Payload:   payload,
	}
	select {
	case l.outbound <- out:
	default:
		// Outbound channel is full; the packet is still in txQueue and
		// Tick will retry it. Push the acks back since we didn't emit them.
		l.pendingAcks = append(acks, l.pendingAcks...)
		for _, a := range acks {
			l.pendingAckSet[a] = struct{}{}
		}
		if l.ackPendingSince.IsZero() && len(l.pendingAcks) > 0 {
			l.ackPendingSince = l.cfg.Clock()
		}
	}
	return nil
}

// emitStandaloneAckLocked sends a P_ACK_V1 packet draining pending acks.
// No-op if no acks pending or remote sid unknown. Caller must hold mu.
//
// On a full outbound channel the acks remain pending so the next Tick can
// retry — no error is surfaced to the caller.
func (l *Layer) emitStandaloneAckLocked() error {
	if len(l.pendingAcks) == 0 || !l.remoteKnown {
		return nil
	}
	acks := l.drainAcksLocked(MaxAcksPerPacket)
	out := OutPacket{
		Opcode:    proto.PAckV1,
		KeyID:     l.keyID,
		SessionID: l.cfg.LocalSessionID,
		Ack:       proto.AckPayload{Acks: acks, RemoteSessionID: l.remoteSessionID},
	}
	select {
	case l.outbound <- out:
	default:
		// Outbound full — restore acks for next tick.
		l.pendingAcks = append(acks, l.pendingAcks...)
		for _, a := range acks {
			l.pendingAckSet[a] = struct{}{}
		}
		if l.ackPendingSince.IsZero() {
			l.ackPendingSince = l.cfg.Clock()
		}
	}
	return nil
}

// drainAcksLocked removes and returns up to max pending acks. Caller must
// hold mu.
func (l *Layer) drainAcksLocked(max int) []uint32 {
	if len(l.pendingAcks) == 0 {
		return nil
	}
	n := min(len(l.pendingAcks), max)
	acks := make([]uint32, n)
	copy(acks, l.pendingAcks[:n])
	for _, a := range acks {
		delete(l.pendingAckSet, a)
	}
	l.pendingAcks = l.pendingAcks[n:]
	if len(l.pendingAcks) == 0 {
		l.ackPendingSince = time.Time{}
	}
	return acks
}

// HandleInbound processes one inbound (already tls-crypt-unwrapped + parsed)
// packet. Drops silently on duplicate or sid mismatch.
func (l *Layer) HandleInbound(in InPacket) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}

	// Lock in remote session-id on first inbound packet from the server.
	if !l.remoteKnown {
		l.remoteSessionID = in.SessionID
		l.remoteKnown = true
		// Wake any Write/Close waiters that were blocked on this.
		l.remoteCond.Broadcast()
	} else if in.SessionID != l.remoteSessionID {
		return ErrSessionIDMismatch
	}

	if in.Opcode == proto.PAckV1 {
		for _, ack := range in.Ack.Acks {
			delete(l.txQueue, ack)
			l.bumpHigherACKsLocked(ack)
		}
		l.queueCond.Broadcast()
		return nil
	}

	// Piggybacked inbound acks: they acknowledge our outbound packets.
	for _, ack := range in.Payload.Acks {
		delete(l.txQueue, ack)
		l.bumpHigherACKsLocked(ack)
	}
	if len(in.Payload.Acks) > 0 {
		l.queueCond.Broadcast()
	}

	// Deduplicate by msg_pid.
	msgPID := in.Payload.MessagePID
	if msgPID < l.nextRxPID {
		// Old (already delivered). Still ack — the peer may have missed our
		// previous ack and is retransmitting.
		l.addPendingAckLocked(msgPID)
		return nil
	}
	if _, dup := l.rxBuffer[msgPID]; dup {
		// Out-of-order duplicate.
		l.addPendingAckLocked(msgPID)
		return nil
	}

	if msgPID == l.nextRxPID {
		// In-order: deliver this and any contiguous buffered packets.
		l.appendReadLocked(in.Payload.Body)
		l.nextRxPID++
		for {
			body, ok := l.rxBuffer[l.nextRxPID]
			if !ok {
				break
			}
			delete(l.rxBuffer, l.nextRxPID)
			l.appendReadLocked(body)
			l.nextRxPID++
		}
	} else {
		// Future packet — buffer until predecessors arrive.
		l.rxBuffer[msgPID] = append([]byte(nil), in.Payload.Body...)
	}
	l.addPendingAckLocked(msgPID)
	return nil
}

// bumpHigherACKsLocked credits an inbound ACK for msgPID=acked toward
// the fast-retransmit counter of every still-pending packet whose
// msgPID is strictly lower. The acked packet itself has already been
// removed from txQueue by the caller, so it never bumps its own
// counter. Caller must hold mu.
func (l *Layer) bumpHigherACKsLocked(acked uint32) {
	for pid, pkt := range l.txQueue {
		if pid < acked {
			pkt.higherACKs++
		}
	}
}

func (l *Layer) addPendingAckLocked(msgPID uint32) {
	if _, ok := l.pendingAckSet[msgPID]; ok {
		return
	}
	l.pendingAckSet[msgPID] = struct{}{}
	l.pendingAcks = append(l.pendingAcks, msgPID)
	if l.ackPendingSince.IsZero() {
		l.ackPendingSince = l.cfg.Clock()
	}
}

func (l *Layer) appendReadLocked(body []byte) {
	if len(body) == 0 {
		return
	}
	l.readBuf = append(l.readBuf, body...)
	l.readCond.Broadcast()
}

// Read implements io.Reader for crypto/tls.
func (l *Layer) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for len(l.readBuf) == 0 {
		if l.closed || l.readClosed {
			if l.readErr != nil {
				return 0, l.readErr
			}
			return 0, io.EOF
		}
		l.readCond.Wait()
	}
	n := copy(p, l.readBuf)
	l.readBuf = l.readBuf[n:]
	return n, nil
}

// Write implements io.Writer for crypto/tls. Chunks input into TLSChunkSize
// pieces, each becoming a P_CONTROL_V1 packet. Blocks while the outbound
// queue is full, waiting on acks to drain it. Also blocks the very first
// chunk until the peer's hard-reset has arrived, so the wire flow is the
// strict 4-way (HARD_RESET_CLIENT → HARD_RESET_SERVER → ACK → first TLS
// fragment) that some servers (e.g. ProtonVPN) demand.
func (l *Layer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Block until peer's session-id is known (HARD_RESET_SERVER received).
	// This adds the synchronization step that strict servers require.
	for !l.remoteKnown && !l.closed {
		l.remoteCond.Wait()
	}
	written := 0
	for len(p) > 0 {
		if l.closed {
			if written > 0 {
				return written, nil
			}
			return 0, ErrClosed
		}
		for len(l.txQueue) >= MaxQueueSize && !l.closed {
			l.queueCond.Wait()
		}
		if l.closed {
			if written > 0 {
				return written, nil
			}
			return 0, ErrClosed
		}
		chunk := p
		if len(chunk) > TLSChunkSize {
			chunk = chunk[:TLSChunkSize]
		}
		if err := l.enqueueAndEmitLocked(proto.PControlV1, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// CloseRead signals end-of-stream to the TLS reader without closing outbound.
// Used when the peer has cleanly exited.
func (l *Layer) CloseRead(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.readClosed = true
	if err != nil {
		l.readErr = err
	}
	l.readCond.Broadcast()
}

// Close tears down the layer. After this, Read returns io.EOF and Write
// returns ErrClosed.
func (l *Layer) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	l.readClosed = true
	if l.readErr == nil {
		l.readErr = io.EOF
	}
	l.readCond.Broadcast()
	l.queueCond.Broadcast()
	l.remoteCond.Broadcast()
	close(l.outbound)
	return nil
}

// Tick drives retransmits and standalone ack emission. Returns
// ErrTooManyRetransmits if any pending packet has been retransmitted
// MaxRetransmits times without ack — caller treats this as fatal.
func (l *Layer) Tick() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	now := l.cfg.Clock()

	for _, pkt := range l.txQueue {
		// Fast retransmit short-circuits the backoff timer when enough
		// later packets have already been ACKed — strong evidence that
		// this one was lost in flight rather than just slow. Still
		// subject to MaxRetransmits so a one-way black hole can't drive
		// an infinite resend.
		fast := pkt.higherACKs >= FastRetransmitThreshold
		if !fast {
			backoffShift := min(pkt.attempts-1, 4)
			backoff := min(InitialRetransmit<<backoffShift, MaxRetransmit)
			if now.Sub(pkt.sentAt) < backoff {
				continue
			}
		}
		if pkt.attempts >= MaxRetransmits {
			return ErrTooManyRetransmits
		}
		if err := l.emitLocked(pkt.opcode, pkt.msgPID, pkt.body); err != nil {
			return err
		}
		pkt.attempts++
		pkt.sentAt = now
		pkt.higherACKs = 0
	}

	if len(l.pendingAcks) > 0 {
		// Count-based fast flush: at MaxAcksPerPacket we're at the
		// per-packet ack ceiling, so waiting longer can only push the
		// surplus into a second standalone packet anyway. Send now.
		// Otherwise observe the grace period to give a piggyback chance.
		if len(l.pendingAcks) >= MaxAcksPerPacket ||
			(!l.ackPendingSince.IsZero() && now.Sub(l.ackPendingSince) >= AckFlushDelay) {
			return l.emitStandaloneAckLocked()
		}
	}
	return nil
}

// PendingAcks returns the count of pending acks (for tests).
func (l *Layer) PendingAcks() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pendingAcks)
}

// QueueLen returns the count of unacked outbound packets (for tests).
func (l *Layer) QueueLen() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.txQueue)
}
