// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trace provides observability hooks for the OpenVPN handshake.
//
// The handshake state machine in internal/control emits events as it
// progresses through its phases (hard-reset, TLS, KEY_METHOD 2 exchange,
// PUSH_REPLY, data-key derivation). Callers — diagnostic tooling, tests,
// or production monitoring — can register a HandshakeTracer to observe
// timing and outcomes without depending on log output.
//
// The default tracer is NoopTracer, which is what every internal site
// substitutes when none is provided. There is no overhead beyond an
// interface method call when tracing is off.
package trace

import "time"

// HandshakeStage names a phase of the OpenVPN client handshake.
type HandshakeStage uint8

const (
	// StageHardReset covers sending P_CONTROL_HARD_RESET_CLIENT_V2/V3
	// and receiving the server's HARD_RESET reply.
	StageHardReset HandshakeStage = iota + 1
	// StageTLSHandshake covers the inner TLS 1.2/1.3 client handshake
	// driven over the reliable layer.
	StageTLSHandshake
	// StageKeyMethod2Send covers building and writing the client's
	// KEY_METHOD 2 message (pre_master, randoms, options, peer-info,
	// optional auth-user-pass).
	StageKeyMethod2Send
	// StageKeyMethod2Recv covers reading the server's KEY_METHOD 2
	// reply (server randoms + auth ack).
	StageKeyMethod2Recv
	// StagePushRequest covers writing the PUSH_REQUEST control message
	// on the established TLS channel.
	StagePushRequest
	// StagePushReply covers receiving and parsing the server's
	// PUSH_REPLY (cipher, peer-id, ifconfig, routes, DNS, MTU).
	StagePushReply
	// StageDataKeys covers TLS-EKM key derivation for the data channel.
	StageDataKeys
	// StageComplete is emitted once after StageDataKeys with a nil error
	// to signal a fully-established session.
	StageComplete
)

// String renders a stage as a short stable token, suitable for logs.
func (s HandshakeStage) String() string {
	switch s {
	case StageHardReset:
		return "hard-reset"
	case StageTLSHandshake:
		return "tls"
	case StageKeyMethod2Send:
		return "km2-send"
	case StageKeyMethod2Recv:
		return "km2-recv"
	case StagePushRequest:
		return "push-request"
	case StagePushReply:
		return "push-reply"
	case StageDataKeys:
		return "data-keys"
	case StageComplete:
		return "complete"
	default:
		return "unknown"
	}
}

// HandshakeEvent is what a tracer receives. One event is emitted at
// the START of each stage; the same stage is reported with a non-nil
// Err if it fails, and that is the last event for that handshake. A
// final StageComplete event with Err==nil marks success.
type HandshakeEvent struct {
	Stage HandshakeStage
	Time  time.Time
	Err   error
}

// HandshakeTracer receives handshake events. Implementations must be
// safe for concurrent use — control.Run today emits events from a
// single goroutine, but the session orchestrator may emit rekey events
// from other goroutines in the future.
type HandshakeTracer interface {
	OnHandshakeEvent(event HandshakeEvent)
}

// NoopTracer discards every event. Used as the default when no tracer
// is configured, so call sites never need a nil check.
type NoopTracer struct{}

// OnHandshakeEvent implements HandshakeTracer.
func (NoopTracer) OnHandshakeEvent(HandshakeEvent) {}

// TracerFunc adapts a plain function to HandshakeTracer.
type TracerFunc func(event HandshakeEvent)

// OnHandshakeEvent implements HandshakeTracer.
func (f TracerFunc) OnHandshakeEvent(event HandshakeEvent) { f(event) }

// Compile-time interface check.
var _ HandshakeTracer = NoopTracer{}
