// SPDX-License-Identifier: AGPL-3.0-or-later

// Package workers provides a small lifecycle manager for the long-running
// goroutines that pump packets between the OpenVPN protocol layers.
//
// The session orchestrator spawns ~10 goroutines (read/write/tick per
// reliable layer, rekey watch, keepalive, two liveness watchdogs, stats,
// control-channel reader). The manager centralises three concerns that
// were previously scattered across the orchestrator:
//
//   - Cancellation. A single Shutdown() call cancels the shared context
//     and is safe to call from multiple sites (sync.Once-guarded). All
//     workers observe ctx.Done() the same way.
//   - Panic recovery. A panic in any worker is logged with the worker
//     name and triggers Shutdown() instead of crashing the process.
//   - Observability. Each worker is named at start; the manager logs
//     start/stop events and exposes Active() for tests and stats.
//
// Workers receive the manager's context as their sole parameter; they are
// expected to exit when it fires. The manager owns the cancel func, so
// callers never have to deal with both ctx and cancel.
package workers

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

// Manager coordinates the lifecycle of a set of cooperating worker
// goroutines. The zero value is invalid; use NewManager.
type Manager struct {
	log *slog.Logger

	ctx          context.Context
	cancel       context.CancelFunc
	shutdownOnce sync.Once

	// onPanic, when non-nil, is invoked from the recover branch of every
	// worker. Useful for routing the panic to a session-level closeErr so
	// the surrounding client can surface it to its caller. Called with
	// the manager's lock NOT held; implementations must be brief and not
	// re-enter the manager.
	onPanic func(worker string, recovered any)

	wg     sync.WaitGroup
	active atomic.Int32
}

// Option configures NewManager.
type Option func(*Manager)

// WithPanicHandler installs a callback invoked when a worker panics. The
// callback receives the worker's name and the recovered value. The manager
// still logs the panic and initiates shutdown regardless.
func WithPanicHandler(fn func(worker string, recovered any)) Option {
	return func(m *Manager) { m.onPanic = fn }
}

// NewManager returns a Manager whose context is derived from parent. If
// parent is nil, context.Background is used.
func NewManager(parent context.Context, log *slog.Logger, opts ...Option) *Manager {
	if parent == nil {
		parent = context.Background()
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(parent)
	m := &Manager{log: log, ctx: ctx, cancel: cancel}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Context returns the manager's shared cancellation context. Workers can
// pass it down to blocking operations.
func (m *Manager) Context() context.Context { return m.ctx }

// ShouldShutdown returns a channel that is closed when Shutdown has been
// invoked (or the parent context fired). Workers that already use a
// select-driven loop can plug this in place of an ad-hoc done channel.
func (m *Manager) ShouldShutdown() <-chan struct{} { return m.ctx.Done() }

// Active returns the number of workers currently running.
func (m *Manager) Active() int32 { return m.active.Load() }

// Go starts a named worker. The function receives the manager's context
// and is expected to return when the context fires. Panics are recovered,
// logged, and trigger Shutdown.
func (m *Manager) Go(name string, fn func(ctx context.Context)) {
	m.wg.Add(1)
	m.active.Add(1)
	go func() {
		defer m.wg.Done()
		defer m.active.Add(-1)
		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()
				m.log.Error("worker panic",
					"worker", name,
					"recovered", fmt.Sprint(r),
					"stack", string(stack),
				)
				if m.onPanic != nil {
					m.onPanic(name, r)
				}
				m.Shutdown()
			}
		}()
		m.log.Debug("worker started", "worker", name)
		fn(m.ctx)
		m.log.Debug("worker stopped", "worker", name)
	}()
}

// Shutdown cancels the manager's context. Safe to call multiple times.
// Workers observe the cancellation via Context().Done() or ShouldShutdown().
// Use Wait to block until they have all returned.
func (m *Manager) Shutdown() {
	m.shutdownOnce.Do(m.cancel)
}

// Wait blocks until every worker has returned. Does NOT call Shutdown;
// the caller must initiate cancellation before (or concurrently with) Wait.
func (m *Manager) Wait() {
	m.wg.Wait()
}
