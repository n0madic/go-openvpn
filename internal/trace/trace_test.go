// SPDX-License-Identifier: AGPL-3.0-or-later

package trace

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestStageString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		stage HandshakeStage
		want  string
	}{
		{StageHardReset, "hard-reset"},
		{StageTLSHandshake, "tls"},
		{StageKeyMethod2Send, "km2-send"},
		{StageKeyMethod2Recv, "km2-recv"},
		{StagePushRequest, "push-request"},
		{StagePushReply, "push-reply"},
		{StageDataKeys, "data-keys"},
		{StageComplete, "complete"},
		{HandshakeStage(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.stage.String(); got != c.want {
			t.Errorf("Stage(%d).String() = %q, want %q", c.stage, got, c.want)
		}
	}
}

func TestNoopTracerNoOp(t *testing.T) {
	t.Parallel()
	// Just verify it doesn't panic and the interface is satisfied.
	var tr HandshakeTracer = NoopTracer{}
	tr.OnHandshakeEvent(HandshakeEvent{Stage: StageHardReset, Time: time.Now()})
	tr.OnHandshakeEvent(HandshakeEvent{Stage: StageComplete, Time: time.Now(), Err: errors.New("x")})
}

func TestTracerFuncCaptures(t *testing.T) {
	t.Parallel()
	var (
		mu      sync.Mutex
		events  []HandshakeEvent
		tracer  HandshakeTracer
		sentErr = errors.New("boom")
	)
	tracer = TracerFunc(func(e HandshakeEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	})
	tracer.OnHandshakeEvent(HandshakeEvent{Stage: StageHardReset, Time: time.Unix(1, 0)})
	tracer.OnHandshakeEvent(HandshakeEvent{Stage: StageTLSHandshake, Time: time.Unix(2, 0), Err: sentErr})

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Stage != StageHardReset || events[1].Stage != StageTLSHandshake {
		t.Errorf("stages out of order: %+v", events)
	}
	if !errors.Is(events[1].Err, sentErr) {
		t.Errorf("captured err = %v, want %v", events[1].Err, sentErr)
	}
}
