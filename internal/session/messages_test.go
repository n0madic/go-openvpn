// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"errors"
	"testing"
	"time"
)

func TestParseRestart(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in         string
		wantDelay  time.Duration
		wantReason string
	}{
		{"RESTART", 0, ""},
		{"RESTART,", 0, ""},
		{"RESTART,server reboot", 0, "server reboot"},
		{"RESTART,30", 30 * time.Second, ""},
		{"RESTART,30,server reboot", 30 * time.Second, "server reboot"},
		{"RESTART,0,backup activation", 0, "backup activation"},
		// Edge case: reason field contains a comma.
		{"RESTART,15,reason, with comma", 15 * time.Second, "reason, with comma"},
		// Non-numeric first field: treat whole remainder as reason.
		{"RESTART,reason,with,commas", 0, "reason,with,commas"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			t.Parallel()
			got := parseRestart(c.in)
			if got.Delay != c.wantDelay {
				t.Errorf("Delay = %s, want %s", got.Delay, c.wantDelay)
			}
			if got.Reason != c.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, c.wantReason)
			}
		})
	}
}

func TestRestartErrorAsTarget(t *testing.T) {
	t.Parallel()
	// Verify RestartError can be unwrapped via errors.As (a common usage
	// pattern from outside the package).
	re := &RestartError{Delay: 5 * time.Second, Reason: "test"}
	var err error = re
	var target *RestartError
	if !errors.As(err, &target) {
		t.Fatal("errors.As failed to extract RestartError")
	}
	if target.Reason != "test" {
		t.Errorf("Reason = %q", target.Reason)
	}
	if target.Delay != 5*time.Second {
		t.Errorf("Delay = %s", target.Delay)
	}
}

func TestRestartErrorString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  *RestartError
		want string
	}{
		{&RestartError{}, "openvpn: server requested RESTART (delay=0s)"},
		{&RestartError{Delay: 30 * time.Second}, "openvpn: server requested RESTART (delay=30s)"},
		{&RestartError{Reason: "reboot"}, "openvpn: server requested RESTART (delay=0s): reboot"},
	}
	for _, c := range cases {
		if got := c.err.Error(); got != c.want {
			t.Errorf("Error() = %q, want %q", got, c.want)
		}
	}
}
