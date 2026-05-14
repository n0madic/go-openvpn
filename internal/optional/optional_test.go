// SPDX-License-Identifier: AGPL-3.0-or-later

package optional

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestZeroIsNone(t *testing.T) {
	t.Parallel()
	var v Value[int]
	if !v.IsNone() {
		t.Errorf("zero Value should be None")
	}
	if v.IsSome() {
		t.Errorf("zero Value should not be Some")
	}
}

func TestSomeAndGet(t *testing.T) {
	t.Parallel()
	v := Some(42)
	if !v.IsSome() {
		t.Errorf("Some(42).IsSome() = false")
	}
	got, ok := v.Get()
	if !ok || got != 42 {
		t.Errorf("Get() = (%d, %v), want (42, true)", got, ok)
	}
}

func TestNoneGet(t *testing.T) {
	t.Parallel()
	v := None[string]()
	got, ok := v.Get()
	if ok || got != "" {
		t.Errorf("Get() on None = (%q, %v), want (\"\", false)", got, ok)
	}
}

func TestUnwrapOr(t *testing.T) {
	t.Parallel()
	if got := Some("hi").UnwrapOr("fallback"); got != "hi" {
		t.Errorf("Some.UnwrapOr = %q, want hi", got)
	}
	if got := None[string]().UnwrapOr("fallback"); got != "fallback" {
		t.Errorf("None.UnwrapOr = %q, want fallback", got)
	}
}

func TestUnwrapPanicsOnNone(t *testing.T) {
	t.Parallel()
	defer func() {
		r := recover()
		err, ok := r.(error)
		if !ok || !errors.Is(err, ErrUnwrapNone) {
			t.Errorf("recover = %v, want ErrUnwrapNone", r)
		}
	}()
	_ = None[int]().Unwrap()
	t.Fatal("Unwrap did not panic")
}

func TestUnwrapOnSomeReturnsValue(t *testing.T) {
	t.Parallel()
	if got := Some(7).Unwrap(); got != 7 {
		t.Errorf("Some(7).Unwrap() = %d, want 7", got)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	t.Parallel()
	type holder struct {
		A Value[int]    `json:"a"`
		B Value[string] `json:"b"`
	}
	in := holder{A: Some(11), B: None[string]()}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":11,"b":null}`
	if got := string(data); got != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}
	var out holder
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !out.A.IsSome() || out.A.Unwrap() != 11 {
		t.Errorf("A round-trip wrong: %+v", out.A)
	}
	if !out.B.IsNone() {
		t.Errorf("B should be None: %+v", out.B)
	}
}

func TestJSONUnmarshalNull(t *testing.T) {
	t.Parallel()
	var v Value[int]
	if err := json.Unmarshal([]byte("null"), &v); err != nil {
		t.Fatal(err)
	}
	if !v.IsNone() {
		t.Errorf("null should decode to None")
	}
}

func TestJSONUnmarshalReplacesPreviousValue(t *testing.T) {
	t.Parallel()
	v := Some(123)
	if err := json.Unmarshal([]byte("null"), &v); err != nil {
		t.Fatal(err)
	}
	if !v.IsNone() {
		t.Errorf("expected None after unmarshalling null")
	}
}
