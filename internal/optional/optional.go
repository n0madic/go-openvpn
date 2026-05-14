// SPDX-License-Identifier: AGPL-3.0-or-later

// Package optional provides a small generic Value[T] type for fields
// whose zero value is indistinguishable from "not set". Inspired by
// ooni/minivpn/internal/optional (which itself follows the Rust
// Option<T> shape).
//
// When to reach for it: pointer types where nil-pointer-pointer
// ambiguity can confuse callers; primitive fields whose zero value
// (0, "", false) is a valid setting on its own; JSON payloads where
// `null` and absence should both decode to "no value".
//
// When NOT to: the OpenVPN PUSH_REPLY fields in this codebase already
// use types whose zero value is naturally distinct (netip.Addr/Prefix
// with IsValid(), slices with len()). Wrapping those in Value[T] adds
// boilerplate without gain. The package exists so future additions
// (typically JSON-parsed config or rarely-set numeric tuning knobs)
// have an idiomatic, well-tested home.
package optional

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Value is an optional value. The zero Value is equivalent to None.
type Value[T any] struct {
	v   T
	set bool
}

// None returns an empty Value of T.
func None[T any]() Value[T] {
	return Value[T]{}
}

// Some returns a Value carrying v.
func Some[T any](v T) Value[T] {
	return Value[T]{v: v, set: true}
}

// IsSome reports whether the Value carries a payload.
func (o Value[T]) IsSome() bool { return o.set }

// IsNone reports whether the Value is empty.
func (o Value[T]) IsNone() bool { return !o.set }

// Get returns (payload, true) when set or (zeroValue, false) otherwise.
// Prefer this over Unwrap when None is a legitimate runtime outcome.
func (o Value[T]) Get() (T, bool) { return o.v, o.set }

// UnwrapOr returns the payload when set or fallback otherwise.
func (o Value[T]) UnwrapOr(fallback T) T {
	if o.set {
		return o.v
	}
	return fallback
}

// Unwrap returns the payload or panics with ErrUnwrapNone if the Value
// is empty. Use Get for non-panicking access.
func (o Value[T]) Unwrap() T {
	if !o.set {
		panic(ErrUnwrapNone)
	}
	return o.v
}

// ErrUnwrapNone is the panic value used by Unwrap on an empty Value.
var ErrUnwrapNone = errors.New("optional: Unwrap on None value")

// MarshalJSON encodes a None Value as JSON null and a Some Value as
// the encoding of its payload.
func (o Value[T]) MarshalJSON() ([]byte, error) {
	if !o.set {
		return []byte("null"), nil
	}
	return json.Marshal(o.v)
}

// UnmarshalJSON decodes a JSON null as None and any other valid JSON
// payload as Some(T).
func (o *Value[T]) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*o = Value[T]{}
		return nil
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*o = Some(v)
	return nil
}
