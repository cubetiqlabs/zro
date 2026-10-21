package service

import (
	"errors"
	"fmt"
)

// Kind classifies a service failure so each transport can map it to its own
// status code without inspecting messages.
type Kind int

const (
	KindInvalid Kind = iota + 1
	KindUnauthenticated
	KindForbidden
	KindNotFound
	KindConflict
	KindExhausted
	KindInternal
)

// Error is the error type returned by Service methods.
type Error struct {
	Kind Kind
	Msg  string
	Err  error
}

func (e *Error) Error() string { return e.Msg }
func (e *Error) Unwrap() error { return e.Err }

func newErr(kind Kind, format string, args ...any) *Error {
	return &Error{Kind: kind, Msg: fmt.Sprintf(format, args...)}
}

// internal hides the cause from clients while keeping it for logs/unwrapping.
func internal(msg string, err error) *Error {
	return &Error{Kind: KindInternal, Msg: msg, Err: err}
}

// KindOf returns the Kind of err, or KindInternal for foreign errors.
func KindOf(err error) Kind {
	var se *Error
	if errors.As(err, &se) {
		return se.Kind
	}
	return KindInternal
}

// Message returns a client-safe message for err.
func Message(err error) string {
	var se *Error
	if errors.As(err, &se) {
		return se.Msg
	}
	return "internal error"
}
