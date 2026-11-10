package py

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
)

// Error is a Python exception: its class name travels with it, because the service writes
// f"{type(exc).__name__}: {exc}" into run records and a reader keys on the class.
type Error struct {
	Type string
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

// Errorf builds an Error of the named Python class.
func Errorf(typ, format string, args ...any) error {
	return &Error{Type: typ, Msg: fmt.Sprintf(format, args...)}
}

// Typed lets an error type name the Python class it stands for.
type Typed interface{ PyType() string }

// TypeName is type(exc).__name__. Errors that do not name a class are mapped to the class the Python
// libraries raised for the same failure (requests' ConnectionError/ReadTimeout, ValueError for a JSON
// decode); anything unrecognised is "Exception".
func TypeName(err error) string {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Type
	}
	var t Typed
	if errors.As(err, &t) {
		return t.PyType()
	}
	var je *JSONDecodeError
	if errors.As(err, &je) {
		return "JSONDecodeError"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "ReadTimeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "ReadTimeout"
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return "ConnectionError"
	}
	return "Exception"
}

// ExcString is f"{type(exc).__name__}: {exc}".
func ExcString(err error) string { return TypeName(err) + ": " + err.Error() }
