// Package pyyaml is a line-by-line Go port of the parts of PyYAML 6.0.2 (pure-Python SafeLoader and
// SafeDumper, as run by CPython 3.12) that nightly-review depends on: yaml.safe_load, yaml.safe_load_all and
// yaml.safe_dump(sort_keys=True, default_flow_style=False).
//
// WHY A PORT AND NOT A GO YAML LIBRARY. A proposal's fingerprint is a sha256 over normalise_body's output,
// and for YAML content that output IS PyYAML's re-serialisation of what PyYAML parsed. Every Proposal object
// already on a cluster is named by such a fingerprint, so the Go service must produce the same bytes for the
// same input or tonight's run re-proposes everything. That includes the cases where PyYAML refuses the input
// (normalise_body then falls back to its text path) and the cases where it raises something that is not a
// YAMLError (which normalise_body does not catch). A Go YAML library resolves scalars by YAML 1.2, accepts and
// rejects different documents and emits different text, so the scanner, parser, composer, resolver,
// constructor, representer, serializer and emitter are all ported here, each function named after the PyYAML
// function it ports.
package pyyaml

import "fmt"

// YAMLError is every exception `except yaml.YAMLError` catches: ReaderError, ScannerError, ParserError,
// ComposerError, ConstructorError, RepresenterError. The message is informative only; nothing compares it.
type YAMLError struct{ Msg string }

func (e *YAMLError) Error() string { return e.Msg }

func yamlErr(context, problem string) *YAMLError {
	switch {
	case context == "":
		return &YAMLError{Msg: problem}
	case problem == "":
		return &YAMLError{Msg: context}
	}
	return &YAMLError{Msg: context + "\n" + problem}
}

// PyError is a Python exception that is NOT a YAMLError — ValueError from int('abc') under an explicit !!int,
// KeyError from !!bool maybe, RecursionError from deep nesting. normalise_body does not catch these; they
// propagate to its caller. Type is the Python class name, Msg is str(exc).
type PyError struct {
	Type string
	Msg  string
}

// Error is str(exc); the class is PyType.
func (e *PyError) Error() string { return e.Msg }

// PyType names the Python class, for f"{type(exc).__name__}: {exc}".
func (e *PyError) PyType() string { return e.Type }

// PyType names the Python class.
func (e *YAMLError) PyType() string { return "YAMLError" }

func pyErr(typ, format string, args ...any) *PyError {
	return &PyError{Type: typ, Msg: fmt.Sprintf(format, args...)}
}

// panic-based unwinding mirrors Python's exceptions inside the deeply recursive ported code; the exported
// entry points recover and return the error.
type raised struct{ err error }

func raise(err error) { panic(raised{err}) }

func catch(err *error) {
	if r := recover(); r != nil {
		if rz, ok := r.(raised); ok {
			*err = rz.err
			return
		}
		panic(r)
	}
}
