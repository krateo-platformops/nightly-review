// Package jsonschema validates the reviewer's responses against the service's own schemas, with the
// error the Python service's jsonschema 4.23 (Draft 2020-12) raised for the same input.
//
// The keywords are the response schemas' and the chart's values.schema.json's (which the test suite
// validates values.yaml against): type, required, properties, additionalProperties, items, enum,
// min/maxLength, min/maxItems, minimum, maximum, pattern and propertyNames.
//
// WHY NOT A GENERAL VALIDATOR. The run records the validation message — "DROPPED proposal[2]: does not
// match the contract (…)" is the note that tells the next prompt change what the model got wrong — and
// that text is jsonschema's: which error best_match picks among several, the message wording, and the
// pprint layout of the failing schema. The schemas are fixed and use a dozen keywords, so this package
// implements exactly those keywords, and exactly jsonschema's choice and formatting of the error.
package jsonschema

import (
	"fmt"
	"math"
	"strings"

	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/pyre"
)

// ValidationError is jsonschema.ValidationError.
type ValidationError struct {
	Message    string
	Validator  string
	Path       []any // instance path: string keys and int indexes
	SchemaPath []any // relative schema path, ending in the failing keyword
	Schema     any
	Instance   any
}

// PyType names the Python class.
func (e *ValidationError) PyType() string { return "ValidationError" }

// Error is str(ValidationError): the message, then the failing schema and the instance, each through
// pprint at width 72 — jsonschema's __str__ after textwrap.dedent.
func (e *ValidationError) Error() string {
	schemaPath := formatIndex("schema", e.SchemaPath[:len(e.SchemaPath)-1])
	instancePath := formatIndex("instance", e.Path)
	return e.Message + "\n\n" +
		"Failed validating " + py.StrRepr(e.Validator) + " in " + schemaPath + ":\n" +
		indent(py.PFormat(e.Schema, 72)) + "\n\n" +
		"On " + instancePath + ":\n" +
		indent(py.PFormat(e.Instance, 72))
}

func indent(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if py.Strip(l) != "" {
			lines[i] = "    " + l
		}
	}
	return strings.Join(lines, "\n")
}

func formatIndex(container string, indices []any) string {
	if len(indices) == 0 {
		return container
	}
	parts := make([]string, len(indices))
	for i, x := range indices {
		parts[i] = py.Repr(x)
	}
	return container + "[" + strings.Join(parts, "][") + "]"
}

// Validate is jsonschema.validate(instance, schema): nil, or the best-matching *ValidationError.
func Validate(instance any, schema *py.OMap) error {
	errs := iterErrors(instance, schema)
	if len(errs) == 0 {
		return nil
	}
	best := errs[0]
	for _, e := range errs[1:] {
		if relevanceLess(best, e) {
			best = e
		}
	}
	return best
}

// relevanceLess reports relevance(a) < relevance(b) with jsonschema's key
// (-len(path), path, validator not in weak, validator in strong, not matches_type); max() keeps the
// first of equals.
func relevanceLess(a, b *ValidationError) bool {
	if len(a.Path) != len(b.Path) {
		return -len(a.Path) < -len(b.Path)
	}
	for i := range a.Path {
		if c := comparePathElem(a.Path[i], b.Path[i]); c != 0 {
			return c < 0
		}
	}
	am, bm := !matchesType(a), !matchesType(b)
	return !am && bm
}

func comparePathElem(x, y any) int {
	switch xv := x.(type) {
	case string:
		yv, _ := y.(string)
		return strings.Compare(xv, yv)
	case int:
		yv, _ := y.(int)
		switch {
		case xv < yv:
			return -1
		case xv > yv:
			return 1
		}
	}
	return 0
}

func matchesType(e *ValidationError) bool {
	expected := py.Get(e.Schema, "type")
	switch t := expected.(type) {
	case string:
		return isType(e.Instance, t)
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && isType(e.Instance, s) {
				return true
			}
		}
	}
	return false
}

func isType(v any, t string) bool {
	switch t {
	case "object":
		return py.IsDict(v)
	case "array":
		return py.IsList(v)
	case "string":
		return py.IsStr(v)
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	case "integer":
		if _, ok := py.AsInt(v); ok {
			return true
		}
		f, ok := v.(float64)
		return ok && !math.IsInf(f, 0) && f == math.Trunc(f)
	case "number":
		if _, ok := py.AsInt(v); ok {
			return true
		}
		_, ok := v.(float64)
		return ok
	}
	return false
}

func number(v any) (float64, bool) {
	if n, ok := py.AsInt(v); ok {
		return float64(n), true
	}
	f, ok := v.(float64)
	return f, ok
}

func newErr(msg string) *ValidationError { return &ValidationError{Message: msg} }

// iterErrors walks one (sub)schema in its own key order, as Validator.iter_errors / descend do.
func iterErrors(instance any, schema *py.OMap) []*ValidationError {
	var out []*ValidationError
	for _, k := range schema.Keys() {
		v, _ := schema.Get(k)
		var errs []*ValidationError
		switch k {
		case "type":
			types, ok := v.([]any)
			if !ok {
				types = []any{v}
			}
			match := false
			for _, t := range types {
				if s, ok := t.(string); ok && isType(instance, s) {
					match = true
				}
			}
			if !match {
				reprs := make([]string, len(types))
				for i, t := range types {
					reprs[i] = py.Repr(t)
				}
				errs = append(errs, newErr(fmt.Sprintf("%s is not of type %s", py.Repr(instance), strings.Join(reprs, ", "))))
			}
		case "required":
			if py.IsDict(instance) {
				for _, p := range py.List(v) {
					if !py.Has(instance, py.Str(p)) {
						errs = append(errs, newErr(fmt.Sprintf("%s is a required property", py.Repr(p))))
					}
				}
			}
		case "additionalProperties":
			if py.IsDict(instance) {
				props := py.Get(schema, "properties")
				var extras []string
				for _, key := range py.DictKeys(instance) {
					if !py.Has(props, key) {
						extras = append(extras, key)
					}
				}
				if sub, ok := v.(*py.OMap); ok {
					for _, extra := range extras {
						errs = append(errs, descend(py.Get(instance, extra), sub, extra, nil)...)
					}
				} else if v == false && len(extras) > 0 {
					sorted := append([]string(nil), extras...)
					sortStrings(sorted)
					reprs := make([]string, len(sorted))
					for i, x := range sorted {
						reprs[i] = py.StrRepr(x)
					}
					verb := "were"
					if len(sorted) == 1 {
						verb = "was"
					}
					errs = append(errs, newErr(fmt.Sprintf("Additional properties are not allowed (%s %s unexpected)",
						strings.Join(reprs, ", "), verb)))
				}
			}
		case "properties":
			if py.IsDict(instance) {
				props := v.(*py.OMap)
				for _, p := range props.Keys() {
					if py.Has(instance, p) {
						sub, _ := props.Get(p)
						errs = append(errs, descend(py.Get(instance, p), sub.(*py.OMap), p, p)...)
					}
				}
			}
		case "items":
			if list, ok := instance.([]any); ok {
				sub := v.(*py.OMap)
				for i, e := range list {
					errs = append(errs, descend(e, sub, i, nil)...)
				}
			}
		case "enum":
			found := false
			s, isStr := instance.(string)
			for _, e := range py.List(v) {
				if es, ok := e.(string); ok && isStr && es == s {
					found = true
				}
			}
			if !found {
				errs = append(errs, newErr(fmt.Sprintf("%s is not one of %s", py.Repr(instance), py.Repr(v))))
			}
		case "minLength", "maxLength":
			if s, ok := instance.(string); ok {
				limit, _ := py.AsInt(v)
				n := int64(py.Len(s))
				if k == "minLength" && n < limit {
					msg := "is too short"
					if limit == 1 {
						msg = "should be non-empty"
					}
					errs = append(errs, newErr(py.Repr(instance)+" "+msg))
				}
				if k == "maxLength" && n > limit {
					msg := "is too long"
					if limit == 0 {
						msg = "is expected to be empty"
					}
					errs = append(errs, newErr(py.Repr(instance)+" "+msg))
				}
			}
		case "minItems", "maxItems":
			if list, ok := instance.([]any); ok {
				limit, _ := py.AsInt(v)
				n := int64(len(list))
				if k == "minItems" && n < limit {
					msg := "is too short"
					if limit == 1 {
						msg = "should be non-empty"
					}
					errs = append(errs, newErr(py.Repr(instance)+" "+msg))
				}
				if k == "maxItems" && n > limit {
					msg := "is too long"
					if limit == 0 {
						msg = "is expected to be empty"
					}
					errs = append(errs, newErr(py.Repr(instance)+" "+msg))
				}
			}
		case "minimum":
			if isType(instance, "number") {
				x, _ := number(instance)
				m, _ := number(v)
				if x < m {
					errs = append(errs, newErr(fmt.Sprintf("%s is less than the minimum of %s", py.Repr(instance), py.Repr(v))))
				}
			}
		case "maximum":
			if isType(instance, "number") {
				x, _ := number(instance)
				m, _ := number(v)
				if x > m {
					errs = append(errs, newErr(fmt.Sprintf("%s is greater than the maximum of %s", py.Repr(instance), py.Repr(v))))
				}
			}
		case "pattern":
			if s, ok := instance.(string); ok {
				re, err := pyre.Compile(py.Str(v), 0)
				if err != nil || !re.MatchString(s) {
					errs = append(errs, newErr(fmt.Sprintf("%s does not match %s", py.Repr(instance), py.Repr(v))))
				}
			}
		case "propertyNames":
			if sub, ok := v.(*py.OMap); ok && py.IsDict(instance) {
				for _, key := range py.DictKeys(instance) {
					errs = append(errs, descend(key, sub, nil, nil)...)
				}
			}
		}
		for _, e := range errs {
			if e.Validator == "" {
				e.Validator, e.Schema, e.Instance = k, schema, instance
			}
			e.SchemaPath = append([]any{k}, e.SchemaPath...)
		}
		out = append(out, errs...)
	}
	return out
}

// descend validates a child instance against a subschema, prefixing the paths as jsonschema does.
func descend(instance any, schema *py.OMap, path any, schemaPath any) []*ValidationError {
	errs := iterErrors(instance, schema)
	for _, e := range errs {
		if path != nil {
			e.Path = append([]any{path}, e.Path...)
		}
		if schemaPath != nil {
			e.SchemaPath = append([]any{schemaPath}, e.SchemaPath...)
		}
	}
	return errs
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
