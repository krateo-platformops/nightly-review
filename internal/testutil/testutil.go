// Package testutil holds what the tests share: reading the repository's YAML the way the Python tests
// did (yaml.safe_load, through the PyYAML port), reading JSON fixtures, and a canonical rendering for
// comparing JSON-shaped values.
package testutil

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/pyyaml"
)

// Root is the repository root.
func Root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// Read returns a repository file's text (decompressed, for a .gz fixture).
func Read(t testing.TB, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(Root(), rel))
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(rel, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if b, err = io.ReadAll(zr); err != nil {
			t.Fatal(err)
		}
	}
	return string(b)
}

// YAML is yaml.safe_load of a repository file, as JSON-shaped values (mappings keep their order).
func YAML(t testing.TB, rel string) any {
	t.Helper()
	v, err := pyyaml.SafeLoad(Read(t, rel))
	if err != nil {
		t.Fatal(err)
	}
	return FromYAML(v)
}

// FromYAML converts loaded YAML into the JSON-shaped values the service handles.
func FromYAML(v pyyaml.Value) any {
	switch x := v.(type) {
	case *pyyaml.Mapping:
		out := py.NewOMap()
		keys, vals := x.Keys(), x.Values()
		for i := range keys {
			out.Set(pyyaml.Str(keys[i]), FromYAML(vals[i]))
		}
		return out
	case *pyyaml.Sequence:
		out := make([]any, len(x.Items))
		for i, e := range x.Items {
			out[i] = FromYAML(e)
		}
		return out
	}
	return v
}

// JSON reads a JSON file (relative to the repository root), keeping object order.
func JSON(t testing.TB, rel string) any {
	t.Helper()
	v, err := py.LoadsJSON(Read(t, rel), true)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Canon renders a JSON-shaped value canonically (sorted keys), for equality checks.
func Canon(v any) string {
	return py.DumpsJSON(py.Plain(v), py.DumpOpts{Indent: -1, SortKeys: true, EnsureASCII: true})
}

// Undeclared lists the paths the apiserver would prune (undeclared) or reject (outside an enum, over a
// maxLength or a maxItems — a rejection fails the WHOLE status write, which is worse than a prune), for a
// value written against a CRD's structural schema.
func Undeclared(value, schema any, path string) []string {
	var out []string
	if py.Get(schema, "x-kubernetes-preserve-unknown-fields") == true {
		return out
	}
	value = py.Plain(value)
	if enum := py.Get(schema, "enum"); enum != nil && value != nil {
		in := false
		for _, e := range py.List(enum) {
			if Canon(e) == Canon(value) {
				in = true
			}
		}
		if !in {
			out = append(out, path+" = "+py.Repr(value)+" not in enum")
		}
	}
	if s, ok := value.(string); ok {
		if n, has := py.AsInt(py.Get(schema, "maxLength")); has && int64(py.Len(s)) > n {
			out = append(out, path+" longer than maxLength")
		}
	}
	if l, ok := value.([]any); ok {
		if n, has := py.AsInt(py.Get(schema, "maxItems")); has && int64(len(l)) > n {
			out = append(out, path+" has more than maxItems")
		}
	}
	switch v := value.(type) {
	case map[string]any:
		props, extra := py.Get(schema, "properties"), py.Get(schema, "additionalProperties")
		for _, k := range py.SortedKeys(v) {
			switch {
			case props != nil && py.Has(props, k):
				out = append(out, Undeclared(v[k], py.Get(props, k), path+"."+k)...)
			case py.IsDict(extra):
				out = append(out, Undeclared(v[k], extra, path+"."+k)...)
			default:
				out = append(out, path+"."+k)
			}
		}
	case []any:
		if items := py.Get(schema, "items"); items != nil {
			for i, e := range v {
				out = append(out, Undeclared(e, items, path+"["+strconv.Itoa(i)+"]")...)
			}
		}
	}
	return out
}
