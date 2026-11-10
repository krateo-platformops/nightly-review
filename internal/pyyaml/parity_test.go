package pyyaml

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture is one input as testdata/gen_fixtures.py recorded it from PyYAML 6.0.2 on CPython 3.12, through the
// real proposals.normalise_body and proposals.fingerprint.
type fixture struct {
	ID               string        `json:"id"`
	Category         string        `json:"category"`
	Content          string        `json:"content"`
	Normalised       *string       `json:"normalised"`
	NormalisedSha256 string        `json:"normalisedSha256"`
	Fingerprint      string        `json:"fingerprint"`
	Error            *fixtureError `json:"error"`
	Text             *string       `json:"text"`
	TextSha256       string        `json:"textSha256"`
	Docs             []fixtureDoc  `json:"docs"`
	DocsError        string        `json:"docs_error"`
	UnsortableSet    bool          `json:"unsortableSet"`
}

type fixtureError struct {
	Type string `json:"type"`
	Msg  string `json:"msg"`
}

type fixtureValue struct {
	Type string  `json:"type"`
	Str  *string `json:"str"`
}

type fixtureDoc struct {
	Type       string        `json:"type"`
	Str        *string       `json:"str"`
	Kind       *fixtureValue `json:"kind"`
	APIVersion *fixtureValue `json:"apiVersion"`
}

// knownDivergent lists inputs whose Python result cannot be reproduced in Go, each with the reason. Nothing
// else may differ.
var knownDivergent = map[string]string{
	// "\ud800" is a lone surrogate. Python keeps it in the str and safe_dump writes it back as \uD800; a Go
	// string cannot hold one (the JSON fixture and the scanner both turn it into U+FFFD).
	"edge-256": "lone surrogate escape",
}

func loadFixtures(t *testing.T, name string) []fixture {
	t.Helper()
	data, err := readGzip(filepath.Join("testdata", name+".gz"))
	if err != nil {
		t.Fatal(err)
	}
	var out []fixture
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func shaHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func fingerprintOf(body string) string {
	key := strings.Join([]string{"Alert", "o/r", "p.yaml", body}, "\x1f")
	return shaHex(key)[:32]
}

func typeName(v Value) string {
	switch v.(type) {
	case nil:
		return "none"
	case bool:
		return "bool"
	case int64:
		return "int"
	case float64:
		return "float"
	case string:
		return "str"
	case []byte:
		return "bytes"
	case *Sequence:
		return "list"
	case *Mapping:
		return "dict"
	case *Set:
		return "set"
	case *Date:
		return "date"
	case *DateTime:
		return "datetime"
	}
	if _, ok := v.(interface{ String() string }); ok {
		return "int"
	}
	return "?"
}

func checkValue(t *failCounter, id, what string, want *fixtureValue, got Value) {
	if want == nil {
		return
	}
	if typeName(got) != want.Type {
		t.Errorf("%s: %s type = %s, Python %s", id, what, typeName(got), want.Type)
		return
	}
	if want.Str != nil && Str(got) != *want.Str {
		t.Errorf("%s: %s str = %q, Python %q", id, what, Str(got), *want.Str)
	}
}

// failCounter wraps *testing.T so each fixture's failures can be counted.
type failCounter struct {
	*testing.T
	n int
}

func (c *failCounter) Errorf(format string, args ...any) {
	c.n++
	c.T.Errorf(format, args...)
}

func runFixtures(tt *testing.T, name string) {
	fixtures := loadFixtures(tt, name)
	equal, skipped := 0, 0
	for _, f := range fixtures {
		if reason, ok := knownDivergent[f.ID]; ok {
			tt.Logf("%s skipped: %s", f.ID, reason)
			skipped++
			continue
		}
		if f.UnsortableSet {
			// Python emits an unsortable set in hash order, randomised per process for str: no fixed output.
			skipped++
			continue
		}
		t := &failCounter{T: tt}
		got, err := NormaliseBody(f.Content, "yaml")
		switch {
		case f.Error != nil:
			var pe *PyError
			if !errors.As(err, &pe) || pe.Type != f.Error.Type {
				t.Errorf("%s (%s): Python raised %s: %s; Go returned %q, %v", f.ID, f.Category, f.Error.Type, f.Error.Msg, got, err)
			}
		case err != nil:
			t.Errorf("%s (%s): Go raised %v; Python returned %q", f.ID, f.Category, err, deref(f.Normalised))
		default:
			if f.Normalised != nil && got != *f.Normalised {
				t.Errorf("%s (%s): content %q\n  Go:     %q\n  Python: %q", f.ID, f.Category, f.Content, got, *f.Normalised)
			}
			if f.NormalisedSha256 != "" && shaHex(got) != f.NormalisedSha256 {
				t.Errorf("%s (%s): content %q: normalised sha differs; Go output %q", f.ID, f.Category, f.Content, got)
			}
			if fingerprintOf(got) != f.Fingerprint {
				t.Errorf("%s (%s): fingerprint differs", f.ID, f.Category)
			}
		}
		text, terr := NormaliseBody(f.Content, "markdown")
		if terr != nil {
			t.Errorf("%s: text path raised %v", f.ID, terr)
		} else if f.Text != nil && text != *f.Text {
			t.Errorf("%s: text path\n  Go:     %q\n  Python: %q", f.ID, text, *f.Text)
		} else if f.TextSha256 != "" && shaHex(text) != f.TextSha256 {
			t.Errorf("%s: text path sha differs: Go %q", f.ID, text)
		}
		docs, derr := SafeLoadAll(f.Content)
		switch {
		case f.DocsError != "":
			var pe *PyError
			var ye *YAMLError
			if f.DocsError == "YAMLError" && !errors.As(derr, &ye) {
				t.Errorf("%s: safe_load_all: Python raised YAMLError, Go %v", f.ID, derr)
			} else if f.DocsError != "YAMLError" && (!errors.As(derr, &pe) || pe.Type != f.DocsError) {
				t.Errorf("%s: safe_load_all: Python raised %s, Go %v", f.ID, f.DocsError, derr)
			}
		case derr != nil:
			t.Errorf("%s: safe_load_all: Go raised %v", f.ID, derr)
		case len(docs) != len(f.Docs):
			t.Errorf("%s: safe_load_all: %d documents, Python %d", f.ID, len(docs), len(f.Docs))
		default:
			for i, d := range docs {
				want := f.Docs[i]
				checkValue(t, f.ID, "doc", &fixtureValue{Type: want.Type, Str: want.Str}, d)
				if m, ok := d.(*Mapping); ok {
					k, _ := m.Get("kind")
					a, _ := m.Get("apiVersion")
					checkValue(t, f.ID, "kind", want.Kind, k)
					checkValue(t, f.ID, "apiVersion", want.APIVersion, a)
				}
			}
		}
		if t.n == 0 {
			equal++
		}
	}
	tt.Logf("%s: %d/%d fixtures equal, %d excluded as irreproducible", name, equal, len(fixtures)-skipped, skipped)
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func TestParityFixed(t *testing.T)     { runFixtures(t, "pyyaml_fixed.json") }
func TestParityGenerated(t *testing.T) { runFixtures(t, "pyyaml_generated.json") }

// readGzip reads a gzipped fixture (the generator compresses them; see testdata/gen_fixtures.py).
func readGzip(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}
