package pyyaml

import (
	"errors"
	"testing"
)

// The behaviours callers rely on beyond normalise_body's output; each expectation was read off PyYAML 6.0.2.

func TestMappingSemantics(t *testing.T) {
	v, err := SafeLoad("1: a\ntrue: b\n1.0: c\nkind: Alert\n")
	if err != nil {
		t.Fatal(err)
	}
	m := v.(*Mapping)
	// {1: 'c', 'kind': 'Alert'}: True and 1.0 hash and compare equal to 1, so they merge into its key.
	if m.Len() != 2 {
		t.Fatalf("len = %d, want 2 (%s)", m.Len(), Str(m))
	}
	if Str(m) != "{1: 'c', 'kind': 'Alert'}" {
		t.Fatalf("str = %s", Str(m))
	}
	if k, ok := m.Get("kind"); !ok || k != "Alert" {
		t.Fatalf("Get(kind) = %v, %v", k, ok)
	}
	if _, ok := m.Get("1"); ok {
		t.Fatal("an int key must not answer a str lookup")
	}
}

func TestErrorClasses(t *testing.T) {
	var ye *YAMLError
	var pe *PyError
	if _, err := SafeLoad("a: 1\n---\nb: 2"); !errors.As(err, &ye) {
		t.Fatalf("two documents: %v, want a YAMLError", err)
	}
	if _, err := SafeLoad("a: !!int abc"); !errors.As(err, &pe) || pe.Type != "ValueError" {
		t.Fatalf("!!int abc: %v, want ValueError", err)
	}
	if _, err := SafeLoad("a: 2020-13-01"); !errors.As(err, &pe) || pe.Type != "ValueError" {
		t.Fatalf("month 13: %v, want ValueError", err)
	}
	if out, err := NormaliseBody("a: [1, 2", "yaml"); err != nil || out != "a: [1, 2" {
		t.Fatalf("unparseable YAML takes the text path: %q, %v", out, err)
	}
}

func TestStrAndTruthiness(t *testing.T) {
	for src, want := range map[string]string{
		"1.0": "1.0", "1e3": "1e3", "1.0e+20": "1e+20", "0.00001": "1e-05", ".inf": "inf", "yes": "True",
		"~": "None", "2020-01-01": "2020-01-01", "2020-01-01 10:00:00Z": "2020-01-01 10:00:00+00:00",
		"0x1f": "31", "[1, a]": "[1, 'a']",
	} {
		v, err := SafeLoad(src)
		if err != nil {
			t.Fatal(err)
		}
		if got := Str(v); got != want {
			t.Errorf("str(safe_load(%q)) = %q, want %q", src, got, want)
		}
	}
	if Truthy(nil) || Truthy("") || Truthy(int64(0)) || !Truthy("x") || !Truthy(&Date{2020, 1, 1}) {
		t.Fatal("truthiness")
	}
	if !IsCollection(&Mapping{}) || !IsCollection(&Sequence{}) || IsCollection(&Set{}) {
		t.Fatal("IsCollection is isinstance(v, (dict, list))")
	}
}
