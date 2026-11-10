package pyyaml

// The fingerprint's canonical form, as its own unit: PyYAML's safe_dump(sort_keys=True,
// default_flow_style=False) output through normalise_body, byte for byte, for named cases grouped by
// what they pin — key order, nested lists, multiline strings and line folding, special characters and
// unicode escaping, scalars that look like strings, and the spelling of null, booleans and numbers.
// The expected values in canonical_cases_test.go were written by PyYAML itself
// (testdata/gen_canonical.py); the generated corpus in parity_test.go covers the same ground at scale.

import "testing"

func TestSafeDumpCanonicalForm(t *testing.T) {
	for _, c := range canonicalCases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NormaliseBody(c.content, "yaml")
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("content %q\n got: %q\nwant: %q", c.content, got, c.want)
			}
		})
	}
}
