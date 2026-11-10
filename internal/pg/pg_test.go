package pg

// The service's queries go through pg8000's named-placeholder conversion in Python; ToStatement must
// produce the same statement and the same argument order, or a query would bind a value to the wrong
// placeholder. testdata/to_statement.json was written by pg8000.native.to_statement itself
// (testdata/gen_to_statement.py).

import (
	"os"
	"reflect"
	"testing"

	"github.com/krateo-platformops/nightly-review/internal/py"
)

func TestToStatementMatchesPg8000(t *testing.T) {
	raw, err := os.ReadFile("testdata/to_statement.json")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := py.LoadsJSON(string(raw), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range py.List(cases) {
		stmt, names := ToStatement(py.Str(py.Get(c, "sql")))
		var want []string
		for _, n := range py.List(py.Get(c, "order")) {
			want = append(want, py.Str(n))
		}
		if stmt != py.Get(c, "statement") || !reflect.DeepEqual(names, want) {
			t.Errorf("%q\n got %q %v\nwant %q %v", py.Get(c, "sql"), stmt, names, py.Get(c, "statement"), want)
		}
	}
}
