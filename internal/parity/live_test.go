package parity

// Real Proposal objects, read from a cluster, against the Go fingerprint. Set NR_LIVE_PROPOSALS to a
// JSON file holding `kubectl get proposals.review.krateo.io -n krateo-system -o json` output (a List, or
// a plain array of objects). Skipped otherwise: cluster data is not committed to this repository.
//
// For each object the fingerprint is recomputed from the four spec fields it is defined over —
// spec.kind, spec.target.repo, spec.target.path, spec.change.{format,content} — and compared with the
// stored spec.fingerprint; the object name with "p-" + its first 16 characters; and the stored subject
// with its own normalisation (a normalised subject must be a fixed point).

import (
	"os"
	"strings"
	"testing"

	"github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/py"
)

func TestLiveProposalsKeepTheirFingerprints(t *testing.T) {
	path := os.Getenv("NR_LIVE_PROPOSALS")
	if path == "" {
		t.Skip("NR_LIVE_PROPOSALS is not set")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- a file the person running the test names
	if err != nil {
		t.Fatal(err)
	}
	doc, err := py.LoadsJSON(string(raw), false)
	if err != nil {
		t.Fatal(err)
	}
	items := py.List(py.Get(doc, "items"))
	if items == nil {
		items = py.List(doc)
	}
	if len(items) == 0 {
		t.Fatal("no Proposal objects in the file, so this proves nothing")
	}
	checked := 0
	for _, p := range items {
		name := py.Str(py.GetPath(p, "metadata", "name"))
		spec := py.Get(p, "spec")
		stored := py.String(py.Get(spec, "fingerprint"))
		got, err := proposals.Fingerprint(spec)
		switch {
		case err != nil:
			t.Errorf("%s: %s", name, py.ExcString(err))
		case got != stored:
			t.Errorf("%s: stored fingerprint %s, Go computes %s", name, stored, got)
		case strings.HasPrefix(name, "p-") && name != "p-"+py.Trunc(stored, 16):
			t.Errorf("%s: not named by its fingerprint %s", name, stored)
		}
		if s, ok := py.Get(spec, "subject").(string); ok {
			if n, _ := proposals.NormaliseSubject(s); n != s {
				t.Errorf("%s: stored subject %q normalises to %q", name, s, n)
			}
		}
		checked++
	}
	t.Logf("%d live Proposals checked", checked)
}
