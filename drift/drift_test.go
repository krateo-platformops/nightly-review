package drift

// Offline tests of the drift check — the logic the drift workflow runs against the installer's live pins
// (tests/test_destinations_drift_logic.py). Each case is one way the seeded destination map can go stale
// without anything failing.

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krateo-platformops/nightly-review/internal/fake"
	"github.com/krateo-platformops/nightly-review/internal/py"
)

const defaultRepo = "oci://ghcr.io/krateo-platformops/charts"

func pins() []any {
	return []any{py.O("name", "snowplow"), py.O("name", "autopilot-x", "repo", "oci://ghcr.io/krateo-agentiko/charts"),
		py.O("name", "cert-manager", "repo", "oci://ghcr.io/krateo-blueprints/charts")}
}

func comps() *py.OMap {
	return py.O("snowplow", py.O("repo", "krateo-platformops/snowplow"),
		"autopilot-x", py.O("repo", "krateo-agentiko/agentiko", "prompt", py.O("repo", "krateo-agentiko/agentiko", "path", "p.yaml")))
}

func unmapped() *py.OMap { return py.O("cert-manager", "upstream") }

func one(t *testing.T, found []string) string {
	t.Helper()
	if len(found) != 1 {
		t.Fatalf("want one problem, got %v", found)
	}
	return found[0]
}

func anyHas(found []string, sub string) bool {
	for _, f := range found {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

func TestInStepIsNoProblem(t *testing.T) {
	if p := Problems(pins(), defaultRepo, comps(), unmapped()); len(p) != 0 {
		t.Fatal(p)
	}
}

func TestANewPinFailsAndSaysWhatToAdd(t *testing.T) {
	msg := one(t, Problems(append(pins(), py.O("name", "new-thing", "repo", "oci://ghcr.io/krateo-agentiko/charts")), defaultRepo, comps(), unmapped()))
	if !strings.Contains(msg, "config.destinations.components.new-thing") || !strings.Contains(msg, "drift/unmapped-components.yaml") {
		t.Fatal(msg)
	}
}

func TestADefaultRegistryPinWithoutAnEntryFails(t *testing.T) {
	msg := one(t, Problems(append(pins(), py.O("name", "plain")), defaultRepo, comps(), unmapped()))
	if !strings.Contains(msg, "plain (published from the default registry) has no destination") || !strings.Contains(msg, "krateo-platformops") {
		t.Fatal(msg)
	}
}

func TestAnEntryInTheWrongOrgFails(t *testing.T) {
	for _, field := range []string{"repo", "prompt"} {
		c := comps()
		entry, _ := c.Get("autopilot-x")
		if field == "repo" {
			entry.(*py.OMap).Set("repo", "krateo-platformops/autopilot")
		} else {
			entry.(*py.OMap).Set("prompt", py.O("repo", "krateo-blueprints/autopilot", "path", "p.yaml"))
		}
		msg := one(t, Problems(pins(), defaultRepo, c, unmapped()))
		if !strings.Contains(msg, "autopilot-x") || !strings.Contains(msg, "from krateo-agentiko") {
			t.Error(field, msg)
		}
	}
}

func TestADefaultRegistryPinIsComparedWithTheDefaultOrg(t *testing.T) {
	c := comps()
	c.Set("snowplow", py.O("repo", "krateo-agentiko/snowplow"))
	msg := one(t, Problems(pins(), defaultRepo, c, unmapped()))
	if !strings.Contains(msg, "snowplow.repo is krateo-agentiko/snowplow") || !strings.Contains(msg, "from krateo-platformops") {
		t.Fatal(msg)
	}
}

func TestTheAllowlistIsCheckedBothWays(t *testing.T) {
	c := comps()
	c.Set("cert-manager", py.O("repo", "krateo-blueprints/x"))
	u := unmapped()
	u.Set("gone", "was pinned once")
	u.Set("autopilot-x", "")
	found := Problems(pins(), defaultRepo, c, u)
	if !anyHas(found, "cert-manager has a destination AND a reason") ||
		!anyHas(found, "gone is in drift/unmapped-components.yaml but the installer no longer pins it") ||
		!anyHas(found, "autopilot-x is in drift/unmapped-components.yaml without a reason") {
		t.Fatal(found)
	}
}

func TestAnUnparseableDefaultRegistryIsAProblem(t *testing.T) {
	if !anyHas(Problems(pins(), "ghcr.io/x", comps(), unmapped()), "ociRepo") {
		t.Fatal()
	}
}

func TestAFailedFetchFailsItNeverSkips(t *testing.T) {
	for _, rt := range []fake.RoundTrip{
		func(*http.Request) (*http.Response, error) { return nil, errors.New("dns") },
		func(r *http.Request) (*http.Response, error) { return fake.Response(r, 404, ""), nil },
	} {
		saved := HTTPClient
		HTTPClient = fake.Client(rt)
		_, _, err := LoadInstaller()
		HTTPClient = saved
		if err == nil || !strings.Contains(err.Error(), "does not pass without them") {
			t.Fatal(err)
		}
	}
}

func TestTheRepoFilesParseAndEveryReasonIsWritten(t *testing.T) {
	c, u, err := LoadLocal()
	if err != nil || !py.Truthy(c) || !py.Truthy(u) {
		t.Fatal(err)
	}
	for _, k := range py.DictKeys(u) {
		if s, ok := py.Get(u, k).(string); !ok || py.Strip(s) == "" {
			t.Error(k)
		}
	}
}

func TestTheNotPinnedRecordHasReasonsAndContradictsNoEntry(t *testing.T) {
	if p, err := NotPinnedProblems(); err != nil || len(p) != 0 {
		t.Fatal(p, err)
	}
}

func TestANotPinnedGlobMatchingAMappedKeyIsAContradiction(t *testing.T) {
	f := filepath.Join(t.TempDir(), "u.yaml")
	if err := os.WriteFile(f, []byte("unmapped: {}\nnotPinned:\n  '*-agent': covers too much\n  bare: ''\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := Allowlist
	Allowlist = f
	t.Cleanup(func() { Allowlist = saved })
	found, err := NotPinnedProblems()
	if err != nil || !anyHas(found, "installer-agent has a destination but matches notPinned") ||
		!anyHas(found, "bare is in drift/unmapped-components.yaml notPinned without a reason") {
		t.Fatal(found, err)
	}
}
