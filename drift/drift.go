// Package drift checks that config.destinations.components still agrees with what the installer
// installs.
//
// WHY THIS EXISTS. The seeded map points each component at a repository verified on 2026-09-30. A map
// that goes stale does not fail loudly: a component pointed at a real-but-wrong repository resolves
// RepoFound and its proposal goes to the wrong place — quieter than the 404 this map replaced. So the
// installer's pins are the reference, read from its main branch every run, and three things must hold:
//
//  1. every pinned component has an entry, or a reviewed reason in drift/unmapped-components.yaml;
//  2. an entry's organisation (and its prompt's) is the organisation the pins publish that component from
//     — `repo: oci://ghcr.io/<org>/charts`, or the installer's default `ociRepo` when a pin has none;
//  3. a component on the default registry is no exception to 1: a missing one is reported as such.
//
// Only the ORGANISATION is compared: the pins name a chart registry, not a source repository, so nothing
// finer can be checked against them. The allowlist is checked both ways — a reason for a component that
// also has an entry, or that is no longer pinned, is an error too, because either means the review is
// stale.
package drift

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/pyre"
	"github.com/krateo-platformops/nightly-review/internal/pyyaml"
)

// Where the installer's pins live, and the repository's own files.
const (
	PinsURL            = "https://raw.githubusercontent.com/krateo-platformops/installer/main/chart/files/component-pins.yaml"
	InstallerValuesURL = "https://raw.githubusercontent.com/krateo-platformops/installer/main/chart/values.yaml"
)

func root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(file))
}

// Allowlist and Values are the repository files the check reads; variables so a test can point them
// elsewhere.
var (
	Allowlist = filepath.Join(root(), "drift", "unmapped-components.yaml")
	Values    = filepath.Join(root(), "helm", "nightly-review", "values.yaml")
)

// HTTPClient fetches the installer's files.
var HTTPClient = &http.Client{Timeout: 30 * time.Second}

var ociOrgRE = pyre.MustCompile(`^oci://[^/]+/([^/]+)(?:/|$)`, 0)

// Fetch returns the text at url, or an error that says what was being fetched and why. NEVER A SKIP: a
// check that passes whenever GitHub is unreachable is a check that passes.
func Fetch(url string) (string, error) {
	resp, err := HTTPClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("cannot fetch %s: %s: %v. The drift check needs the installer's pins to compare against and "+
			"does not pass without them.", url, py.TypeName(err), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("cannot fetch %s: HTTP %d. The drift check needs the installer's pins to compare against and "+
			"does not pass without them.", url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// OCIOrg is oci://ghcr.io/krateo-agentiko/charts -> krateo-agentiko; "" when it is not that shape.
func OCIOrg(repo any) string {
	s, _ := repo.(string)
	if m := ociOrgRE.Match(s); m != nil {
		return m.Group(1)
	}
	return ""
}

// Problems lists every disagreement, each as one line saying what to add or change. Empty means in
// step. pins is the installer's components list; components and unmapped are dicts.
func Problems(pins []any, defaultRepo any, components, unmapped any) []string {
	defaultOrg := OCIOrg(defaultRepo)
	var out []string
	if defaultOrg == "" {
		out = append(out, fmt.Sprintf("installer chart/values.yaml ociRepo %s is not oci://<host>/<org>/...; cannot tell which "+
			"organisation the default registry is", py.Repr(defaultRepo)))
	}
	pinned := py.NewOMap()
	for _, pin := range pins {
		if name := py.Get(pin, "name"); py.Truthy(name) {
			pinned.Set(py.Str(name), pin)
		}
	}
	for _, name := range pinned.Keys() {
		pin, _ := pinned.Get(name)
		onDefault := !py.Truthy(py.Get(pin, "repo"))
		org := defaultOrg
		if !onDefault {
			org = OCIOrg(py.Get(pin, "repo"))
		}
		if !py.Has(components, name) || py.Get(components, name) == nil {
			if !py.Has(unmapped, name) {
				where := "the default registry"
				if !onDefault {
					where = py.Str(py.Get(pin, "repo"))
				}
				out = append(out, fmt.Sprintf("%s (published from %s) has no destination: add config.destinations.components.%s to "+
					"helm/nightly-review/values.yaml (a repository in %s, verified with `gh api repos/<owner>/<name>`), or add "+
					"`%s: <reason>` to drift/unmapped-components.yaml", name, where, name, orNone(org), name))
			}
			continue
		}
		entry := py.Get(components, name)
		if py.Has(unmapped, name) {
			out = append(out, fmt.Sprintf("%s has a destination AND a reason to be unmapped: remove it from drift/unmapped-components.yaml", name))
		}
		for _, f := range []struct {
			field string
			repo  any
		}{{"repo", py.Get(entry, "repo")}, {"prompt.repo", py.Get(py.Or(py.Get(entry, "prompt"), map[string]any{}), "repo")}} {
			if py.Truthy(f.repo) && org != "" {
				owner, _, _ := strings.Cut(py.Str(f.repo), "/")
				if owner != org {
					out = append(out, fmt.Sprintf("config.destinations.components.%s.%s is %s, but the installer publishes %s from %s: "+
						"fix the entry, or the pin", name, f.field, py.Str(f.repo), name, org))
				}
			}
		}
	}
	for _, name := range py.DictKeys(unmapped) {
		reason := py.Get(unmapped, name)
		if _, ok := pinned.Get(name); !ok {
			out = append(out, fmt.Sprintf("%s is in drift/unmapped-components.yaml but the installer no longer pins it: remove the line", name))
		}
		if s, ok := reason.(string); !ok || py.Strip(s) == "" {
			out = append(out, fmt.Sprintf("%s is in drift/unmapped-components.yaml without a reason: say why it is unmapped", name))
		}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "None"
	}
	return s
}

func loadYAML(text string) (any, error) {
	v, err := pyyaml.SafeLoad(text)
	if err != nil {
		return nil, err
	}
	return fromYAML(v), nil
}

func fromYAML(v pyyaml.Value) any {
	switch x := v.(type) {
	case *pyyaml.Mapping:
		out := py.NewOMap()
		keys, vals := x.Keys(), x.Values()
		for i := range keys {
			out.Set(pyyaml.Str(keys[i]), fromYAML(vals[i]))
		}
		return out
	case *pyyaml.Sequence:
		out := make([]any, len(x.Items))
		for i, e := range x.Items {
			out[i] = fromYAML(e)
		}
		return out
	}
	return v
}

func readYAML(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return loadYAML(string(b))
}

// LoadLocal reads config.destinations.components from the chart's values and the allowlist's
// `unmapped`.
func LoadLocal() (any, any, error) {
	values, err := readYAML(Values)
	if err != nil {
		return nil, nil, err
	}
	allow, err := readYAML(Allowlist)
	if err != nil {
		return nil, nil, err
	}
	return py.GetPath(values, "config", "destinations", "components"), py.Or(py.Get(allow, "unmapped"), py.NewOMap()), nil
}

// NotPinnedProblems checks `notPinned`, which records unmapped components the pins do not name (a probe,
// benchmark agents, per-kind controllers). Nothing to compare them with, so only the reason is required
// — and a glob that also matches a mapped key is a contradiction.
func NotPinnedProblems() ([]string, error) {
	components, _, err := LoadLocal()
	if err != nil {
		return nil, err
	}
	allow, err := readYAML(Allowlist)
	if err != nil {
		return nil, err
	}
	extra := py.Or(py.Get(allow, "notPinned"), py.NewOMap())
	var out []string
	for _, pattern := range py.DictKeys(extra) {
		if s, ok := py.Get(extra, pattern).(string); !ok || py.Strip(s) == "" {
			out = append(out, fmt.Sprintf("%s is in drift/unmapped-components.yaml notPinned without a reason", pattern))
		}
		for _, key := range py.DictKeys(components) {
			if py.Fnmatchcase(key, pattern) {
				out = append(out, fmt.Sprintf("%s has a destination but matches notPinned %s: remove one", key, py.StrRepr(pattern)))
			}
		}
	}
	return out, nil
}

// LoadInstaller reads the installer's pins and its default registry from its main branch.
func LoadInstaller() ([]any, any, error) {
	pinsText, err := Fetch(PinsURL)
	if err != nil {
		return nil, nil, err
	}
	valuesText, err := Fetch(InstallerValuesURL)
	if err != nil {
		return nil, nil, err
	}
	pinsDoc, err := loadYAML(pinsText)
	if err != nil {
		return nil, nil, err
	}
	valuesDoc, err := loadYAML(valuesText)
	if err != nil {
		return nil, nil, err
	}
	pins := py.List(py.Get(py.Or(pinsDoc, py.NewOMap()), "components"))
	if len(pins) == 0 {
		return nil, nil, fmt.Errorf("%s has no `components`: the pins moved or changed shape; update PinsURL", PinsURL)
	}
	return pins, py.Get(py.Or(valuesDoc, py.NewOMap()), "ociRepo"), nil
}
