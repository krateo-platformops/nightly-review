// Package failures reads the day's real failures: the Incidents the platform opened, and the
// Compositions that were not healthy.
//
// WHY THESE COME FIRST. Every other source is a sample. ClickHouse's top error patterns are ranked by
// VOLUME, so a chatty component's warnings push a real failure out of the top 25, and a composition that
// failed validation once, was fixed by a person and never logged again does not rank at all. An Incident
// is a failure the platform already noticed, investigated and (often) fixed; a Composition that went
// not-Ready is a failure a person saw. Both are read straight from the apiserver, not ranked, and both
// reach the prompt AHEAD of the log patterns — prompt.BuildUserMessage orders them first.
//
// READ-ONLY, THROUGH THE SERVICE'S OWN ServiceAccount. `list` on incidents.observability.krateo.io, on
// every composition.krateo.io resource and on compositiondefinitions.core.krateo.io, cluster-wide
// (templates/rbac.yaml). Nothing here gets a Secret, and nothing writes.
//
// WHAT THE INCIDENT KIND DOES AND DOES NOT RECORD. There is no "affected object" field. What an Incident
// does carry: spec.alertRef and spec.trigger (what opened it), status.rootCause, status.howToFix (bash
// scripts, plus applyAction — the fix as ONE Kubernetes write, which names the object the fix changes),
// and status.analyzedResources. So the affected object is applyAction's target when there is one, else
// the first analysed resource that is not the Alert itself — and it is labelled as such, never presented
// as a field the Incident has.
//
// WHAT A COMPOSITION'S CONDITIONS CAN AND CANNOT SAY. Only the CURRENT conditions are visible:
//   - Synced=True is re-stamped on every reconcile, so a Synced transition to True says nothing about a
//     recovery and is never counted as one.
//   - Ready=True's lastTransitionTime does move only on a real transition, so Ready=True stamped inside
//     the window, on a composition created before it, means it was NOT Ready earlier in the window and
//     recovered. A chart upgrade's rollout produces the same stamp, and the corpus says so.
//
// A composition that failed and recovered TWICE in the window shows only the last recovery. Stated, not
// fixed: fixing it would need an event history this service does not keep.
package failures

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/krateo-platformops/nightly-review/internal/evidence"
	"github.com/krateo-platformops/nightly-review/internal/kube"
	"github.com/krateo-platformops/nightly-review/internal/prompt"
	"github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/pyre"
	"github.com/krateo-platformops/nightly-review/internal/synchealth"
	"github.com/krateo-platformops/nightly-review/internal/targets"
)

// Source names.
const (
	IncidentsSource    = "incidents"
	CompositionsSource = "compositions"
)

const (
	incidentGroup, incidentVersion, incidentPlural = "observability.krateo.io", "v1alpha1", "incidents"
	compositionGroup                               = "composition.krateo.io"
	cdGroup, cdVersion, cdPlural                   = "core.krateo.io", "v1alpha1", "compositiondefinitions"
)

// Bounds.
var (
	MaxIncidents               = 25
	MaxFailing                 = 40
	MaxRecovered               = 25
	MaxRefused                 = 25
	MaxGone                    = 10
	MaxEventGroups             = 300
	EventReasonsPerComposition = 3
	EventMessageChars          = 300
	TextChars                  = 400
)

// ociRE is the convention every Krateo chart release follows: the org-wide release-oci workflow
// publishes each Chart.yaml of github.com/<org>/<repo> as oci://ghcr.io/<org>/charts/<chart name>, and
// the Blueprint Builder's publish names the repository after the blueprint. So a blueprint's chart name
// IS its source repository's name — for a single-chart repository. A repository that carries several
// charts breaks it, and the TargetResolved check is what says so.
var ociRE = pyre.MustCompile(`^oci://ghcr\.io/([A-Za-z0-9][A-Za-z0-9-]{0,38})/charts/([A-Za-z0-9._-]{1,100})/?$`, 0)

func parse(ts any) (time.Time, bool) { return synchealth.Parse(ts) }

func inWindow(ts any, frm, to time.Time, okFrm, okTo bool) bool {
	t, ok := parse(ts)
	return ok && okFrm && okTo && !t.Before(frm) && !t.After(to)
}

func short(text any, n int) string {
	s := ""
	if py.Truthy(text) {
		s = py.Str(text)
	}
	s = py.JoinFields(s)
	if py.Len(s) <= n {
		return s
	}
	return py.Trunc(s, n-1) + "…"
}

func ref(ns, kind, name string) string {
	if ns != "" {
		return kind + " " + ns + "/" + name
	}
	return kind + " " + name
}

// BlueprintRepo is the (org, name) of the source repository a CompositionDefinition's chart URL
// implies. Only the OCI shape is derivable: a classic Helm repository names an INDEX, not the repository
// that holds the chart's source, so nothing is guessed for it.
func BlueprintRepo(chartURL any) (string, string, bool) {
	m := ociRE.Match(py.Strip(py.Str(py.Or(chartURL, ""))))
	if m == nil {
		return "", "", false
	}
	return m.Group(1), m.Group(2), true
}

// --- incidents -------------------------------------------------------------------------------------

type refEntry struct{ what, group, ns, resource, name string }

// affected is (what, ref, composition) — the object the incident is about, as far as the Incident
// records one.
func affected(inc any) (string, string, string) {
	st := py.Or(py.Get(inc, "status"), map[string]any{})
	action := py.Or(py.Get(py.Or(py.Get(st, "howToFix"), map[string]any{}), "applyAction"), map[string]any{})
	composition := ""
	var refs []refEntry
	if py.Truthy(py.Get(action, "resource")) && py.Truthy(py.Get(action, "name")) {
		api := py.Str(py.Or(py.Get(action, "apiVersion"), ""))
		group := ""
		if i := strings.LastIndex(api, "/"); i >= 0 {
			group = api[:i]
		}
		refs = append(refs, refEntry{"fix target", group, py.Str(py.Or(py.Get(action, "namespace"), "")),
			py.Str(py.Get(action, "resource")), py.Str(py.Get(action, "name"))})
	}
	alert := py.Or(py.GetPath(inc, "spec", "alertRef"), map[string]any{})
	for _, r := range py.List(py.Get(st, "analyzedResources")) {
		gvr := strings.Split(py.Str(py.Or(py.Get(r, "gvr"), "")), "/")
		group := ""
		if len(gvr) == 3 {
			group = gvr[0]
		}
		resource := gvr[len(gvr)-1]
		// The Alert that opened it and the Incident itself are what was investigated FROM, not the failure.
		if (resource == "alerts" && py.Get(r, "name") == py.Get(alert, "name")) ||
			(resource == incidentPlural && py.Get(r, "name") == py.GetPath(inc, "metadata", "name")) {
			continue
		}
		refs = append(refs, refEntry{"examined", group, py.Str(py.Or(py.Get(r, "namespace"), "")), resource,
			py.Str(py.Or(py.Get(r, "name"), ""))})
	}
	for _, r := range refs {
		if r.group == compositionGroup && composition == "" {
			composition = ref(r.ns, r.resource, r.name)
		}
	}
	if len(refs) == 0 {
		return "", "", composition
	}
	r := refs[0]
	kind := r.resource
	if r.group != "" {
		kind += "." + r.group
	}
	return r.what, ref(r.ns, kind, r.name), composition
}

// fixSummary is the fix in one line: the apply script's first comment (the analysis writes the intent
// there) and, when the fix is one API write, that write.
func fixSummary(inc any) string {
	fix := py.Or(py.GetPath(inc, "status", "howToFix"), map[string]any{})
	intent := ""
	for _, ln := range py.SplitLines(py.Str(py.Or(py.Get(fix, "apply"), ""))) {
		if strings.HasPrefix(ln, "#") && !strings.HasPrefix(ln, "#!") && py.StripChars(ln, "# ") != "" {
			intent = py.Strip(py.LStripChars(ln, "# "))
			break
		}
	}
	action := py.Or(py.Get(fix, "applyAction"), map[string]any{})
	write := ""
	if py.Truthy(py.Get(action, "verb")) && py.Truthy(py.Get(action, "resource")) {
		where := ""
		if py.Truthy(py.Get(action, "namespace")) {
			where = py.Str(py.Get(action, "namespace")) + "/"
		}
		name := any("")
		if py.Has(action, "name") {
			name = py.Get(action, "name")
		}
		write = fmt.Sprintf("one API write: %s %s %s%s", py.Str(py.Get(action, "verb")), py.Str(py.Get(action, "resource")),
			where, py.Str(name))
	}
	var parts []string
	for _, x := range []string{short(intent, 240), write} {
		if x != "" {
			parts = append(parts, x)
		}
	}
	return strings.Join(parts, "; ")
}

func lifecycle(inc any) string {
	spec, st := py.Or(py.Get(inc, "spec"), map[string]any{}), py.Or(py.Get(inc, "status"), map[string]any{})
	out := py.Str(py.Or(py.Get(st, "state"), "unknown"))
	res := py.Or(py.Get(st, "resolution"), map[string]any{})
	if py.Truthy(py.Get(res, "by")) {
		who := "its verify check"
		if py.Get(res, "by") == "user" {
			who = "a person"
		}
		out += fmt.Sprintf(" (ended by %s at %s)", who, getOr(res, "at", "?"))
	}
	if py.Truthy(py.Get(spec, "applied")) {
		out += "; a person applied the fix"
	}
	return out
}

// getOr is d.get(key, def) rendered by an f-string.
func getOr(d any, key, def string) string {
	if py.Has(d, key) {
		return py.Str(py.Get(d, key))
	}
	return def
}

// Incidents is (body, stats): every Incident opened, fired, analysed or ended inside the window, newest
// first, ended ones ahead of open ones — an incident that ended is a failure somebody had to fix.
func Incidents(ctx context.Context, api kube.CustomObjects, window prompt.Window) (string, map[string]any) {
	frm, okF := parse(window.From)
	to, okT := parse(window.To)
	stats := map[string]any{"ok": true, "queried": int64(1), "returned": int64(0), "findings": int64(0)}
	items, err := synchealth.List(ctx, api, incidentGroup, incidentVersion, incidentPlural, stats)
	if err != nil {
		// A cluster without the incident controller has no such kind: nothing to read, not a failure.
		if kube.StatusOf(err) == 404 {
			return "", map[string]any{"ok": true, "queried": int64(0), "returned": int64(0), "empty": true,
				"note": "incidents.observability.krateo.io is not served by this cluster"}
		}
		return "", map[string]any{"ok": false, "queried": int64(1), "returned": int64(0),
			"error": py.Trunc(proposals.RedactString(py.TypeName(err)+": "+py.Trunc(err.Error(), 200)), 300)}
	}
	stats["returned"] = int64(len(items))

	type hit struct {
		inc  any
		last time.Time
	}
	var hits []hit
	for _, i := range items {
		st, meta := py.Or(py.Get(i, "status"), map[string]any{}), py.Or(py.Get(i, "metadata"), map[string]any{})
		var touched []time.Time
		for _, t := range []any{py.GetPath(py.Or(py.Get(i, "spec"), map[string]any{}), "triggeredAt"), py.Get(st, "lastFiredAt"),
			py.Get(st, "completedAt"), py.Get(py.Or(py.Get(st, "resolution"), map[string]any{}), "at"),
			py.Get(meta, "creationTimestamp")} {
			if inWindow(t, frm, to, okF, okT) {
				pt, _ := parse(t)
				touched = append(touched, pt)
			}
		}
		if len(touched) == 0 {
			continue
		}
		last := touched[0]
		for _, t := range touched[1:] {
			if t.After(last) {
				last = t
			}
		}
		hits = append(hits, hit{i, last})
	}
	ended := func(h hit) bool {
		s := py.GetPath(h.inc, "status", "state")
		return s == "Resolved" || s == "Closed"
	}
	sort.SliceStable(hits, func(a, b int) bool {
		ea, eb := ended(hits[a]), ended(hits[b])
		if ea != eb {
			return ea
		}
		return hits[a].last.After(hits[b].last)
	})
	stats["findings"] = int64(len(hits))
	if len(hits) == 0 {
		stats["empty"] = true
		stats["note"] = fmt.Sprintf("%d Incident(s) in the cluster; none opened, fired or ended in the window", len(items))
		return "", stats
	}
	lines := []string{fmt.Sprintf("- %d Incident(s) opened, fired, analysed or ended in the window (of %d in the cluster). "+
		"Ended ones first: those are failures the platform or a person had to fix.", len(hits), len(items))}
	for k, h := range hits {
		if k >= MaxIncidents {
			break
		}
		inc := h.inc
		meta := py.Or(py.Get(inc, "metadata"), map[string]any{})
		spec := py.Or(py.Get(inc, "spec"), map[string]any{})
		st := py.Or(py.Get(inc, "status"), map[string]any{})
		alert := py.Or(py.Get(spec, "alertRef"), map[string]any{})
		lines = append(lines, fmt.Sprintf("- Incident %s/%s: %s; trigger %s %s; opened %s, last fired %s, firings %s",
			py.Str(py.Get(meta, "namespace")), py.Str(py.Get(meta, "name")), lifecycle(inc),
			py.Str(py.Or(py.Get(spec, "trigger"), "alert")), getOr(alert, "name", ""), getOr(spec, "triggeredAt", "?"),
			getOr(st, "lastFiredAt", "?"), getOr(st, "firings", "?")))
		what, r, composition := affected(inc)
		if r != "" {
			line := fmt.Sprintf("    affected (%s): %s", what, r)
			if composition != "" && composition != r {
				line += "; composition " + composition
			}
			lines = append(lines, line)
		}
		rc := py.Or(py.Get(st, "rootCause"), map[string]any{})
		if py.Truthy(py.Get(rc, "statement")) {
			lines = append(lines, fmt.Sprintf("    root cause [%s, confidence %s]: %s", getOr(rc, "category", "?"),
				getOr(rc, "confidence", "?"), short(py.Get(rc, "statement"), TextChars)))
		}
		if fix := fixSummary(inc); fix != "" {
			lines = append(lines, "    remediation: "+fix)
		}
		if py.Truthy(py.Get(st, "error")) {
			lines = append(lines, "    analysis failed: "+short(py.Get(st, "error"), 200))
		}
	}
	if len(hits) > MaxIncidents {
		lines = append(lines, fmt.Sprintf("- ... and %d more Incident(s) in the window, not listed", len(hits)-MaxIncidents))
		stats["note"] = fmt.Sprintf("listed %d of %d Incidents in the window", MaxIncidents, len(hits))
	}
	return evidence.Cap(proposals.RedactString(strings.Join(lines, "\n")), stats), stats
}

// --- compositions ----------------------------------------------------------------------------------

func conds(obj any) map[string]any {
	out := map[string]any{}
	for _, c := range py.List(py.GetPath(obj, "status", "conditions")) {
		if py.IsDict(c) {
			out[py.Str(py.Get(c, "type"))] = c
		}
	}
	return out
}

// definition is what the evidence says about a CompositionDefinition.
type definition struct {
	name, namespace, url, version, repoName any
}

type nsName struct{ ns, name any }

// definitions is (byName, byKind, order): CompositionDefinitions keyed by (namespace, name) and by the
// Kind they serve.
func definitions(ctx context.Context, api kube.CustomObjects) (map[nsName]*definition, map[string]*definition, []nsName, error) {
	items, err := synchealth.List(ctx, api, cdGroup, cdVersion, cdPlural, map[string]any{})
	if err != nil {
		return nil, nil, nil, err
	}
	byName, byKind := map[nsName]*definition{}, map[string]*definition{}
	var order []nsName
	for _, cd := range items {
		meta := py.Or(py.Get(cd, "metadata"), map[string]any{})
		spec := py.Or(py.Get(cd, "spec"), map[string]any{})
		st := py.Or(py.Get(cd, "status"), map[string]any{})
		chart := py.Or(py.Get(spec, "chart"), map[string]any{})
		info := &definition{name: py.Get(meta, "name"), namespace: py.Get(meta, "namespace"), url: py.Get(chart, "url"),
			version: py.Get(chart, "version"), repoName: py.Get(chart, "repo")}
		key := nsName{py.Get(meta, "namespace"), py.Get(meta, "name")}
		if _, ok := byName[key]; !ok {
			order = append(order, key)
		}
		byName[key] = info
		if k := py.Get(st, "kind"); py.Truthy(k) {
			if _, ok := byKind[py.Str(k)]; !ok {
				byKind[py.Str(k)] = info
			}
		}
	}
	return byName, byKind, order, nil
}

func blueprintOf(obj any, byName map[nsName]*definition, byKind map[string]*definition) *definition {
	labels := py.GetPath(obj, "metadata", "labels")
	key := nsName{py.Get(labels, "krateo.io/composition-definition-namespace"), py.Get(labels, "krateo.io/composition-definition-name")}
	if d := byName[key]; d != nil {
		return d
	}
	return byKind[py.Str(py.Get(obj, "kind"))]
}

// BlueprintText is the blueprint and, when its org is one config.destinations.blueprints allows, the
// source repository a proposal about it lands in. Other orgs' charts are named without a repository:
// their components are mapped explicitly in config.destinations.components, and a derived name there
// would only mislead.
func BlueprintText(bp map[string]any, obj any, blueprints map[string]string) string {
	st := py.Or(py.Get(obj, "status"), map[string]any{})
	if bp == nil {
		url, ver := py.Get(st, "helmChartUrl"), py.Get(st, "helmChartVersion")
		if py.Truthy(url) {
			return fmt.Sprintf("no CompositionDefinition found for it; chart %s@%s", py.Str(url), py.Str(ver))
		}
		return "no CompositionDefinition found"
	}
	repo := blueprints[py.Str(bp["name"])]
	out := fmt.Sprintf("blueprint %s (CompositionDefinition %s/%s, chart %s", py.Str(bp["name"]), py.Str(bp["namespace"]),
		py.Str(bp["name"]), py.Str(bp["url"]))
	if py.Truthy(bp["repoName"]) {
		out += " " + py.Str(bp["repoName"])
	}
	out += " @ " + py.Str(bp["version"])
	if repo != "" {
		out += "; source repository " + repo
	}
	return out + ")"
}

func (d *definition) asMap() map[string]any {
	if d == nil {
		return nil
	}
	return map[string]any{"name": d.name, "namespace": d.namespace, "url": d.url, "version": d.version, "repoName": d.repoName}
}

// EventGroup is one (composition, reason) group of Warning events.
type EventGroup struct {
	Kind, Namespace, Name, UID, Reason string
	Count                              int64
	FirstSeen, LastSeen, Message       string
}

// ReadEvents reads the window's Warning event groups; Compositions takes one so a test can stand in.
type ReadEvents func(ctx context.Context, window prompt.Window) ([]*EventGroup, string, error)

// Compositions is (body, stats, blueprints). body lists every composition NOT Ready or NOT Synced now,
// and every one that RECOVERED inside the window, each with its blueprint; blueprints maps every
// CompositionDefinition whose OCI chart is published by one of `orgs` to the "org/repo" its chart URL
// implies, in the order the definitions were listed.
func Compositions(ctx context.Context, api kube.CustomObjects, discover synchealth.Discover, window prompt.Window,
	orgs []string, readEvents ReadEvents) (string, map[string]any, []targets.NamedRepo) {
	frm, okF := parse(window.From)
	to, okT := parse(window.To)
	stats := map[string]any{"ok": true, "queried": int64(0), "returned": int64(0), "findings": int64(0)}
	if readEvents == nil {
		readEvents = WarningEvents
	}
	fail := func(what string, err error) {
		stats["ok"] = false
		stats["error"] = py.Trunc(py.Str(py.Or(stats["error"], ""))+
			proposals.RedactString(fmt.Sprintf("%s: %s; ", what, py.Trunc(err.Error(), 160))), 500)
	}

	served, err := discover(ctx, compositionGroup)
	if err != nil {
		if kube.StatusOf(err) == 404 {
			return "", map[string]any{"ok": true, "queried": int64(0), "returned": int64(0), "empty": true,
				"note": compositionGroup + " is not served by this cluster"}, nil
		}
		fail("discovery of "+compositionGroup, err)
		return "", stats, nil
	}
	byName, byKind, order, err := definitions(ctx, api)
	if err != nil {
		// Degraded, not blank: the compositions still answer, they only lose their blueprint.
		byName, byKind, order = map[nsName]*definition{}, map[string]*definition{}, nil
		fail(cdPlural, err)
	}

	// EVERY blueprint with a derivable source in an allowed org, not only the failing ones': an Incident
	// can be about a composition that is healthy again, and its proposal belongs in that blueprint's
	// repository too.
	allowed := map[string]bool{}
	for _, o := range orgs {
		allowed[py.Lower(o)] = true
	}
	blueprints := map[string]string{}
	var found []targets.NamedRepo
	var foundIdx = map[string]int{}
	for _, key := range order {
		bp := byName[key]
		if !py.Truthy(bp.name) {
			continue
		}
		org, name, ok := BlueprintRepo(bp.url)
		if !ok || !allowed[py.Lower(org)] {
			continue
		}
		n := py.Str(bp.name)
		blueprints[n] = org + "/" + name
		if i, seen := foundIdx[n]; seen {
			found[i].Repo = org + "/" + name
		} else {
			foundIdx[n] = len(found)
			found = append(found, targets.NamedRepo{Name: n, Repo: org + "/" + name})
		}
	}
	groups, note, err := readEvents(ctx, window)
	if err != nil {
		// Degraded, not blank: conditions still answer; a failure fixed in the window is what is lost.
		groups, note = nil, ""
		fail("warning events (ClickHouse)", err)
	}
	if note != "" {
		stats["note"] = note
	}
	var warn int64
	for _, g := range groups {
		warn += g.Count
	}
	stats["warningEvents"] = warn
	byUID := map[string][]*EventGroup{}
	type refKey struct{ ns, kind, name string }
	byRef := map[refKey][]*EventGroup{}
	for _, g := range groups {
		if g.UID != "" {
			byUID[g.UID] = append(byUID[g.UID], g)
		}
		k := refKey{g.Namespace, g.Kind, g.Name}
		byRef[k] = append(byRef[k], g)
	}
	matched := map[*EventGroup]bool{}

	type failingItem struct {
		obj any
		bad []any
		ev  []*EventGroup
	}
	type refusedItem struct {
		obj any
		ev  []*EventGroup
	}
	type recoveredItem struct {
		obj   any
		ready any
	}
	var failing []failingItem
	var refused []refusedItem
	var recovered []recoveredItem
	for _, s := range served {
		items, err := synchealth.List(ctx, api, compositionGroup, s.Version, s.Plural, stats)
		if err != nil {
			fail(s.Plural+"."+compositionGroup, err)
			continue
		}
		stats["queried"] = py.Int(stats["queried"]) + 1
		stats["returned"] = py.Int(stats["returned"]) + int64(len(items))
		for _, obj := range items {
			m, _ := obj.(map[string]any)
			if m != nil {
				if _, ok := m["kind"]; !ok {
					m["kind"] = s.Kind
				}
			}
			meta := py.Get(obj, "metadata")
			// BY UID OR BY name+namespace+kind: an event recorded before a composition was deleted and
			// recreated under the same name is still about the composition a person sees under that name.
			var ev []*EventGroup
			if uid, ok := py.Get(meta, "uid").(string); ok {
				ev = byUID[uid]
			}
			if len(ev) == 0 {
				ev = byRef[refKey{py.Str(py.Or(py.Get(meta, "namespace"), "")), py.Str(py.Get(obj, "kind")), py.Str(py.Get(meta, "name"))}]
			}
			for _, g := range ev {
				matched[g] = true
			}
			cs := conds(obj)
			var bad []any
			for _, t := range []string{"Ready", "Synced"} {
				if c := cs[t]; py.Truthy(c) && py.Get(c, "status") != "True" {
					bad = append(bad, c)
				}
			}
			ready := py.Or(cs["Ready"], map[string]any{})
			synced := py.Or(cs["Synced"], map[string]any{})
			created, okC := parse(py.Get(meta, "creationTimestamp"))
			switch {
			case len(bad) > 0:
				failing = append(failing, failingItem{obj, bad, ev})
			case len(ev) > 0 && py.Get(synced, "status") == "True":
				refused = append(refused, refusedItem{obj, ev})
			case py.Get(ready, "status") == "True" && inWindow(py.Get(ready, "lastTransitionTime"), frm, to, okF, okT) &&
				okC && okF && created.Before(frm):
				recovered = append(recovered, recoveredItem{obj, ready})
			}
		}
	}
	type goneItem struct {
		key refKey
		ev  []*EventGroup
	}
	var gone []*goneItem
	goneIdx := map[refKey]*goneItem{}
	for _, g := range groups {
		if matched[g] {
			continue
		}
		k := refKey{g.Namespace, g.Kind, g.Name}
		if gi, ok := goneIdx[k]; ok {
			gi.ev = append(gi.ev, g)
		} else {
			gi = &goneItem{key: k, ev: []*EventGroup{g}}
			goneIdx[k] = gi
			gone = append(gone, gi)
		}
	}

	stats["failing"], stats["recovered"] = int64(len(failing)), int64(len(refused)+len(recovered))
	stats["findings"] = int64(len(failing) + len(refused) + len(recovered) + len(gone))
	if py.Int(stats["findings"]) == 0 {
		if stats["ok"] == true {
			stats["empty"] = true
			stats["note"] = fmt.Sprintf("%d composition(s): all Ready and Synced, none recovered and no Warning events in the window",
				py.Int(stats["returned"]))
		}
		return "", stats, found
	}

	since := func(c any) string {
		t := py.Get(c, "lastTransitionTime")
		if !py.Truthy(t) {
			return "no time"
		}
		where := " (before the window)"
		if inWindow(t, frm, to, okF, okT) {
			where = " (in the window)"
		}
		return "since " + py.Str(t) + where
	}
	bpText := func(obj any) string {
		return BlueprintText(blueprintOf(obj, byName, byKind).asMap(), obj, blueprints)
	}
	maxLast := func(ev []*EventGroup) string {
		m := ""
		for i, g := range ev {
			if i == 0 || g.LastSeen > m {
				m = g.LastSeen
			}
		}
		return m
	}

	sort.SliceStable(failing, func(a, b int) bool {
		ka, kb := failing[a], failing[b]
		for _, pair := range [][2]string{
			{py.Str(py.Get(ka.obj, "kind")), py.Str(py.Get(kb.obj, "kind"))},
			{metaGet(ka.obj, "namespace"), metaGet(kb.obj, "namespace")},
			{py.Str(py.GetPath(ka.obj, "metadata", "name")), py.Str(py.GetPath(kb.obj, "metadata", "name"))},
		} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
		return false
	})
	sort.SliceStable(refused, func(a, b int) bool { return maxLast(refused[a].ev) > maxLast(refused[b].ev) })
	sort.SliceStable(recovered, func(a, b int) bool {
		return py.Str(py.Or(py.Get(recovered[a].ready, "lastTransitionTime"), "")) >
			py.Str(py.Or(py.Get(recovered[b].ready, "lastTransitionTime"), ""))
	})

	var lines []string
	if len(failing) > 0 {
		lines = append(lines, fmt.Sprintf("- %d composition(s) NOT healthy now:", len(failing)))
		for i, f := range failing {
			if i >= MaxFailing {
				break
			}
			var parts []string
			for _, c := range f.bad {
				msg := short(py.Get(c, "message"), 300)
				if msg == "" {
					msg = "no message"
				}
				parts = append(parts, fmt.Sprintf("%s=%s/%s %s: %s", py.Str(py.Get(c, "type")), py.Str(py.Get(c, "status")),
					py.Str(py.Or(py.Get(c, "reason"), "-")), since(c), msg))
			}
			lines = append(lines, fmt.Sprintf("  - %s: ", ref(metaGetRaw(f.obj, "namespace"), py.Str(py.Get(f.obj, "kind")),
				py.Str(py.GetPath(f.obj, "metadata", "name"))))+strings.Join(parts, "; "))
			lines = append(lines, "    "+bpText(f.obj))
			lines = append(lines, eventLines(f.ev)...)
		}
		if len(failing) > MaxFailing {
			lines = append(lines, fmt.Sprintf("  - ... and %d more not listed", len(failing)-MaxFailing))
		}
	}
	if len(refused) > 0 {
		lines = append(lines, fmt.Sprintf("- %d composition(s) RECOVERED after being REFUSED — Warning events on the "+
			"composition inside the window, Synced=True now. Each was refused by the apiserver or its controller "+
			"and is not any more — fixed by a person, or transient; the message says which:", len(refused)))
		for i, r := range refused {
			if i >= MaxRefused {
				break
			}
			var reasons []string
			seenReason := map[string]bool{}
			for _, g := range r.ev {
				if !seenReason[g.Reason] {
					seenReason[g.Reason] = true
					reasons = append(reasons, g.Reason)
				}
			}
			lines = append(lines, fmt.Sprintf("  - %s: recovered (was refused: %s); %s",
				ref(metaGetRaw(r.obj, "namespace"), py.Str(py.Get(r.obj, "kind")), py.Str(py.GetPath(r.obj, "metadata", "name"))),
				strings.Join(reasons, ", "), bpText(r.obj)))
			lines = append(lines, eventLines(r.ev)...)
		}
		if len(refused) > MaxRefused {
			lines = append(lines, fmt.Sprintf("  - ... and %d more not listed", len(refused)-MaxRefused))
		}
	}
	if len(recovered) > 0 {
		lines = append(lines, fmt.Sprintf("- %d composition(s) RECOVERED in the window — Ready=True stamped inside it on "+
			"a composition created before it, so it was not Ready earlier in the window (a chart "+
			"upgrade's rollout stamps the same; weigh these beside the incidents and log patterns):", len(recovered)))
		for i, r := range recovered {
			if i >= MaxRecovered {
				break
			}
			lines = append(lines, fmt.Sprintf("  - %s: Ready=True/%s since %s; %s",
				ref(metaGetRaw(r.obj, "namespace"), py.Str(py.Get(r.obj, "kind")), py.Str(py.GetPath(r.obj, "metadata", "name"))),
				py.Str(py.Or(py.Get(r.ready, "reason"), "-")), py.Str(py.Get(r.ready, "lastTransitionTime")), bpText(r.obj)))
		}
		if len(recovered) > MaxRecovered {
			lines = append(lines, fmt.Sprintf("  - ... and %d more not listed", len(recovered)-MaxRecovered))
		}
	}
	if len(gone) > 0 {
		lines = append(lines, fmt.Sprintf("- %d composition(s) with Warning events in the window that NO LONGER EXIST "+
			"(deleted since):", len(gone)))
		sorted := append([]*goneItem(nil), gone...)
		sort.SliceStable(sorted, func(a, b int) bool { return maxLast(sorted[a].ev) > maxLast(sorted[b].ev) })
		for i, g := range sorted {
			if i >= MaxGone {
				break
			}
			lines = append(lines, fmt.Sprintf("  - %s:", ref(g.key.ns, g.key.kind, g.key.name)))
			lines = append(lines, eventLines(g.ev)...)
		}
		if len(gone) > MaxGone {
			lines = append(lines, fmt.Sprintf("  - ... and %d more not listed", len(gone)-MaxGone))
		}
	}
	var cut []string
	for _, c := range []struct {
		what   string
		n, cap int
	}{{"failing", len(failing), MaxFailing}, {"refused-then-recovered", len(refused), MaxRefused},
		{"recovered", len(recovered), MaxRecovered}, {"deleted", len(gone), MaxGone}} {
		if c.n > c.cap {
			cut = append(cut, fmt.Sprintf("%d of %d %s", c.cap, c.n, c.what))
		}
	}
	if len(cut) > 0 {
		var parts []string
		if py.Truthy(stats["note"]) {
			parts = append(parts, py.Str(stats["note"]))
		}
		parts = append(parts, "listed "+strings.Join(cut, ", "))
		stats["note"] = strings.Join(parts, "; ")
	}
	return evidence.Cap(proposals.RedactString(strings.Join(lines, "\n")), stats), stats, found
}

// metaGet is f["metadata"].get(key, "") as a sort key.
func metaGet(obj any, key string) string {
	md := py.Get(obj, "metadata")
	if !py.Has(md, key) {
		return ""
	}
	return py.Str(py.Get(md, key))
}

// metaGetRaw is m.get(key) for _ref: an absent or null namespace is "no namespace".
func metaGetRaw(obj any, key string) string {
	v := py.GetPath(obj, "metadata", key)
	if !py.Truthy(v) {
		return ""
	}
	return py.Str(v)
}

// eventLines renders one line per reason for one composition: how many, first and last seen, and the
// latest message.
func eventLines(groups []*EventGroup) []string {
	sorted := append([]*EventGroup(nil), groups...)
	sort.SliceStable(sorted, func(a, b int) bool { return sorted[a].LastSeen > sorted[b].LastSeen })
	var out []string
	for i, g := range sorted {
		if i >= EventReasonsPerComposition {
			break
		}
		msg := short(g.Message, EventMessageChars)
		if msg == "" {
			msg = "no message"
		}
		out = append(out, fmt.Sprintf("    warning event %s x%d, first %s, last %s: %s", g.Reason, g.Count, g.FirstSeen, g.LastSeen, msg))
	}
	return out
}

// WarningEventsSQL reads WARNING EVENTS ON COMPOSITIONS FROM CLICKHOUSE — NOT THE EVENTS API, which
// keeps an Event for about an hour: a refusal fixed in the morning is gone from it by the nightly run.
// The collector's k8sobjects receiver writes each Event watch notification as one otel_logs row,
// telemetry.source 'k8s-events', with the notification as JSON in Body. DELETED rows are the apiserver
// EXPIRING an Event, a copy of one already recorded: excluded, or every occurrence counts twice. The
// window bound is the same {from}/{to} text substitution, in the same index-friendly format, as every
// configured query (evidence.ChTime).
const WarningEventsSQL = `
SELECT kind, namespace, name, uid, reason, sum(n) AS count,
       toString(min(first)) AS firstSeen, toString(max(last)) AS lastSeen, argMax(msg, last) AS message
FROM (
  SELECT JSONExtractString(Body, 'object', 'involvedObject', 'kind')      AS kind,
         JSONExtractString(Body, 'object', 'involvedObject', 'namespace') AS namespace,
         JSONExtractString(Body, 'object', 'involvedObject', 'name')      AS name,
         JSONExtractString(Body, 'object', 'involvedObject', 'uid')       AS uid,
         JSONExtractString(Body, 'object', 'reason')                      AS reason,
         JSONExtractString(Body, 'object', 'metadata', 'uid')             AS event,
         greatest(max(JSONExtractInt(Body, 'object', 'count')),
                  max(JSONExtractInt(Body, 'object', 'series', 'count')), 1) AS n,
         min(Timestamp) AS first, max(Timestamp) AS last,
         substring(argMax(JSONExtractString(Body, 'object', 'message'), Timestamp), 1, 600) AS msg
  FROM otel_logs
  WHERE Timestamp BETWEEN '{from}' AND '{to}'
    AND ResourceAttributes['telemetry.source'] = 'k8s-events'
    AND JSONExtractString(Body, 'type') != 'DELETED'
    AND JSONExtractString(Body, 'object', 'type') = 'Warning'
    AND startsWith(JSONExtractString(Body, 'object', 'involvedObject', 'apiVersion'), 'composition.krateo.io/')
  GROUP BY kind, namespace, name, uid, reason, event
)
GROUP BY kind, namespace, name, uid, reason
ORDER BY lastSeen DESC
LIMIT {limit}
`

// WarningEvents reads Warning events on composition.krateo.io objects in the window, one group per
// (composition, reason), through the same ClickHouse endpoint and credentials as the configured queries.
// Not configured is a note, not a failure — the conditions still answer. A failed query is an error.
func WarningEvents(ctx context.Context, window prompt.Window) ([]*EventGroup, string, error) {
	if evidence.ClickhouseURL == "" {
		return []*EventGroup{}, "warning events not read: CLICKHOUSE_URL is not configured", nil
	}
	sql := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(WarningEventsSQL, "{from}", evidence.ChTime(window.From)),
		"{to}", evidence.ChTime(window.To)), "{limit}", strconv.Itoa(MaxEventGroups))
	text, err := evidence.Post(ctx, sql+"\nFORMAT JSONEachRow", MaxEventGroups)
	if err != nil {
		return nil, "", err
	}
	groups := []*EventGroup{}
	for _, ln := range py.SplitLines(text) {
		row, err := py.LoadsJSON(ln, false)
		if err != nil {
			continue
		}
		if !py.IsDict(row) || !py.Truthy(py.Get(row, "kind")) || !py.Truthy(py.Get(row, "name")) {
			continue
		}
		count := pyIntOr1(py.Get(row, "count"))
		groups = append(groups, &EventGroup{
			Kind: py.Str(py.Get(row, "kind")), Namespace: py.Str(py.Or(py.Get(row, "namespace"), "")),
			Name: py.Str(py.Get(row, "name")), UID: py.Str(py.Or(py.Get(row, "uid"), "")),
			Reason: py.Str(py.Or(py.Get(row, "reason"), "-")), Count: count,
			FirstSeen: py.Trunc(py.Str(py.Or(py.Get(row, "firstSeen"), "?")), 19),
			LastSeen:  py.Trunc(py.Str(py.Or(py.Get(row, "lastSeen"), "?")), 19),
			Message:   py.Str(py.Or(py.Get(row, "message"), "")),
		})
	}
	note := ""
	if len(groups) >= MaxEventGroups {
		note = fmt.Sprintf("warning events: the first %d (composition, reason) groups only", MaxEventGroups)
	}
	return groups, note, nil
}

// pyIntOr1 is int(row.get("count") or 1), with 1 for a value int() refuses.
func pyIntOr1(v any) int64 {
	if !py.Truthy(v) {
		return 1
	}
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	case bool:
		return 1
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(strings.ReplaceAll(x, "_", "")), 10, 64)
		if err != nil {
			return 1
		}
		return n
	}
	return 1
}
