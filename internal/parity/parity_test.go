// Package parity asserts that the Go port computes, for the same input, byte-identical values to the
// Python service wherever those values are compared after the switch: fingerprints and Proposal names,
// normalised subjects, redacted fields, aimed targets and the notes a run records, the prompts the
// reviewer is sent, the sync-stall check's proposal bodies, and jsonschema's validation messages.
//
// Every expected value in testdata/ was computed by the Python functions themselves, run from the last
// Python commit by testdata/gen_fixtures.py (its header says how to regenerate). A failure here means an
// existing Proposal CR on a cluster would no longer match what the Go service computes.
package parity

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/nightly-review/internal/analysis"
	"github.com/krateo-platformops/nightly-review/internal/autopilot"
	"github.com/krateo-platformops/nightly-review/internal/evidence"
	"github.com/krateo-platformops/nightly-review/internal/failures"
	"github.com/krateo-platformops/nightly-review/internal/jsonschema"
	"github.com/krateo-platformops/nightly-review/internal/kube"
	"github.com/krateo-platformops/nightly-review/internal/prompt"
	"github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/publish"
	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/synchealth"
	"github.com/krateo-platformops/nightly-review/internal/targets"
	"github.com/krateo-platformops/nightly-review/internal/testutil"
)

func fixture(t *testing.T, name string) any {
	return testutil.JSON(t, "internal/parity/testdata/"+name+".gz")
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return v.(string)
}

func check(t *testing.T, failures *int, what string, got, want any) {
	t.Helper()
	g, w := testutil.Canon(got), testutil.Canon(want)
	if g != w {
		*failures++
		if *failures <= 15 {
			t.Errorf("%s\n got: %s\nwant: %s", what, trunc(g), trunc(w))
		}
	}
}

func trunc(s string) string {
	if len(s) > 1500 {
		return s[:1500] + "…"
	}
	return s
}

func TestRedactionMatchesPython(t *testing.T) {
	cases := fixture(t, "redact.json").([]any)
	bad := 0
	for _, c := range cases {
		check(t, &bad, fmt.Sprintf("redact(%q)", py.Get(c, "in")), proposals.RedactString(str(py.Get(c, "in"))), py.Get(c, "out"))
	}
	t.Logf("%d redaction cases, %d differ", len(cases), bad)
}

func TestSubjectNormalisationMatchesPython(t *testing.T) {
	cases := fixture(t, "subjects.json").([]any)
	bad := 0
	for _, c := range cases {
		var got any
		if s, ok := proposals.NormaliseSubject(py.Get(c, "in")); ok {
			got = s
		}
		check(t, &bad, fmt.Sprintf("normalise_subject(%s)", py.Repr(py.Get(c, "in"))), got, py.Get(c, "out"))
	}
	t.Logf("%d subjects, %d differ", len(cases), bad)
}

func outcome(v any, err error) any {
	if err != nil {
		return map[string]any{"exception": py.TypeName(err)}
	}
	return map[string]any{"ok": v}
}

func values(t *testing.T) (any, any) {
	cfg := py.Get(testutil.YAML(t, "helm/nightly-review/values.yaml"), "config")
	return py.Get(cfg, "targets"), py.GetPath(cfg, "destinations", "components")
}

// TestProposalsMatchPython is the acceptance criterion: for every proposal of the corpus, the
// fingerprint, the target key, the subject, ValidateBatch's kept proposals and notes (with and without
// the item check), and the aimed target, note and recomputed fingerprint under three configurations are
// exactly Python's.
func TestProposalsMatchPython(t *testing.T) {
	obs, comps := values(t)
	cases := fixture(t, "proposals.json").([]any)
	bad, fingerprints, dropped := 0, 0, 0
	schema := func(p any) error { return jsonschema.Validate(p, prompt.ResponseSchema) }
	item := func(p any) error { return jsonschema.Validate(p, prompt.ItemSchema) }
	for i, c := range cases {
		in := py.Get(c, "input")
		what := fmt.Sprintf("case %d %s", i, trunc(testutil.Canon(in)))
		if py.IsDict(in) {
			fp, err := proposals.Fingerprint(in)
			check(t, &bad, what+" fingerprint", outcome(fp, err), py.Get(c, "fingerprint"))
			if err == nil {
				fingerprints++
			}
			tk, err := proposals.TargetKey(in)
			check(t, &bad, what+" target_key", outcome(tk, err), py.Get(c, "targetKey"))
			var subject any
			if s, ok := proposals.NormaliseSubject(py.Get(in, "subject")); ok {
				subject = s
			}
			check(t, &bad, what+" subject", subject, py.Get(c, "subject"))
		}
		batch := func(schemaCheck, itemCheck proposals.Check) any {
			payload := py.O("proposals", []any{deepCopy(in)})
			kept, notes, err := proposals.ValidateBatch(payload, schemaCheck, itemCheck)
			if err != nil {
				return map[string]any{"exception": py.TypeName(err)}
			}
			if notes == nil {
				notes = []string{}
			}
			return map[string]any{"ok": []any{kept, notes}}
		}
		got := batch(schema, item)
		check(t, &bad, what+" validate_batch", byDesign(&dropped, got, py.Get(c, "batch")), py.Get(c, "batch"))
		noItem := batch(func(any) error { return nil }, nil)
		check(t, &bad, what+" validate_batch(no item check)", byDesign(&dropped, noItem, py.Get(c, "batchNoItemCheck")), py.Get(c, "batchNoItemCheck"))

		var aimed []any
		if ok, isOK := got.(map[string]any)["ok"]; isOK {
			for _, k := range ok.([]any)[0].([]map[string]any) {
				for _, cfg := range []struct {
					name        string
					kinds, comp any
				}{{"values", obs, comps}, {"none", map[string]any{}, map[string]any{}}, {"kindsOnly", obs, map[string]any{}}} {
					q := deepCopy(k).(map[string]any)
					note := targets.Aim(q, cfg.kinds, cfg.comp)
					var nd any
					if py.Get(q["target"], "repo") == "" {
						nd = targets.NoDestinationCondition(q, cfg.kinds, cfg.comp)
					}
					var noteV any
					if note != "" {
						noteV = note
					}
					aimed = append(aimed, map[string]any{"config": cfg.name, "note": noteV, "target": q["target"],
						"fingerprint": proposals.MustFingerprint(q), "noDestination": nd})
				}
			}
		}
		if aimed == nil {
			aimed = []any{}
		}
		check(t, &bad, what+" aim", aimed, py.Get(c, "aimed"))
	}
	t.Logf("%d proposals (%d fingerprinted), %d batches differ by design, %d values differ", len(cases), fingerprints, dropped, bad)
}

// byDesign is the one place this port leaves Python on purpose. Where
// Python's validate_batch raised because a proposal's content could not be
// read (a non-YAMLError out of the parser, an unhashable kind), the WHOLE
// night failed; Go drops that one proposal with a note naming the same
// exception (after any notes the earlier checks wrote, such as a
// redaction). That outcome is mapped back to Python's exception so the rest
// of the comparison still runs; anything else is returned unchanged and
// must match exactly.
func byDesign(dropped *int, got, want any) any {
	exc, raised := py.Get(want, "exception").(string)
	ok, isOK := got.(map[string]any)["ok"].([]any)
	if !raised || !isOK || len(ok[0].([]map[string]any)) != 0 {
		return got
	}
	notes := ok[1].([]string)
	if len(notes) == 0 {
		return got
	}
	last := notes[len(notes)-1]
	if !strings.HasPrefix(last, "DROPPED proposal[0] (") || !strings.Contains(last, "could not be read as") || !strings.Contains(last, "("+exc+": ") {
		return got
	}
	*dropped++
	return map[string]any{"exception": exc}
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case *py.OMap:
		out := py.NewOMap()
		for _, k := range x.Keys() {
			e, _ := x.Get(k)
			out.Set(k, deepCopy(e))
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	}
	return v
}

// fakeSync is the sync-stall tests' _Api: lists by plural and Configurations by (plural, name).
type fakeSync struct {
	kube.CustomObjects
	lists   any
	configs map[[2]string]any
}

func (f *fakeSync) ListCluster(_ context.Context, group, version, plural string, _ kube.ListOpts) (map[string]any, error) {
	items := py.List(py.Get(f.lists, plural))
	if items == nil {
		items = []any{}
	}
	return map[string]any{"items": deepCopy(items), "metadata": map[string]any{}}, nil
}

func (f *fakeSync) GetNamespaced(_ context.Context, group, version, ns, plural, name string) (map[string]any, error) {
	if c, ok := f.configs[[2]string{plural, name}]; ok {
		return py.Plain(c).(map[string]any), nil
	}
	return nil, py.Errorf("KeyError", "%s", name)
}

var served = map[string][]kube.Served{
	"github.com": nil,
	"github.krateo.io": {{Version: "v2022-11-28", Plural: "repositories", Kind: "Repository", Namespaced: true},
		{Version: "v2022-11-28", Plural: "pullrequests", Kind: "PullRequest", Namespaced: true},
		{Version: "v1alpha1", Plural: "repositoryconfigurations", Kind: "RepositoryConfiguration", Namespaced: true},
		{Version: "v1alpha1", Plural: "pullrequestconfigurations", Kind: "PullRequestConfiguration", Namespaced: true}},
	"git.krateo.io": {{Version: "v1alpha1", Plural: "repoes", Kind: "Repo", Namespaced: true},
		{Version: "v1alpha1", Plural: "localresources", Kind: "LocalResource", Namespaced: true}},
}

// TestSyncStallFindingsMatchPython runs the sync-stall check on the Python tests' outage fixtures and
// compares the corpus block, the stats, the proposals, their fingerprints, and what the service boundary
// makes of them.
func TestSyncStallFindingsMatchPython(t *testing.T) {
	fx := fixture(t, "synchealth.json")
	creds := map[string]any{"key": "token", "name": "git-provider-credentials", "namespace": "krateo-system"}
	cfg := map[string]any{"spec": map[string]any{"authentication": map[string]any{"bearer": map[string]any{"tokenRef": creds}}}}
	configs := map[[2]string]any{{"repositoryconfigurations", "github-blueprints-config"}: cfg,
		{"pullrequestconfigurations", "github-blueprints-config"}: cfg}
	groups := py.O("github.krateo.io", py.O("component", "github-provider-kog", "kinds", []any{}),
		"git.krateo.io", py.O("component", "git-provider", "kinds", []any{}))
	now := time.Date(2026, 10, 1, 14, 0, 0, 0, time.UTC)
	discover := func(_ context.Context, g string) ([]kube.Served, error) { return served[g], nil }
	bad := 0
	for _, c := range py.List(py.Get(fx, "sync")) {
		name := py.Str(py.Get(c, "name"))
		body, stats, props := synchealth.Gather(context.Background(), &fakeSync{lists: py.Get(c, "lists"), configs: configs},
			discover, now, groups, 15)
		var bodyV any
		if body != "" {
			bodyV = body
		}
		check(t, &bad, name+" body", bodyV, py.Get(c, "body"))
		check(t, &bad, name+" stats", stats, py.Get(c, "stats"))
		if props == nil {
			props = []map[string]any{}
		}
		check(t, &bad, name+" props", props, py.Get(c, "props"))
		var fps []any
		for _, p := range props {
			fps = append(fps, proposals.MustFingerprint(p))
		}
		if fps == nil {
			fps = []any{}
		}
		check(t, &bad, name+" fingerprints", fps, py.Get(c, "fingerprints"))

		saved := targets.Components
		targets.Components = py.O("git-provider", py.O("repo", "o/git-provider", "pathPrefix", "docs"))
		kept, notes, err := serviceFindings(props)
		targets.Components = saved
		if err != nil {
			t.Fatal(err)
		}
		check(t, &bad, name+" kept", kept, py.Get(c, "kept"))
		check(t, &bad, name+" notes", notes, py.Get(c, "notes"))
	}
	for _, c := range py.List(py.Get(fx, "classify")) {
		sig, desc := synchealth.Classify(py.Get(c, "reason"), py.Get(c, "message"))
		check(t, &bad, fmt.Sprintf("classify(%s, %s)", py.Repr(py.Get(c, "reason")), py.Repr(py.Get(c, "message"))),
			[]any{sig, desc}, py.Get(c, "out"))
	}
	if bad > 0 {
		t.Logf("%d values differ", bad)
	}
}

// serviceFindings is review.serviceFindings (unexported there; this is the same sequence).
func serviceFindings(props []map[string]any) ([]map[string]any, []string, error) {
	items := make([]any, len(props))
	for i, p := range props {
		items[i] = deepCopy(p)
	}
	kept, notes, err := proposals.ValidateBatch(map[string]any{"proposals": items},
		func(p any) error { return jsonschema.Validate(p, prompt.ResponseSchema) },
		func(p any) error { return jsonschema.Validate(p, prompt.ItemSchema) })
	if err != nil {
		return nil, nil, err
	}
	out := []string{}
	for _, n := range notes {
		out = append(out, "sync-stall "+n)
	}
	for _, p := range kept {
		if moved := targets.Aim(p, nil, nil); moved != "" && strings.Contains(moved, " cleared: ") {
			out = append(out, moved)
		}
		p["fingerprint"] = proposals.MustFingerprint(p)
	}
	if kept == nil {
		kept = []map[string]any{}
	}
	return kept, out, nil
}

func TestPromptsMatchPython(t *testing.T) {
	fx := fixture(t, "prompts.json")
	bad := 0
	check(t, &bad, "SYSTEM", prompt.System, py.Get(fx, "system"))
	check(t, &bad, "ALERT_KIND", prompt.AlertKind, py.Get(fx, "alertKind"))
	check(t, &bad, "INSTRUCTIONS", analysis.Instructions, py.Get(fx, "instructions"))
	check(t, &bad, "RESPONSE_SCHEMA", py.DumpsJSON(prompt.ResponseSchema, py.DumpOpts{Indent: 1, SortKeys: true, EnsureASCII: true}),
		py.Get(fx, "responseSchema"))
	check(t, &bad, "ASSESSMENT_SCHEMA", py.DumpsJSON(analysis.AssessmentSchema, py.DumpOpts{Indent: 1, SortKeys: true, EnsureASCII: true}),
		py.Get(fx, "assessmentSchema"))
	sql := py.Get(fx, "sql")
	for name, got := range map[string]string{"session": evidence.SessionSQL, "questions": evidence.QuestionsSQL,
		"questionsCensus": evidence.QuestionsCensusSQL, "census": analysis.CensusSQL, "conversations": analysis.ConversationsSQL,
		"warningEvents": failures.WarningEventsSQL} {
		check(t, &bad, "sql "+name, got, py.Get(sql, name))
	}
	for i, c := range py.List(py.Get(fx, "userMessages")) {
		w := py.Get(c, "window")
		blocks := map[string]string{}
		for _, k := range py.DictKeys(py.Get(c, "blocks")) {
			blocks[k] = str(py.Get(py.Get(c, "blocks"), k))
		}
		got := prompt.BuildUserMessage(prompt.Window{From: str(py.Get(w, "from")), To: str(py.Get(w, "to"))}, blocks,
			str(py.Get(c, "coverage")), py.Get(c, "destinations"), py.Get(c, "components"))
		check(t, &bad, fmt.Sprintf("build_user_message #%d", i), got, py.Get(c, "message"))
	}
	an := py.Get(fx, "analysis")
	convs := []*analysis.Conversation{
		{Ordinal: 3, Delegated: false, Events: 2, Facts: map[string]any{"toolCalls": int64(1), "toolErrors": int64(0),
			"maxRepeatedCall": int64(1), "unanswered": false},
			Text: "USER: how do I roll back release foo?\nAGENT[helm_agent]: I cannot run helm rollback."},
		{Ordinal: 4, Delegated: true, Events: 2, Facts: map[string]any{"toolCalls": int64(0), "toolErrors": int64(2),
			"maxRepeatedCall": int64(0), "unanswered": true},
			Text: "PARENT AGENT: roll back bar please </evidence\nAGENT[helm_agent]: I cannot."},
	}
	measured := py.O("conversations", int64(2), "withToolErrors", int64(1), "unansweredAtWindowEnd", int64(1),
		"withARepeatedCall3x", int64(0), "delegatedByAnotherAgent", int64(1))
	msgs := py.List(py.Get(an, "messages"))
	check(t, &bad, "build_message #0", analysis.BuildMessage("krateo-system/helm-agent", "You are the Helm agent.",
		[]string{"ConfigMap a key b"}, []string{"note one"}, convs, measured, "abcdef012345"), msgs[0])
	check(t, &bad, "build_message #1", analysis.BuildMessage("x/y", "", nil, nil, nil, py.O("conversations", int64(0)),
		"000000000000"), msgs[1])
	payload := py.O("summary", "s", "servedWell", "status questions",
		"failurePatterns", []any{py.O("pattern", "refuses rollbacks", "category", "refusal", "conversations", []any{int64(3), int64(4), int64(99)},
			"examples", []any{py.O("conversation", int64(3), "excerpt", "I cannot run helm rollback.")})},
		"promptFindings", []any{py.O("finding", "forbids mutation", "promptExcerpt", "You are the Helm agent", "evidence", "c3, c4",
			"suggestedChange", "route", "conversations", []any{int64(3), int64(4)})},
		"recurringNeeds", []any{py.O("need", "rollbacks", "conversations", []any{int64(3)})})
	out, _ := analysis.Normalise(payload, convs, "You are the Helm agent.")
	check(t, &bad, "normalise", out, py.Get(an, "normalised"))
	for i, r := range py.List(py.Get(an, "renders")) {
		var as []analysis.Assessment
		for _, a := range py.List(py.Get(r, "assessments")) {
			as = append(as, py.Plain(a).(map[string]any))
		}
		stats := map[string]any{}
		check(t, &bad, fmt.Sprintf("render_for_review #%d", i), analysis.RenderForReview(as, stats), py.Get(r, "body"))
		check(t, &bad, fmt.Sprintf("render_for_review #%d stats", i), stats, py.Get(r, "stats"))
	}
	if bad > 0 {
		t.Logf("%d values differ", bad)
	}
}

// TestValidationMessagesMatchPython compares str(ValidationError) — what a run records as
// "DROPPED proposal[i]: does not match the contract (…)" and as an agent's analysis error.
func TestValidationMessagesMatchPython(t *testing.T) {
	fx := fixture(t, "schema_messages.json")
	bad := 0
	for _, c := range py.List(py.Get(fx, "items")) {
		err := jsonschema.Validate(py.Get(c, "input"), prompt.ItemSchema)
		got := ""
		if err != nil {
			got = err.Error()
		}
		check(t, &bad, "item "+trunc(testutil.Canon(py.Get(c, "input"))), got, py.Get(c, "message"))
	}
	for _, c := range py.List(py.Get(fx, "assessment")) {
		in := py.Get(c, "input")
		err := jsonschema.Validate(analysis.Lenient(in), analysis.AssessmentSchema)
		var got any
		if err != nil {
			got = err.Error()
		}
		check(t, &bad, "assessment "+testutil.Canon(in), got, py.Get(c, "message"))
	}
	if bad > 0 {
		t.Logf("%d messages differ", bad)
	}
}

func TestSmallFunctionsMatchPython(t *testing.T) {
	fx := fixture(t, "misc.json")
	bad := 0
	for _, c := range py.List(py.Get(fx, "chTime")) {
		check(t, &bad, "_ch_time "+str(py.Get(c, "in")), evidence.ChTime(str(py.Get(c, "in"))), py.Get(c, "out"))
	}
	for _, c := range py.List(py.Get(fx, "parse")) {
		var got any
		if v, ok := synchealth.Parse(py.Get(c, "in")); ok {
			got = py.Isoformat(v)
		}
		check(t, &bad, "_parse "+py.Repr(py.Get(c, "in")), got, py.Get(c, "out"))
	}
	for _, c := range py.List(py.Get(fx, "contextId")) {
		check(t, &bad, "context_id", autopilot.ContextID(str(py.Get(c, "run")), str(py.Get(c, "scope"))), py.Get(c, "out"))
	}
	for _, c := range py.List(py.Get(fx, "norm")) {
		check(t, &bad, "_norm", analysis.Norm(str(py.Get(c, "in"))), py.Get(c, "out"))
	}
	for _, c := range py.List(py.Get(fx, "found")) {
		check(t, &bad, "_found", analysis.Found(str(py.Get(c, "excerpt")), str(py.Get(c, "haystack"))), py.Get(c, "out"))
	}
	for _, c := range py.List(py.Get(fx, "agentKey")) {
		check(t, &bad, "_agent_key", evidence.AgentKey(str(py.Get(c, "in"))), py.Get(c, "out"))
	}
	for _, c := range py.List(py.Get(fx, "fileName")) {
		check(t, &bad, "_file_name "+trunc(testutil.Canon(py.Get(c, "in"))), targets.FileName(py.Plain(py.Get(c, "in"))), py.Get(c, "out"))
	}
	for _, c := range py.List(py.Get(fx, "blueprintRepo")) {
		var got any
		if o, n, ok := failures.BlueprintRepo(py.Get(c, "in")); ok {
			got = []any{o, n}
		}
		check(t, &bad, "blueprint_repo", got, py.Get(c, "out"))
	}
	bodies := py.List(py.Get(fx, "prBody"))
	p0 := map[string]any{"kind": "Alert", "subject": "svc/some-signal", "title": "t", "rationale": "r", "confidence": "medium",
		"evidence": []any{map[string]any{"source": "clickhouse", "summary": "s", "observedCount": int64(9)},
			map[string]any{"source": "kubernetes", "summary": "é"}},
		"target": map[string]any{"repo": "org/allowed", "path": "p.yaml"}, "change": map[string]any{"format": "yaml", "content": "a: 1"},
		"fingerprint": strings.Repeat("f", 32)}
	check(t, &bad, "_pr_body #0", publish.PRBody(p0, "rr-1", map[string]any{"b": "SELECT 2", "a": "SELECT 1"}), bodies[0])
	p1 := map[string]any{"kind": "Alert", "subject": "svc/some-signal", "title": "t", "rationale": "r", "confidence": "medium",
		"evidence": []any{map[string]any{"source": "clickhouse", "summary": "s", "observedCount": int64(9)}},
		"target":   map[string]any{"repo": "o/r"}, "change": map[string]any{"format": "diff", "content": "日本"}}
	check(t, &bad, "_pr_body #1", publish.PRBody(p1, "rr-2", nil), bodies[1])
	for _, c := range py.List(py.Get(fx, "slug")) {
		check(t, &bad, "_slug", proposals.Slug(str(py.Get(c, "in"))), py.Get(c, "out"))
	}
	if bad > 0 {
		t.Logf("%d values differ", bad)
	}
}
