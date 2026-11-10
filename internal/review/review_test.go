package review

// Whole runs through Main against a fake apiserver (the main.main()-driven cases of
// tests/test_platform_review_service.py, test_spec_decision.py, test_failures.py and test_sync_stall.py,
// and tests/test_terminate.py).
//
// EVERYTHING THE SERVICE WRITES IS DECLARED. Structural schemas PRUNE undeclared fields on write,
// silently. So this drives a whole run on every rich path — truncation, a supersession, a publish — and
// walks every object and status it wrote against the CRDs in this repo.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/krateo-platformops/nightly-review/internal/analysis"
	"github.com/krateo-platformops/nightly-review/internal/autopilot"
	"github.com/krateo-platformops/nightly-review/internal/evidence"
	"github.com/krateo-platformops/nightly-review/internal/fake"
	FX "github.com/krateo-platformops/nightly-review/internal/fixtures"
	"github.com/krateo-platformops/nightly-review/internal/jsonschema"
	"github.com/krateo-platformops/nightly-review/internal/kube"
	"github.com/krateo-platformops/nightly-review/internal/logging"
	"github.com/krateo-platformops/nightly-review/internal/pg"
	"github.com/krateo-platformops/nightly-review/internal/prompt"
	P "github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/publish"
	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/synchealth"
	"github.com/krateo-platformops/nightly-review/internal/targets"
	"github.com/krateo-platformops/nightly-review/internal/testutil"
)

var ctx = context.Background()

func set[T any](t *testing.T, p *T, v T) {
	saved := *p
	*p = v
	t.Cleanup(func() { *p = saved })
}

func prop(kind, subject, content, repo, path, format string) map[string]any {
	p := map[string]any{"kind": kind, "title": "t", "rationale": "r", "confidence": "low",
		"evidence": []any{map[string]any{"source": "clickhouse", "summary": "s"}},
		"target":   map[string]any{"repo": repo, "path": path}, "change": map[string]any{"format": format, "content": content}}
	if subject != "" {
		p["subject"] = subject
	}
	return p
}

func with(p map[string]any, kv ...any) map[string]any {
	for i := 0; i+1 < len(kv); i += 2 {
		p[kv[i].(string)] = kv[i+1]
	}
	return p
}

func stored(name, subject, run string) map[string]any {
	spec := map[string]any{"kind": "Alert", "target": map[string]any{"repo": "org/old", "path": name + ".yaml"}, "fingerprint": "fp-" + name,
		"producedBy": map[string]any{"runRef": run}}
	if subject != "" {
		spec["subject"] = subject
	}
	return map[string]any{"metadata": map[string]any{"name": name}, "spec": spec, "status": map[string]any{"phase": "Proposed"}}
}

const real = "apiVersion: observability.krateo.io/v1alpha1\nkind: Alert\nmetadata: {name: x, namespace: krateo-system}\n" +
	"spec: {interval: 15m, threshold: 1, thresholdType: above, where: \"Body LIKE '%x%'\"}\n"

var obs = py.O("Alert", py.O("repo", "krateo-platformops/observability", "pathPrefix", "charts/krateo-observability/templates"))

type driven struct {
	api   *fake.API
	asked []askCall
	heads []head
	logs  *bytes.Buffer
}

type askCall struct{ Scope, Message string }

type head struct {
	url  string
	auth string
}

// connect makes Connect hand out the fake apiserver.
func connect(t *testing.T, api kube.CustomObjects, core kube.ConfigMaps) {
	set(t, &Connect, func() (*Clients, error) { return &Clients{API: api, Core: core}, nil })
}

// drive runs Main on every rich path, returning the fake apiserver and what the run sent out.
func drive(t *testing.T, askFails bool, extra ...map[string]any) *driven {
	t.Helper()
	busy := map[string]any{"metadata": map[string]any{"namespace": "krateo-system", "name": "busy",
		"annotations": map[string]any{"krateo.io/prompt-repo": "krateo-agentiko/busy-agent"}},
		"spec": map[string]any{"type": "Declarative", "declarative": map[string]any{
			"systemMessage":  "{{include \"prompts/busy\"}}\nBe brief.",
			"promptTemplate": map[string]any{"dataSources": []any{map[string]any{"alias": "prompts", "kind": "ConfigMap", "name": "busy-prompts"}}}}}}
	api := fake.NewAPI(stored("p-old", "snowplow/sar-unauthorized", "rr-older"), stored("p-legacy", "", "rr-old"))
	api.Alerts = []any{map[string]any{"metadata": map[string]any{"name": "a"}, "spec": map[string]any{"displayName": "A", "threshold": int64(1)}}}
	api.Agents = []any{map[string]any{"metadata": map[string]any{"namespace": "krateo-system", "name": "never-used"}}, busy}
	api.Flexes = []any{map[string]any{"metadata": map[string]any{"name": "page-dashboard", "annotations": map[string]any{"krateo.io/nav-path": "/dashboard"}}},
		map[string]any{"metadata": map[string]any{"name": "dashboard-row-1"}}}
	// 2026-10-01's outage, read by the sync-stall check through discovery: two findings — and the day's
	// failures: Incidents, CompositionDefinitions and a failing composition.
	for k, v := range FX.Outage(24, 24, 19, 3, 60*24*365) {
		api.Cluster[k] = v
	}
	api.Cluster["incidents"], api.Cluster["compositiondefinitions"] = FX.Incidents(), FX.CDs()
	for k, v := range FX.Comps() {
		api.Cluster[k] = v
	}
	api.Configs = FX.SyncConfigs()
	set(t, &synchealth.Groups, any(FX.SyncGroups()))
	set(t, &synchealth.Discoverer, func(synchealth.PathGetter) synchealth.Discover {
		return func(_ context.Context, g string) ([]kube.Served, error) {
			if g == "composition.krateo.io" {
				return FX.CompServed, nil
			}
			return FX.SyncServed[g], nil
		}
	})
	connect(t, api, fake.ConfigMaps{"busy-prompts": {Name: "busy-prompts", Data: map[string]string{"busy": "You are busy. Always cite the tool you used."},
		Annotations: map[string]string{}}})
	set(t, &DryRun, false)

	// ClickHouse: a windowed query that answers, so stats carries `queries`; MaxChars tiny so every source
	// is truncated and records truncated/truncatedAtChars/droppedChars.
	t.Setenv("CLICKHOUSE_QUERIES", `{"errors": "SELECT 1 WHERE t BETWEEN '{from}' AND '{to}'"}`)
	set(t, &evidence.ClickhouseURL, "http://clickhouse.invalid")
	set(t, &evidence.MaxChars, 10)
	set(t, &evidence.Post, func(context.Context, string, int) (string, error) { return "[\"svc\", 5]\n[\"svc2\", 3]\n", nil })

	// kagent: one busy agent and one deployed-never-used, the questions read on its richest path, and the
	// analyse stage's two reads — busy has two conversations (one over the session cap), a tool result over
	// its cap, and an event too large to fetch.
	now := time.Now().UTC()
	q := `{"Author": "user", "Content": {"role": "user", "parts": [{"text": "why is my composition not ready?"}]}}`
	set(t, &analysis.MaxSessions, 1)
	set(t, &analysis.MaxToolResultChars, 50)
	busyID := "krateo_system__NS__busy"
	conn := &fake.Conn{Answer: func(sql string, _ map[string]any) ([][]any, error) {
		switch {
		case strings.Contains(sql, "AS delegated"):
			return [][]any{{busyID, int64(2), int64(5), int64(1)}, {"krateo_system__NS__gone", int64(1), int64(1), int64(0)}}, nil
		case strings.Contains(sql, "dense_rank"):
			return [][]any{{busyID, int64(1), "agent", int64(5), int64(1), q, int64(len(q))},
				{busyID, int64(1), "agent", int64(5), int64(2), `{"Author": "busy", "Content": {"parts": [{"functionResponse": ` +
					`{"name": "k8s_get", "response": {"result": "` + strings.Repeat("y", 400) + `"}}}]}}`, int64(500)},
				{busyID, int64(1), "agent", int64(5), int64(3), nil, int64(999999)},
				{busyID, int64(1), "agent", int64(5), int64(4), `{"Author": "busy", "Content": {"parts": [{"text": "It is not ready ` +
					`because its child failed."}]}}`, int64(90)}}, nil
		case strings.Contains(sql, "WITH q AS"):
			return [][]any{{"s1", busyID, q, int64(9)}, {"s1", busyID, "not json", int64(9)}}, nil
		case strings.Contains(sql, "AS user_authored"):
			return [][]any{{int64(20), int64(9), int64(2), int64(2)}}, nil
		}
		return [][]any{{busyID, int64(40), int64(4), int64(3), now}, {"krateo_system__NS__gone", int64(2), int64(0), int64(1), now.Add(-30 * 24 * time.Hour)}}, nil
	}}
	set(t, &pg.Connect, func(context.Context, pg.Params) (pg.Conn, error) { return conn, nil })
	set(t, &evidence.KagentDBUser, "u")
	set(t, &evidence.KagentDBPassword, "p")

	assessment := map[string]any{"summary": "busy mostly answers", "servedWell": "readiness questions",
		"failurePatterns": []any{map[string]any{"pattern": "skips the child", "category": "made-up-category", "conversations": []any{int64(1), int64(77)},
			"examples": []any{map[string]any{"conversation": int64(1), "excerpt": "its child failed"},
				map[string]any{"conversation": int64(1), "excerpt": "an invented quote here"}}}},
		"promptFindings": []any{map[string]any{"finding": "no rule to name the failing child", "promptExcerpt": "Always cite the tool you used",
			"evidence": "c1", "suggestedChange": "add: name the failing child", "conversations": []any{int64(1)}}},
		"recurringNeeds": []any{map[string]any{"need": "why is my composition not ready", "conversations": []any{int64(1)}}}}
	proposalsOut := []any{
		with(prop("Alert", "Snowplow/SAR Unauthorized", real, "krateo-platformops/snowplow", "x.yaml", "yaml"), "confidence", "high"),
		with(prop("Documentation", "kagent:agent never used", "# x", "krateo-platformops/does-not-exist", "x.yaml", "markdown"), "confidence", "low"),
		with(prop("Prompt", "busy/skips-the-child", "+ name it", "krateo-platformops/guessed", "prompts/busy.md", "diff"), "confidence", "medium"),
		with(prop("Widget", "portal/missing-page", "kind: Page", "krateo-platformops/portal-guess", "pages/p.yaml", "yaml"), "confidence", "low"),
	}
	for _, e := range extra {
		proposalsOut = append(proposalsOut, e)
	}
	payload := map[string]any{"summary": "one real finding and one aimed at a missing repo", "proposals": proposalsOut}
	d := &driven{api: api, logs: &bytes.Buffer{}}
	set(t, &autopilot.ServiceJWT, func(context.Context) string { return "" })
	set(t, &autopilot.Ask, func(_ context.Context, system, message, run, token, scope string, timeout int) (any, string, autopilot.Usage, error) {
		d.asked = append(d.asked, askCall{scope, message})
		if askFails && scope == "" {
			return nil, "", nil, py.Errorf("TimeoutError", "the reviewer did not answer")
		}
		if scope != "" {
			return fake.DeepCopy(assessment), "{}", autopilot.Usage{"inputTokens": int64(40), "outputTokens": int64(5), "totalTokens": int64(45)}, nil
		}
		return fake.DeepCopy(payload), "{}", autopilot.TokenUsage(map[string]any{"metadata": map[string]any{"kagent_usage_metadata": map[string]any{
			"promptTokenCount": int64(9), "candidatesTokenCount": int64(3), "totalTokenCount": int64(12)}}}), nil
	})
	set(t, &publish.PublishVersion, func(context.Context) (string, error) { return "v1-8-53", nil })
	// The chart's values.yaml destinations, as the CronJob would pass them. busy's prompt is configured in
	// a DIFFERENT repository from the one its Agent's annotation declares; kagent points at a repository
	// GitHub denies; `portal` is not configured at all.
	set(t, &targets.Destinations, any(obs))
	set(t, &targets.Components, any(py.O(
		"busy", py.O("repo", "krateo-agentiko/busy-agent", "prompt", py.O("repo", "krateo-agentiko/busy-prompts", "path", "helm/busy/files/prompts-eng.yaml")),
		"kagent", py.O("repo", "krateo-platformops/does-not-exist", "pathPrefix", "docs"))))
	set(t, &targets.Blueprints, py.NewOMap())
	set(t, &targets.HTTPClient, fake.Client(func(r *http.Request) (*http.Response, error) {
		d.heads = append(d.heads, head{r.URL.String(), r.Header.Get("Authorization")})
		if strings.Contains(r.URL.String(), "does-not-exist") {
			return fake.Response(r, 404, ""), nil
		}
		return fake.Response(r, 200, ""), nil
	}))
	set(t, &logging.Default, logging.New(d.logs))

	want := 0
	if askFails {
		want = 1
	}
	if code := Main(ctx); code != want {
		t.Fatalf("Main returned %d, want %d; logs:\n%s", code, want, d.logs)
	}
	return d
}

func crdSchema(t *testing.T, name string) any {
	doc := testutil.YAML(t, "helm/nightly-review-crds/templates/"+name)
	return py.GetPath(py.List(py.GetPath(doc, "spec", "versions"))[0], "schema", "openAPIV3Schema")
}

func runStatuses(a *fake.API) []map[string]any { return a.StatusesOf("reviewruns") }

func final(a *fake.API) map[string]any { s := runStatuses(a); return s[len(s)-1] }

func notes(t *testing.T, st map[string]any) string {
	for _, c := range py.List(st["conditions"]) {
		if py.Get(c, "type") == "ValidationNotes" {
			return py.Str(py.Get(c, "message"))
		}
	}
	t.Fatal("no ValidationNotes")
	return ""
}

func mainMessage(t *testing.T, d *driven) string {
	var out []string
	for _, a := range d.asked {
		if a.Scope == "" {
			out = append(out, a.Message)
		}
	}
	if len(out) != 1 {
		t.Fatalf("%d main asks", len(out))
	}
	return out[0]
}

func TestEveryReviewrunStatusTheServiceWritesIsDeclared(t *testing.T) {
	d := drive(t, false)
	schema := py.GetPath(crdSchema(t, "reviewrun.crd.yaml"), "properties", "status")
	writes := runStatuses(d.api)
	if len(writes) == 0 {
		t.Fatal("the run wrote no status at all")
	}
	f := py.Plain(final(d.api))
	ev := py.Get(f, "evidence")
	// The run exercised what it is meant to, or this test proves nothing.
	if !py.Truthy(py.GetPath(ev, "clickhouse", "queries")) || py.GetPath(ev, "clickhouse", "truncated") != true {
		t.Fatal(py.Get(ev, "clickhouse"))
	}
	ks := py.Get(ev, "kagent-sessions")
	if py.Get(ks, "questions") != int64(1) || py.GetPath(ks, "shapes", "unparseable") != int64(1) || py.Int(py.Get(ks, "droppedMessages")) <= 0 {
		t.Fatal(ks)
	}
	if py.GetPath(ev, "kubernetes", "returned") != int64(2) || py.GetPath(ev, "incidents", "ok") != true ||
		py.GetPath(ev, "incidents", "returned") != int64(4) || py.GetPath(ev, "compositions", "ok") != true ||
		py.GetPath(ev, "compositions", "failing") != int64(1) {
		t.Fatal(ev)
	}
	m := mainMessage(t, d)
	if strings.Index(m, `source="compositions"`) > strings.Index(m, `source="clickhouse"`) {
		t.Fatal("the day's failures must come first")
	}
	if !py.Truthy(py.Get(f, "summary")) || py.GetPath(f, "model", "inputTokens") != int64(9) {
		t.Fatal(f)
	}
	var names []string
	for _, s := range py.List(py.Get(f, "steps")) {
		names = append(names, py.Str(py.Get(s, "name")))
	}
	if !reflect.DeepEqual(names, []string{"gather", "analyse", "ask", "validate", "publish", "record"}) {
		t.Fatal(names)
	}
	aa := py.Get(ev, "agent-analysis")
	agents := py.List(py.Get(aa, "agents"))
	busy := agents[0]
	if len(agents) != 1 || py.Get(aa, "ok") != true || py.Get(aa, "returned") != int64(1) ||
		py.Get(py.List(py.Get(aa, "skipped"))[0], "reason") != "not deployed" || py.Int(py.Get(busy, "droppedChars")) <= 999999 ||
		py.Get(busy, "droppedSessions") != int64(1) || py.GetPath(busy, "tokens", "totalTokens") != int64(45) ||
		py.Get(busy, "promptRepo") != "krateo-agentiko/busy-agent" || py.Get(busy, "unverifiedExamples") != int64(1) {
		t.Fatal(aa)
	}
	a := py.List(py.GetPath(f, "agentAnalysis", "assessments"))[0]
	fp := py.List(py.Get(a, "failurePatterns"))[0]
	if py.Get(fp, "category") != "other" || py.Get(fp, "count") != int64(1) ||
		!py.Truthy(py.Get(py.List(py.Get(a, "promptFindings"))[0], "promptExcerpt")) || !py.Truthy(py.Get(a, "recurringNeeds")) {
		t.Fatal(a)
	}
	if testutil.Canon(py.GetPath(f, "usage", "total")) != testutil.Canon(map[string]any{"calls": int64(2), "reportedCalls": int64(2),
		"inputTokens": int64(49), "outputTokens": int64(8), "totalTokens": int64(57)}) {
		t.Fatal(py.GetPath(f, "usage", "total"))
	}
	if py.Get(ks, "questionsFolded") != int64(1) || py.GetPath(f, "proposals", "superseded") != int64(1) {
		t.Fatal(ks, py.Get(f, "proposals"))
	}
	for _, st := range writes {
		if u := testutil.Undeclared(st, schema, "status"); len(u) != 0 {
			t.Fatal(u)
		}
	}
}

func TestEveryProposalTheServiceWritesIsDeclared(t *testing.T) {
	d := drive(t, false)
	schema := py.Get(crdSchema(t, "proposal.crd.yaml"), "properties")
	created := d.api.CreatesOf("proposals")
	if len(created) != 6 {
		t.Fatal("four from the model, two from the sync-stall check:", len(created))
	}
	var agents []string
	for _, b := range created {
		agents = append(agents, py.Str(py.GetPath(b, "spec", "producedBy", "agent")))
		if u := testutil.Undeclared(b["spec"], py.Get(schema, "spec"), "spec"); len(u) != 0 {
			t.Fatal(u)
		}
	}
	sort.Strings(agents)
	if !reflect.DeepEqual(agents, []string{"krateo-autopilot", "krateo-autopilot", "krateo-autopilot", "krateo-autopilot",
		"nightly-review/sync-stall", "nightly-review/sync-stall"}) {
		t.Fatal(agents)
	}
	superseded, resolved := false, false
	for _, st := range d.api.StatusesOf("proposals") {
		superseded = superseded || py.Truthy(st["supersededBy"])
		for _, c := range py.List(st["conditions"]) {
			resolved = resolved || py.Get(c, "type") == "TargetResolved"
		}
		if u := testutil.Undeclared(st, py.Get(schema, "status"), "status"); len(u) != 0 {
			t.Fatal(u)
		}
	}
	if !superseded || !resolved {
		t.Fatal(superseded, resolved)
	}
}

func TestTheLegacySubjectlessProposalSurvivesARunUntouched(t *testing.T) {
	d := drive(t, false)
	if st, ok := d.api.Proposals["p-legacy"]["status"].(map[string]any); ok && st["phase"] != "Proposed" {
		t.Fatal(st)
	}
}

func createdBy(d *driven, kind string) []map[string]any {
	var out []map[string]any
	for _, b := range d.api.CreatesOf("proposals") {
		if py.GetPath(b, "spec", "kind") == kind {
			out = append(out, b)
		}
	}
	return out
}

func targetCond(t *testing.T, d *driven, b map[string]any) map[string]any {
	st := d.api.Proposals[py.Str(py.GetPath(b, "metadata", "name"))]["status"]
	for _, c := range py.List(py.Get(st, "conditions")) {
		if py.Get(c, "type") == "TargetResolved" {
			return c.(map[string]any)
		}
	}
	t.Fatal("no TargetResolved")
	return nil
}

func TestAMissingRepoIsRecordedAndWrittenButGetsNoClaim(t *testing.T) {
	d := drive(t, false)
	c := targetCond(t, d, createdBy(d, "Documentation")[0])
	if c["status"] != "False" || c["reason"] != "NotFoundOrPrivate" {
		t.Fatal(c)
	}
	var repos []string
	for _, b := range d.api.CreatesOf("builderpublishes") {
		repos = append(repos, py.Str(py.GetPath(b, "spec", "target", "repo")))
	}
	if !reflect.DeepEqual(repos, []string{"observability", "busy-prompts"}) {
		t.Fatal(repos)
	}
}

func TestAPromptProposalGoesWhereTheValuesSayNotWhereTheAgentDeclares(t *testing.T) {
	d := drive(t, false)
	p := createdBy(d, "Prompt")
	if len(p) != 1 || testutil.Canon(py.GetPath(p[0], "spec", "target")) !=
		`{"path": "helm/busy/files/prompts-eng.yaml", "repo": "krateo-agentiko/busy-prompts"}` {
		t.Fatal(p)
	}
}

func TestAProposalWithNoDestinationIsWrittenWithoutARepoAndNeverPublished(t *testing.T) {
	d := drive(t, false)
	w := createdBy(d, "Widget")[0]
	if testutil.Canon(py.GetPath(w, "spec", "target")) != `{"path": "p.yaml", "repo": ""}` ||
		py.GetPath(w, "spec", "fingerprint") != P.MustFingerprint(py.Get(w, "spec")) {
		t.Fatal(w)
	}
	c := targetCond(t, d, w)
	if c["status"] != "False" || c["reason"] != "NoDestination" ||
		c["message"] != "no destination configured for component portal; add it to config.destinations" {
		t.Fatal(c)
	}
	for _, b := range d.api.CreatesOf("builderpublishes") {
		repo := py.Str(py.GetPath(b, "spec", "target", "repo"))
		if strings.Contains(repo, "portal-guess") || repo == "" {
			t.Fatal(repo)
		}
	}
	for _, h := range d.heads {
		if strings.Count(strings.SplitN(strings.TrimRight(h.url, "/"), "/repos/", 2)[1], "/") != 1 {
			t.Fatal("an empty repository must never reach the existence check:", h.url)
		}
	}
	if !strings.Contains(notes(t, final(d.api)), "Widget proposal krateo-platformops/portal-guess/pages/p.yaml cleared: no destination configured "+
		"for component portal") {
		t.Fatal(notes(t, final(d.api)))
	}
}

func TestTheMainReviewGetsTheAssessmentAndNotTheTranscript(t *testing.T) {
	d := drive(t, false)
	var analyse []string
	for _, a := range d.asked {
		if a.Scope != "" {
			analyse = append(analyse, a.Message)
		}
	}
	m := mainMessage(t, d)
	if len(analyse) != 1 || !strings.Contains(analyse[0], "It is not ready because its child failed.") || !strings.Contains(analyse[0], "yyyyyyyyyy") {
		t.Fatal(analyse)
	}
	if !strings.Contains(m, `source="agent-analysis"`) || !strings.Contains(m, "FAILURE [other] in 1 conversation(s)") ||
		strings.Contains(strings.ReplaceAll(m, `"its child failed"`, ""), "because its child failed") || strings.Contains(m, "yyyyyyyyyy") {
		t.Fatal("only the verified excerpt may reach the main review")
	}
	if !strings.Contains(strings.Split(m, "DATA REGION")[0], "use the spelling listed: busy, kagent") {
		t.Fatal("the configured components must reach the model")
	}
}

// A cheap static belt under the run above: a key added on a path the fake run does not reach is still
// caught if it is assigned the usual way.
func TestEveryStatsKeyEvidenceAssignsBySubscriptIsDeclared(t *testing.T) {
	declared := py.GetPath(crdSchema(t, "reviewrun.crd.yaml"), "properties", "status", "properties", "evidence", "additionalProperties", "properties")
	src := testutil.Read(t, "internal/evidence/evidence.go")
	written := regexp.MustCompile(`stats\["(\w+)"\]\s*=`).FindAllStringSubmatch(src, -1)
	if len(written) == 0 {
		t.Fatal("no stats keys found, so this proves nothing")
	}
	for _, w := range written {
		if !py.Has(declared, w[1]) {
			t.Error(w[1])
		}
	}
}

func TestARetargetedProposalIsNamedByItsNewTarget(t *testing.T) {
	d := drive(t, false)
	for _, b := range d.api.CreatesOf("proposals") {
		spec := py.Plain(b["spec"]).(map[string]any)
		if spec["fingerprint"] != P.MustFingerprint(spec) || py.GetPath(b, "metadata", "name") != publish.ProposalName(spec) {
			t.Fatal(spec["kind"])
		}
	}
	a := createdBy(d, "Alert")[0]
	if testutil.Canon(py.GetPath(a, "spec", "target")) !=
		`{"path": "charts/krateo-observability/templates/x.yaml", "repo": "krateo-platformops/observability"}` {
		t.Fatal(py.GetPath(a, "spec", "target"))
	}
	if !strings.Contains(notes(t, final(d.api)), "Alert proposal retargeted krateo-platformops/snowplow/x.yaml -> krateo-platformops/observability/"+
		"charts/krateo-observability/templates/x.yaml (config.targets.Alert)") {
		t.Fatal(notes(t, final(d.api)))
	}
}

func TestTheRunStatesItsCoverageInTheSummaryAndToTheModel(t *testing.T) {
	d := drive(t, false)
	f := py.Plain(final(d.api))
	cov := py.Get(f, "coverage")
	if py.Get(cov, "complete") != false || py.Get(cov, "conversationsRead") != int64(1) || py.Get(cov, "conversationsTotal") != int64(2) ||
		!(py.Int(py.Get(cov, "charsRead")) > 0 && py.Int(py.Get(cov, "charsRead")) < py.Int(py.Get(cov, "charsTotal"))) ||
		py.Get(cov, "charsTotalIsLowerBound") != true {
		t.Fatal(cov)
	}
	srcs := map[string]bool{}
	for _, c := range py.List(py.Get(cov, "sourcesCut")) {
		srcs[py.Str(py.Get(c, "source"))] = true
	}
	sentence := py.Str(py.Get(cov, "sentence"))
	m := mainMessage(t, d)
	if !srcs["clickhouse"] || !srcs["kagent-sessions"] || !strings.HasPrefix(py.Str(py.Get(f, "summary")), sentence+" one real finding") ||
		!strings.Contains(sentence, "Based on 1 of 2 agent conversations") || !strings.Contains(strings.Split(m, "DATA REGION")[0], sentence) ||
		!strings.Contains(m, "busy: 1 conversation(s) of 2 in the window analysed") {
		t.Fatal(sentence, srcs)
	}
}

// FAKE_TOKEN is deliberately NOT secret-shaped: redaction must not be what hides it.
const fakeToken = "tok-nightly-FAKE-0c9d2b7e"

func TestTheCheckTokenReachesNothingButTheCheck(t *testing.T) {
	t.Setenv(targets.TokenEnv, fakeToken)
	d := drive(t, false)
	if len(d.heads) == 0 {
		t.Fatal("the token must be on the existence check's HEAD, or this proves nothing")
	}
	for _, h := range d.heads {
		if h.auth != "Bearer "+fakeToken {
			t.Fatal(h)
		}
	}
	written, _ := json.Marshal(map[string]any{"creates": d.api.Creates, "status": d.api.StatusWrites, "patches": d.api.SpecPatches,
		"stored": d.api.Proposals})
	asked, _ := json.Marshal(d.asked)
	if strings.Contains(string(written), fakeToken) || strings.Contains(string(asked), fakeToken) || strings.Contains(d.logs.String(), fakeToken) {
		t.Fatal("the token leaked")
	}
	// Mutation guard on the guard: the serialisations above did capture the run.
	if !strings.Contains(string(written), "krateo-platformops/observability") || !strings.Contains(string(asked), "agent-analysis") {
		t.Fatal("the serialisations captured nothing")
	}
}

// --- the sync-stall check inside a whole run -------------------------------------------------------

func TestTheSyncStallFindingsAreRecordedAndToldToTheModel(t *testing.T) {
	d := drive(t, false)
	sh := py.GetPath(py.Plain(final(d.api)), "evidence", "sync-health")
	if py.Get(sh, "ok") != true || py.Get(sh, "stalled") != int64(70) || py.Get(sh, "findings") != int64(2) || py.Get(sh, "thresholdMinutes") != int64(15) {
		t.Fatal(sh)
	}
	m := mainMessage(t, d)
	if !strings.Contains(m, `source="sync-health"`) || !strings.Contains(m, "subject git-provider/credential-rejected") {
		t.Fatal("not told")
	}
	subjects := map[string]bool{}
	for _, b := range d.api.CreatesOf("proposals") {
		subjects[py.Str(py.GetPath(b, "spec", "subject"))] = true
	}
	if !subjects["git-provider/credential-rejected"] || !subjects["github-provider-kog/credential-rejected"] {
		t.Fatal(subjects)
	}
}

func TestTheSyncStallFindingsAreWrittenEvenWhenTheModelDoesNotAnswer(t *testing.T) {
	d := drive(t, true)
	f := py.Plain(final(d.api))
	if py.Get(f, "phase") != "Failed" || py.GetPath(f, "proposals", "created") != int64(2) {
		t.Fatal(f)
	}
	var record any
	for _, s := range py.List(py.Get(f, "steps")) {
		if py.Get(s, "name") == "record" {
			record = s
		}
	}
	if py.Get(record, "phase") != "Succeeded" || !strings.Contains(py.Str(py.Get(record, "message")), "sync-stall findings only") {
		t.Fatal(record)
	}
	for _, b := range d.api.CreatesOf("proposals") {
		if py.GetPath(b, "spec", "producedBy", "agent") != "nightly-review/sync-stall" {
			t.Fatal(b)
		}
	}
	if len(d.api.CreatesOf("builderpublishes")) != 0 {
		t.Fatal("never published from here")
	}
	schema := py.GetPath(crdSchema(t, "reviewrun.crd.yaml"), "properties", "status")
	for _, st := range runStatuses(d.api) {
		if u := testutil.Undeclared(st, schema, "status"); len(u) != 0 {
			t.Fatal(u)
		}
	}
}

func TestAModelProposalAboutAServiceSubjectIsDropped(t *testing.T) {
	dup := with(prop("Documentation", "Git-Provider/credential rejected", "# token expired", "x/y", "x.yaml", "markdown"), "confidence", "medium")
	d := drive(t, false, dup)
	created := d.api.CreatesOf("proposals")
	if len(created) != 6 {
		t.Fatal("the four model proposals and the two service ones; not the duplicate:", len(created))
	}
	for _, b := range created {
		if py.GetPath(b, "spec", "subject") == "git-provider/credential-rejected" && py.GetPath(b, "spec", "producedBy", "agent") != "nightly-review/sync-stall" {
			t.Fatal(b)
		}
	}
	if !strings.Contains(notes(t, final(d.api)), "DROPPED model Documentation proposal about git-provider/credential-rejected: the sync-stall "+
		"check already proposed that subject this run") {
		t.Fatal(notes(t, final(d.api)))
	}
}

// --- the service boundary on the sync-stall findings (test_sync_stall.py) ---------------------------

func gatherOutage(t *testing.T, lists map[string][]any) []map[string]any {
	a := fake.NewAPI()
	a.Cluster, a.Configs = lists, FX.SyncConfigs()
	_, _, props := synchealth.Gather(ctx, a, func(_ context.Context, g string) ([]kube.Served, error) { return FX.SyncServed[g], nil },
		FX.SyncNow, FX.SyncGroups(), 15)
	return props
}

func TestACredentialQuotedInAControllerMessageIsRedactedEverywhere(t *testing.T) {
	leak := "ghp_" + strings.Repeat("A", 36)
	msg := "401 Unauthorized: request with Authorization: Bearer " + leak + " token=" + strings.Repeat("z", 20) + " rejected"
	a := fake.NewAPI()
	a.Cluster = map[string][]any{"repoes": {FX.Obj("x", FX.Err(msg, 600), nil, nil, "krateo-system")}}
	body, _, props := synchealth.Gather(ctx, a, func(_ context.Context, g string) ([]kube.Served, error) { return FX.SyncServed[g], nil },
		FX.SyncNow, FX.SyncGroups(), 15)
	kept, _, err := serviceFindings(props)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(kept)
	all := string(blob) + body
	if strings.Contains(all, leak) || strings.Contains(all, strings.Repeat("z", 20)) || !strings.Contains(all, "<REDACTED") {
		t.Fatal(all)
	}
}

func TestEveryFindingPassesTheModelsOwnContractAndLandsWhereTheValuesSay(t *testing.T) {
	set(t, &targets.Components, any(py.O("git-provider", py.O("repo", "o/git-provider", "pathPrefix", "docs"))))
	props := gatherOutage(t, FX.DefaultOutage())
	for _, p := range props {
		if err := jsonschema.Validate(p, prompt.ItemSchema); err != nil {
			t.Fatal(err)
		}
	}
	kept, _, err := serviceFindings(props)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]map[string]any{}
	for _, p := range kept {
		by[py.Str(p["subject"])] = p
		if p["fingerprint"] != P.MustFingerprint(p) {
			t.Fatal(p)
		}
	}
	if testutil.Canon(by["git-provider/credential-rejected"]["target"]) != `{"path": "docs/git-provider-credential-rejected.md", "repo": "o/git-provider"}` ||
		py.GetPath(by["github-provider-kog/credential-rejected"], "target", "repo") != "" {
		t.Fatal(by)
	}
}

func TestAServiceFindingIsAimedWithoutARetargetNoteEveryNight(t *testing.T) {
	set(t, &targets.Components, any(py.O("git-provider", py.O("repo", "o/git-provider", "pathPrefix", "docs"))))
	props := gatherOutage(t, FX.DefaultOutage())
	for _, p := range props {
		if py.GetPath(p, "target", "repo") != "" {
			t.Fatal(p["target"])
		}
	}
	_, ns, err := serviceFindings(props)
	if err != nil {
		t.Fatal(err)
	}
	var cleared []string
	for _, n := range ns {
		if strings.Contains(n, "retargeted") {
			t.Fatal(n)
		}
		if strings.Contains(n, "cleared") {
			cleared = append(cleared, n)
		}
	}
	if !reflect.DeepEqual(cleared, []string{"Documentation proposal github-provider-kog-credential-rejected.md cleared: no destination configured " +
		"for component github-provider-kog; add it to config.destinations"}) {
		t.Fatal(cleared)
	}
}

// --- spec.decision through a run (test_spec_decision.py) -------------------------------------------

func TestARunMirrorsFirstAndLeavesARejectedRepeatAlone(t *testing.T) {
	p := with(prop("Alert", "snowplow/sar-unauthorized", "a: 1\n", "krateo-platformops/snowplow", "x.yaml", "yaml"), "confidence", "high")
	rejected := stored("p-dec", "snowplow/sar-unauthorized", "rr-old")
	rejected["spec"].(map[string]any)["decision"] = map[string]any{"phase": "Rejected", "reason": "no", "decidedBy": "admin",
		"decidedAt": "2026-09-28T10:00:00Z"}
	rejected["spec"].(map[string]any)["fingerprint"] = P.MustFingerprint(p)
	api := fake.NewAPI(rejected)
	api.LabelPatches = true
	connect(t, api, fake.ConfigMaps{})
	set(t, &DryRun, true)
	ok := func() map[string]any { return map[string]any{"ok": true, "queried": int64(1), "returned": int64(1)} }
	set(t, &clickhouse, func(context.Context, *py.OMap, prompt.Window) (string, map[string]any) { return "evidence", ok() })
	set(t, &kagentSessions, func(context.Context, kube.CustomObjects, prompt.Window, int) (*evidence.SessionsBody, map[string]any) {
		return &evidence.SessionsBody{Text: "evidence"}, ok()
	})
	set(t, &kubernetes, func(context.Context, kube.CustomObjects) (string, map[string]any) { return "evidence", ok() })
	set(t, &autopilot.ServiceJWT, func(context.Context) string { return "" })
	set(t, &autopilot.Ask, func(context.Context, string, string, string, string, string, int) (any, string, autopilot.Usage, error) {
		return map[string]any{"summary": "s", "proposals": []any{fake.DeepCopy(p)}}, "{}", autopilot.Usage{}, nil
	})
	set(t, &targets.Resolve, func(context.Context, string, map[string]targets.Condition) targets.Condition {
		return targets.Condition{"type": "TargetResolved", "status": "True", "reason": "RepoFound"}
	})
	// The values put snowplow where the proposal already points, so aiming leaves its fingerprint alone.
	set(t, &targets.Components, any(py.O("snowplow", py.O("repo", "krateo-platformops/snowplow"))))
	set(t, &logging.Default, logging.New(&bytes.Buffer{}))
	if code := Main(ctx); code != 0 {
		t.Fatal(code)
	}
	if len(api.CreatesOf("proposals")) != 0 || api.Proposals["p-dec"]["status"].(map[string]any)["phase"] != "Rejected" {
		t.Fatal(api.CreatesOf("proposals"), api.Proposals["p-dec"]["status"])
	}
	for _, w := range api.SpecPatches {
		if w.Plural == "proposals" && w.Name == "p-dec" {
			t.Fatal("the rejected object's spec was re-asserted")
		}
	}
	f := final(api)
	props := f["proposals"].(map[string]any)
	if props["created"] != int64(0) || props["deduplicated"] != int64(0) {
		t.Fatal(props)
	}
	for _, s := range py.List(f["steps"]) {
		if py.Get(s, "name") == "validate" && !strings.Contains(py.Str(py.Get(s, "message")), "1 already decided") {
			t.Fatal(s)
		}
	}
}

// --- a manual run beside the scheduled one (test_failures.py) ---------------------------------------

func TestAManualRunIsNamedFromItsStartAndASameMinuteClashTakesTheSeconds(t *testing.T) {
	set(t, &JobName, "nightly-review-manual-x7k2p")
	api := fake.NewAPI()
	api.Taken["rr-20261005-1037"] = true
	start := time.Date(2026, 10, 5, 10, 37, 12, 0, time.UTC)
	window := map[string]any{"from": "a", "to": "b"}
	name, err := createRun(ctx, api, start, window)
	if err != nil || name != "rr-20261005-103712" {
		t.Fatal(name, err)
	}
	if !reflect.DeepEqual(py.GetPath(api.CreatesOf("reviewruns")[0], "metadata", "labels"), map[string]any{"review.krateo.io/job": "nightly-review-manual-x7k2p"}) {
		t.Fatal(api.CreatesOf("reviewruns")[0])
	}
	if name, _ := createRun(ctx, fake.NewAPI(), start, window); name != "rr-20261005-1037" {
		t.Fatal(name)
	}
}

func TestARunStartedWhileAnotherIsRunningRecordsItselfAsNotRun(t *testing.T) {
	now := FX.FailNow
	running := map[string]any{"metadata": map[string]any{"name": "rr-20261005-0200"},
		"status": map[string]any{"phase": "Running", "startedAt": py.Isoformat(now.Add(-20 * time.Minute))}}
	stale := map[string]any{"metadata": map[string]any{"name": "rr-20261001-0200"},
		"status": map[string]any{"phase": "Running", "startedAt": py.Isoformat(now.Add(-4 * 24 * time.Hour))}}
	api := fake.NewAPI()
	api.Runs = []any{stale}
	if runInProgress(ctx, api, now) != "" {
		t.Fatal("killed past its handler: not in progress")
	}
	api.Runs = []any{running, stale}
	set(t, &Now, func() time.Time { return now })
	connect(t, api, nil)
	asked := 0
	set(t, &autopilot.Ask, func(context.Context, string, string, string, string, string, int) (any, string, autopilot.Usage, error) {
		asked++
		return nil, "", nil, errors.New("no")
	})
	set(t, &logging.Default, logging.New(&bytes.Buffer{}))
	if Main(ctx) != 0 || asked != 0 {
		t.Fatal("nothing was reviewed")
	}
	st := runStatuses(api)
	if len(st) != 1 || api.StatusWrites[0].Name != "rr-20261005-0900" || st[0]["phase"] != "Failed" ||
		!strings.Contains(st[0]["error"].(string), "rr-20261005-0200 was still running") {
		t.Fatal(api.StatusWrites)
	}
}

// --- SIGTERM (test_terminate.py) ---------------------------------------------------------------------

func TestSigtermRecordsTheRunAndItsRunningStepAsFailed(t *testing.T) {
	api := fake.NewAPI()
	r := &run{api: api, name: "rr-x", ev: py.NewOMap(), st: map[string]any{"phase": "Running", "steps": []any{
		map[string]any{"name": "gather", "phase": "Succeeded"},
		map[string]any{"name": "analyse", "phase": "Running", "startedAt": "2026-09-30T02:00:00+00:00"}}}}
	code := -1
	set(t, &Exit, func(c int) { code = c })
	set(t, &logging.Default, logging.New(&bytes.Buffer{}))
	terminate(ctx, r, syscall.SIGTERM)
	if code != 143 || len(api.StatusWrites) != 1 || api.StatusWrites[0].Name != "rr-x" {
		t.Fatal(code, api.StatusWrites)
	}
	st := api.StatusWrites[0].Body["status"].(map[string]any)
	var phases []string
	for _, s := range st["steps"].([]any) {
		phases = append(phases, s.(map[string]any)["phase"].(string))
	}
	if st["phase"] != "Failed" || !strings.Contains(st["error"].(string), "activeDeadlineSeconds") ||
		!reflect.DeepEqual(phases, []string{"Succeeded", "Failed"}) || !py.Truthy(st["finishedAt"]) {
		t.Fatal(st)
	}
}

// The handler is wired to the process's SIGTERM, not only callable.
func TestTheHandlerIsInstalledForSigterm(t *testing.T) {
	api := fake.NewAPI()
	r := &run{api: api, name: "rr-y", ev: py.NewOMap(), st: map[string]any{"phase": "Running", "steps": []any{}}}
	done := make(chan int, 1)
	set(t, &Exit, func(c int) { done <- c })
	set(t, &logging.Default, logging.New(&bytes.Buffer{}))
	stop := onTerminate(ctx, r)
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-done:
		if c != 143 {
			t.Fatal(c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not run")
	}
}

// One proposal whose YAML the parser cannot construct used to fail the whole night: the run was recorded
// Failed and every other proposal was lost. Now the run completes, the bad one is named in the run's
// notes, and the rest — the model's four and the sync-stall check's two — are written as before.
func TestOneUnreadableProposalIsSkippedAndTheNightCompletes(t *testing.T) {
	bad := with(prop("Policy", "gateway/bad-date", "a: 2020-13-45\n", "x/y", "policy.yaml", "yaml"), "confidence", "low")
	d := drive(t, false, bad)
	f := final(d.api)
	if f["phase"] == "Failed" {
		t.Fatalf("the run failed: %v", f["error"])
	}
	created := d.api.CreatesOf("proposals")
	if len(created) != 6 {
		t.Fatal("the model's four and the sync-stall check's two, without the unreadable one:", len(created))
	}
	for _, b := range created {
		if py.GetPath(b, "spec", "subject") == "gateway/bad-date" {
			t.Fatal("the unreadable proposal was written")
		}
	}
	n := notes(t, f)
	if !strings.Contains(n, "DROPPED proposal[4] (Policy): its change.content could not be read as yaml (ValueError: ") {
		t.Fatal(n)
	}
	for _, s := range py.List(f["steps"]) {
		if py.Get(s, "name") == "validate" && (py.Get(s, "phase") != "Succeeded" || !strings.Contains(py.Str(py.Get(s, "message")), "4 valid")) {
			t.Fatal(s)
		}
	}
}
