package synchealth_test

// The sync-stall check: which conditions count, how they group, what reaches a Proposal, and that a
// Secret is named and never read (tests/test_sync_stall.py; the cases that go through the service
// boundary are in package review). The fixtures are shaped like 2026-10-01 on 057.

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/nightly-review/internal/fake"
	F "github.com/krateo-platformops/nightly-review/internal/fixtures"
	"github.com/krateo-platformops/nightly-review/internal/jsonschema"
	"github.com/krateo-platformops/nightly-review/internal/kube"
	"github.com/krateo-platformops/nightly-review/internal/prompt"
	P "github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/py"
	S "github.com/krateo-platformops/nightly-review/internal/synchealth"
)

var ctx = context.Background()

func discover(_ context.Context, g string) ([]kube.Served, error) { return F.SyncServed[g], nil }

func api(lists map[string][]any, configs map[[2]string]map[string]any, fail ...string) *fake.API {
	a := fake.NewAPI()
	a.Cluster = lists
	if configs != nil {
		a.Configs = configs
	}
	for _, f := range fail {
		a.Fail[f] = fmt.Errorf("403 forbidden: %s", f)
	}
	return a
}

type result struct {
	api   *fake.API
	body  string
	stats map[string]any
	props []map[string]any
}

func run(lists map[string][]any, groups any, threshold int, configs map[[2]string]map[string]any, fail ...string) result {
	if configs == nil {
		configs = F.SyncConfigs()
	}
	if groups == nil {
		groups = F.SyncGroups()
	}
	a := api(lists, configs, fail...)
	body, stats, props := S.Gather(ctx, a, discover, F.SyncNow, groups, threshold)
	return result{a, body, stats, props}
}

func bySubject(props []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, p := range props {
		out[p["subject"].(string)] = p
	}
	return out
}

func lists(objs ...map[string]any) []any {
	out := make([]any, len(objs))
	for i, o := range objs {
		out[i] = o
	}
	return out
}

func obj(name string, synced, ready *F.Cond) map[string]any {
	return F.Obj(name, synced, ready, nil, "krateo-system")
}

// --- which conditions count ---------------------------------------------------------------------

func TestSustainedFailuresAreGroupedByComponentAndPattern(t *testing.T) {
	r := run(F.DefaultOutage(), nil, 15, nil)
	if r.stats["ok"] != true || r.stats["stalled"] != int64(70) || r.stats["findings"] != int64(2) || r.stats["freshFailures"] != int64(0) {
		t.Fatal(r.stats)
	}
	by := bySubject(r.props)
	kog := by["github-provider-kog/credential-rejected"]
	ev := kog["evidence"].([]any)[0].(map[string]any)
	title := kog["title"].(string)
	if len(by) != 2 || ev["observedCount"] != int64(48) || !strings.Contains(title, "Repository x24") ||
		!strings.Contains(title, "PullRequest x24") || !strings.Contains(title, "credential rejected") {
		t.Fatal(kog)
	}
	if by["git-provider/credential-rejected"]["evidence"].([]any)[0].(map[string]any)["observedCount"] != int64(22) {
		t.Fatal(by["git-provider/credential-rejected"])
	}
	if !strings.Contains(r.body, "48x credential rejected") || !strings.Contains(r.body, "22x credential rejected") {
		t.Fatal(r.body)
	}
}

func TestAFreshFailureUnderTheThresholdIsCountedNotReported(t *testing.T) {
	r := run(map[string][]any{"repositories": lists(obj("a", F.Err(F.Msg401(1), 5), nil))}, nil, 15, nil)
	if len(r.props) != 0 || r.stats["stalled"] != int64(0) || r.stats["freshFailures"] != int64(1) ||
		!strings.Contains(r.body, "failing for less than 15m") || !strings.Contains(r.body, "Repository.github.krateo.io x1") {
		t.Fatal(r.stats, r.body)
	}
}

func TestReadyStaleButSyncedTrueIsNeverReported(t *testing.T) {
	r := run(map[string][]any{"repoes": lists(
		obj("old-ready", &F.Cond{Status: "True", Reason: "ReconcileSuccess", Message: "", Ago: 5}, &F.Cond{Status: "True", Reason: "Available", Message: "", Ago: 60 * 24 * 14}),
		obj("contradictory", &F.Cond{Status: "True", Reason: "ReconcileSuccess", Message: "", Ago: 5}, F.Err("401 Unauthorized", 600)))}, nil, 15, nil)
	if len(r.props) != 0 || r.stats["stalled"] != int64(0) || r.stats["freshFailures"] != int64(0) || r.body != "" ||
		r.stats["returned"] != int64(2) {
		t.Fatal(r.stats)
	}
}

func TestReadyFalseCountsOnlyForAReconcileErrorAndOnlyWithoutASyncedVerdict(t *testing.T) {
	r := run(map[string][]any{"repoes": lists(obj("no-synced-err", nil, F.Err("401 Unauthorized", 600)),
		obj("creating", nil, &F.Cond{Status: "False", Reason: "Creating", Message: "", Ago: 600}), obj("deleting", nil, &F.Cond{Status: "False", Reason: "Deleting", Message: "", Ago: 600}))}, nil, 15, nil)
	if r.stats["stalled"] != int64(1) || len(r.props) != 1 || r.props[0]["subject"] != "git-provider/credential-rejected" {
		t.Fatal(r.stats, r.props)
	}
}

func TestAPausedReconcileIsIntentNotAStall(t *testing.T) {
	r := run(map[string][]any{"repoes": lists(obj("p", &F.Cond{Status: "False", Reason: "ReconcilePaused", Message: "", Ago: 600}, nil))}, nil, 15, nil)
	if len(r.props) != 0 || r.stats["stalled"] != int64(0) {
		t.Fatal(r.stats)
	}
}

func TestAConditionWithoutATransitionTimeIsNotCalledSustained(t *testing.T) {
	o := obj("x", F.Err("401 Unauthorized", 300), nil)
	delete(o["status"].(map[string]any)["conditions"].([]any)[0].(map[string]any), "lastTransitionTime")
	r := run(map[string][]any{"repoes": lists(o)}, nil, 15, nil)
	if len(r.props) != 0 || r.stats["freshFailures"] != int64(1) {
		t.Fatal(r.stats)
	}
}

// --- patterns -----------------------------------------------------------------------------------

func signal(msg string) string { s, _ := S.Classify("ReconcileError", msg); return s }

func TestAMessageIsReadForWhatWentWrong(t *testing.T) {
	for msg, want := range map[string]string{
		"GET https://api.github.com/repos/o/r: 401 Unauthorized":                                        "credential-rejected",
		"authentication required: Invalid username or token":                                            "credential-rejected",
		"401 Unauthorized: repository not found":                                                        "credential-rejected",
		"403 Forbidden: Resource not accessible by personal access token":                               "permission-denied",
		"repository not found":                                                                          "remote-not-found",
		"GET .../repos/o/r: 404 Not Found":                                                              "remote-not-found",
		"API rate limit exceeded for user":                                                              "rate-limited",
		`Get "https://github.com/o/r.git/info/refs?service=git-upload-pack": context deadline exceeded`: "remote-unreachable",
		"422 Unprocessable Entity: No commits between main and b":                                       "remote-rejected-request",
	} {
		if got := signal(msg); got != want {
			t.Errorf("%q -> %q, want %q", msg, got, want)
		}
	}
}

func TestAnUnknownMessageIsNamedByItsFirstClauseWithoutItsParticulars(t *testing.T) {
	a := signal("failed to download file: creating destination file: open /tmp/rest-dynamic-controller/pullrequest.yaml: no such file")
	b := signal("failed to download file: open /tmp/x/repository.yaml: 2 errors")
	if a != b || a != "failed-to-download-file" {
		t.Fatal(a, b)
	}
}

// --- secrets are named, never read --------------------------------------------------------------

func TestTheSecretIsNamedFromSpecRefsAndConfigurationsAndNeverRead(t *testing.T) {
	r := run(F.DefaultOutage(), nil, 15, nil)
	for _, p := range r.props {
		if !strings.Contains(p["change"].(map[string]any)["content"].(string), "krateo-system/git-provider-credentials") ||
			!strings.Contains(p["rationale"].(string), "krateo-system/git-provider-credentials") {
			t.Fatal(p)
		}
	}
	if !strings.Contains(bySubject(r.props)["github-provider-kog/credential-rejected"]["change"].(map[string]any)["content"].(string),
		"RepositoryConfiguration krateo-system/github-blueprints-config") {
		t.Fatal("configuration not named")
	}
	// One read per Configuration per run, and only of the provider's own kinds — never a Secret.
	var gets []string
	for _, rd := range r.api.Reads {
		if strings.HasPrefix(rd, "get ") {
			gets = append(gets, strings.Fields(rd)[1])
		}
		if strings.Contains(rd, "secret") {
			t.Fatal(rd)
		}
	}
	if !reflect.DeepEqual(gets, []string{"repositoryconfigurations", "pullrequestconfigurations"}) &&
		!reflect.DeepEqual(gets, []string{"pullrequestconfigurations", "repositoryconfigurations"}) {
		t.Fatal(gets)
	}
}

func TestSecretRefsTakesNamesOnlyAndIgnoresRefsThatAreNotSecretKeys(t *testing.T) {
	spec := map[string]any{"configurationRef": map[string]any{"name": "cfg"}, "a": map[string]any{"tokenRef": map[string]any{"name": "t", "key": "token"}},
		"list": []any{map[string]any{"passwordRef": map[string]any{"name": "p", "namespace": "other", "key": "pw"}}}}
	if got := S.SecretRefs(spec, "ns"); !reflect.DeepEqual(got, map[string]bool{"ns/t": true, "other/p": true}) {
		t.Fatal(got)
	}
}

// --- the contract and the fingerprint -------------------------------------------------------------

func TestEveryFindingPassesTheModelsOwnContract(t *testing.T) {
	for _, p := range run(F.DefaultOutage(), nil, 15, nil).props {
		if err := jsonschema.Validate(p, prompt.ItemSchema); err != nil {
			t.Fatal(err)
		}
	}
}

func fingerprints(props []map[string]any) []string {
	var out []string
	for _, p := range props {
		out = append(out, P.MustFingerprint(p))
	}
	return out
}

func TestTheSameOutageOnTheNextNightIsTheSameFingerprint(t *testing.T) {
	_, _, a := S.Gather(ctx, api(F.DefaultOutage(), F.SyncConfigs()), discover, F.SyncNow, F.SyncGroups(), 15)
	_, _, b := S.Gather(ctx, api(F.DefaultOutage(), F.SyncConfigs()), discover, F.SyncNow.Add(24*time.Hour), F.SyncGroups(), 15)
	if !reflect.DeepEqual(fingerprints(a), fingerprints(b)) {
		t.Fatal("the body moved by itself")
	}
}

func TestAChangedOutageIsANewBodyUnderTheSameSubject(t *testing.T) {
	_, _, a := S.Gather(ctx, api(F.DefaultOutage(), F.SyncConfigs()), discover, F.SyncNow, F.SyncGroups(), 15)
	_, _, b := S.Gather(ctx, api(F.Outage(30, 24, 19, 3, 420), F.SyncConfigs()), discover, F.SyncNow, F.SyncGroups(), 15)
	k := "github-provider-kog/credential-rejected"
	if P.MustFingerprint(bySubject(a)[k]) == P.MustFingerprint(bySubject(b)[k]) {
		t.Fatal()
	}
}

// --- discovery, configuration and failure ---------------------------------------------------------

func listed(a *fake.API) []string {
	var out []string
	for _, r := range a.Reads {
		if strings.HasPrefix(r, "list ") {
			f := strings.Fields(r)
			out = append(out, f[len(f)-1])
		}
	}
	return out
}

func TestKindsComeFromDiscoveryAndTheValuesMayNarrowThem(t *testing.T) {
	r := run(F.DefaultOutage(), py.O("git.krateo.io", py.O("component", "git-provider", "kinds", []any{"Repo"})), 15, nil)
	if !reflect.DeepEqual(listed(r.api), []string{"repoes"}) {
		t.Fatal(listed(r.api))
	}
	r = run(F.DefaultOutage(), py.O("git.krateo.io", py.O("component", "git-provider", "kinds", []any{})), 15, nil)
	if !reflect.DeepEqual(listed(r.api), []string{"repoes", "localresources"}) {
		t.Fatal(listed(r.api))
	}
}

func TestNoGroupIsHardcodedAndAnEmptyMapSaysItCheckedNothing(t *testing.T) {
	if S.Groups.(*py.OMap).Len() != 0 {
		t.Fatal("which groups are checked is the chart's values, never the code's")
	}
	r := run(F.DefaultOutage(), py.NewOMap(), 15, nil)
	if r.body != "" || len(r.props) != 0 || r.stats["empty"] != true || !strings.Contains(r.stats["note"].(string), "config.syncStall.groups is empty") {
		t.Fatal(r.stats)
	}
	r = run(F.DefaultOutage(), py.O("git.krateo.io", nil), 15, nil)
	if r.stats["empty"] != true {
		t.Fatal("a group dropped with null is not checked")
	}
}

func TestAKindThatCannotBeReadDegradesTheSourceAndTheRestStillReport(t *testing.T) {
	r := run(F.DefaultOutage(), nil, 15, nil, "pullrequests")
	if r.stats["ok"] != false || !strings.Contains(r.stats["error"].(string), "pullrequests.github.krateo.io") || len(bySubject(r.props)) != 2 {
		t.Fatal(r.stats)
	}
}

func TestAFailedDiscoveryDegradesTheSource(t *testing.T) {
	broken := func(context.Context, string) ([]kube.Served, error) { return nil, errors.New("discovery down") }
	_, stats, props := S.Gather(ctx, api(nil, nil), broken, F.SyncNow, F.SyncGroups(), 15)
	if stats["ok"] != false || !strings.Contains(stats["error"].(string), "discovery of") || len(props) != 0 {
		t.Fatal(stats)
	}
}

type docs map[string]any

func (d docs) GetPath(_ context.Context, path string) (any, error) { return py.Plain(d[path]), nil }

func TestTheDiscovererTakesEveryVersionPreferredFirstAndSkipsSubresources(t *testing.T) {
	d := docs{
		"/apis/github.krateo.io": py.O("preferredVersion", py.O("version", "v2022-11-28"),
			"versions", []any{py.O("version", "v2022-11-28"), py.O("version", "v1alpha1")}),
		"/apis/github.krateo.io/v2022-11-28": py.O("resources", []any{
			py.O("name", "repositories", "kind", "Repository", "namespaced", true, "verbs", []any{"get", "list"}),
			py.O("name", "repositories/status", "kind", "Repository", "verbs", []any{"get"})}),
		"/apis/github.krateo.io/v1alpha1": py.O("resources", []any{
			py.O("name", "repositoryconfigurations", "kind", "RepositoryConfiguration", "namespaced", true, "verbs", []any{"list"}),
			py.O("name", "repositories", "kind", "Repository", "verbs", []any{"list"})}),
	}
	got, err := S.Discoverer(d)(ctx, "github.krateo.io")
	want := []kube.Served{{Version: "v2022-11-28", Plural: "repositories", Kind: "Repository", Namespaced: true},
		{Version: "v1alpha1", Plural: "repositoryconfigurations", Kind: "RepositoryConfiguration", Namespaced: true}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
}

func TestTheFindingsAreCappedAndTheCapIsRecorded(t *testing.T) {
	saved := S.MaxFindings
	S.MaxFindings = 1
	t.Cleanup(func() { S.MaxFindings = saved })
	r := run(F.DefaultOutage(), nil, 15, nil)
	if len(r.props) != 1 || r.stats["findings"] != int64(1) || !strings.Contains(r.stats["note"].(string), "not proposed") ||
		!strings.Contains(r.body, "not proposed (over the per-run cap)") {
		t.Fatal(r.stats, r.body)
	}
}

// --- review of #40: one regression test per finding ------------------------------------------------

func TestGithubsRateLimit403IsRateLimitedNotPermissionDenied(t *testing.T) {
	for _, msg := range []string{"403 API rate limit exceeded for user ID 123",
		"403 You have exceeded a secondary rate limit. Please wait a few minutes"} {
		if signal(msg) != "rate-limited" {
			t.Error(msg, signal(msg))
		}
	}
}

func TestAStatusCodeCountsOnlyInHTTPContext(t *testing.T) {
	for msg, want := range map[string]string{
		"update pull request 401 in org/repo: 422 Unprocessable Entity":           "remote-rejected-request",
		"sync krateo-blueprints/r-404-old: branch is protected":                   "sync-krateo-blueprints",
		"GET https://api.github.com/repos/o/r-404-old: 500 Internal Server Error": "get-internal-server-error",
		"unexpected status code: 404":                                             "remote-not-found",
		"request failed: status 401":                                              "credential-rejected",
	} {
		if got := signal(msg); got != want {
			t.Errorf("%q -> %q, want %q", msg, got, want)
		}
	}
}

func TestAMissingLocalSecretIsItsOwnPatternWithItsOwnAdvice(t *testing.T) {
	msg := `cannot get credentials: secrets "git-provider-credentials" not found`
	if signal(msg) != "local-secret-missing" {
		t.Fatal(signal(msg))
	}
	r := run(map[string][]any{"repoes": lists(obj("x", F.Err(msg, 600), nil))}, nil, 15, nil)
	content := r.props[0]["change"].(map[string]any)["content"].(string)
	if len(r.props) != 1 || r.props[0]["subject"] != "git-provider/local-secret-missing" ||
		!strings.Contains(content, "does not exist in the cluster") || strings.Contains(content, "deleted or renamed repository") {
		t.Fatal(r.props)
	}
}

func TestTheFallbackStripsURLsBeforeItTakesTheFirstClause(t *testing.T) {
	a := signal("GET https://api.github.com/repos/o/a: unexpected end of JSON input")
	b := signal("GET https://api.github.com/repos/o/b?x=1: unexpected end of JSON input")
	if a != b || a != "get-unexpected-end-of-json-input" {
		t.Fatal(a, b)
	}
}

func TestATransitionTimeWithoutAZoneIsUTCAndCostsNothing(t *testing.T) {
	naive := obj("naive", F.Err("401 Unauthorized", 600), nil)
	naive["status"].(map[string]any)["conditions"].([]any)[0].(map[string]any)["lastTransitionTime"] =
		F.SyncNow.Add(-2 * time.Hour).Format("2006-01-02T15:04:05")
	r := run(map[string][]any{"repoes": lists(naive, obj("z", F.Err("401 Unauthorized", 600), nil))}, nil, 15, nil)
	if r.stats["ok"] != true || r.stats["stalled"] != int64(2) || len(r.props) != 1 {
		t.Fatal(r.stats)
	}
}

func TestAConfiguredGroupTheClusterDoesNotServeIsANoteNotAFailure(t *testing.T) {
	d := func(_ context.Context, g string) ([]kube.Served, error) {
		if g == "github.krateo.io" {
			return nil, &kube.APIError{Status: 404, Reason: "Not Found"}
		}
		return F.SyncServed[g], nil
	}
	_, stats, props := S.Gather(ctx, api(F.DefaultOutage(), F.SyncConfigs()), d, F.SyncNow, F.SyncGroups(), 15)
	if stats["ok"] != true || !strings.Contains(stats["note"].(string), "github.krateo.io is not served by this cluster") ||
		len(props) != 1 || props[0]["subject"] != "git-provider/credential-rejected" {
		t.Fatal(stats, props)
	}
}

func TestAConfigurationThatCannotBeReadLeavesTheSecretUnnamedAndTheSourceOK(t *testing.T) {
	r := run(F.Outage(24, 24, 0, 0, 420), nil, 15, map[[2]string]map[string]any{}) // every lookup fails
	if _, has := r.stats["error"]; r.stats["ok"] != true || has {
		t.Fatal(r.stats)
	}
	for _, p := range r.props {
		if strings.Contains(p["rationale"].(string), "git-provider-credentials") {
			t.Fatal(p["rationale"])
		}
	}
	clusterScoped := F.Obj("c", F.Err("401 Unauthorized", 600), nil, map[string]any{"configurationRef": map[string]any{"name": "cfg"}}, "")
	r = run(map[string][]any{"repositories": lists(clusterScoped)}, nil, 15, nil)
	for _, rd := range r.api.Reads {
		if strings.HasPrefix(rd, "get ") {
			t.Fatal("no namespace: no lookup")
		}
	}
	if r.stats["ok"] != true {
		t.Fatal(r.stats)
	}
}
