package publish_test

// Publishing through the platform's own chain, the phase vocabulary, supersession and a person's
// spec.decision (the publish cases of tests/test_review_bookkeeping.py, test_platform_review_service.py
// and test_spec_decision.py).

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/krateo-platformops/nightly-review/internal/fake"
	"github.com/krateo-platformops/nightly-review/internal/kube"
	P "github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/publish"
	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/testutil"
)

var ctx = context.Background()

func prop(content, repo, path string) map[string]any {
	p := map[string]any{"kind": "Documentation", "title": "t", "rationale": "r", "confidence": "low", "evidence": []any{},
		"target": map[string]any{"repo": repo, "path": path}, "change": map[string]any{"format": "yaml", "content": content}}
	p["fingerprint"] = P.MustFingerprint(p)
	return p
}

// --- the phase vocabulary ----------------------------------------------------------------------

func TestTheOpenPhasesAreOneSharedConstant(t *testing.T) {
	if !reflect.DeepEqual(publish.OpenPhases, map[string]bool{"": true, publish.PhaseProposed: true, publish.PhasePrOpen: true}) {
		t.Fatal(publish.OpenPhases)
	}
}

func proposalSchema(t *testing.T) any {
	doc := testutil.YAML(t, "helm/nightly-review-crds/templates/proposal.crd.yaml")
	return py.GetPath(py.List(py.GetPath(doc, "spec", "versions"))[0], "schema", "openAPIV3Schema", "properties")
}

func enumOf(v any) map[string]bool {
	out := map[string]bool{}
	for _, e := range py.List(v) {
		out[py.Str(e)] = true
	}
	return out
}

func TestEveryPhaseThePublisherWritesIsDeclaredInTheCRDEnum(t *testing.T) {
	declared := enumOf(py.GetPath(proposalSchema(t), "status", "properties", "phase", "enum"))
	for p := range publish.WrittenPhases {
		if !declared[p] {
			t.Error(p)
		}
	}
}

// --- BuilderPublish ----------------------------------------------------------------------------

func TestAProposalBecomesABuilderpublishClaimNotAGithubCall(t *testing.T) {
	api := fake.NewAPI()
	p := prop("replicas: 3\n", "krateo-platformops/monitoring", "alerts/x.yaml")
	p["title"] = "Alert on x"
	out, err := publish.CreatePublishClaim(ctx, api, p, "rr-1", "v1-8-46", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := api.Creates[0]
	spec := c.Body["spec"].(map[string]any)
	if c.Plural != "builderpublishes" || c.Body["apiVersion"] != "composition.krateo.io/v1-8-46" || spec["builder"] != "review" ||
		spec["repository"].(map[string]any)["create"] != false ||
		!reflect.DeepEqual(spec["target"], map[string]any{"namespace": "krateo-platformops", "repo": "monitoring"}) ||
		!reflect.DeepEqual(spec["files"], []any{map[string]any{"path": "alerts/x.yaml", "content": "replicas: 3\n"}}) ||
		spec["pullRequest"].(map[string]any)["create"] != true || out.Name != spec["name"] ||
		out.Name != "review-"+p["fingerprint"].(string)[:12] {
		t.Fatal(c.Body, out)
	}
}

func TestTheClaimNameIsStableSoTheSameSuggestionReassertsOneClaim(t *testing.T) {
	api := fake.NewAPI()
	p := prop("replicas: 3\n", "krateo-platformops/installer", "README.md")
	a, _ := publish.CreatePublishClaim(ctx, api, p, "rr-1", "v1-8-46", nil)
	b, _ := publish.CreatePublishClaim(ctx, api, p, "rr-2", "v1-8-46", nil)
	if a.Name != b.Name {
		t.Fatal(a, b)
	}
}

func TestAMalformedTargetRepoFailsLoudlyRatherThanPublishingSomewhereOdd(t *testing.T) {
	_, err := publish.CreatePublishClaim(ctx, fake.NewAPI(), prop("x: 1\n", "not-an-owner-slash-name", "README.md"), "rr-1", "v1-8-46", nil)
	if py.TypeName(err) != "ValueError" {
		t.Fatal(err)
	}
}

func TestAnExistingClaimIsReassertedNotDuplicated(t *testing.T) {
	api := fake.NewAPI()
	p := prop("replicas: 3\n", "krateo-platformops/installer", "README.md")
	api.Taken["review-"+p["fingerprint"].(string)[:12]] = true
	if _, err := publish.CreatePublishClaim(ctx, api, p, "rr-1", "v1-8-46", nil); err != nil || len(api.SpecPatches) != 1 {
		t.Fatal(err, api.SpecPatches)
	}
}

func TestPublishHoldsNoGithubSurfaceAnyMore(t *testing.T) {
	src, err := os.ReadFile("publish.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{`"net/http"`, "GITHUB_TOKEN", "api.github.com", "base64"} {
		if strings.Contains(string(src), gone) {
			t.Errorf("%q still reachable from publish.go", gone)
		}
	}
}

func TestThePublishVersionIsAServedOneNeverTheStorageVersion(t *testing.T) {
	saved := publish.ReadCRDVersions
	t.Cleanup(func() { publish.ReadCRDVersions = saved })
	crd := func(vs ...kube.CRDVersion) func(context.Context, string) ([]kube.CRDVersion, error) {
		return func(context.Context, string) ([]kube.CRDVersion, error) { return vs, nil }
	}
	publish.ReadCRDVersions = crd(kube.CRDVersion{Name: "vacuum", Served: false, Storage: true}, kube.CRDVersion{Name: "v1-8-46", Served: true, Storage: false})
	if v, _ := publish.PublishVersion(ctx); v != "v1-8-46" {
		t.Fatal(v)
	}
	publish.ReadCRDVersions = crd(kube.CRDVersion{Name: "vacuum", Served: false, Storage: true}, kube.CRDVersion{Name: "v1-8-44", Served: true, Storage: false},
		kube.CRDVersion{Name: "v1-8-46", Served: true, Storage: false})
	if v, _ := publish.PublishVersion(ctx); v != "v1-8-46" {
		t.Fatal("newest served version, not list order:", v)
	}
}

// --- supersession by subject (test_platform_review_service.py) -----------------------------------

func stored(name, kind, subject, phase, run, repo, fp string) map[string]any {
	if kind == "" {
		kind = "Alert"
	}
	if phase == "" {
		phase = "Proposed"
	}
	if run == "" {
		run = "rr-old"
	}
	if repo == "" {
		repo = "org/old"
	}
	if fp == "" {
		fp = "fp-" + name
	}
	spec := map[string]any{"kind": kind, "target": map[string]any{"repo": repo, "path": name + ".yaml"}, "fingerprint": fp,
		"producedBy": map[string]any{"runRef": run}}
	if subject != "" {
		spec["subject"] = subject
	}
	return map[string]any{"metadata": map[string]any{"name": name}, "spec": spec, "status": map[string]any{"phase": phase}}
}

func alert(subject, content string) map[string]any {
	p := map[string]any{"kind": "Alert", "title": "t", "rationale": "r", "confidence": "low",
		"evidence": []any{map[string]any{"source": "clickhouse", "summary": "s"}},
		"target":   map[string]any{"repo": "org/repo", "path": "x.yaml"}, "change": map[string]any{"format": "yaml", "content": content}}
	if subject != "" {
		p["subject"] = subject
	}
	return p
}

func index(t *testing.T, api *fake.API, run string, decided map[string]string) *publish.Indexes {
	t.Helper()
	idx, err := publish.OpenIndex(ctx, api, run, decided)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func classify(t *testing.T, p map[string]any, idx *publish.Indexes, decided map[string]string) P.Classification {
	t.Helper()
	c, err := P.Classify(p, idx.ByFingerprint, idx.ByTarget, idx.BySubject, decided)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func is(c P.Classification, action string, priors ...string) bool {
	if c.Action != action {
		return false
	}
	if action == "supersede" {
		return reflect.DeepEqual(c.Priors, priors)
	}
	if action == "dedup" || action == "decided" {
		return c.Name == priors[0]
	}
	return true
}

func TestANewProposalSupersedesAnOpenOneAboutTheSameFindingInAnotherRepo(t *testing.T) {
	api := fake.NewAPI(stored("p-old", "", "snowplow/sar-unauthorized", "", "", "org/elsewhere", ""))
	if c := classify(t, alert("snowplow/sar-unauthorized", "a: 1\n"), index(t, api, "rr-new", nil), nil); !is(c, "supersede", "p-old") {
		t.Fatal(c)
	}
}

func TestNullSubjectsNeverGroupWithEachOther(t *testing.T) {
	api := fake.NewAPI(stored("p-legacy-1", "", "", "", "", "", ""), stored("p-legacy-2", "", "", "", "", "", ""))
	idx := index(t, api, "rr-new", nil)
	if len(idx.BySubject) != 0 || !is(classify(t, alert("", "a: 1\n"), idx, nil), "new") {
		t.Fatal(idx.BySubject)
	}
}

func TestASubjectMatchNeedsTheSameKind(t *testing.T) {
	api := fake.NewAPI(stored("p-doc", "Documentation", "snowplow/sar-unauthorized", "", "", "", ""))
	if c := classify(t, alert("snowplow/sar-unauthorized", "a: 1\n"), index(t, api, "rr-new", nil), nil); !is(c, "new") {
		t.Fatal(c)
	}
}

func TestOnlyAProposedOneIsSupersededBySubject(t *testing.T) {
	for _, phase := range []string{"PrOpen", "Superseded", "Merged", "Rejected", "Refused", "Failed"} {
		api := fake.NewAPI(stored("p-old", "", "snowplow/sar-unauthorized", phase, "", "", ""))
		if idx := index(t, api, "rr-new", nil); len(idx.BySubject) != 0 {
			t.Error(phase)
		}
	}
}

func TestAProposalWithAnOpenPRIsNeverSupersededByTargetEither(t *testing.T) {
	s := stored("p-pr", "", "", "PrOpen", "", "org/old", "")
	idx := index(t, fake.NewAPI(s), "rr-new", nil)
	sameFile := alert("", "a: 1\n")
	sameFile["target"] = fake.DeepCopy(s["spec"].(map[string]any)["target"])
	if len(idx.ByTarget) != 0 || !is(classify(t, sameFile, idx, nil), "new") {
		t.Fatal(idx.ByTarget)
	}
}

func TestAProposedOneIsStillSupersededByTarget(t *testing.T) {
	s := stored("p-old", "", "", "", "", "org/old", "")
	sameFile := alert("", "a: 1\n")
	sameFile["target"] = fake.DeepCopy(s["spec"].(map[string]any)["target"])
	if c := classify(t, sameFile, index(t, fake.NewAPI(s), "rr-new", nil), nil); !is(c, "supersede", "p-old") {
		t.Fatal(c)
	}
}

func TestAProposalFromTheSameRunIsNotSupersededBySubject(t *testing.T) {
	api := fake.NewAPI(stored("p-sibling", "", "snowplow/sar-unauthorized", "", "rr-new", "", ""))
	if len(index(t, api, "rr-new", nil).BySubject) != 0 {
		t.Fatal()
	}
}

func TestAnExactRepeatIsStillADuplicateNotASupersession(t *testing.T) {
	p := alert("snowplow/sar-unauthorized", "a: 1\n")
	api := fake.NewAPI(stored("p-old", "", "snowplow/sar-unauthorized", "", "", "", P.MustFingerprint(p)))
	if c := classify(t, p, index(t, api, "rr-new", nil), nil); !is(c, "dedup", "p-old") {
		t.Fatal(c)
	}
}

func TestSupersessionWritesSupersededbyAndATerminalPhase(t *testing.T) {
	api := fake.NewAPI(stored("p-old", "", "s/x", "", "", "", ""))
	if err := publish.MarkSuperseded(ctx, api, "p-old", "p-new", "r"); err != nil {
		t.Fatal(err)
	}
	w := api.StatusWrites[0]
	st := w.Body["status"].(map[string]any)
	if len(api.StatusWrites) != 1 || w.Name != "p-old" || st["phase"] != publish.PhaseSuperseded || st["supersededBy"] != "p-new" {
		t.Fatal(api.StatusWrites)
	}
}

func TestASupersededPriorIsForgottenSoItIsNotCountedTwice(t *testing.T) {
	api := fake.NewAPI(stored("p-old", "", "snowplow/sar-unauthorized", "", "", "", ""))
	idx := index(t, api, "rr-new", nil)
	c := classify(t, alert("snowplow/sar-unauthorized", "a: 1\n"), idx, nil)
	for _, n := range c.Priors {
		publish.Forget(n, idx)
	}
	if c2 := classify(t, alert("snowplow/sar-unauthorized", "a: 2\n"), idx, nil); !is(c2, "new") {
		t.Fatal(c2)
	}
}

// --- spec.decision (test_spec_decision.py) ----------------------------------------------------------

func decided(name, phase, statusPhase string, decision map[string]any) map[string]any {
	p := stored(name, "", "snowplow/sar-unauthorized", statusPhase, "", "", "")
	d := map[string]any{"phase": phase}
	for k, v := range decision {
		d[k] = v
	}
	p["spec"].(map[string]any)["decision"] = d
	return p
}

func TestTheDecisionWinsOverAStatusThatHasNotCaughtUp(t *testing.T) {
	if publish.EffectivePhase(decided("p", "Rejected", "Proposed", nil)) != "Rejected" {
		t.Fatal()
	}
}

func TestAMergedPRIsLaterThanTheDecisionThatOpenedIt(t *testing.T) {
	if publish.EffectivePhase(decided("p", "PrOpen", "Merged", map[string]any{"claim": "c"})) != "Merged" {
		t.Fatal()
	}
}

func TestWithoutADecisionStatusIsThePhase(t *testing.T) {
	if publish.EffectivePhase(stored("p", "", "", "Superseded", "", "", "")) != "Superseded" {
		t.Fatal()
	}
}

func TestADecisionThisServiceCannotReadIsIgnoredNotGuessed(t *testing.T) {
	for _, bad := range []any{map[string]any{"phase": "Merged"}, map[string]any{"phase": nil}, "Rejected", map[string]any{}} {
		p := stored("p", "", "", "", "", "", "")
		p["spec"].(map[string]any)["decision"] = bad
		if publish.Decision(p) != nil || publish.EffectivePhase(p) != "Proposed" {
			t.Error(bad)
		}
	}
}

func TestADecidedProposalIsInNoneOfTheOpenIndexes(t *testing.T) {
	for _, phase := range []string{"Rejected", "PrOpen"} {
		dec := map[string]string{}
		idx := index(t, fake.NewAPI(decided("p-dec", phase, "Proposed", map[string]any{"claim": "c"})), "rr-new", dec)
		if len(idx.ByFingerprint)+len(idx.ByTarget)+len(idx.BySubject) != 0 || !reflect.DeepEqual(dec, map[string]string{"fp-p-dec": "p-dec"}) {
			t.Error(phase, idx, dec)
		}
	}
}

func TestARewordingOfARejectedFindingIsNewNotASupersession(t *testing.T) {
	dec := map[string]string{}
	idx := index(t, fake.NewAPI(decided("p-dec", "Rejected", "Proposed", nil)), "rr-new", dec)
	if c := classify(t, alert("snowplow/sar-unauthorized", "b: 2\n"), idx, dec); !is(c, "new") {
		t.Fatal(c)
	}
}

func TestAnExactRepeatOfARejectedProposalIsDecidedNotRewritten(t *testing.T) {
	p := alert("snowplow/sar-unauthorized", "a: 1\n")
	d := decided("p-dec", "Rejected", "Proposed", nil)
	d["spec"].(map[string]any)["fingerprint"] = P.MustFingerprint(p)
	dec := map[string]string{}
	if c := classify(t, p, index(t, fake.NewAPI(d), "rr-new", dec), dec); !is(c, "decided", "p-dec") {
		t.Fatal(c)
	}
}

func TestAPersonDecidedStatusWithoutASpecDecisionIsRespectedToo(t *testing.T) {
	for _, phase := range []string{"Rejected", "Merged"} {
		p := alert("snowplow/sar-unauthorized", "a: 1\n")
		dec := map[string]string{}
		idx := index(t, fake.NewAPI(stored("p-old", "", "", phase, "", "", P.MustFingerprint(p))), "rr-new", dec)
		if c := classify(t, p, idx, dec); !is(c, "decided", "p-old") {
			t.Error(phase, c)
		}
	}
}

func TestTheServicesOwnTerminalPhasesCanStillReopen(t *testing.T) {
	p := alert("snowplow/sar-unauthorized", "a: 1\n")
	dec := map[string]string{}
	idx := index(t, fake.NewAPI(stored("p-sup", "", "", "Superseded", "", "", P.MustFingerprint(p))), "rr-new", dec)
	if len(dec) != 0 || !is(classify(t, p, idx, dec), "new") {
		t.Fatal(dec)
	}
}

func TestCallersThatPassNoDecidedIndexKeepWorking(t *testing.T) {
	idx := index(t, fake.NewAPI(decided("p-dec", "Rejected", "Proposed", nil)), "rr-new", nil)
	if len(idx.ByFingerprint)+len(idx.ByTarget)+len(idx.BySubject) != 0 {
		t.Fatal(idx)
	}
}

func labelAPI(ps ...map[string]any) *fake.API {
	a := fake.NewAPI(ps...)
	a.LabelPatches = true
	return a
}

func mirror(t *testing.T, a *fake.API) int {
	n, err := publish.MirrorDecisions(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTheMirrorCopiesTheDecisionOntoStatus(t *testing.T) {
	a := labelAPI(decided("p-dec", "Rejected", "Proposed", map[string]any{"reason": "not our problem", "decidedBy": "admin",
		"decidedAt": "2026-09-29T10:00:00Z"}))
	if mirror(t, a) != 1 || len(a.StatusWrites) != 1 || a.StatusWrites[0].Plural != "proposals" || a.StatusWrites[0].Name != "p-dec" {
		t.Fatal(a.StatusWrites)
	}
	if !reflect.DeepEqual(a.StatusWrites[0].Body["status"], map[string]any{"phase": "Rejected", "reason": "not our problem",
		"decidedBy": "admin", "decidedAt": "2026-09-29T10:00:00Z"}) {
		t.Fatal(a.StatusWrites[0].Body)
	}
}

func TestTheMirrorIsIdempotent(t *testing.T) {
	a := labelAPI(decided("p-dec", "PrOpen", "Proposed", map[string]any{"claim": "bp-1", "decidedBy": "admin", "decidedAt": "2026-09-29T10:00:00Z"}))
	if mirror(t, a) != 1 {
		t.Fatal()
	}
	writes := len(a.StatusWrites) + len(a.SpecPatches)
	if mirror(t, a) != 0 || len(a.StatusWrites)+len(a.SpecPatches) != writes {
		t.Fatal("a second pass wrote again")
	}
}

func TestTheClaimLandsOnTheLabelTheServiceAlreadyUses(t *testing.T) {
	a := labelAPI(decided("p-dec", "PrOpen", "Proposed", map[string]any{"claim": "bp-1"}))
	mirror(t, a)
	if len(a.SpecPatches) != 1 || !reflect.DeepEqual(a.SpecPatches[0].Body, map[string]any{"metadata": map[string]any{
		"labels": map[string]any{publish.ClaimLabel: "bp-1"}}}) {
		t.Fatal("only the label, never the spec", a.SpecPatches)
	}
}

func TestAFieldTheDecisionLacksIsNotClearedFromStatus(t *testing.T) {
	p := decided("p-dec", "Rejected", "Proposed", nil)
	p["status"].(map[string]any)["decidedAt"] = "2026-09-01T00:00:00Z"
	a := labelAPI(p)
	mirror(t, a)
	if a.Proposals["p-dec"]["status"].(map[string]any)["decidedAt"] != "2026-09-01T00:00:00Z" {
		t.Fatal(a.Proposals["p-dec"]["status"])
	}
}

func TestTheMirrorDoesNotPullAMergedProposalBackToPropen(t *testing.T) {
	a := labelAPI(decided("p-dec", "PrOpen", "Merged", map[string]any{"claim": "bp-1"}))
	mirror(t, a)
	if len(a.StatusWrites) != 0 {
		t.Fatal(a.StatusWrites)
	}
}

func TestTheDecisionPhasesAreTheCRDs(t *testing.T) {
	decl := py.GetPath(proposalSchema(t), "spec", "properties", "decision")
	if !reflect.DeepEqual(enumOf(py.GetPath(decl, "properties", "phase", "enum")), publish.DecisionPhases) {
		t.Fatal(py.GetPath(decl, "properties", "phase", "enum"))
	}
	for _, k := range []string{"phase", "reason", "decidedBy", "decidedAt", "claim"} {
		if !py.Has(py.Get(decl, "properties"), k) {
			t.Error(k)
		}
	}
}

func TestEveryMirroredPhaseIsAStatusPhase(t *testing.T) {
	status := enumOf(py.GetPath(proposalSchema(t), "status", "properties", "phase", "enum"))
	for p := range publish.DecisionPhases {
		if !status[p] || !publish.WrittenPhases[p] {
			t.Error(p)
		}
	}
}

func TestWhatTheMirrorWritesIsDeclared(t *testing.T) {
	schema := py.Get(proposalSchema(t), "status")
	a := labelAPI(decided("p-a", "Rejected", "Proposed", map[string]any{"reason": "r", "decidedBy": "u", "decidedAt": "2026-09-29T10:00:00Z"}),
		decided("p-b", "PrOpen", "Proposed", map[string]any{"claim": "bp", "decidedBy": "u"}))
	mirror(t, a)
	if len(a.StatusWrites) != 2 {
		t.Fatal(a.StatusWrites)
	}
	for _, w := range a.StatusWrites {
		if u := testutil.Undeclared(w.Body["status"], schema, "status"); len(u) != 0 {
			t.Fatal(u)
		}
	}
}
