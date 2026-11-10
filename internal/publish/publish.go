// Package publish writes the outcome: a Proposal object per suggestion, and a BuilderPublish claim
// carrying the change.
//
// THIS SERVICE NO LONGER TALKS TO GITHUB, AND NO LONGER HOLDS A TOKEN. It used to branch, PUT a file and
// open a pull request over the REST API with its own credential. Everything below now renders a claim to
// the platform's own publish chain — Repository -> Repo -> LocalResource per file -> PullRequest — which
// portal-builder and blueprint-builder already use. The credential is git-provider's, the ordering gate
// that stops GitHub's 422 ("no commits between main and the branch") is the chain's, and PullRequest is
// level-based so a re-render cannot open a second one.
//
// THE AGENT STILL NEVER WRITES. That split is unchanged and is still the whole safety argument; what
// changed is that the service does not hold a write credential either.
package publish

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/krateo-platformops/nightly-review/internal/env"
	"github.com/krateo-platformops/nightly-review/internal/kube"
	"github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/py"
)

// Configuration.
var (
	Namespace = env.Str("NAMESPACE", "krateo-system")
	// PublishBuilder sets krateo.io/builder on every CR the chain renders.
	PublishBuilder = env.Str("PUBLISH_BUILDER", "review")
)

// The service's own group, and the publish chain's. The BuilderPublish KIND is version-pinned in the
// served CRD (v1-8-46 and so on), and that version moves with every portal release — so it is
// DISCOVERED at run time rather than compiled in. A hardcoded version would publish nothing the morning
// after a portal bump, and would do it quietly.
const (
	Group, Version = "review.krateo.io", "v1alpha1"
	PublishGroup   = "composition.krateo.io"
	PublishPlural  = "builderpublishes"
)

func now() string { return py.Isoformat(py.Now()) }

// ReadCRDVersions reads a CRD's versions. Set by the run to the real client; a test stands in for it.
var ReadCRDVersions func(ctx context.Context, name string) ([]kube.CRDVersion, error)

// PublishVersion is the served version of the BuilderPublish kind, read from the CRD rather than
// assumed. It costs one GET and turns "publishing silently stopped after a portal roll" into a normal
// failure with a name attached. A variable so a test can stand in for it.
var PublishVersion = func(ctx context.Context) (string, error) {
	versions, err := ReadCRDVersions(ctx, PublishPlural+"."+PublishGroup)
	if err != nil {
		return "", err
	}
	// SERVED, NEVER STORAGE. On 057 this CRD carries two versions: the composition version that is
	// actually served, and `vacuum` — which is marked storage:true and served:FALSE, and carries no spec
	// schema at all. Preferring the storage version, which is the reflex, returns `vacuum` and every claim
	// then fails with "no matches for kind". Measured on the cluster rather than reasoned about.
	var served []string
	for _, v := range versions {
		if v.Served {
			served = append(served, v.Name)
		}
	}
	if len(served) == 0 {
		return "", py.Errorf("RuntimeError", "%s.%s serves no version", PublishPlural, PublishGroup)
	}
	if len(served) > 1 {
		// Several served versions is a portal mid-migration. Take the newest by the v<major>-<minor>-
		// <patch> ordering the composition versions use, rather than whichever the API happened to list.
		sort.SliceStable(served, func(i, j int) bool { return compareKeys(versionKey(served[j]), versionKey(served[i])) < 0 })
	}
	return served[0], nil
}

func versionKey(name string) []int {
	var out []int
	for _, x := range strings.Split(strings.TrimLeft(name, "v"), "-") {
		if x != "" && isDigits(x) {
			n, _ := strconv.Atoi(x)
			out = append(out, n)
		}
	}
	return out
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func compareKeys(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return len(a) - len(b)
}

// Claim is what CreatePublishClaim returns.
type Claim struct {
	Name, APIVersion, Branch string
}

// CreatePublishClaim renders one proposal as a BuilderPublish claim.
//
// IT IS `builder: review`, AND THAT MATTERS MORE THAN IT LOOKS. The value sets krateo.io/builder on
// every CR the chain renders and is interpolated into each commit message, and the portal's lists select
// on it. Publishing as `blueprint` would make an overnight machine suggestion indistinguishable from a
// blueprint a person authored.
//
// REPOSITORY CREATION IS OFF. A review proposal targets a repository that already exists; the chain's
// default is to create one, which for a typo'd target would mean conjuring a repository rather than
// failing. `target.base` is left at the chain's default rather than discovered, because discovering a
// default branch is a GitHub call and not holding a GitHub credential is the point.
func CreatePublishClaim(ctx context.Context, api kube.CustomObjects, p map[string]any, runName, version string,
	queriesRun map[string]any) (*Claim, error) {
	target := py.Get(p, "target")
	repoFull := py.Str(py.Get(target, "repo"))
	org, repo, _ := strings.Cut(repoFull, "/")
	if org == "" || repo == "" {
		return nil, py.Errorf("ValueError", "target.repo %s is not owner/name", py.StrRepr(repoFull))
	}
	fingerprint := py.Str(p["fingerprint"])
	fp := py.Trunc(fingerprint, 12)
	name := "review-" + fp
	branch := "review/" + strings.ToLower(py.Str(p["kind"])) + "-" + fp
	path := py.Str(py.Get(target, "path"))
	if !py.Truthy(py.Get(target, "path")) {
		path = "proposals/" + fingerprint + ".yaml"
	}
	if version == "" {
		v, err := PublishVersion(ctx)
		if err != nil {
			return nil, err
		}
		version = v
	}
	spec := map[string]any{
		"name":       name,
		"branch":     branch,
		"builder":    PublishBuilder,
		"target":     map[string]any{"namespace": org, "repo": repo},
		"repository": map[string]any{"create": false},
		"files":      []any{map[string]any{"path": path, "content": py.Get(py.Get(p, "change"), "content")}},
		"pullRequest": map[string]any{
			"create": true,
			"title":  "review: " + py.Str(p["title"]),
			"body":   PRBody(p, runName, queriesRun),
		},
	}
	body := map[string]any{
		"apiVersion": PublishGroup + "/" + version,
		"kind":       "BuilderPublish",
		"metadata": map[string]any{
			"name":      name,
			"namespace": Namespace,
			"labels": map[string]any{
				"review.krateo.io/run":         runName,
				"review.krateo.io/fingerprint": py.Trunc(fingerprint, 63),
			},
		},
		"spec": spec,
	}
	if _, err := api.CreateNamespaced(ctx, PublishGroup, version, Namespace, PublishPlural, body); err != nil {
		// ALREADY THERE IS NORMAL. The name derives from the fingerprint, so the same suggestion on a
		// later night lands on the same claim. The chain is level-based; re-asserting the spec is how it is
		// meant to be driven, and it will not open a second pull request.
		if kube.StatusOf(err) != 409 {
			return nil, err
		}
		if _, err := api.PatchNamespaced(ctx, PublishGroup, version, Namespace, PublishPlural, name,
			map[string]any{"spec": spec}); err != nil {
			return nil, err
		}
	}
	return &Claim{Name: name, APIVersion: PublishGroup + "/" + version, Branch: branch}, nil
}

// PRBody leads with the EVIDENCE, not the suggestion.
//
// A reviewer's first question is "why do you think so", and a proposal that answers it last gets
// approved on tone. The queries THIS SERVICE ISSUED are rendered below, verbatim, so the claim can be
// re-run and disagreed with — the model is no longer asked to restate them, because when it was it
// supplied a reconstruction that matched nothing that ran.
func PRBody(p map[string]any, runName string, queriesRun map[string]any) string {
	var ev []string
	for _, e := range py.List(p["evidence"]) {
		line := "- **" + py.Str(py.Get(e, "source")) + "**"
		if oc := py.Get(e, "observedCount"); oc != nil {
			line += " (" + py.Str(oc) + " observed)"
		}
		line += " — " + py.Str(py.Get(e, "summary"))
		ev = append(ev, line)
	}
	// THE QUERIES THE SERVICE RAN, NOT THE ONES THE MODEL REMEMBERS RUNNING. These come from evidence.go,
	// which issued them.
	ran := ""
	if len(queriesRun) > 0 {
		var blocks []string
		for _, name := range py.SortedKeys(queriesRun) {
			blocks = append(blocks, fmt.Sprintf("`%s`\n```sql\n%s\n```", name, py.Str(queriesRun[name])))
		}
		ran = "\n\n## Queries this run issued\n\n" + strings.Join(blocks, "\n\n")
	}
	target := py.Get(p, "target")
	path := "(new file)"
	if py.Truthy(py.Get(target, "path")) {
		path = py.Str(py.Get(target, "path"))
	}
	change := py.Get(p, "change")
	return "**Proposed by the nightly platform review — not by a person.** Confidence: `" + py.Str(p["confidence"]) + "`.\n" +
		"\n" +
		"## Why\n" +
		"\n" +
		py.Str(p["rationale"]) + "\n" +
		"\n" +
		"## Evidence\n" +
		"\n" +
		strings.Join(ev, "\n") + ran + "\n" +
		"\n" +
		"## What this changes\n" +
		"\n" +
		"`" + path + "` — " + py.Str(py.Get(change, "format")) + ", " + strconv.Itoa(py.Len(py.Str(py.Get(change, "content")))) + " bytes.\n" +
		"\n" +
		"---\n" +
		"\n" +
		"Confidence is the reviewing model's own judgement of the evidence above, and nothing checks it. If\n" +
		"the evidence does not persuade you, the\n" +
		"right outcome is to close this — a rejected proposal is a working loop, not a failed one.\n" +
		"\n" +
		"Produced by `ReviewRun/" + runName + "` · tracked as `Proposal` in `" + Namespace + "`.\n" +
		"\n" +
		"🤖 Generated with [Claude Code](https://claude.com/claude-code)\n"
}

// THE PHASE VOCABULARY, DECLARED ONCE.
//
// These values used to be bare strings written in one function and matched by literal in another. They
// agreed, so nothing was wrong — but the agreement was invisible and unenforced, and renaming one of
// them would have made OpenIndex match nothing, which does not fail: it silently reports every proposal
// as new and re-proposes the entire backlog.
//
// WrittenPhases is asserted against the CRD's own enum by the test suite, because the apiserver rejects
// an undeclared phase at WRITE time — long after the review has been done and paid for.
const (
	PhaseProposed   = "Proposed"
	PhasePrOpen     = "PrOpen"
	PhaseSuperseded = "Superseded"
	PhaseFailed     = "Failed"
	PhaseRejected   = "Rejected"
	PhaseMerged     = "Merged"
)

// OpenPhases are the phases of an undecided proposal ("" is an absent phase, Python's None).
var OpenPhases = map[string]bool{"": true, PhaseProposed: true, PhasePrOpen: true}

// WrittenPhases are what this service writes; Rejected is written as the mirror of a person's
// spec.decision.
var WrittenPhases = map[string]bool{PhaseProposed: true, PhasePrOpen: true, PhaseSuperseded: true, PhaseFailed: true,
	PhaseRejected: true}

// DecisionPhases are what a person may record in spec.decision. Asserted against the CRD's decision enum
// by the suite.
var DecisionPhases = map[string]bool{PhasePrOpen: true, PhaseRejected: true}

// PersonDecidedPhases are A PERSON'S VERDICT, as opposed to the service's own bookkeeping. Superseded and
// Failed are this service's to set and to undo — the same finding coming back is a reason to re-open
// one. Rejected and Merged are somebody's answer, and a later night re-proposing the same fingerprint must
// not rewrite them.
var PersonDecidedPhases = map[string]bool{PhaseRejected: true, PhaseMerged: true}

// Decision is spec.decision when it carries a phase this service recognises, else nil. A malformed one
// is ignored rather than trusted: the CRD enum should make it impossible, and a proposal this code cannot
// read is left for a person rather than guessed at.
func Decision(p any) any {
	d := py.Get(py.Or(py.Get(p, "spec"), map[string]any{}), "decision")
	if ph, ok := py.Get(d, "phase").(string); ok && py.IsDict(d) && DecisionPhases[ph] {
		return d
	}
	return nil
}

// phaseStr reads a phase value: "" for absent/null (Python's None), and a non-string as no known phase.
func phaseStr(v any) (string, bool) {
	if v == nil {
		return "", true
	}
	s, ok := v.(string)
	return s, ok
}

// EffectivePhase is THE PHASE TO ACT ON: spec.decision's when there is one, status.phase otherwise.
//
// The spec wins because it is newer by construction. The portal writes the decision into the spec
// (snowplow /call cannot reach the status subresource) and this service copies it to status only on its
// next run — so for up to a night status still says Proposed about a proposal a person has already
// rejected.
//
// ONE EXCEPTION: a PrOpen decision whose status has already moved on to Merged. Merge is the outcome the
// pull request reached, and it is later than the decision that opened it.
func EffectivePhase(p any) any {
	statusPhase := py.Get(py.Or(py.Get(p, "status"), map[string]any{}), "phase")
	d := Decision(p)
	if d == nil {
		return statusPhase
	}
	if py.Get(d, "phase") == PhasePrOpen && statusPhase == PhaseMerged {
		return statusPhase
	}
	return py.Get(d, "phase")
}

// PersonDecided reports whether a person has answered this proposal. Either route counts: spec.decision
// or a person-decided phase already on status.
func PersonDecided(p any) bool {
	if Decision(p) != nil {
		return true
	}
	ph, ok := EffectivePhase(p).(string)
	return ok && PersonDecidedPhases[ph]
}

// ProposalName is the Proposal's object name, derived from its fingerprint. Exposed so a supersession
// can name its successor BEFORE the successor is written — the old proposal's supersededBy is set first.
func ProposalName(p map[string]any) string { return "p-" + py.Trunc(py.Str(p["fingerprint"]), 16) }

// CreateProposalCR writes one Proposal. `agent` is who produced the finding, for producedBy.agent: the
// model by default; the sync-stall check names itself, because a counted finding and a judged one should
// not read alike.
func CreateProposalCR(ctx context.Context, api kube.CustomObjects, p map[string]any, runName string, claim *Claim,
	phase string, failure error, conditions []map[string]any, agent string) (string, error) {
	if phase == "" {
		phase = PhaseProposed
	}
	labels := map[string]any{
		"review.krateo.io/kind":       p["kind"],
		"review.krateo.io/run":        runName,
		"review.krateo.io/confidence": p["confidence"],
	}
	// THE CLAIM IS RECORDED AS A LABEL, NOT A STATUS FIELD, and deliberately so: the Proposal CRD is
	// structural with no preserve-unknown-fields, so an undeclared status key is pruned SILENTLY. A label
	// needs no schema change and is selectable, which is what a later reconciler will use to find the
	// claim whose pull request it must read back.
	if claim != nil {
		labels["review.krateo.io/publish-claim"] = claim.Name
	}
	// `subject` only when there is one. The field is optional in the CRD — every proposal written before
	// it existed lacks it — and a JSON null is not an absent string to the apiserver.
	spec := map[string]any{}
	for _, k := range []string{"kind", "subject", "title", "rationale", "evidence", "confidence", "target", "change", "fingerprint"} {
		if v, ok := p[k]; ok && v != nil {
			spec[k] = v
		}
	}
	if agent == "" {
		agent = "krateo-autopilot"
	}
	spec["producedBy"] = map[string]any{"runRef": runName, "agent": agent}
	name := ProposalName(p)
	obj := map[string]any{
		"apiVersion": Group + "/" + Version, "kind": "Proposal",
		"metadata": map[string]any{"name": name, "namespace": Namespace, "labels": labels},
		"spec":     spec,
	}
	created, err := api.CreateNamespaced(ctx, Group, Version, Namespace, "proposals", obj)
	if err != nil {
		// ALREADY THERE, AND THAT IS NORMAL NOW. The name is derived from the fingerprint, and a refused
		// proposal recurs every night with the same one. Before this, night two died on a 409 from a name
		// night one had created.
		if kube.StatusOf(err) != 409 {
			return "", err
		}
		if _, err := api.PatchNamespaced(ctx, Group, Version, Namespace, "proposals", name, map[string]any{"spec": spec}); err != nil {
			return "", err
		}
		if created, err = api.GetNamespaced(ctx, Group, Version, Namespace, "proposals", name); err != nil {
			return "", err
		}
	}
	// PUBLISHING IS ASYNCHRONOUS NOW, so this run cannot know the pull request. It created a claim; the
	// chain opens the PR minutes later, on its own reconcile. Writing PrOpen here would be a guess, and
	// writing status.pullRequest would be a fabrication. Proposed is the honest phase for "handed to the
	// chain, not yet decided".
	conds := []any{}
	for _, c := range conditions {
		m := map[string]any{}
		for k, v := range c {
			m[k] = v
		}
		m["lastTransitionTime"] = now()
		conds = append(conds, m)
	}
	status := map[string]any{"phase": phase, "conditions": conds}
	if failure != nil {
		status["phase"] = PhaseFailed
		status["error"] = py.Trunc(failure.Error(), 500)
	}
	createdName := py.Str(py.GetPath(created, "metadata", "name"))
	if _, err := api.PatchNamespacedStatus(ctx, Group, Version, Namespace, "proposals", createdName,
		map[string]any{"status": status}); err != nil {
		return "", err
	}
	return createdName, nil
}

// Indexes are OpenIndex's answer.
type Indexes struct {
	ByFingerprint map[string]string
	ByTarget      map[string]proposals.Ref
	BySubject     map[string][]proposals.Ref
}

// OpenIndex builds (byFingerprint, byTarget, bySubject) over proposals that are still undecided.
//
// Three indexes because there are three questions. By fingerprint answers "have we said exactly this?" —
// a duplicate, dropped. By target answers "have we said something else about this same file?" — and by
// subject "have we said something else about this same FINDING?". Both of those are replacements.
//
// THE TWO REPLACEMENT INDEXES ARE NARROWER THAN THE FINGERPRINT ONE, deliberately:
//   - PROPOSED ONLY, not PrOpen — for target AND subject. A proposal in PrOpen has a person's pull
//     request hanging off it, and retiring it on the strength of a model's next opinion would orphan work
//     somebody is doing.
//   - EARLIER RUNS ONLY (subject). Two proposals in one run sharing a subject are the model splitting one
//     finding across two changes, not tonight replacing last night.
//   - NEVER A NULL SUBJECT. Legacy proposals carry none; see proposals.SubjectKey.
//
// A PERSON-DECIDED PROPOSAL IS IN NONE OF THE THREE. They go to `decided` (fingerprint -> name) when the
// caller passes a map, so Classify can say the suggestion was already answered and the run leaves the
// object alone. Read through EffectivePhase, so a decision the service has not mirrored yet counts.
func OpenIndex(ctx context.Context, api kube.CustomObjects, runName string, decided map[string]string) (*Indexes, error) {
	got, err := api.ListNamespaced(ctx, Group, Version, Namespace, "proposals")
	if err != nil {
		return nil, err
	}
	idx := &Indexes{ByFingerprint: map[string]string{}, ByTarget: map[string]proposals.Ref{},
		BySubject: map[string][]proposals.Ref{}}
	for _, p := range py.List(got["items"]) {
		spec := py.Or(py.Get(p, "spec"), map[string]any{})
		fpv := py.Get(spec, "fingerprint")
		name := py.Str(py.GetPath(p, "metadata", "name"))
		if !py.Truthy(fpv) || !py.Truthy(py.Get(spec, "kind")) {
			continue
		}
		fp := py.Str(fpv)
		if PersonDecided(p) {
			if decided != nil {
				decided[fp] = name
			}
			continue
		}
		phase, ok := phaseStr(EffectivePhase(p))
		if !ok || !OpenPhases[phase] {
			continue
		}
		idx.ByFingerprint[fp] = name
		if phase == PhaseProposed {
			tk, err := proposals.TargetKey(spec)
			if err != nil {
				return nil, err
			}
			idx.ByTarget[tk] = proposals.Ref{Fingerprint: fp, Name: name}
		}
		if key, ok := proposals.SubjectKey(spec); ok && phase == PhaseProposed &&
			py.Get(py.Or(py.Get(spec, "producedBy"), map[string]any{}), "runRef") != runName {
			idx.BySubject[key] = append(idx.BySubject[key], proposals.Ref{Fingerprint: fp, Name: name})
		}
	}
	return idx, nil
}

// Forget drops a superseded proposal from the indexes, so a second proposal in the same run cannot
// supersede it again and count it twice.
func Forget(name string, idx *Indexes) {
	for k, v := range idx.ByTarget {
		if v.Name == name {
			delete(idx.ByTarget, k)
		}
	}
	for k, refs := range idx.BySubject {
		var kept []proposals.Ref
		for _, r := range refs {
			if r.Name != name {
				kept = append(kept, r)
			}
		}
		idx.BySubject[k] = kept
	}
}

// MarkSuperseded marks the open proposal this one replaces. Status only — the spec of a superseded
// proposal is left exactly as it was, because it is the record of what was suggested and when.
// supersededBy was declared in the CRD from the start and never written; `decidedAt` is set because
// Superseded is terminal.
func MarkSuperseded(ctx context.Context, api kube.CustomObjects, name, by, reason string) error {
	status := map[string]any{"phase": PhaseSuperseded, "decidedAt": now(), "decidedBy": "nightly-review"}
	if by != "" {
		status["supersededBy"] = by
	}
	if reason != "" {
		status["reason"] = reason
	}
	_, err := api.PatchNamespacedStatus(ctx, Group, Version, Namespace, "proposals", name, map[string]any{"status": status})
	return err
}

// ClaimLabel is the label a Proposal's publish claim is recorded under.
const ClaimLabel = "review.krateo.io/publish-claim"

var mirrored = []string{"phase", "decidedBy", "decidedAt", "reason"}

// MirrorDecisions copies every person's spec.decision onto status and returns the number of proposals
// written.
//
// STATUS STAYS THE SERVICE'S RECORD; spec.decision IS THE PERSON'S INPUT. The portal can only write the
// spec, so without this the status of a decided proposal would say Proposed forever, and every reader
// would have to know to look in two places.
//
// IDEMPOTENT BY COMPARISON, NOT BY FLAG: a proposal is written only when a mirrored field differs, so a
// run over a hundred already-mirrored decisions makes no writes at all, and a run that died halfway
// finishes the rest next time. Fields the decision does not carry are left as they are rather than
// cleared.
//
// THE CLAIM IS MIRRORED TO THE LABEL, not to status: status has no field for it, and the label is where
// this service already records the claims it creates itself.
func MirrorDecisions(ctx context.Context, api kube.CustomObjects) (int, error) {
	got, err := api.ListNamespaced(ctx, Group, Version, Namespace, "proposals")
	if err != nil {
		return 0, err
	}
	written := 0
	for _, p := range py.List(got["items"]) {
		d := Decision(p)
		if d == nil {
			continue
		}
		name := py.Str(py.GetPath(p, "metadata", "name"))
		status := py.Or(py.Get(p, "status"), map[string]any{})
		diff := map[string]any{}
		// A merged PR is later than the decision that opened it (see EffectivePhase): status already says
		// more than the decision does, so it is left alone.
		if EffectivePhase(p) == py.Get(d, "phase") {
			for _, k := range mirrored {
				if v := py.Get(d, k); v != nil && !jsonEqual(py.Get(status, k), v) {
					diff[k] = v
				}
			}
		}
		claim := py.Get(d, "claim")
		labels := py.Or(py.GetPath(py.Or(p, map[string]any{}), "metadata", "labels"), map[string]any{})
		wrote := false
		if len(diff) > 0 {
			if _, err := api.PatchNamespacedStatus(ctx, Group, Version, Namespace, "proposals", name,
				map[string]any{"status": diff}); err != nil {
				return written, err
			}
			wrote = true
		}
		if py.Truthy(claim) && !jsonEqual(py.Get(labels, ClaimLabel), claim) {
			if _, err := api.PatchNamespaced(ctx, Group, Version, Namespace, "proposals", name,
				map[string]any{"metadata": map[string]any{"labels": map[string]any{ClaimLabel: claim}}}); err != nil {
				return written, err
			}
			wrote = true
		}
		if wrote {
			written++
		}
	}
	return written, nil
}

// jsonEqual is Python's == for JSON-shaped scalars (1 == 1.0, True == 1).
func jsonEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if x, ok := num(a); ok {
		if y, ok := num(b); ok {
			return x == y
		}
		return false
	}
	return py.Repr(a) == py.Repr(b)
}

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case int64:
		return float64(x), true
	case int:
		return float64(x), true
	case float64:
		return x, true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}
