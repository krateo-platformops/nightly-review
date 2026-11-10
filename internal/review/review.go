// Package review is one nightly run, start to finish. Invoked by the CronJob; runs once and exits.
//
// THE RUN MUST NEVER END QUIETLY WRONG. Its phase distinguishes Completed from PartiallyCompleted from
// Failed, and every source records why it did or did not answer. A guard that turns failure into green
// is how a sink can be dead for a week while every tick is a tick — this package exists partly to not do
// that.
package review

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/krateo-platformops/nightly-review/internal/analysis"
	"github.com/krateo-platformops/nightly-review/internal/autopilot"
	"github.com/krateo-platformops/nightly-review/internal/coverage"
	"github.com/krateo-platformops/nightly-review/internal/env"
	"github.com/krateo-platformops/nightly-review/internal/evidence"
	"github.com/krateo-platformops/nightly-review/internal/failures"
	"github.com/krateo-platformops/nightly-review/internal/jsonschema"
	"github.com/krateo-platformops/nightly-review/internal/kube"
	"github.com/krateo-platformops/nightly-review/internal/logging"
	"github.com/krateo-platformops/nightly-review/internal/prompt"
	"github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/publish"
	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/synchealth"
	"github.com/krateo-platformops/nightly-review/internal/targets"
)

// The ReviewRun kind and the run's configuration.
const Group, Version = "review.krateo.io", "v1alpha1"

var (
	Namespace   = env.Str("NAMESPACE", "krateo-system")
	WindowHours = env.Int("WINDOW_HOURS", "24")
	DryRun      = strings.ToLower(env.Str("DRY_RUN", "false")) == "true"
	// JobDeadlineSeconds is the Job's own deadline (jobDeadlineSeconds): a ReviewRun still Running and
	// younger than this is a run in progress; an older one was killed past its SIGTERM handler and is not.
	JobDeadlineSeconds = env.IntOr("JOB_DEADLINE_SECONDS", "3600")
	// JobName is the Job this pod belongs to (the downward API's batch.kubernetes.io/job-name label), so
	// the portal can find the ReviewRun a "Run review now" Job produced. Empty outside a Job.
	JobName = env.Str("JOB_NAME", "")
)

// Now is the run's clock (_now). A variable so a test can fix it.
var Now = py.Now

func iso() string { return py.Isoformat(Now()) }

// Clients are the run's handles on the apiserver.
type Clients struct {
	API   kube.CustomObjects
	Core  kube.ConfigMaps
	Paths synchealth.PathGetter
	CRDs  func(ctx context.Context, name string) ([]kube.CRDVersion, error)
}

// Connect is config.load_incluster_config() and the API objects. A variable so a test can stand in a
// fake apiserver.
var Connect = func() (*Clients, error) {
	c, err := kube.InCluster()
	if err != nil {
		return nil, err
	}
	return &Clients{API: c, Core: c, Paths: c, CRDs: c.CRDVersions}, nil
}

// Exit ends the process; a variable so the SIGTERM test can observe the code.
var Exit = os.Exit

// The evidence sources, as variables so a test can stand in for one (the Python suite patched
// main.evidence.<source>).
var (
	clickhouse     = evidence.Clickhouse
	kagentSessions = evidence.KagentSessions
	kubernetes     = evidence.Kubernetes
)

// run is the ReviewRun status under construction, shared with the SIGTERM handler. Every write to it —
// and every write to a map stored inside it — happens under mu, so the handler sees a consistent record.
type run struct {
	mu   sync.Mutex
	api  kube.CustomObjects
	name string
	st   map[string]any
	ev   *py.OMap // st["evidence"], in the order sources answered
}

func (r *run) with(f func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f()
}

// evidence returns status.evidence as coverage reads it.
func (r *run) evidenceMap() map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, k := range r.ev.Keys() {
		v, _ := r.ev.Get(k)
		out[k], _ = v.(map[string]any)
	}
	return out
}

func (r *run) setEvidence(name string, stats map[string]any) {
	r.with(func() { r.ev.Set(name, stats) })
}

// patch writes the whole status (a merge-patch replaces arrays, which is what keeps steps in order).
func (r *run) patch(ctx context.Context) error {
	var body map[string]any
	r.with(func() { body = map[string]any{"status": deepCopy(r.st).(map[string]any)} })
	return patchStatus(ctx, r.api, r.name, body)
}

func patchStatus(ctx context.Context, api kube.CustomObjects, name string, body map[string]any) error {
	_, err := api.PatchNamespacedStatus(ctx, Group, Version, Namespace, "reviewruns", name, body)
	return err
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	case *py.OMap:
		out := py.NewOMap()
		for _, k := range x.Keys() {
			e, _ := x.Get(k)
			out.Set(k, deepCopy(e))
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	}
	return v
}

// steps is status.steps[]: gather, analyse, ask, validate, publish, record — each with its own clock and
// outcome.
//
// WHY A RUN NEEDS MORE THAN ITS PHASE. A Failed run said THAT it failed and, through `error`, roughly
// why, but not WHERE: a 900-second ask that timed out and a validation that refused the answer in 40ms
// both read `Failed`. The portal's run view needs the stage, and a person needs to know whether the model
// was ever called — the expensive part — before deciding what to rerun.
//
// Every transition is patched immediately rather than at the end, so a run killed mid-ask still says
// which step it died in.
type steps struct{ r *run }

func newSteps(r *run) *steps {
	r.with(func() { r.st["steps"] = []any{} })
	return &steps{r}
}

func (s *steps) entry(name string) map[string]any {
	list := s.r.st["steps"].([]any)
	for _, e := range list {
		if m := e.(map[string]any); m["name"] == name {
			return m
		}
	}
	e := map[string]any{"name": name}
	s.r.st["steps"] = append(list, e)
	return e
}

func (s *steps) start(ctx context.Context, name string) error {
	s.r.with(func() {
		e := s.entry(name)
		e["phase"], e["startedAt"] = "Running", iso()
	})
	return s.r.patch(ctx)
}

// end records an outcome. No patch here: every end is followed by the next start or by the run's own
// final patch, and the final patch carries this entry. One write per transition, not two.
func (s *steps) end(name, phase, message string) {
	if phase == "" {
		phase = "Succeeded"
	}
	s.r.with(func() {
		e := s.entry(name)
		now := iso()
		if _, ok := e["startedAt"]; !ok {
			e["startedAt"] = now
		}
		e["phase"], e["finishedAt"] = phase, now
		if message != "" {
			e["message"] = py.Trunc(message, 500)
		}
	})
}

func (s *steps) skip(name, message string) { s.end(name, "Skipped", message) }

func logLine(ctx context.Context, msg string) { logging.Print(ctx, msg) }

// Main runs one review and returns the process exit code. An error no step handles — the Python
// service's uncaught exception — is logged and exits 1, leaving the run's record as it stood.
func Main(ctx context.Context) int {
	code, err := mainRun(ctx)
	if err != nil {
		logLine(ctx, fmt.Sprintf("[run] unhandled error: %s", py.ExcString(err)))
		return 1
	}
	return code
}

func safely[T any](f func() T) (out T, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = py.Errorf("Exception", "%v", p)
		}
	}()
	return f(), nil
}

func mainRun(ctx context.Context) (int, error) {
	clients, err := Connect()
	if err != nil {
		return 1, err
	}
	api := clients.API
	if clients.CRDs != nil {
		publish.ReadCRDVersions = clients.CRDs
	}

	to := Now()
	frm := to.Add(-time.Duration(WindowHours) * time.Hour)
	window := prompt.Window{From: py.Isoformat(frm), To: py.Isoformat(to)}
	windowMap := map[string]any{"from": window.From, "to": window.To}
	busy := runInProgress(ctx, api, to)
	runName, err := createRun(ctx, api, to, windowMap)
	if err != nil {
		return 1, err
	}
	if busy != "" {
		// A "Run review now" Job while another review is still running, or the night's schedule firing
		// during a manual one. The CronJob's concurrencyPolicy: Forbid only governs the Jobs the CronJob
		// itself creates, so a Job made from it by hand is not held back by it — this is what is.
		// Recorded as a run of its own, so the person who pressed the button sees why nothing happened.
		err := patchStatus(ctx, api, runName, map[string]any{"status": map[string]any{
			"phase": "Failed", "startedAt": py.Isoformat(to), "finishedAt": iso(),
			"error": fmt.Sprintf("not run: review %s was still running; two reviews at once would read the same "+
				"window and write the same proposals twice", busy)}})
		if err != nil {
			return 1, err
		}
		logLine(ctx, fmt.Sprintf("[run] %s is still running; %s recorded as not run", busy, runName))
		return 0, nil
	}
	// PEOPLE'S DECISIONS FIRST, AND ON EVERY RUN — before the gather, so a night whose ask or validation
	// fails still brings status up to date. OpenIndex reads spec.decision as authoritative anyway, so a
	// failure here costs the status its freshness for a night and nothing else, which is why it is logged
	// and does not fail the run.
	if mirrored, err := publish.MirrorDecisions(ctx, api); err != nil {
		logLine(ctx, fmt.Sprintf("[run] could not mirror decisions: %s", err))
	} else if mirrored > 0 {
		logLine(ctx, fmt.Sprintf("[run] mirrored %d decision(s) onto status", mirrored))
	}

	r := &run{api: api, name: runName, ev: py.NewOMap()}
	r.st = map[string]any{"phase": "Running", "startedAt": py.Isoformat(to), "evidence": r.ev}
	st := newSteps(r)
	stop := onTerminate(ctx, r)
	defer stop()
	if err := st.start(ctx, "gather"); err != nil {
		return 1, err
	}

	token := autopilot.ServiceJWT(ctx)
	rawQueries, set := os.LookupEnv("CLICKHOUSE_QUERIES")
	if !set {
		rawQueries = "{}"
	}
	queriesAny, err := py.LoadsJSON(rawQueries, true)
	if err != nil {
		return 1, err
	}
	queries, _ := queriesAny.(*py.OMap)
	if queries == nil {
		queries = py.NewOMap()
	}

	blocks := map[string]string{}
	chBody, chStats := clickhouse(ctx, queries, window)
	sessions, ksStats := kagentSessions(ctx, api, window, 200)
	kBody, kStats := kubernetes(ctx, api)
	r.setEvidence("clickhouse", chStats)
	if chBody != "" {
		blocks["clickhouse"] = chBody
	}
	r.setEvidence("kagent-sessions", ksStats)
	if sessions != nil && sessions.Text != "" {
		blocks["kagent-sessions"] = sessions.Text
	}
	r.setEvidence("kubernetes", kStats)
	if kBody != "" {
		blocks["kubernetes"] = kBody
	}

	// THE DAY'S REAL FAILURES: the Incidents of the window, and the Compositions that were not healthy in
	// it. Read from the apiserver, not ranked by log volume, and placed first in the prompt. The
	// compositions read also yields each blueprint's source repository, from its CompositionDefinition,
	// for targets to aim a proposal about that blueprint at.
	type readResult struct {
		body  string
		stats map[string]any
		found []targets.NamedRepo
	}
	discover := synchealth.Discoverer(clients.Paths)
	for _, src := range []struct {
		name string
		read func() readResult
	}{
		{failures.IncidentsSource, func() readResult {
			b, s := failures.Incidents(ctx, api, window)
			return readResult{b, s, nil}
		}},
		{failures.CompositionsSource, func() readResult {
			b, s, f := failures.Compositions(ctx, api, discover, window, targets.BlueprintOrgs(nil), nil)
			return readResult{b, s, f}
		}},
	} {
		res, err := safely(src.read)
		if err != nil {
			res = readResult{"", map[string]any{"ok": false, "error": py.Trunc(proposals.RedactString(py.ExcString(err)), 300)}, nil}
		}
		r.setEvidence(src.name, res.stats)
		if res.body != "" {
			blocks[src.name] = res.body
		}
		if len(res.found) > 0 {
			targets.RegisterBlueprints(res.found, nil)
		}
	}

	// THE SERVICE'S OWN FINDINGS: resources out of sync past the threshold (synchealth). Counted, not
	// judged, so they do not wait for the model — validated, redacted and aimed here, through the same
	// boundary as the model's proposals, and WRITTEN EVEN WHEN THE ASK FAILS. 2026-10-01's expired token
	// went unreported for hours; a backstop that also died whenever the model did would not have been one.
	type syncResult struct {
		body  string
		stats map[string]any
		props []map[string]any
	}
	sres, err := safely(func() syncResult {
		b, s, p := synchealth.Gather(ctx, api, discover, time.Time{}, nil, -1)
		return syncResult{b, s, p}
	})
	if err != nil {
		sres = syncResult{"", map[string]any{"ok": false, "error": py.Trunc(proposals.RedactString(py.ExcString(err)), 300)}, nil}
	}
	r.setEvidence(synchealth.Source, sres.stats)
	if sres.body != "" {
		blocks[synchealth.Source] = sres.body
	}
	service, serviceNotes, err := serviceFindings(sres.props)
	if err != nil {
		return 1, err
	}

	if len(blocks) == 0 {
		// Nothing answered. This is a FAILED run, not an uneventful one — "no proposals" from a healthy
		// night and "no proposals" from a blind one look identical on a dashboard and mean opposite things.
		st.end("gather", "Failed", "no evidence source answered")
		r.with(func() {
			r.st["phase"], r.st["finishedAt"] = "Failed", iso()
			r.st["error"] = "no evidence source answered; nothing was reviewed"
		})
		if err := recordServiceOnly(ctx, r, st, service); err != nil {
			return 1, err
		}
		if err := r.patch(ctx); err != nil {
			return 1, err
		}
		logLine(ctx, "[run] no evidence; failed")
		return 1, nil
	}
	var failedSources []string
	r.with(func() {
		for _, k := range r.ev.Keys() {
			v, _ := r.ev.Get(k)
			if !py.Truthy(py.Get(v, "ok")) {
				failedSources = append(failedSources, k)
			}
		}
	})
	gatherMsg := "answered: " + strings.Join(py.SortedKeys(blocks), ", ")
	if len(failedSources) > 0 {
		gatherMsg += "; failed: " + strings.Join(failedSources, ", ")
	}
	st.end("gather", "", gatherMsg)

	// EVERY MODEL CALL THE RUN MAKES, with the usage each reported — see usageOf.
	var calls []map[string]any

	// THE ANALYSE STAGE: one call per agent over its conversations in full, and only the ASSESSMENTS go on
	// to the main call. It degrades, never blanks: one agent's failure is recorded on that agent; all of
	// them failing is ok:false on the source, the run becomes PartiallyCompleted, and the main review still
	// runs on everything else.
	if err := st.start(ctx, "analyse"); err != nil {
		return 1, err
	}
	type analysed struct {
		assessments []analysis.Assessment
		stats       map[string]any
		calls       []map[string]any
	}
	ares, err := safely(func() analysed {
		a, s, c := analysis.Analyse(ctx, api, clients.Core, window, runName, token, analysis.AskFunc(autopilot.Ask))
		return analysed{a, s, c}
	})
	if err != nil {
		ares = analysed{nil, map[string]any{"ok": false, "scope": analysis.Scope,
			"error": py.Trunc(proposals.RedactString(py.ExcString(err)), 300)}, nil}
	}
	astats := ares.stats
	r.setEvidence("agent-analysis", astats)
	calls = append(calls, ares.calls...)
	if len(ares.assessments) > 0 {
		r.with(func() {
			blocks["agent-analysis"] = analysis.RenderForReview(ares.assessments, astats)
			r.st["agentAnalysis"] = map[string]any{"assessments": analysis.Stored(ares.assessments)}
			// Not paid for twice: the questions of every agent the analysis read are folded to a pointer.
			if _, ok := blocks["kagent-sessions"]; ok {
				sessions = evidence.FoldQuestions(sessions, ksStats, analysis.CoveredAgentKeys(ares.assessments))
				blocks["kagent-sessions"] = sessions.Text
			}
		})
	}
	agentsFailed := 0
	for _, rec := range py.List(astats["agents"]) {
		if py.Truthy(py.Get(rec, "error")) {
			agentsFailed++
		}
	}
	analysePhase := "Failed"
	if py.Truthy(astats["ok"]) {
		analysePhase = "Succeeded"
	}
	analyseMsg := py.Str(py.Or(py.Or(astats["error"], astats["note"]), ""))
	if analyseMsg == "" {
		returned := any(int64(0))
		if v, ok := astats["returned"]; ok {
			returned = v
		}
		analyseMsg = fmt.Sprintf("%s agent(s) analysed, %d failed", py.Str(returned), agentsFailed)
	}
	st.end("analyse", analysePhase, analyseMsg)

	// A SOURCE THAT FAILED IS DEGRADATION. A SOURCE THAT IS LEGITIMATELY EMPTY IS NOT.
	//
	// `empty` used to count as degraded on the reasoning that a source returning nothing has not really
	// been read. That was right for a source that might have had something; it is wrong for one that
	// CANNOT. So: not-ok is degradation; empty is degradation only when nothing explains it. A source that
	// says `ok` and carries a note about why it is empty has been read, and the answer was "nothing".
	var degraded, explainedEmpty []string
	var cov map[string]any
	r.with(func() {
		for _, k := range r.ev.Keys() {
			s, _ := r.ev.Get(k)
			ok, empty, note := py.Truthy(py.Get(s, "ok")), py.Truthy(py.Get(s, "empty")), py.Truthy(py.Get(s, "note"))
			if !ok || (empty && !note) {
				degraded = append(degraded, k)
			}
			if ok && empty && note {
				explainedEmpty = append(explainedEmpty, k)
			}
		}
		// WHAT THE REVIEW IS ABOUT TO SEE, counted before it sees it — so the main model is told, and so a
		// run that fails at the ask still records it. When anything was cut the sentence is the summary
		// until the model's own is appended to it; see package coverage.
		cov = coverage.Compute(r.evidenceMap())
		r.st["coverage"] = cov
		if !py.Truthy(cov["complete"]) {
			r.st["summary"] = cov["sentence"]
		}
	})
	if len(explainedEmpty) > 0 {
		logLine(ctx, fmt.Sprintf("[run] empty but explained, not counted as degraded: %s", py.Repr(explainedEmpty)))
	}

	// `raw` is bound OUTSIDE the ask on purpose. When validation refuses a response, the one thing needed
	// to fix it is the response. ASK AND VALIDATE ARE TWO STEPS, because they fail for unrelated reasons
	// and the fix for each is different: an ask that fails is the agent or the network; a validation that
	// fails is the contract.
	raw := ""
	step := "ask"
	var payload any
	var kept []map[string]any
	var notes []string
	err = func() error {
		if err := st.start(ctx, "ask"); err != nil {
			return err
		}
		components := py.NewOMap()
		for _, k := range targets.Blueprints.Keys() {
			v, _ := targets.Blueprints.Get(k)
			components.Set(k, v)
		}
		for _, k := range py.DictKeys(targets.Components) {
			components.Set(k, py.Get(targets.Components, k))
		}
		message := prompt.BuildUserMessage(window, blocks, py.Str(cov["sentence"]), targets.Destinations, components)
		var usage autopilot.Usage
		var aerr error
		payload, raw, usage, aerr = autopilot.Ask(ctx, prompt.System, message, runName, token, "", 0)
		if aerr != nil {
			return aerr
		}
		st.end("ask", "", "")
		// THE MODEL FIELD IS WRITTEN ONLY WHEN THE AGENT REPORTED USAGE. Absent means "not reported".
		call := map[string]any{"step": "ask"}
		for k, v := range usage {
			call[k] = v
		}
		calls = append(calls, call)
		r.with(func() {
			if len(usage) > 0 {
				r.st["model"] = map[string]any(usage)
			}
			r.st["usage"] = usageOf(calls)
		})
		step = "validate"
		if err := st.start(ctx, "validate"); err != nil {
			return err
		}
		var verr error
		kept, notes, verr = proposals.ValidateBatch(payload,
			func(p any) error { return jsonschema.Validate(p, prompt.ResponseSchema) },
			func(p any) error { return jsonschema.Validate(p, prompt.ItemSchema) })
		return verr
	}()
	if err != nil {
		msg := py.ExcString(err)
		r.with(func() {
			if len(calls) > 0 {
				r.st["usage"] = usageOf(calls)
			}
		})
		st.end(step, "Failed", msg)
		// REDACTED BEFORE IT IS STORED OR PRINTED, through the same path a proposal takes. This text is
		// model output summarising a corpus that has held credentials, and a diagnostic that leaks one into
		// a CR and a pod log is a worse bug than the failure it explains.
		excerpt := ""
		if raw != "" {
			excerpt = py.Trunc(proposals.RedactString(raw), 1800)
		}
		r.with(func() {
			r.st["phase"], r.st["finishedAt"], r.st["error"] = "Failed", iso(), py.Trunc(msg, 500)
			if excerpt != "" {
				r.st["conditions"] = []any{map[string]any{"type": "AgentResponse", "status": "False", "reason": "Unusable",
					"message": excerpt, "lastTransitionTime": iso()}}
			}
		})
		if err := recordServiceOnly(ctx, r, st, service); err != nil {
			return 1, err
		}
		if err := r.patch(ctx); err != nil {
			return 1, err
		}
		logLine(ctx, fmt.Sprintf("[run] agent/validation failed: %s", err.Error()))
		if excerpt != "" {
			logLine(ctx, fmt.Sprintf("[run] response began: %s", py.Trunc(excerpt, 600)))
		}
		return 1, nil
	}

	// The model's own account of the night, which the response contract has always asked for and the run
	// never kept. Redacted like every other model string before it reaches a CR.
	modelSummary := ""
	if s, ok := py.Get(payload, "summary").(string); ok && py.IsDict(payload) {
		modelSummary = proposals.RedactString(s)
	}
	if summary := coverage.Summary(cov, modelSummary); summary != "" {
		r.with(func() { r.st["summary"] = summary })
	}

	// WHERE A PROPOSAL LANDS IS NEVER THE MODEL'S TO CHOOSE. The chart's values say it — config.targets
	// per kind, then config.destinations.components per subject component — and a proposal they name no
	// destination for gets none. Before classification and publishing, and the FINGERPRINT IS RECOMPUTED
	// after a move: a proposal named by a target it no longer has would never dedup against itself
	// tomorrow (#34 retargeted without recomputing).
	for _, p := range kept {
		if moved := targets.Aim(p, nil, nil); moved != "" {
			notes = append(notes, moved)
			fp, err := proposals.Fingerprint(p)
			if err != nil {
				return 1, err
			}
			p["fingerprint"] = fp
		}
	}
	// The service's own findings were aimed when they were validated, after the gather. A MODEL proposal
	// about the same subject is dropped: the prompt says those groups are already proposed, and a model
	// that writes one anyway would supersede the counted finding with a judged copy of it or sit beside it
	// as a duplicate the reader has to reconcile.
	notes = append(notes, serviceNotes...)
	serviceSubjects := map[string]bool{}
	for _, p := range service {
		if s := py.Get(p, "subject"); py.Truthy(s) {
			serviceSubjects[py.Str(s)] = true
		}
	}
	var modelKept []map[string]any
	for _, p := range kept {
		if s, ok := p["subject"].(string); ok && serviceSubjects[s] {
			notes = append(notes, fmt.Sprintf("DROPPED model %s proposal about %s: the sync-stall check already proposed "+
				"that subject this run", py.Str(p["kind"]), s))
			continue
		}
		modelKept = append(modelKept, p)
	}
	modelCount := len(modelKept)
	kept = append(modelKept, service...)

	// Decided per proposal, BEFORE anything is written; see planOf.
	plan, deduped, answered, err := planOf(ctx, api, runName, kept)
	if err != nil {
		return 1, err
	}
	unresolved := 0
	for _, it := range plan {
		if it.target["status"] == "False" {
			unresolved++
		}
	}
	vmsg := fmt.Sprintf("%d valid", modelCount)
	if len(service) > 0 {
		vmsg += fmt.Sprintf(" + %d from the sync-stall check", len(service))
	}
	vmsg += fmt.Sprintf(", %d duplicate, %d already decided, %d unresolved target(s)", deduped, answered, unresolved)
	if len(notes) > 0 {
		vmsg += fmt.Sprintf(", %d note(s)", len(notes))
	}
	st.end("validate", "", vmsg)

	// The queries this run ACTUALLY issued, by name, straight from the source that issued them. The pull
	// request body quotes these rather than the model's recollection of them.
	queriesRun, _ := py.Or(chStats["queries"], map[string]any{}).(map[string]any)
	claims := map[string]claimResult{}
	if DryRun {
		// THE NORMAL CASE, NOT A DEGRADED ONE. The portal opens pull requests per proposal, from the
		// Proposal object, when a person decides to; this service stays in dry run permanently. The step
		// is recorded as Skipped so the run says so rather than implying publishing was attempted.
		st.skip("publish", "dryRun: pull requests are opened from the portal, per proposal")
	} else {
		if err := st.start(ctx, "publish"); err != nil {
			return 1, err
		}
		// Resolved ONCE per run rather than per proposal: the BuilderPublish kind is version-pinned by the
		// portal release that shipped it, and a run that published ten proposals should not make ten
		// identical discovery calls — nor straddle a version change halfway through a night.
		version, err := publish.PublishVersion(ctx)
		if err != nil {
			logLine(ctx, fmt.Sprintf("[publish] cannot resolve the BuilderPublish version: %s", err))
			version = ""
		}
		failed := 0
		for _, it := range plan {
			// A repository GitHub says does not exist gets no claim: repository.create is false, so the
			// chain would fail on it, later and less legibly. The proposal is still written below.
			if it.target["status"] == "False" {
				continue
			}
			fp := py.Str(it.prop["fingerprint"])
			claim, err := publish.CreatePublishClaim(ctx, api, it.prop, runName, version, queriesRun)
			if err != nil {
				failed++
				claims[fp] = claimResult{nil, err}
				logLine(ctx, fmt.Sprintf("[publish] claim failed for %s: %s", py.Repr(it.prop["title"]), err))
				continue
			}
			claims[fp] = claimResult{claim, nil}
		}
		phase, msg := "Succeeded", "nothing to publish"
		if failed > 0 {
			phase = "Failed"
		}
		if len(claims) > 0 {
			msg = fmt.Sprintf("%d claim(s), %d failed", len(claims)-failed, failed)
		}
		st.end("publish", phase, msg)
	}

	if err := st.start(ctx, "record"); err != nil {
		return 1, err
	}
	created, superseded, refs, err := record(ctx, api, runName, plan, claims, service)
	if err != nil {
		return 1, err
	}
	st.end("record", "", fmt.Sprintf("%d written, %d superseded", created, superseded))

	retention := env.Int("RUN_RETENTION_DAYS", "30")
	var phase string
	r.with(func() {
		phase = "Completed"
		if len(degraded) > 0 {
			phase = "PartiallyCompleted"
		}
		r.st["phase"] = phase
		r.st["finishedAt"] = iso()
		// `refused` is intentionally not written any more: the allowlist that produced it is gone. The
		// field stays in the CRD so the runs that recorded one remain readable.
		r.st["proposals"] = map[string]any{"created": int64(created), "deduplicated": int64(deduped),
			"superseded": int64(superseded), "refs": refs}
		r.st["expiresAt"] = py.Isoformat(Now().Add(time.Duration(retention) * 24 * time.Hour))
		if len(notes) > 0 {
			// Validation notes are part of the record: a dropped alert kind, a subject that could not be
			// normalised, a redaction — each is something the next change to the prompt needs to know.
			r.st["conditions"] = []any{map[string]any{"type": "ValidationNotes", "status": "True", "reason": "Notes",
				"message": py.Trunc(strings.Join(notes, " | "), 2000), "lastTransitionTime": iso()}}
		}
	})
	if err := r.patch(ctx); err != nil {
		return 1, err
	}
	if degraded == nil {
		degraded = []string{}
	}
	logLine(ctx, fmt.Sprintf("[run] %s: %d proposed, %d deduped, %d already decided, %d superseded, %d unresolved target(s), degraded=%s",
		phase, created, deduped, answered, superseded, unresolved, py.Repr(degraded)))
	return 0, nil
}

type claimResult struct {
	claim *publish.Claim
	err   error
}

// runInProgress returns the name of a ReviewRun still Running and younger than the Job's deadline, or
// "". Best effort: a list that fails must not stop the night's review, so it answers "" and the run goes
// ahead.
func runInProgress(ctx context.Context, api kube.CustomObjects, now time.Time) string {
	got, err := api.ListNamespaced(ctx, Group, Version, Namespace, "reviewruns")
	if err != nil {
		logLine(ctx, fmt.Sprintf("[run] could not list ReviewRuns to check for one in progress: %s", err))
		return ""
	}
	for _, r := range py.List(got["items"]) {
		st := py.Or(py.Get(r, "status"), map[string]any{})
		started, ok := synchealth.Parse(py.Get(st, "startedAt"))
		if py.Get(st, "phase") == "Running" && ok && now.Sub(started).Seconds() < float64(JobDeadlineSeconds) {
			return py.Str(py.GetPath(r, "metadata", "name"))
		}
	}
	return ""
}

// createRun creates this run's ReviewRun and returns its name: rr-YYYYMMDD-HHMM from the ACTUAL start
// time. The nightly schedule makes rr-…-0200; a run started by hand at 10:37 makes rr-…-1037, so the two
// never share a name. Two started inside the same minute would, and the second must not fail on a 409
// before it has reviewed anything — it takes the seconds as well, rr-YYYYMMDD-HHMMSS.
func createRun(ctx context.Context, api kube.CustomObjects, start time.Time, window map[string]any) (string, error) {
	var labels map[string]any
	if JobName != "" && py.Len(JobName) <= 63 {
		labels = map[string]any{"review.krateo.io/job": JobName}
	}
	formats := []string{"%Y%m%d-%H%M", "%Y%m%d-%H%M%S"}
	for i, f := range formats {
		name := "rr-" + py.Strftime(start, f)
		meta := map[string]any{"name": name, "namespace": Namespace}
		if labels != nil {
			meta["labels"] = labels
		}
		_, err := api.CreateNamespaced(ctx, Group, Version, Namespace, "reviewruns", map[string]any{
			"apiVersion": Group + "/" + Version, "kind": "ReviewRun", "metadata": meta,
			// incidents and compositions are NOT listed: spec.sources is an enum in the CRD, and an image
			// rolled ahead of its CRDs would have every run refused at creation. status.evidence records
			// them, which is where a reader looks for what answered.
			"spec": map[string]any{"window": window, "sources": []any{"clickhouse", "kagent-sessions", "kubernetes",
				"agent-analysis", synchealth.Source}, "dryRun": DryRun},
		})
		if err == nil {
			return name, nil
		}
		if _, isAPI := err.(*kube.APIError); !isAPI || kube.StatusOf(err) != 409 || i == len(formats)-1 {
			return "", err
		}
	}
	return "", py.Errorf("RuntimeError", "unreachable")
}

// serviceFindings passes the sync-stall check's proposals through the SAME boundary as the model's —
// the contract's item schema, redaction, subject normalisation, fingerprint — then aims them by the
// values like any other. Their strings come from controller messages, which quote remote APIs: as
// untrusted as anything else in the corpus.
func serviceFindings(props []map[string]any) ([]map[string]any, []string, error) {
	if len(props) == 0 {
		return nil, nil, nil
	}
	items := make([]any, len(props))
	for i, p := range props {
		items[i] = p
	}
	kept, notes, err := proposals.ValidateBatch(map[string]any{"proposals": items},
		func(p any) error { return jsonschema.Validate(p, prompt.ResponseSchema) },
		func(p any) error { return jsonschema.Validate(p, prompt.ItemSchema) })
	if err != nil {
		return nil, nil, err
	}
	for i, n := range notes {
		notes[i] = "sync-stall " + n
	}
	for _, p := range kept {
		moved := targets.Aim(p, nil, nil)
		// Only "no destination" is worth a note: the service set no repository of its own, so a
		// "retargeted" line would be the values doing their job, every night.
		if moved != "" && strings.Contains(moved, " cleared: ") {
			notes = append(notes, moved)
		}
		fp, err := proposals.Fingerprint(p)
		if err != nil {
			return nil, nil, err
		}
		p["fingerprint"] = fp
	}
	return kept, notes, nil
}

type planItem struct {
	prop   map[string]any
	priors []string
	target targets.Condition
}

// planOf decides, per proposal and BEFORE anything is written, which are duplicates, which replace an
// open one, and whether the repository each names exists. The existence check lives here because it is
// a fact about the proposal, not about publishing — a dry run needs it as much as a live one.
func planOf(ctx context.Context, api kube.CustomObjects, runName string, kept []map[string]any) ([]planItem, int, int, error) {
	decided := map[string]string{}
	idx, err := publish.OpenIndex(ctx, api, runName, decided)
	if err != nil {
		return nil, 0, 0, err
	}
	var plan []planItem
	deduped, answered := 0, 0
	resolved := map[string]targets.Condition{}
	for _, p := range kept {
		// FOUR OUTCOMES. Identical to something already open is a duplicate; identical to something a
		// person already answered is left alone; the same finding (kind + subject) or the same file with a
		// different body is a replacement, and saying so is what `superseded` meant.
		c, err := proposals.Classify(p, idx.ByFingerprint, idx.ByTarget, idx.BySubject, decided)
		if err != nil {
			return nil, 0, 0, err
		}
		switch c.Action {
		case "dedup":
			deduped++
			continue
		case "decided":
			// Not counted as deduplicated: the ReviewRun declares that as "an OPEN proposal already carried
			// the fingerprint", and this one is closed. The step message carries the count.
			answered++
			continue
		}
		// No destination is not a question for GitHub: there is no repository to ask about, and the
		// condition says which value is missing. False, so the publish loop gives it no claim.
		var cond targets.Condition
		if repo := py.Get(p["target"], "repo"); py.Truthy(repo) {
			cond = targets.Resolve(ctx, py.Str(repo), resolved)
		} else {
			cond = targets.NoDestinationCondition(p, nil, nil)
		}
		var priors []string
		if c.Action == "supersede" {
			priors = c.Priors
		}
		plan = append(plan, planItem{p, priors, cond})
		// Forgotten as soon as they are claimed, so a second proposal in this run with the same subject
		// does not supersede the same prior again and count it twice.
		for _, name := range priors {
			publish.Forget(name, idx)
		}
	}
	return plan, deduped, answered, nil
}

// record writes the plan: (created, superseded, refs). A proposal from the sync-stall check says so in
// producedBy.agent: it was counted by the service, and a reader weighing it should not think a model
// judged it.
func record(ctx context.Context, api kube.CustomObjects, runName string, plan []planItem, claims map[string]claimResult,
	service []map[string]any) (int, int, []any, error) {
	serviceFPs := map[string]bool{}
	for _, p := range service {
		serviceFPs[py.Str(p["fingerprint"])] = true
	}
	created, superseded := 0, 0
	refs := []any{}
	for _, it := range plan {
		name := publish.ProposalName(it.prop)
		for _, prior := range it.priors {
			if err := publish.MarkSuperseded(ctx, api, prior, name, fmt.Sprintf("superseded by %s in %s", name, runName)); err != nil {
				return 0, 0, nil, err
			}
			superseded++
		}
		fp := py.Str(it.prop["fingerprint"])
		cr := claims[fp]
		agent := ""
		if serviceFPs[fp] {
			agent = synchealth.Agent
		}
		ref, err := publish.CreateProposalCR(ctx, api, it.prop, runName, cr.claim, "", cr.err,
			[]map[string]any{it.target}, agent)
		if err != nil {
			return 0, 0, nil, err
		}
		refs = append(refs, ref)
		created++
	}
	return created, superseded, refs, nil
}

// recordServiceOnly writes the sync-stall findings for a run that fails before its own record step:
// they never depended on the model, and a credential outage is exactly the night the rest may fail too.
// Never published — publishing is the record step's, and this run did not reach it. A failure here is
// logged and leaves the run's own failure as the story.
func recordServiceOnly(ctx context.Context, r *run, st *steps, service []map[string]any) error {
	if len(service) == 0 {
		return nil
	}
	if err := st.start(ctx, "record"); err != nil {
		return err
	}
	err := func() error {
		plan, deduped, _, err := planOf(ctx, r.api, r.name, service)
		if err != nil {
			return err
		}
		created, superseded, refs, err := record(ctx, r.api, r.name, plan, map[string]claimResult{}, service)
		if err != nil {
			return err
		}
		r.with(func() {
			r.st["proposals"] = map[string]any{"created": int64(created), "deduplicated": int64(deduped),
				"superseded": int64(superseded), "refs": refs}
		})
		st.end("record", "", fmt.Sprintf("sync-stall findings only: %d written, %d superseded", created, superseded))
		return nil
	}()
	if err != nil {
		st.end("record", "Failed", "sync-stall findings: "+py.ExcString(err))
		logLine(ctx, fmt.Sprintf("[run] could not record the sync-stall findings: %s", err))
	}
	return nil
}

// usageOf is status.usage: every model call with the tokens IT reported, and a total over the ones that
// did.
//
// HONEST ABOUT WHAT IT DOES NOT KNOW. A call that reported nothing is listed with no token fields, and
// the total says how many calls it covers — a total summed over three of five calls is not the night's
// cost, and without `reportedCalls` beside it nothing would say so.
func usageOf(calls []map[string]any) map[string]any {
	keys := []string{"inputTokens", "outputTokens", "totalTokens"}
	var reported []map[string]any
	for _, c := range calls {
		for _, k := range keys {
			if _, ok := c[k]; ok {
				reported = append(reported, c)
				break
			}
		}
	}
	total := map[string]any{"calls": int64(len(calls)), "reportedCalls": int64(len(reported))}
	for _, k := range keys {
		any := false
		var sum int64
		for _, c := range reported {
			if v, ok := c[k]; ok {
				any = true
				sum += py.Int(v)
			}
		}
		if any {
			total[k] = sum
		}
	}
	shown := calls
	if len(shown) > 40 {
		shown = shown[:40]
	}
	list := make([]any, len(shown))
	for i, c := range shown {
		list[i] = c
	}
	return map[string]any{"calls": list, "total": total}
}

// onTerminate makes sure a run the Job kills does not stay Running forever.
//
// The analyse stage made the run depend on external model calls for up to ~25 more minutes, so the
// CronJob carries activeDeadlineSeconds. When that deadline (or an eviction) fires, the kubelet sends
// SIGTERM and waits terminationGracePeriodSeconds before SIGKILL. Without this handler the ReviewRun
// would say Running, with a step Running, indefinitely: a record that lies about a run that is over. The
// handler runs on its own goroutine, so it fires even while a model call is blocked.
func onTerminate(ctx context.Context, r *run) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case sig := <-ch:
			terminate(ctx, r, sig)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// terminate records the run and its running step as Failed, patches, and exits 143.
func terminate(ctx context.Context, r *run, sig os.Signal) {
	r.with(func() {
		now := iso()
		for _, e := range py.List(r.st["steps"]) {
			if m, ok := e.(map[string]any); ok && m["phase"] == "Running" {
				m["phase"], m["finishedAt"], m["message"] = "Failed", now, "terminated (SIGTERM)"
			}
		}
		r.st["phase"], r.st["finishedAt"] = "Failed", now
		r.st["error"] = "terminated before finishing: the Job's activeDeadlineSeconds was reached, or the pod was evicted"
	})
	defer func() {
		num := 15
		if s, ok := sig.(syscall.Signal); ok {
			num = int(s)
		}
		logLine(ctx, fmt.Sprintf("[run] terminated by signal %d; recorded as Failed", num))
		Exit(143)
	}()
	_ = r.patch(ctx)
}
