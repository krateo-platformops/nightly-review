// Package synchealth finds Krateo-managed resources that have been out of sync for longer than anyone
// should have to notice.
//
// WHY THIS EXISTS. On 2026-10-01 the GitHub token in krateo-system/git-provider-credentials expired.
// Every github.krateo.io Repository and PullRequest and every git.krateo.io Repo and LocalResource went
// Synced=False with a 401 and stayed that way for hours — 0 of 24 Repositories synced — and nothing on
// the platform said so. It was found because a publish stalled and a person went looking.
//
// WHAT IT IS, AND WHAT IT IS NOT. A deterministic check, run by the nightly review: no model decides
// whether a resource is failing, and none decides the count. It lists every kind the API serves in the
// configured groups (config.syncStall.groups — DISCOVERED, so a provider that grows a kind is covered the
// night it ships), keeps the objects whose Synced condition is False (or, with no Synced verdict, whose
// Ready is False for a reconcile-error reason) for longer than config.syncStall.thresholdMinutes by the
// condition's own lastTransitionTime, and groups them by provider component and by what the message says
// went wrong. Each group becomes ONE Proposal, written by the service whether or not the model call
// succeeds that night. It is a NIGHTLY BACKSTOP.
//
// THE CONDITION CLOCK HAS ONE BLIND SPOT, stated rather than discovered. provider-runtime's
// SetConditions replaces a condition whenever its MESSAGE changes, and stamps a new lastTransitionTime
// when it does — so a failure whose message carries something that changes every reconcile looks
// perpetually fresh and is never reported as sustained. Every failure under the threshold is therefore
// counted on the run (`freshFailures`) and listed in the corpus.
//
// SECRETS ARE NAMED, NEVER READ. A credential is found by its REFERENCE: a `{name, key}` mapping under a
// `*Ref` key in the failing object's spec or in the spec of the Configuration its `configurationRef`
// names. No Secret is ever fetched, and this service's ServiceAccount still has no verb on Secrets.
package synchealth

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/krateo-platformops/nightly-review/internal/env"
	"github.com/krateo-platformops/nightly-review/internal/kube"
	"github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/pyre"
)

// Configuration. Groups is config.syncStall.groups (group -> {component, kinds}), as JSON. EMPTY HERE,
// like every destination: which groups are checked is the chart's values, never the code's. Empty
// disables the check, and says so.
var (
	Groups           = envJSON("SYNC_STALL_GROUPS")
	ThresholdMinutes = env.IntOr("SYNC_STALL_THRESHOLD_MINUTES", "15")
	// ReadyErrorReasons: Ready=False counts as failing only for these reasons, and only when there is no
	// Synced verdict — Ready is also False while an object is being created or deleted, which is
	// progress, not a stall.
	ReadyErrorReasons = csv("SYNC_STALL_READY_REASONS", "ReconcileError")
	// IgnoreReasons: Synced=False that is somebody's intent rather than a failure — a paused reconcile.
	IgnoreReasons = csv("SYNC_STALL_IGNORE_REASONS", "ReconcilePaused")
)

// Bounds.
var (
	Page        = 500
	MaxPages    = 20 // 10,000 objects of one kind; past that the kind is recorded as cut
	MaxFindings = 10 // one Proposal per (component, pattern); a night that wants more is one incident
)

const (
	examples     = 3
	messageChars = 300
	// Source is the evidence name.
	Source = "sync-health"
	// Agent is producedBy.agent on this check's Proposals.
	Agent = "nightly-review/sync-stall"
)

func envJSON(name string) any {
	raw := os.Getenv(name)
	if raw == "" {
		raw = "{}"
	}
	v, err := py.LoadsJSON(raw, true)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", name, err))
	}
	return v
}

func csv(name, def string) []string {
	raw := os.Getenv(name)
	if raw == "" {
		raw = def
	}
	var out []string
	for _, r := range strings.Split(raw, ",") {
		if s := py.Strip(r); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// http is a status code in HTTP context: beside its reason phrase ("401 Unauthorized") or after a word
// that introduces a status ("status 404", "returned 403"). A bare number is an object's particulars —
// "update pull request 401 in org/repo: 422 Unprocessable Entity" is a 422, and a repository named
// r-404-old is not a 404.
func http(code int, phrase string) string {
	return fmt.Sprintf(`\b(?:http(?:/[\d.]+)?|status(?:\s*code)?|code|returned|got|answered|response)\s*[:=]?\s*%d\b`+
		`|\b%d\s+%s`, code, code, phrase)
}

type pattern struct {
	signal, description string
	re                  *pyre.Regexp
}

// Patterns say what a message says went wrong, most specific first. Each is a stable signal for the
// Proposal's subject, so the same outage tomorrow is the same finding, whatever the counts.
var Patterns = []pattern{
	// A Secret the object (or its Configuration) names does not exist IN THIS CLUSTER. Before every
	// remote pattern: the apiserver's `secrets "x" not found` would otherwise read as a deleted repository.
	{"local-secret-missing", "a Secret the resources reference does not exist in the cluster",
		pyre.MustCompile(`\bsecrets?\s+\"[^\"]*\"\s+not found|\bsecret\b[^:]{0,80}\bnot found\b`, pyre.I)},
	// Before permission-denied: GitHub answers a primary or secondary rate limit with 403, not 429.
	{"rate-limited", "rate limited by the remote API",
		pyre.MustCompile(http(429, "Too Many Requests")+`|rate.?limit|too many requests`, pyre.I)},
	{"credential-rejected", "credential rejected — expired, revoked or wrong",
		pyre.MustCompile(http(401, "Unauthori[sz]ed")+
			`|\bunauthori[sz]ed\b|bad credentials|authentication (?:failed|required)|invalid (?:token|credentials)`, pyre.I)},
	{"permission-denied", "permission denied — token scope, SSO authorisation or an org policy",
		pyre.MustCompile(http(403, "Forbidden")+`|\bforbidden\b|resource not accessible|permission denied`, pyre.I)},
	{"remote-not-found", "remote object not found — deleted, renamed, or not visible to the credential",
		pyre.MustCompile(http(404, "Not Found")+`|repository not found|\bnot found\b`, pyre.I)},
	{"remote-rejected-request", "remote rejected the request as invalid",
		pyre.MustCompile(http(422, "Unprocessable")+`|\bunprocessable\b`, pyre.I)},
	{"remote-unreachable", "remote unreachable — timeout, DNS or connection",
		pyre.MustCompile(`deadline exceeded|timed? ?out|connection refused|connection reset|no such host|\bEOF\b`, pyre.I)},
}

var (
	urlRE           = pyre.MustCompile(`https?://\S+`, 0)
	fallbackStripRE = pyre.MustCompile(`\"[^\"]*\"|'[^']*'|/\S+|\b[0-9a-f]{7,}\b|\d+`, 0)
)

// Classify returns (signal, description) for a failing condition. A message no pattern knows is named
// by its first clause with every quoted string, URL, path and number taken out — Go wraps errors
// outermost-first, so the first clause is the operation that failed and the rest is this object's
// particulars.
func Classify(reason, message any) (string, string) {
	text := py.Str(py.Or(message, ""))
	for _, p := range Patterns {
		if p.re.MatchString(text) {
			return p.signal, p.description
		}
	}
	// URLs out BEFORE the split: "GET https://api.github.com/...: ..." split on its first colon is `GET https`.
	first, _, _ := strings.Cut(urlRE.Sub(text, " "), ": ")
	head := fallbackStripRE.Sub(first, " ")
	slug := py.StripChars(py.Trunc(proposals.Slug(head), 60), "-")
	if slug == "" {
		slug = proposals.Slug(py.Str(py.Or(reason, "")))
		if slug == "" {
			slug = "unknown"
		}
	}
	desc := py.Trunc(py.JoinFields(head), 120)
	if desc == "" {
		desc = "no message"
	}
	return slug, py.Str(py.Or(reason, "failing")) + ": " + desc
}

// Parse reads a condition time. A time with no zone is UTC, as the apiserver writes it. Left naive,
// comparing it with the aware cutoff raised TypeError and cost the night every sync finding.
func Parse(ts any) (time.Time, bool) {
	s, ok := ts.(string)
	if !ok {
		return time.Time{}, false
	}
	t, _, err := py.FromISOFormat(strings.ReplaceAll(s, "Z", "+00:00"))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func conditions(obj any) map[string]any {
	out := map[string]any{}
	for _, c := range py.List(py.GetPath(obj, "status", "conditions")) {
		if py.IsDict(c) {
			out[py.Str(py.Get(c, "type"))] = c
		}
	}
	return out
}

func in(v any, xs []string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// FailingCondition is the condition that says this object is failing, or nil.
//
// Synced is the reconcile's verdict and wins: Synced=True is a healthy object however old or odd its
// Ready condition looks, and a Synced=False carrying an ignored reason (a paused reconcile) is intent.
// Ready is consulted only when there is no Synced verdict at all, and only for a reconcile-error reason.
func FailingCondition(obj any) any {
	conds := conditions(obj)
	synced, ready := conds["Synced"], conds["Ready"]
	if py.Truthy(synced) && py.Get(synced, "status") == "True" {
		return nil
	}
	if py.Truthy(synced) && py.Get(synced, "status") == "False" {
		if in(py.Get(synced, "reason"), IgnoreReasons) {
			return nil
		}
		return synced
	}
	if py.Truthy(ready) && py.Get(ready, "status") == "False" && in(py.Get(ready, "reason"), ReadyErrorReasons) {
		return ready
	}
	return nil
}

// SecretRefs is every `{name, key}` mapping under a `*Ref` key — the Kubernetes shape of a pointer at
// one key of a Secret — as "namespace/name". NAMES ONLY: nothing here, or anywhere in this service,
// reads the Secret.
func SecretRefs(spec any, namespace string) map[string]bool {
	out := map[string]bool{}
	var walk func(node any)
	walk = func(node any) {
		switch {
		case py.IsDict(node):
			for _, k := range py.DictKeys(node) {
				v := py.Get(node, k)
				if strings.HasSuffix(k, "Ref") && py.IsDict(v) && py.IsStr(py.Get(v, "name")) && py.Has(v, "key") {
					ns := py.Get(v, "namespace")
					if !py.Truthy(ns) {
						ns = namespace
					}
					out[py.Str(ns)+"/"+py.Str(py.Get(v, "name"))] = true
				} else {
					walk(v)
				}
			}
		case py.IsList(node):
			for _, v := range py.List(node) {
				walk(v)
			}
		}
	}
	walk(spec)
	return out
}

// Discover lists what a group serves: (version, plural, kind, namespaced), kinds once each.
type Discover func(ctx context.Context, group string) ([]kube.Served, error)

// PathGetter is a raw GET, as ApiClient.call_api.
type PathGetter interface {
	GetPath(ctx context.Context, path string) (any, error)
}

// Discoverer reads the API's discovery documents: every version the group serves, PREFERRED FIRST,
// because a group's kinds need not share one — on 057 github.krateo.io serves its resources at
// v2022-11-28 and their Configurations at v1alpha1, so a scan of the preferred version alone would never
// see a Configuration. A kind is taken at the first version that serves it. Discovery needs no RBAC
// beyond being authenticated. A variable so a test can stand in for discovery.
var Discoverer = func(client PathGetter) Discover {
	return func(ctx context.Context, group string) ([]kube.Served, error) {
		doc, err := client.GetPath(ctx, "/apis/"+group)
		if err != nil {
			return nil, err
		}
		preferred := py.String(py.GetPath(doc, "preferredVersion", "version"))
		var versions []string
		if preferred != "" {
			versions = append(versions, preferred)
		}
		for _, v := range py.List(py.Get(doc, "versions")) {
			if s := py.String(py.Get(v, "version")); s != "" && s != preferred {
				versions = append(versions, s)
			}
		}
		seen := map[string]bool{}
		var out []kube.Served
		for _, version := range versions {
			res, err := client.GetPath(ctx, "/apis/"+group+"/"+version)
			if err != nil {
				return nil, err
			}
			for _, r := range py.List(py.Get(res, "resources")) {
				name := py.String(py.Get(r, "name"))
				kind := py.String(py.Get(r, "kind"))
				hasList := false
				for _, v := range py.List(py.Get(r, "verbs")) {
					if v == "list" {
						hasList = true
					}
				}
				if strings.Contains(name, "/") || !hasList || seen[kind] {
					continue
				}
				seen[kind] = true
				out = append(out, kube.Served{Version: version, Plural: name, Kind: kind,
					Namespaced: py.Truthy(py.Get(r, "namespaced"))})
			}
		}
		return out, nil
	}
}

// List pages through every object of one kind, cluster-wide, recording a cut on stats.
func List(ctx context.Context, api kube.CustomObjects, group, version, plural string, stats map[string]any) ([]any, error) {
	var items []any
	token := ""
	for i := 0; i < MaxPages; i++ {
		got, err := api.ListCluster(ctx, group, version, plural, kube.ListOpts{Limit: Page, Continue: token})
		if err != nil {
			return nil, err
		}
		items = append(items, py.List(got["items"])...)
		token = py.String(py.GetPath(got, "metadata", "continue"))
		if token == "" {
			return items, nil
		}
	}
	stats["note"] = py.Str(py.Or(stats["note"], "")) + fmt.Sprintf("%s.%s: stopped after %d objects; ", plural, group, len(items))
	stats["truncated"] = true
	return items, nil
}

// group is one (component, pattern) finding.
type group struct {
	component, signal, description string
	count                          int
	kinds                          *py.Counter
	groups                         map[string]bool
	examples                       []string
	since                          time.Time
	reasons                        *py.Counter
	messages                       *py.Counter
	secrets                        map[string]bool
	configurations                 map[string]bool
}

// Gather runs the check: (body, stats, proposals). body is the corpus block for the main review (empty
// when nothing is out of sync); proposals are this check's own findings, in the shape the model's are
// validated in, one per (component, pattern) — written by the run whether or not the model answers.
//
// EACH GROUP AND EACH KIND FAILS ON ITS OWN, like every source: a kind that 403s is recorded, ok:false
// makes the run PartiallyCompleted, and the kinds that answered still produce their findings.
//
// now, groups and threshold override the clock and the configuration (zero values mean the defaults).
func Gather(ctx context.Context, api kube.CustomObjects, discover Discover, now time.Time, groups any,
	threshold int) (string, map[string]any, []map[string]any) {
	if now.IsZero() {
		now = py.Now()
	}
	if groups == nil {
		groups = Groups
	}
	if threshold < 0 {
		threshold = ThresholdMinutes
	}
	cutoff := now.Add(-time.Duration(threshold) * time.Minute)
	stats := map[string]any{"ok": true, "queried": int64(0), "returned": int64(0), "stalled": int64(0),
		"freshFailures": int64(0), "findings": int64(0), "thresholdMinutes": int64(threshold)}
	var configured []string
	for _, g := range py.DictKeys(groups) {
		if g != "" && py.IsDict(py.Get(groups, g)) {
			configured = append(configured, g)
		}
	}
	if len(configured) == 0 {
		stats["empty"] = true
		stats["note"] = "config.syncStall.groups is empty; nothing was checked"
		return "", stats, nil
	}
	sort.Strings(configured)

	fail := func(what string, err error) {
		stats["ok"] = false
		stats["error"] = py.Trunc(py.Str(py.Or(stats["error"], ""))+
			proposals.RedactString(fmt.Sprintf("%s: %s; ", what, py.Trunc(err.Error(), 160))), 500)
	}

	grouped := map[[2]string]*group{}
	var groupOrder [][2]string
	fresh := py.NewCounter()
	configCache := map[[4]string]map[string]bool{}
	for _, g := range configured {
		cfg := py.Get(groups, g)
		component := py.Str(py.Get(cfg, "component"))
		if !py.Truthy(py.Get(cfg, "component")) {
			component, _, _ = strings.Cut(g, ".")
		}
		only := map[string]bool{}
		for _, k := range py.List(py.Get(cfg, "kinds")) {
			only[py.Str(k)] = true
		}
		served, err := discover(ctx, g)
		if err != nil {
			// A configured group this cluster does not serve (its provider is not installed) is nothing to
			// check, not a failure: degrading on it would make every run PartiallyCompleted.
			if kube.StatusOf(err) == 404 {
				stats["note"] = py.Str(py.Or(stats["note"], "")) + g + " is not served by this cluster; nothing to check; "
				continue
			}
			fail("discovery of "+g, err)
			continue
		}
		byKind := map[string]kube.Served{}
		for _, s := range served {
			byKind[s.Kind] = s
		}
		for _, s := range served {
			if len(only) > 0 && !only[s.Kind] {
				continue
			}
			items, err := List(ctx, api, g, s.Version, s.Plural, stats)
			if err != nil {
				fail(s.Plural+"."+g, err)
				continue
			}
			stats["queried"] = py.Int(stats["queried"]) + 1
			stats["returned"] = py.Int(stats["returned"]) + int64(len(items))
			for _, obj := range items {
				c := FailingCondition(obj)
				if c == nil {
					continue
				}
				since, ok := Parse(py.Get(c, "lastTransitionTime"))
				if !ok || since.After(cutoff) {
					fresh.Add(s.Kind+"."+g, 1)
					continue
				}
				signal, description := Classify(py.Get(c, "reason"), py.Get(c, "message"))
				key := [2]string{component, signal}
				gr, exists := grouped[key]
				if !exists {
					gr = &group{component: component, signal: signal, description: description,
						kinds: py.NewCounter(), groups: map[string]bool{}, since: since, reasons: py.NewCounter(),
						messages: py.NewCounter(), secrets: map[string]bool{}, configurations: map[string]bool{}}
					grouped[key] = gr
					groupOrder = append(groupOrder, key)
				}
				meta := py.Get(obj, "metadata")
				ns := py.Str(py.Or(py.Get(meta, "namespace"), ""))
				gr.count++
				gr.kinds.Add(s.Kind, 1)
				gr.groups[g] = true
				reason := py.Or(py.Get(c, "reason"), "-")
				gr.reasons.Add(fmt.Sprintf("%s=%s/%s", py.Str(py.Get(c, "type")), py.Str(py.Get(c, "status")), py.Str(reason)), 1)
				msg := py.Str(py.Or(py.Get(c, "message"), ""))
				gr.messages.Add(proposals.RedactString(py.Trunc(msg, messageChars)), 1)
				if since.Before(gr.since) {
					gr.since = since
				}
				if len(gr.examples) < examples {
					where := ""
					if ns != "" {
						where = ns + "/"
					}
					gr.examples = append(gr.examples, fmt.Sprintf("%s %s%s", s.Kind, where, py.Str(py.Get(meta, "name"))))
				}
				spec := py.Or(py.Get(obj, "spec"), map[string]any{})
				for k := range SecretRefs(spec, ns) {
					gr.secrets[k] = true
				}
				ref := py.Get(spec, "configurationRef")
				if py.IsDict(ref) && py.Truthy(py.Get(ref, "name")) {
					cns := py.Str(py.Or(py.Get(ref, "namespace"), ns))
					gr.configurations[fmt.Sprintf("%sConfiguration %s/%s", s.Kind, cns, py.Str(py.Get(ref, "name")))] = true
					var cfgServed *kube.Served
					if cs, ok := byKind[s.Kind+"Configuration"]; ok {
						cfgServed = &cs
					}
					for k := range configurationSecrets(ctx, api, g, cfgServed, cns, py.Str(py.Get(ref, "name")), configCache) {
						gr.secrets[k] = true
					}
				}
			}
		}
	}
	stalled := 0
	findings := make([]*group, 0, len(groupOrder))
	for _, k := range groupOrder {
		stalled += grouped[k].count
		findings = append(findings, grouped[k])
	}
	stats["stalled"] = int64(stalled)
	stats["freshFailures"] = int64(fresh.Total())

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.count != b.count {
			return a.count > b.count
		}
		if a.component != b.component {
			return a.component < b.component
		}
		return a.signal < b.signal
	})
	if len(findings) > MaxFindings {
		stats["note"] = py.Str(py.Or(stats["note"], "")) + fmt.Sprintf("%d smaller group(s) not proposed (over %d); "+
			"they are in the corpus; ", len(findings)-MaxFindings, MaxFindings)
	}
	n := len(findings)
	if n > MaxFindings {
		n = MaxFindings
	}
	stats["findings"] = int64(n)
	if py.Truthy(stats["note"]) {
		stats["note"] = py.Trunc(py.StripChars(py.Str(stats["note"]), "; "), 500)
	}
	if len(findings) == 0 && fresh.Len() == 0 {
		return "", stats, nil
	}
	props := make([]map[string]any, n)
	for i, g := range findings[:n] {
		props[i] = proposal(g, threshold)
	}
	return proposals.RedactString(render(findings, fresh, threshold, props)), stats, props
}

// configurationSecrets is the Secret NAMES a Configuration's spec points at. The Configuration is a
// custom resource in the provider's own group; it is read, the Secret is not.
//
// BEST EFFORT, NEVER A FAILURE OF THE SOURCE. `<Kind>Configuration` is a naming convention, not a
// contract, and a reference may carry no namespace; when the lookup cannot be made or answers nothing,
// the Secret is simply left unnamed. The finding stands without it.
func configurationSecrets(ctx context.Context, api kube.CustomObjects, grp string, served *kube.Served, namespace, name string,
	cache map[[4]string]map[string]bool) map[string]bool {
	if served == nil || namespace == "" {
		return nil
	}
	key := [4]string{grp, served.Plural, namespace, name}
	if hit, ok := cache[key]; ok {
		return hit
	}
	obj, err := api.GetNamespaced(ctx, grp, served.Version, namespace, served.Plural, name)
	if err != nil {
		cache[key] = map[string]bool{}
	} else {
		cache[key] = SecretRefs(py.Or(py.Get(obj, "spec"), map[string]any{}), namespace)
	}
	return cache[key]
}

func kindsText(g *group) string {
	var parts []string
	for _, kv := range g.kinds.MostCommon(-1) {
		parts = append(parts, fmt.Sprintf("%s x%d", kv.Key, kv.Count))
	}
	return strings.Join(parts, ", ")
}

func reasonsText(g *group) string {
	var parts []string
	for _, kv := range g.reasons.MostCommon(-1) {
		parts = append(parts, fmt.Sprintf("%s x%d", kv.Key, kv.Count))
	}
	return strings.Join(parts, ", ")
}

func sortedSet(m map[string]bool) []string {
	out := py.SortedKeys(m)
	return out
}

func head(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

func sinceText(g *group) string { return py.Strftime(g.since, "%Y-%m-%dT%H:%M:%SZ") }

func title(g *group, threshold int) string {
	return py.Trunc(fmt.Sprintf("%s: %d resource(s) out of sync for over %dm — %s (%s)", g.component, g.count, threshold,
		g.description, kindsText(g)), 200)
}

// content is THE PROPOSAL'S BODY, and it HOLDS NOTHING THAT MOVES BY ITSELF. No "for 7 hours", no "as
// of": the fingerprint is computed over it, and the same outage on the next night must produce the same
// body, so it deduplicates instead of piling up. A real change — more objects, another kind, another
// Secret — is a new body under the same subject, and supersedes.
func content(g *group, threshold int) string {
	lines := []string{
		fmt.Sprintf("# %s: resources out of sync — %s", g.component, g.description), "",
		fmt.Sprintf("Measured by the nightly review's sync-stall check, not judged by a model: Krateo-managed "+
			"resources whose Synced condition is False (or whose Ready is False for a reconcile error) "+
			"for longer than %d minutes, by the condition's own lastTransitionTime.", threshold), "",
		fmt.Sprintf("- **Objects:** %d — ", g.count) + kindsText(g),
		"- **API group(s):** " + strings.Join(sortedSet(g.groups), ", "),
		"- **Failing since (earliest):** " + sinceText(g),
		"- **Conditions:** " + reasonsText(g),
		"- **Examples:** " + strings.Join(g.examples, "; "),
	}
	if len(g.configurations) > 0 {
		lines = append(lines, "- **Configurations referenced:** "+strings.Join(head(sortedSet(g.configurations), 10), ", "))
	}
	if len(g.secrets) > 0 {
		lines = append(lines, "- **Secrets referenced (names only; never read):** "+strings.Join(head(sortedSet(g.secrets), 10), ", "))
	}
	lines = append(lines, "", "## What the controllers say", "")
	for _, kv := range g.messages.MostCommon(3) {
		lines = append(lines, fmt.Sprintf("- x%d: `%s`", kv.Count, strings.ReplaceAll(kv.Key, "`", "'")))
	}
	lines = append(lines, "", "## What to check", "")
	switch g.signal {
	case "credential-rejected", "permission-denied":
		lines = append(lines, "The credential these resources use was refused. Expiry, revocation, a narrowed scope "+
			"and a missing SSO authorisation all look like this. Rotate or re-authorise the token in "+
			"the Secret(s) above; the controllers retry on their own, so the conditions clear without "+
			"touching the resources.")
	case "local-secret-missing":
		lines = append(lines, "A Secret these resources (or their Configuration) reference does not exist in the cluster: "+
			"deleted, renamed, or never created in that namespace. Nothing is wrong on the remote side. "+
			"Recreate the Secret named in the controllers' message; the controllers retry on their own.")
	case "remote-not-found":
		lines = append(lines, "The remote object is gone or invisible to the credential: a deleted or renamed "+
			"repository, or a token that lost access to it.")
	default:
		lines = append(lines, "Read the controller's message above against the provider's logs; the objects are "+
			"retried on every reconcile and clear by themselves once the cause is fixed.")
	}
	lines = append(lines, "", "This is a nightly backstop: it finds a stall up to a day after it starts. An in-cluster "+
		"alert on these conditions would find it in minutes.")
	return strings.Join(lines, "\n") + "\n"
}

// proposal is a finding in the contract's own shape, so it crosses the same trust boundary as the
// model's: ValidateBatch redacts it, normalises the subject and fingerprints it; targets.Aim gives it
// the component's configured destination.
func proposal(g *group, threshold int) map[string]any {
	secrets := sortedSet(g.secrets)
	rationale := fmt.Sprintf("%d %s resource(s) (%s) have been failing since %s — %s. Counted by the service from the "+
		"objects' conditions; no model judged it, so confidence is the count's, not an opinion.",
		g.count, strings.Join(sortedSet(g.groups), ", "), kindsText(g), sinceText(g), g.description)
	if len(secrets) > 0 {
		rationale += fmt.Sprintf(" They use the credential(s) in %s (names only; Secrets are never read).",
			strings.Join(head(secrets, 5), ", "))
	}
	summary := fmt.Sprintf("%d object(s) with ", g.count) + reasonsText(g) +
		fmt.Sprintf(" for over %dm; e.g. ", threshold) + strings.Join(g.examples, "; ")
	return map[string]any{
		"kind":       "Documentation",
		"subject":    g.component + "/" + g.signal,
		"title":      title(g, threshold),
		"rationale":  py.Trunc(rationale, 4000),
		"confidence": "high",
		"evidence": []any{map[string]any{"source": "kubernetes", "observedCount": int64(g.count),
			"summary": py.Trunc(summary, 2000)}},
		// No repository of its own: targets.Aim gives it the configured one. A placeholder here read as
		// the model's guess and made Aim note a "retarget" every night.
		"target": map[string]any{"repo": "", "path": g.component + "-" + g.signal + ".md"},
		"change": map[string]any{"format": "markdown", "content": content(g, threshold)},
	}
}

func render(findings []*group, fresh *py.Counter, threshold int, props []map[string]any) string {
	lines := []string{fmt.Sprintf("- OUT OF SYNC for over %dm, measured by this service (each group below is ALREADY "+
		"written as a Proposal by the service under the subject shown; do not propose it again):", threshold)}
	for _, g := range findings {
		subject := g.component + "/" + g.signal
		var p map[string]any
		for _, q := range props {
			if q["subject"] == subject {
				p = q
				break
			}
		}
		line := fmt.Sprintf("  - %dx %s [%s: ", g.count, g.description, strings.Join(sortedSet(g.groups), ", ")) + kindsText(g) + "]"
		if p != nil {
			line += " — subject " + py.Str(p["subject"])
		} else {
			line += " — not proposed (over the per-run cap)"
		}
		line += "; since " + sinceText(g)
		if len(g.secrets) > 0 {
			line += "; Secrets referenced: " + strings.Join(head(sortedSet(g.secrets), 5), ", ")
		}
		lines = append(lines, line)
		for _, kv := range g.messages.MostCommon(1) {
			lines = append(lines, fmt.Sprintf("    > x%d: %s", kv.Count, kv.Key))
		}
	}
	if fresh.Len() > 0 {
		var parts []string
		for _, kv := range fresh.MostCommon(10) {
			parts = append(parts, fmt.Sprintf("%s x%d", kv.Key, kv.Count))
		}
		lines = append(lines, fmt.Sprintf("- failing for less than %dm, or with no lastTransitionTime (not reported; a "+
			"message that changes every reconcile resets the clock and stays here): ", threshold)+strings.Join(parts, ", "))
	}
	return strings.Join(lines, "\n")
}
