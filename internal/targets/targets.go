// Package targets answers two questions about a proposal: where the chart's values say it lands, and
// whether that repository actually exists. The second is recorded as a condition, never enforced.
//
// WHY EXISTENCE IS A QUESTION AT ALL. `target.repo` used to be chosen by the model, and it invents
// repositories. Of the twenty proposals on 057 on 2026-09-29, TWELVE named a repository that does not
// exist. A reviewer reading one of those has no way to tell from the object that the pull request it
// proposes could never be opened.
//
// A NORMAL STATE, NOT A REJECTION. A proposal aimed at a repository that does not exist still carries a
// real finding. So it is written, with TargetResolved=False, and a human (or the portal) re-aims it.
//
// AUTHENTICATED WHEN THE CHART SAYS SO, WITH A CREDENTIAL THIS SERVICE CANNOT GO AND FETCH.
// config.targetCheck.tokenSecret names a key of an EXISTING Secret and the CronJob injects it as
// TARGET_CHECK_TOKEN through `valueFrom.secretKeyRef`. The KUBELET reads that Secret, not this service:
// the ServiceAccount still holds no `get` on Secrets. The value is used in exactly one place: the
// Authorization header of the HEAD below. It is never logged, never in a condition, never in a prompt.
//
// WHAT EACH ANSWER MEANS DEPENDS ON WHETHER A TOKEN WAS SENT.
//   - anonymous 404: NotFoundOrPrivate. GitHub answers 404 for a PRIVATE repository to an anonymous
//     caller, exactly as for a missing one, and the message says the check cannot tell them apart.
//   - authenticated 404: RepoNotFound. Definitive for every repository the credential can see.
//   - authenticated 200 on a private repository: RepoFound. That is the point of sending it.
//   - 401: the credential was REJECTED. Unknown/CheckFailed, never RepoNotFound.
//
// WHERE A PROPOSAL LANDS IS CONFIGURATION, NEVER A MODEL CHOICE AND NEVER CODE (see Aim). The
// destination comes from the chart's values and only from there — config.targets per kind, then
// config.destinations.components per component — and a proposal neither names gets NO repository rather
// than the model's guess (TargetResolved False/NoDestination).
package targets

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/pyre"
)

// APIURL is TARGET_CHECK_API_URL. Empty disables the check: every proposal then records
// TargetResolved=Unknown/CheckDisabled, which is visibly different from a check that ran and found
// nothing.
var APIURL = envDefault("TARGET_CHECK_API_URL", "https://api.github.com")

// Timeout is the HEAD's timeout.
const Timeout = 10 * time.Second

// HTTPClient performs the existence check. Redirects are followed (a RENAMED repository answers 301 to
// its new name and still exists); Go's client, like requests, drops Authorization on a redirect to
// another host, so the token cannot follow one off GitHub.
var HTTPClient = &http.Client{Timeout: Timeout}

// GitHub's own rules for owner and repository names. THIS IS A SECURITY CHECK AS WELL AS A SHAPE ONE:
// the string is about to become part of a URL. `../`, `?`, `#` or a second slash could steer the request
// at a different endpoint; nothing outside this alphabet reaches the HTTP client. (Python's `$`, which
// these keep, also matches before one trailing newline.)
var (
	NameRE = pyre.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`, 0)
	RepoRE = pyre.MustCompile(`^[A-Za-z0-9._-]{1,100}$`, 0)
)

// Type is the condition type.
const Type = "TargetResolved"

// TokenEnv is the env var the CronJob fills from config.targetCheck.tokenSecret. Read at CALL time
// rather than at start, so nothing keeps a copy in a package variable that a later change could print.
const TokenEnv = "TARGET_CHECK_TOKEN"

// Destinations is config.targets (kind -> {repo, pathPrefix}), as JSON: the KIND OVERRIDE, which wins
// over everything. Components is config.destinations.components (component -> {repo, pathPrefix,
// prompt?: {repo, path}}). BOTH LIVE IN THE CHART'S values.yaml AND NOWHERE ELSE — not here, and not as
// a values.schema.json default. Empty here, so a run without them aims nothing: every proposal then
// records NoDestination, which is the honest state for an install that has not said where anything goes.
var (
	Destinations = envJSON("TARGET_DESTINATIONS")
	Components   = envJSON("TARGET_COMPONENTS")
	// BlueprintPolicy is config.destinations.blueprints ({orgs, pathPrefix}): WHICH ORGS a blueprint's
	// source repository may be DERIVED in. A blueprint's repository is read, each run, from the chart URL
	// of the CompositionDefinition that serves it (failures.Compositions) — cluster data, not model output.
	BlueprintPolicy = envJSON("TARGET_BLUEPRINTS")
	// Blueprints maps a blueprint COMPONENT ("blueprint-<name>", as a subject carries it) to "org/repo",
	// filled once per run by RegisterBlueprints. Never from the model. Insertion-ordered like the dict it
	// ports.
	Blueprints = py.NewOMap()
)

func envDefault(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

// envJSON is json.loads(os.environ.get(name) or "{}"), keeping key order. A malformed value fails the
// start, as an exception at import time did.
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

// BlueprintOrgs is the orgs config.destinations.blueprints allows a derived destination in.
func BlueprintOrgs(policy any) []string {
	if policy == nil {
		policy = BlueprintPolicy
	}
	var out []string
	for _, o := range py.List(py.Get(policy, "orgs")) {
		if s, ok := o.(string); ok && NameRE.Match(s) != nil {
			out = append(out, s)
		}
	}
	return out
}

// BlueprintComponent is the subject component a finding about this blueprint will actually carry.
//
// failures renders a blueprint in the compositions evidence as `blueprint <name>`, and the prompt tells
// the model to spell the subject's component exactly as the evidence spells it. By the time Destination
// sees it, NormaliseSubject has folded the space, so the component is `blueprint-<name>`. The registry
// has to be keyed on that same string (#44).
func BlueprintComponent(name string) (string, bool) {
	norm, ok := proposals.NormaliseSubject("blueprint " + name + "/x")
	if !ok {
		return "", false
	}
	c, _, _ := strings.Cut(norm, "/")
	return c, true
}

// BlueprintKeys is every component spelling that should find this blueprint: the evidence spelling the
// prompt asks for, and the bare name this registry has always held.
func BlueprintKeys(name string) []string {
	var out []string
	if c, ok := BlueprintComponent(name); ok && c != "" {
		out = append(out, c)
	}
	if norm, ok := proposals.NormaliseSubject(name + "/x"); ok {
		if c, _, _ := strings.Cut(norm, "/"); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// NamedRepo is one entry of a {name: "org/repo"} map, in order.
type NamedRepo struct {
	Name string
	Repo string
}

// RegisterBlueprints remembers this run's derived blueprint repositories, keyed like a subject's
// component. Anything outside the allowed orgs, or not a GitHub owner/name, is dropped here as well as
// where it was derived: this is the boundary, the derivation is only its first user.
func RegisterBlueprints(found []NamedRepo, policy any) *py.OMap {
	allowed := map[string]bool{}
	for _, o := range BlueprintOrgs(policy) {
		allowed[py.Lower(o)] = true
	}
	Blueprints = py.NewOMap()
	for _, f := range found {
		owner, rname, _ := strings.Cut(f.Repo, "/")
		keys := BlueprintKeys(f.Name)
		if len(keys) > 0 && allowed[py.Lower(owner)] && NameRE.Match(owner) != nil && RepoRE.Match(rname) != nil {
			for _, k := range keys {
				Blueprints.Set(k, f.Repo)
			}
		}
	}
	out := py.NewOMap()
	for _, k := range Blueprints.Keys() {
		v, _ := Blueprints.Get(k)
		out.Set(k, v)
	}
	return out
}

// Condition is a TargetResolved condition (lastTransitionTime is the writer's to add).
type Condition map[string]any

func cond(status, reason, message string) Condition {
	return Condition{"type": Type, "status": status, "reason": reason, "message": py.Trunc(message, 500)}
}

// Resolve returns the TargetResolved condition for `owner/name`, asking each repository once per run
// when given a cache. A variable so a test can stand in for GitHub.
//
// True/RepoFound, False/NotFoundOrPrivate (anonymous 404), False/RepoNotFound (authenticated 404),
// False/InvalidRepo, or Unknown with CheckFailed/CheckDisabled — Unknown is not a softer False: it
// means this run could not ask, and says why.
var Resolve = func(ctx context.Context, repo string, cache map[string]Condition) Condition {
	if cache != nil {
		if c, ok := cache[repo]; ok {
			return c
		}
	}
	c := resolve(ctx, repo)
	if cache != nil {
		cache[repo] = c
	}
	return c
}

func resolve(ctx context.Context, repo string) Condition {
	owner, name, _ := strings.Cut(repo, "/")
	if NameRE.Match(owner) == nil || RepoRE.Match(name) == nil || name == "." || name == ".." {
		return cond("False", "InvalidRepo", py.StrRepr(repo)+" is not a GitHub owner/name")
	}
	if APIURL == "" {
		return cond("Unknown", "CheckDisabled", "config.targetCheckApiUrl is empty; existence not checked")
	}
	url := fmt.Sprintf("%s/repos/%s/%s", py.RStripChars(APIURL, "/"), owner, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return cond("Unknown", "CheckFailed", fmt.Sprintf("HEAD %s: %s", url, py.TypeName(err)))
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "krateo-nightly-review")
	token := py.Strip(os.Getenv(TokenEnv))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		// The exception's TYPE only: its text can carry the request, and the request carries the token.
		return cond("Unknown", "CheckFailed", fmt.Sprintf("HEAD %s: %s", url, py.TypeName(err)))
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == 200:
		return cond("True", "RepoFound", fmt.Sprintf("%s/%s exists", owner, name))
	case resp.StatusCode == 401 && token != "":
		return cond("Unknown", "CheckFailed", fmt.Sprintf("HEAD %s answered 401: the configured credential "+
			"(config.targetCheck.tokenSecret) was rejected — expired, revoked or wrong. Says nothing about the repository.", url))
	case resp.StatusCode == 404 && token != "":
		return cond("False", "RepoNotFound", fmt.Sprintf("No repository %s/%s visible to the configured credential. "+
			"Definitive for the organisations that credential can read; a private repository elsewhere would also answer 404.",
			owner, name))
	case resp.StatusCode == 404:
		// NOT "RepoNotFound": krateo-agentiko/agentiko and incident-agent are private and are exactly
		// where a Prompt proposal belongs. The reason names both possibilities, so a UI can show
		// "unverified" rather than "wrong".
		return cond("False", "NotFoundOrPrivate", fmt.Sprintf("No public repository %s/%s. It does not exist, or it "+
			"is private — an anonymous check cannot tell those apart.", owner, name))
	}
	// 403 and 429 are the rate limit; anything else is GitHub having a bad night. Neither says anything
	// about the repository, so neither may be recorded as if it did.
	return cond("Unknown", "CheckFailed", fmt.Sprintf("HEAD %s answered %d", url, resp.StatusCode))
}

var fileRE = pyre.MustCompile(`[^A-Za-z0-9._-]+`, 0)

var extensions = map[string]string{"yaml": ".yaml", "markdown": ".md", "diff": ".diff"}

// NoDestination is the reason of a proposal the values give no destination.
const NoDestination = "NoDestination"

// Component is the subject's component half, normalised the way the subject itself is. What a finding
// is ABOUT decides where it lands — never the repository the model proposed.
func Component(p any) (string, bool) {
	subject, ok := proposals.NormaliseSubject(py.Get(p, "subject"))
	if !ok {
		return "", false
	}
	c, _, _ := strings.Cut(subject, "/")
	return c, true
}

// components is the configured map with its keys normalised like a subject's component, so `Snowplow`
// in the values meets `snowplow` in a subject. A key that normalises to nothing is dropped. Later keys
// win over earlier ones that normalise the same, as in the dict this ports.
func components(m any) map[string]any {
	out := map[string]any{}
	for _, key := range py.DictKeys(m) {
		entry := py.Get(m, key)
		norm, ok := proposals.NormaliseSubject(key + "/x")
		if ok && py.IsDict(entry) {
			c, _, _ := strings.Cut(norm, "/")
			out[c] = entry
		}
	}
	return out
}

// posixName is pathlib.PurePosixPath(path).name.
func posixName(path string) string {
	var last string
	for _, part := range strings.Split(path, "/") {
		if part != "" && part != "." {
			last = part
		}
	}
	return last
}

// FileName is the model's file name, reduced to a safe alphabet — it becomes a path in a pull request.
// With no usable basename the subject names the file, so one finding keeps one file across nights.
func FileName(p any) string {
	target := py.Get(p, "target")
	if !py.Has(p, "target") {
		target = map[string]any{}
	}
	path := py.Get(target, "path")
	if !py.Truthy(path) {
		path = ""
	}
	base := py.LStripChars(fileRE.Sub(posixName(py.Str(path)), "-"), ".-")
	if base == "" {
		format := py.Get(py.Or(py.Get(p, "change"), map[string]any{}), "format")
		subject := py.Or(py.Get(p, "subject"), "proposal")
		ext, ok := extensions[py.Str(format)]
		if !ok || !py.IsStr(format) {
			ext = ".txt"
		}
		base = fileRE.Sub(strings.ReplaceAll(py.Str(subject), "/", "-"), "-") + ext
	}
	return py.Trunc(base, 200)
}

// Destination returns (repo, path, source) from the values, or ("", "", why) when they name none.
//
// PRECEDENCE, and why in this order:
//  1. config.targets[kind] — a kind override. Every Alert is an observability.krateo.io Alert CR whatever
//     it is about, so it lands in the observability chart whatever the component.
//  2. config.destinations.components[component] — the component the subject names. For a Prompt
//     proposal, only that entry's `prompt: {repo, path}`: a prompt is ONE file, so the path is taken
//     exactly, and an entry without `prompt` is no destination for a Prompt.
//  3. a BLUEPRINT's source repository, when the component is a blueprint whose OCI chart is published by
//     an org config.destinations.blueprints.orgs allows. Never for a Prompt.
//  4. nothing: no destination. The model's own choice is never the fallback.
//
// destinations and components nil mean the configured ones.
func Destination(p any, destinations, comps any) (repo, path, source string, ok bool) {
	kinds := destinations
	if kinds == nil {
		kinds = Destinations
	}
	if comps == nil {
		comps = Components
	}
	cm := components(comps)
	kind := py.Get(p, "kind")
	kindStr := py.Str(kind)
	var over any
	if py.IsStr(kind) { // kinds.get(kind): only a str can equal a configured kind
		over = py.Get(kinds, kindStr)
	}
	if py.IsDict(over) && py.Truthy(py.Get(over, "repo")) {
		return py.Str(py.Get(over, "repo")), join(py.Get(over, "pathPrefix"), FileName(p)), "config.targets." + kindStr, true
	}
	comp, hasComp := Component(p)
	var entry any
	var derived any
	if hasComp {
		entry = cm[comp]
		derived, _ = Blueprints.Get(comp)
	}
	if !py.IsDict(entry) && py.Truthy(derived) && kindStr != "Prompt" {
		// 3. A blueprint: its source repository, from its CompositionDefinition's chart URL.
		prefix := py.Get(py.Or(BlueprintPolicy, map[string]any{}), "pathPrefix")
		named := comp
		if !strings.HasPrefix(comp, "blueprint-") {
			named = "blueprint " + comp
		}
		return py.Str(derived), join(prefix, FileName(p)),
			named + ": the CompositionDefinition's chart URL (config.destinations.blueprints)", true
	}
	if !py.IsDict(entry) {
		if hasComp {
			return "", "", "no destination configured for component " + comp + "; add it to config.destinations", false
		}
		return "", "", "no subject component to look a destination up by; the subject could not be normalised", false
	}
	if kindStr == "Prompt" {
		pr := py.Get(entry, "prompt")
		if !(py.IsDict(pr) && py.Truthy(py.Get(pr, "repo")) && py.Truthy(py.Get(pr, "path"))) {
			return "", "", "no prompt destination configured for component " + comp + "; add config.destinations.components." +
				comp + ".prompt", false
		}
		return py.Str(py.Get(pr, "repo")), py.StripChars(py.Str(py.Get(pr, "path")), "/"),
			"config.destinations.components." + comp + ".prompt", true
	}
	if !py.Truthy(py.Get(entry, "repo")) {
		return "", "", "no destination configured for component " + comp + "; add it to config.destinations", false
	}
	return py.Str(py.Get(entry, "repo")), join(py.Get(entry, "pathPrefix"), FileName(p)),
		"config.destinations.components." + comp, true
}

func join(prefix any, name string) string {
	pfx := ""
	if py.Truthy(prefix) {
		pfx = py.StripChars(py.Str(prefix), "/")
	}
	if pfx != "" {
		return pfx + "/" + name
	}
	return name
}

// Aim points a proposal at the destination the values give it, or at none. It returns a
// ValidationNotes line when it changed something, else "". THE CALLER RE-FINGERPRINTS: the target is
// part of the fingerprint, and a proposal named by its old target would neither dedup tomorrow nor
// supersede.
//
// NO DESTINATION CLEARS target.repo. Keeping the model's guess would be keeping exactly what this
// replaces. The path keeps only the file name, because its directory belonged to the guessed
// repository. The proposal is still written — the finding is real — and NoDestinationCondition is its
// TargetResolved condition.
func Aim(p map[string]any, destinations, comps any) string {
	target, ok := p["target"].(map[string]any)
	if !ok { // proposal.setdefault("target", {}); a validated proposal always has one
		target = map[string]any{}
		p["target"] = target
	}
	oldRepo := py.Get(target, "repo")
	oldPath := py.Get(target, "path")
	old := py.StripChars(py.Str(py.Or(oldRepo, ""))+"/"+py.Str(py.Or(oldPath, "")), "/")
	repo, path, source, found := Destination(p, destinations, comps)
	if !found {
		fileName := FileName(p)
		target["repo"], target["path"] = "", fileName
		shown := old
		if shown == "" {
			shown = "(no target)"
		}
		return fmt.Sprintf("%s proposal %s cleared: %s", py.Str(p["kind"]), shown, source)
	}
	target["repo"], target["path"] = repo, path
	next := repo + "/" + path
	if next == old {
		return ""
	}
	return fmt.Sprintf("%s proposal retargeted %s -> %s (%s)", py.Str(p["kind"]), old, next, source)
}

// NoDestinationCondition is the TargetResolved condition of a proposal the values give no destination:
// False, because it cannot become a pull request as it stands, with a reason a UI can tell apart from a
// repository GitHub denied. The message is recomputed from kind and subject — both untouched by Aim.
func NoDestinationCondition(p any, destinations, comps any) Condition {
	_, _, why, _ := Destination(p, destinations, comps)
	return cond("False", NoDestination, why)
}
