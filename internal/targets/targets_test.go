package targets_test

// Where a proposal lands, and whether its repository exists (tests/test_blueprint_destination.py and the
// TargetResolved / config.targets / config.destinations cases of test_platform_review_service.py and
// test_failures.py).

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/krateo-platformops/nightly-review/internal/failures"
	"github.com/krateo-platformops/nightly-review/internal/fake"
	P "github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/py"
	T "github.com/krateo-platformops/nightly-review/internal/targets"
	"github.com/krateo-platformops/nightly-review/internal/testutil"
)

func restore(t *testing.T) {
	d, c, bp, b, client := T.Destinations, T.Components, T.BlueprintPolicy, T.Blueprints, T.HTTPClient
	t.Setenv(T.TokenEnv, "")
	t.Cleanup(func() {
		T.Destinations, T.Components, T.BlueprintPolicy, T.Blueprints, T.HTTPClient = d, c, bp, b, client
	})
}

func prop(kind, subject string, hasSubject bool, repo, path string, hasPath bool, format string) map[string]any {
	target := map[string]any{"repo": repo}
	if hasPath {
		target["path"] = path
	}
	p := map[string]any{"kind": kind, "title": "t", "rationale": "r", "confidence": "low",
		"evidence": []any{map[string]any{"source": "clickhouse", "summary": "s"}}, "target": target,
		"change": map[string]any{"format": format, "content": "a: 1\n"}}
	if hasSubject {
		p["subject"] = subject
	}
	return p
}

func alertProp(repo, path string) map[string]any {
	return prop("Alert", "snowplow/sar-unauthorized", true, repo, path, true, "yaml")
}

// --- the blueprint contract (#44) ---------------------------------------------------------------

var policy = py.O("orgs", []any{"krateo-blueprints"}, "pathPrefix", "proposals")
var found = []T.NamedRepo{{Name: "meetup-site", Repo: "krateo-blueprints/meetup-site"}}

// evidenceComponent is the component a model obeying the prompt would write, derived from the evidence
// line itself.
func evidenceComponent(t *testing.T, name string) string {
	text := failures.BlueprintText(map[string]any{"name": name, "namespace": "krateo-system", "url": "oci://x", "version": "0.3.0"},
		map[string]any{}, map[string]string{})
	if !strings.HasPrefix(text, "blueprint "+name+" (") {
		t.Fatal(text)
	}
	norm, _ := P.NormaliseSubject(strings.Split(text, " (")[0] + "/x")
	c, _, _ := strings.Cut(norm, "/")
	return c
}

func TestTheRegistryKeyIsTheComponentTheEvidenceProduces(t *testing.T) {
	restore(t)
	reg := T.RegisterBlueprints(found, policy)
	c, _ := T.BlueprintComponent("meetup-site")
	if c != evidenceComponent(t, "meetup-site") {
		t.Fatal(c)
	}
	if _, ok := reg.Get(evidenceComponent(t, "meetup-site")); !ok {
		t.Fatal(reg.Keys())
	}
}

func TestABlueprintFindingLandsInTheBlueprintRepository(t *testing.T) {
	restore(t)
	// pathPrefix is read from the package-level policy, not from RegisterBlueprints' argument.
	T.BlueprintPolicy = policy
	T.RegisterBlueprints(found, policy)
	repo, path, source, _ := T.Destination(map[string]any{"kind": "Documentation",
		"subject": evidenceComponent(t, "meetup-site") + "/cpu-request-exceeds-limit",
		"target":  map[string]any{"path": "resource-configuration.md"}}, map[string]any{}, map[string]any{})
	if repo != "krateo-blueprints/meetup-site" || path != "proposals/resource-configuration.md" || !strings.Contains(source, "blueprint") {
		t.Fatal(repo, path, source)
	}
}

func TestBothSpellingsResolveSoNothingThatWorkedStopsWorking(t *testing.T) {
	restore(t)
	reg := T.RegisterBlueprints(found, policy)
	if !reflect.DeepEqual(reg.Keys(), []string{"blueprint-meetup-site", "meetup-site"}) {
		t.Fatal(reg.Keys())
	}
	for _, subject := range []string{"blueprint-meetup-site/cpu-request-exceeds-limit", "meetup-site/cpu-request-exceeds-limit"} {
		repo, _, _, _ := T.Destination(map[string]any{"kind": "Documentation", "subject": subject, "target": map[string]any{}},
			map[string]any{}, map[string]any{})
		if repo != "krateo-blueprints/meetup-site" {
			t.Error(subject, repo)
		}
	}
}

func TestAPromptProposalStillNeverDerivesABlueprintRepository(t *testing.T) {
	restore(t)
	T.RegisterBlueprints(found, policy)
	repo, _, why, _ := T.Destination(map[string]any{"kind": "Prompt", "subject": evidenceComponent(t, "meetup-site") + "/x",
		"target": map[string]any{}}, map[string]any{}, map[string]any{})
	if repo != "" {
		t.Fatal(why)
	}
}

func TestAnOrgOutsideThePolicyDerivesNothing(t *testing.T) {
	restore(t)
	if T.RegisterBlueprints([]T.NamedRepo{{Name: "other", Repo: "someone-else/other"}}, policy).Len() != 0 {
		t.Fatal()
	}
}

func TestABlueprintProposalLandsInItsDerivedRepositoryUnderTheAllowedOrgs(t *testing.T) {
	restore(t)
	T.BlueprintPolicy = py.O("orgs", []any{"krateo-blueprints"}, "pathPrefix", "chart")
	T.Blueprints = py.NewOMap()
	T.Components = py.O("github-provider-kog", py.O("repo", "krateo-blueprints/github-provider-kog", "pathPrefix", "docs"))
	got := T.RegisterBlueprints([]T.NamedRepo{{"tenant-db", "krateo-blueprints/tenant-db"},
		{"github-provider-kog", "krateo-blueprints/github-provider-kog"}, {"evil", "someone-else/repo"},
		{"bad", "krateo-blueprints/../x"}}, nil)
	want := map[string]any{"blueprint-tenant-db": "krateo-blueprints/tenant-db", "tenant-db": "krateo-blueprints/tenant-db",
		"blueprint-github-provider-kog": "krateo-blueprints/github-provider-kog",
		"github-provider-kog":           "krateo-blueprints/github-provider-kog"}
	if !reflect.DeepEqual(py.Plain(got), want) {
		t.Fatal(py.Plain(got))
	}
	fp := func(kind, subject string) map[string]any {
		return map[string]any{"kind": kind, "subject": subject, "target": map[string]any{"repo": "x", "path": "docs/values-schema.json"}}
	}
	p := fp("Documentation", "blueprint-tenant-db/size-pattern-rejected")
	if !strings.Contains(T.Aim(p, nil, nil), "retargeted") || !reflect.DeepEqual(p["target"], map[string]any{"repo": "krateo-blueprints/tenant-db",
		"path": "chart/values-schema.json"}) {
		t.Fatal(p["target"])
	}
	p = fp("Documentation", "tenant-db/size-pattern-rejected")
	if !strings.Contains(T.Aim(p, nil, nil), "retargeted") || p["target"].(map[string]any)["repo"] != "krateo-blueprints/tenant-db" {
		t.Fatal(p["target"])
	}
	// The components map wins over a derived destination.
	p = fp("Documentation", "github-provider-kog/x")
	T.Aim(p, nil, nil)
	if p["target"].(map[string]any)["path"] != "docs/values-schema.json" {
		t.Fatal(p["target"])
	}
	// Never a Prompt; and an org outside the allow-list derives nothing.
	p = fp("Prompt", "tenant-db/size-pattern-rejected")
	if !strings.Contains(T.Aim(p, nil, nil), " cleared: ") || p["target"].(map[string]any)["repo"] != "" {
		t.Fatal(p["target"])
	}
	p = fp("Documentation", "evil/x")
	if !strings.Contains(T.Aim(p, nil, nil), " cleared: ") {
		t.Fatal(p["target"])
	}
}

func TestNoOrgAllowedMeansNothingIsDerived(t *testing.T) {
	restore(t)
	T.BlueprintPolicy = map[string]any{}
	T.Blueprints = py.NewOMap()
	if T.RegisterBlueprints([]T.NamedRepo{{"tenant-db", "krateo-blueprints/tenant-db"}}, nil).Len() != 0 {
		t.Fatal()
	}
}

// --- TargetResolved -----------------------------------------------------------------------------

type head struct {
	code    int
	urls    []string
	headers []http.Header
}

func (h *head) install(t *testing.T) {
	T.HTTPClient = fake.Client(func(r *http.Request) (*http.Response, error) {
		h.urls = append(h.urls, r.URL.String())
		h.headers = append(h.headers, r.Header.Clone())
		return fake.Response(r, h.code, ""), nil
	})
}

func resolve(repo string) T.Condition { return T.Resolve(context.Background(), repo, nil) }

func TestTheConditionSaysWhatGithubAnsweredAndNoMore(t *testing.T) {
	for _, c := range []struct {
		code           int
		status, reason string
	}{{200, "True", "RepoFound"}, {404, "False", "NotFoundOrPrivate"}, {403, "Unknown", "CheckFailed"},
		{429, "Unknown", "CheckFailed"}, {502, "Unknown", "CheckFailed"}} {
		restore(t)
		(&head{code: c.code}).install(t)
		got := resolve("krateo-platformops/x")
		if got["type"] != "TargetResolved" || got["status"] != c.status || got["reason"] != c.reason {
			t.Error(c.code, got)
		}
	}
}

func TestA404AdmitsItCannotTellPrivateFromMissing(t *testing.T) {
	restore(t)
	(&head{code: 404}).install(t)
	if !strings.Contains(resolve("o/r")["message"].(string), "private") {
		t.Fatal()
	}
}

func TestAModelChosenRepoNeverReachesAURLUnlessItIsOwnerName(t *testing.T) {
	for _, repo := range []string{"../../user", "o/r?x=1", "o/r#f", "o/r/extra", "o", "/r", "o/..", "o r/x"} {
		restore(t)
		h := &head{code: 200}
		h.install(t)
		c := resolve(repo)
		if len(h.urls) != 0 || c["status"] != "False" || c["reason"] != "InvalidRepo" {
			t.Error(repo, c, h.urls)
		}
	}
}

func TestEachRepositoryIsAskedOncePerRun(t *testing.T) {
	restore(t)
	h := &head{code: 200}
	h.install(t)
	cache := map[string]T.Condition{}
	for i := 0; i < 5; i++ {
		T.Resolve(context.Background(), "o/r", cache)
	}
	if len(h.urls) != 1 {
		t.Fatal(h.urls)
	}
}

func TestTheAnonymousCheckSendsNoCredential(t *testing.T) {
	restore(t)
	h := &head{code: 404}
	h.install(t)
	if resolve("krateo-agentiko/agentiko")["reason"] != "NotFoundOrPrivate" || h.headers[0].Get("Authorization") != "" {
		t.Fatal(h.headers)
	}
}

func TestWithAToken404IsDefinitiveAnd401IsAboutTheCredential(t *testing.T) {
	for _, c := range []struct {
		code           int
		status, reason string
	}{{200, "True", "RepoFound"}, {404, "False", "RepoNotFound"}, {401, "Unknown", "CheckFailed"},
		{403, "Unknown", "CheckFailed"}, {502, "Unknown", "CheckFailed"}} {
		restore(t)
		t.Setenv(T.TokenEnv, "tok-under-test")
		h := &head{code: c.code}
		h.install(t)
		got := resolve("krateo-agentiko/installer-agent")
		if got["status"] != c.status || got["reason"] != c.reason || h.headers[0].Get("Authorization") != "Bearer tok-under-test" ||
			strings.Contains(testutil.Canon(got), "tok-under-test") {
			t.Error(c.code, got)
		}
		if c.code == 401 && !(strings.Contains(got["message"].(string), "credential") && strings.Contains(got["message"].(string), "rejected")) {
			t.Error(got["message"])
		}
	}
}

func TestABlankTokenIsTheAnonymousCheck(t *testing.T) {
	restore(t)
	t.Setenv(T.TokenEnv, "  ")
	h := &head{code: 404}
	h.install(t)
	if resolve("o/r")["reason"] != "NotFoundOrPrivate" || h.headers[0].Get("Authorization") != "" {
		t.Fatal(h.headers)
	}
}

// --- config.targets / config.destinations --------------------------------------------------------

var obs = py.O("Alert", py.O("repo", "krateo-platformops/observability", "pathPrefix", "charts/krateo-observability/templates"))

var comps = py.O(
	"snowplow", py.O("repo", "krateo-platformops/snowplow", "pathPrefix", "docs"),
	"kagent", py.O("repo", "krateo-agentiko/kagent", "pathPrefix", "docs"),
	"installer-agent", py.O("repo", "krateo-agentiko/installer-agent", "pathPrefix", "docs",
		"prompt", py.O("repo", "krateo-agentiko/installer-agent", "path", "helm/installer-agent/files/prompts-eng.yaml")))

func TestAnAlertGoesWhereTheChartSaysWhateverTheModelChose(t *testing.T) {
	p := alertProp("krateo-observability", "alerts/snowplow-sar-unauthorized.yaml")
	note := T.Aim(p, obs, nil)
	if !reflect.DeepEqual(p["target"], map[string]any{"repo": "krateo-platformops/observability",
		"path": "charts/krateo-observability/templates/snowplow-sar-unauthorized.yaml"}) ||
		!strings.Contains(note, "krateo-observability/alerts/snowplow-sar-unauthorized.yaml -> krateo-platformops/observability") ||
		!strings.Contains(note, "config.targets.Alert") {
		t.Fatal(p["target"], note)
	}
}

func TestTheDestinationIsTheChartsValuesAndAbsentMeansNoDestination(t *testing.T) {
	restore(t)
	values := testutil.YAML(t, "helm/nightly-review/values.yaml")
	cfg := py.Get(values, "config")
	if testutil.Canon(py.Get(cfg, "targets")) != testutil.Canon(obs) ||
		testutil.Canon(py.GetPath(cfg, "targetCheck", "tokenSecret")) != `{"key": "token", "name": "gh-token"}` ||
		py.GetPath(cfg, "destinations", "components", "snowplow", "repo") != "krateo-platformops/snowplow" {
		t.Fatal(py.Get(cfg, "targets"))
	}
	if T.Destinations.(*py.OMap).Len() != 0 || T.Components.(*py.OMap).Len() != 0 {
		t.Fatal("the code must not carry its own default destination")
	}
	p := alertProp("krateo-observability", "alerts/a.yaml")
	if !strings.Contains(T.Aim(p, nil, nil), "cleared") || !reflect.DeepEqual(p["target"], map[string]any{"repo": "", "path": "a.yaml"}) {
		t.Fatal(p["target"])
	}
}

func TestTheModelKeepsOnlyASafeFileName(t *testing.T) {
	for _, c := range []struct {
		path    string
		hasPath bool
		want    string
	}{{"../../.github/workflows/x.yaml", true, "x.yaml"}, {"a/b c;$(id).yaml", true, "b-c-id-.yaml"},
		{"", true, "snowplow-sar-unauthorized.yaml"}, {"", false, "snowplow-sar-unauthorized.yaml"}} {
		p := prop("Alert", "snowplow/sar-unauthorized", true, "org/repo", c.path, c.hasPath, "yaml")
		if !c.hasPath {
			p["target"].(map[string]any)["path"] = nil
		}
		T.Aim(p, obs, nil)
		if got := p["target"].(map[string]any)["path"]; got != "charts/krateo-observability/templates/"+c.want {
			t.Error(c.path, got)
		}
	}
}

func TestAComponentInTheValuesIsRetargetedKeepingTheModelsFileName(t *testing.T) {
	p := prop("Documentation", "Snowplow/SAR Unauthorized", true, "krateo-platformops/snowplow-docs", "guides/sar/why.md", true, "markdown")
	note := T.Aim(p, obs, comps)
	if !reflect.DeepEqual(p["target"], map[string]any{"repo": "krateo-platformops/snowplow", "path": "docs/why.md"}) ||
		note != "Documentation proposal retargeted krateo-platformops/snowplow-docs/guides/sar/why.md -> "+
			"krateo-platformops/snowplow/docs/why.md (config.destinations.components.snowplow)" {
		t.Fatal(p["target"], note)
	}
}

func TestAPromptProposalLandsAtThePromptPathExactly(t *testing.T) {
	p := prop("Prompt", "installer-agent/repeated-get-resource-yaml", true, "krateo-agentiko/installer-agent",
		"prompts/installer_agent.txt", true, "diff")
	note := T.Aim(p, obs, comps)
	if !reflect.DeepEqual(p["target"], map[string]any{"repo": "krateo-agentiko/installer-agent",
		"path": "helm/installer-agent/files/prompts-eng.yaml"}) || !strings.Contains(note, "(config.destinations.components.installer-agent.prompt)") {
		t.Fatal(p["target"], note)
	}
}

func TestAPromptProposalAboutAComponentWithoutAPromptHasNoDestination(t *testing.T) {
	p := prop("Prompt", "snowplow/x", true, "krateo-platformops/snowplow", "x.yaml", true, "diff")
	T.Aim(p, obs, comps)
	c := T.NoDestinationCondition(p, obs, comps)
	if p["target"].(map[string]any)["repo"] != "" || c["status"] != "False" || c["reason"] != "NoDestination" ||
		!strings.Contains(c["message"].(string), "config.destinations.components.snowplow.prompt") {
		t.Fatal(p["target"], c)
	}
}

func TestNoDestinationClearsTheModelsGuessAndSaysWhichComponent(t *testing.T) {
	p := prop("Policy", "tk-swarm-ro/idle", true, "krateo-platformops/kagent", "policies/tk-swarm-ro-idle.yaml", true, "yaml")
	note := T.Aim(p, obs, comps)
	if !reflect.DeepEqual(p["target"], map[string]any{"repo": "", "path": "tk-swarm-ro-idle.yaml"}) ||
		note != "Policy proposal krateo-platformops/kagent/policies/tk-swarm-ro-idle.yaml cleared: no destination configured "+
			"for component tk-swarm-ro; add it to config.destinations" {
		t.Fatal(p["target"], note)
	}
	if !reflect.DeepEqual(map[string]any(T.NoDestinationCondition(p, obs, comps)), map[string]any{"type": "TargetResolved",
		"status": "False", "reason": "NoDestination",
		"message": "no destination configured for component tk-swarm-ro; add it to config.destinations"}) {
		t.Fatal(T.NoDestinationCondition(p, obs, comps))
	}
}

func TestASubjectThatCannotBeNormalisedHasNoDestination(t *testing.T) {
	p := prop("Documentation", "", false, "krateo-platformops/snowplow", "x.yaml", true, "markdown")
	T.Aim(p, obs, comps)
	if p["target"].(map[string]any)["repo"] != "" || !strings.Contains(T.NoDestinationCondition(p, obs, comps)["message"].(string), "no subject component") {
		t.Fatal(p["target"])
	}
}

func TestPrecedenceIsKindThenComponentThenNone(t *testing.T) {
	snowplow := py.O("repo", "krateo-platformops/snowplow", "pathPrefix", "docs",
		"prompt", py.O("repo", "krateo-agentiko/snowplow-agent", "path", "p.yaml"))
	withPrompt := py.O("snowplow", snowplow, "kagent", py.Get(comps, "kagent"), "installer-agent", py.Get(comps, "installer-agent"))
	for _, c := range []struct {
		kind         string
		kinds        any
		repo, source string
	}{{"Alert", obs, "krateo-platformops/observability", "config.targets.Alert"},
		{"Documentation", obs, "krateo-platformops/snowplow", "config.destinations.components.snowplow"},
		{"Alert", map[string]any{}, "krateo-platformops/snowplow", "config.destinations.components.snowplow"},
		{"Prompt", py.O("Prompt", py.O("repo", "o/prompts", "pathPrefix", "p")), "o/prompts", "config.targets.Prompt"}} {
		p := prop(c.kind, "snowplow/sar-unauthorized", true, "org/repo", "f.yaml", true, "yaml")
		repo, _, source, _ := T.Destination(p, c.kinds, withPrompt)
		if repo != c.repo || source != c.source {
			t.Error(c.kind, repo, source)
		}
	}
}

func TestAnAbsentMapGivesNoDestinationButTheKindOverrideStillApplies(t *testing.T) {
	for _, components := range []any{nil, map[string]any{}} {
		restore(t)
		T.Components = py.NewOMap()
		doc := prop("Documentation", "snowplow/x", true, "krateo-platformops/snowplow", "x.yaml", true, "markdown")
		T.Aim(doc, obs, components)
		alert := prop("Alert", "snowplow/x", true, "org/repo", "x.yaml", true, "yaml")
		T.Aim(alert, obs, components)
		if doc["target"].(map[string]any)["repo"] != "" || alert["target"].(map[string]any)["repo"] != "krateo-platformops/observability" {
			t.Fatal(doc["target"], alert["target"])
		}
	}
}

func TestConfiguredKeysMeetSubjectsHoweverEitherIsCased(t *testing.T) {
	p := prop("Documentation", "snowplow/x", true, "org/repo", "x.yaml", true, "markdown")
	T.Aim(p, map[string]any{}, py.O("Snowplow", py.O("repo", "krateo-platformops/snowplow")))
	if p["target"].(map[string]any)["repo"] != "krateo-platformops/snowplow" {
		t.Fatal(p["target"])
	}
}

var rr0200 = [][4]string{
	{"Alert", "snowplow/subjectaccessreview-unauthorized", "krateo-observability", "alerts/snowplow-subjectaccessreview-unauthorized.yaml"},
	{"Alert", "github-provider-kog-pullrequest-controller/cannot-observe-external-resource", "krateo-observability",
		"alerts/kog-provider-cannot-observe-external-resource.yaml"},
	{"Prompt", "installer-agent/repeated-get-resource-yaml", "krateo-agentiko/installer-agent", "prompts/installer_agent.txt"},
	{"Alert", "installer-chart-inspector/rbac-generation-http-500", "krateo-observability", "alerts/chart-inspector-rbac-generation-failure.yaml"},
	{"Prompt", "autopilot/suggest-widget-kinds-to-specialist", "krateo-agentiko/agentiko", "prompts/autopilot.txt"},
}

func TestRr202609300200ReplayedThroughTheSeededValues(t *testing.T) {
	cfg := py.Get(testutil.YAML(t, "helm/nightly-review/values.yaml"), "config")
	var got [][2]string
	for _, r := range rr0200 {
		p := prop(r[0], r[1], true, r[2], r[3], true, "yaml")
		T.Aim(p, py.Get(cfg, "targets"), py.GetPath(cfg, "destinations", "components"))
		got = append(got, [2]string{p["target"].(map[string]any)["repo"].(string), p["target"].(map[string]any)["path"].(string)})
	}
	o := "charts/krateo-observability/templates/"
	want := [][2]string{{"krateo-platformops/observability", o + "snowplow-subjectaccessreview-unauthorized.yaml"},
		{"krateo-platformops/observability", o + "kog-provider-cannot-observe-external-resource.yaml"},
		{"krateo-agentiko/installer-agent", "helm/installer-agent/files/prompts-eng.yaml"},
		{"krateo-platformops/observability", o + "chart-inspector-rbac-generation-failure.yaml"},
		{"krateo-agentiko/agentiko", "chart/files/prompts-eng.yaml"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestEveryAgentInTheSeededValuesHasItsPrompt(t *testing.T) {
	c := py.GetPath(testutil.YAML(t, "helm/nightly-review/values.yaml"), "config", "destinations", "components")
	for _, agent := range []string{"autopilot", "frontend-agent", "core-provider-agent", "installer-agent", "incident-agent",
		"clickstack-agent", "snowplow-agent", "authn-agent", "k8s-agent", "helm-agent"} {
		if !strings.HasPrefix(py.Str(py.GetPath(c, agent, "prompt", "repo")), "krateo-agentiko/") || !py.Truthy(py.GetPath(c, agent, "prompt", "path")) {
			t.Error(agent)
		}
	}
}

func TestAnAlreadyCorrectTargetIsNoNote(t *testing.T) {
	if note := T.Aim(alertProp("krateo-platformops/observability", "charts/krateo-observability/templates/x.yaml"), obs, nil); note != "" {
		t.Fatal(note)
	}
}
