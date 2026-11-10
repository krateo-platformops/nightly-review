// Package chart holds the tests that read the Helm charts and CRDs against the code that depends on them
// (the chart, RBAC, policy and values cases of tests/test_platform_review_service.py,
// test_spec_decision.py and test_failures.py). It has no code of its own.
package chart

import (
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/krateo-platformops/nightly-review/internal/jsonschema"
	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/testutil"
)

func TestTheRbacStillGrantsNoSecretRead(t *testing.T) {
	rbac := testutil.Read(t, "helm/nightly-review/templates/rbac.yaml")
	granted := regexp.MustCompile(`(?m)^\s*resources:\s*\[(.*)\]`).FindAllStringSubmatch(rbac, -1)
	if len(granted) <= 5 {
		t.Fatal("no rules found, so this test proves nothing")
	}
	for _, g := range granted {
		if strings.Contains(strings.ToLower(g[1]), "secrets") {
			t.Fatal(g[0])
		}
	}
	cron := testutil.Read(t, "helm/nightly-review/templates/cronjob.yaml")
	after := strings.SplitN(cron, "TARGET_CHECK_TOKEN", 2)
	if !strings.Contains(cron, "name: TARGET_CHECK_TOKEN") || len(after) < 2 || !strings.Contains(py.Trunc(after[1], 300), "optional: true") {
		t.Fatal("the token must arrive by an optional secretKeyRef")
	}
}

// No repository of the platform's orgs appears in the service's code outside comments. Ported from the
// Python check over string tokens: Go comments are not string literals, so every literal is checked.
func TestNoDestinationIsHardcodedInTheCode(t *testing.T) {
	root := testutil.Root()
	for _, pkg := range []string{"targets", "review", "prompt", "analysis", "publish", "proposals", "synchealth", "failures"} {
		files, _ := filepath.Glob(filepath.Join(root, "internal", pkg, "*.go"))
		if len(files) == 0 {
			t.Fatalf("no sources in %s, so this proves nothing", pkg)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var s scanner.Scanner
			fset := token.NewFileSet()
			s.Init(fset.AddFile(f, fset.Base(), len(src)), src, nil, 0)
			for {
				_, tok, lit := s.Scan()
				if tok == token.EOF {
					break
				}
				// The module's own import paths name this repository, not a destination.
				if tok != token.STRING || strings.HasPrefix(lit, `"github.com/krateo-platformops/nightly-review/`) {
					continue
				}
				for _, org := range []string{"krateo-platformops", "krateo-agentiko", "krateo-blueprints"} {
					if strings.Contains(lit, org+"/") {
						t.Errorf("%s: %s", filepath.Base(f), py.Trunc(lit, 80))
					}
				}
			}
		}
	}
}

// Keys this repository added to values.schema.json. core-provider applies schema defaults straight into
// the live composition CR spec, so a `default` there is a silent live override, not documentation.
var newSchemaKeys = []string{"targets", "targetCheck", "destinations", "syncStall"}

func defaults(node any, path string) []string {
	var out []string
	switch {
	case py.IsDict(node):
		if py.Has(node, "default") {
			out = append(out, path)
		}
		for _, k := range py.DictKeys(node) {
			out = append(out, defaults(py.Get(node, k), path+"."+k)...)
		}
	case py.IsList(node):
		for i, v := range py.List(node) {
			out = append(out, defaults(v, path+"["+string(rune('0'+i))+"]")...)
		}
	}
	return out
}

func TestNoNewSchemaKeyCarriesADefault(t *testing.T) {
	cfg := py.GetPath(testutil.JSON(t, "helm/nightly-review/values.schema.json"), "properties", "config", "properties")
	for _, k := range newSchemaKeys {
		if !py.Has(cfg, k) {
			t.Fatalf("config.%s is not declared, so this test proves nothing", k)
		}
		if d := defaults(py.Get(cfg, k), "config."+k); len(d) != 0 {
			t.Error(d)
		}
	}
}

func TestTheChartPassesTheComponentsMapAndSurvivesItsAbsence(t *testing.T) {
	cron := testutil.Read(t, "helm/nightly-review/templates/cronjob.yaml")
	after := strings.SplitN(cron, "TARGET_COMPONENTS", 2)
	if !strings.Contains(cron, "name: TARGET_COMPONENTS") || len(after) < 2 ||
		!strings.Contains(py.Trunc(after[1], 200), `dig "destinations" "components" dict .Values.config`) {
		t.Fatal("the chart does not dig for the components map")
	}
	if !strings.Contains(testutil.Read(t, "internal/targets/targets.go"), `envJSON("TARGET_COMPONENTS")`) {
		t.Fatal("the env name is not the one the code reads")
	}
}

func TestTheChartRendersTheAnonymousCheckWhenTheKeyIsAbsent(t *testing.T) {
	cron := testutil.Read(t, "helm/nightly-review/templates/cronjob.yaml")
	if !strings.Contains(cron, `dig "targetCheck" "tokenSecret" dict .Values.config`) || strings.Contains(cron, ".Values.config.targetCheck.") {
		t.Fatal()
	}
}

func TestTheSeededValuesValidateAgainstTheSchema(t *testing.T) {
	schema := testutil.JSON(t, "helm/nightly-review/values.schema.json").(*py.OMap)
	values := testutil.YAML(t, "helm/nightly-review/values.yaml")
	if err := jsonschema.Validate(values, schema); err != nil {
		t.Fatal(err)
	}
	bad := testutil.YAML(t, "helm/nightly-review/values.yaml")
	py.GetPath(bad, "config", "destinations", "components", "snowplow").(*py.OMap).Set("repo", "krateo-platformops")
	if err := jsonschema.Validate(bad, schema); err == nil {
		t.Fatal("a repository without an owner passed the schema")
	}
}

func TestTheChartGrantsTheSyncCheckReadOnlyOnItsGroupsAndNeverTheCoreGroup(t *testing.T) {
	rbac := testutil.Read(t, "helm/nightly-review/templates/rbac.yaml")
	block := strings.SplitN(strings.SplitN(rbac, "-sync-read", 2)[1], "---", 2)[0]
	if !regexp.MustCompile(`verbs: \["get", "list"\]`).MatchString(block) || strings.Contains(block, "create") || strings.Contains(block, "patch") {
		t.Fatal(block)
	}
	if !strings.Contains(rbac, `fail (printf "config.syncStall.groups`) {
		t.Fatal("a group without a dot (the core group) must fail")
	}
	cron := testutil.Read(t, "helm/nightly-review/templates/cronjob.yaml")
	if !strings.Contains(cron, `dig "syncStall" dict .Values.config`) || !strings.Contains(cron, "name: SYNC_STALL_GROUPS") {
		t.Fatal(cron)
	}
	if !strings.Contains(testutil.Read(t, "internal/synchealth/synchealth.go"), `envJSON("SYNC_STALL_GROUPS")`) {
		t.Fatal("the env name is not the one the code reads")
	}
}

func nulls(o any, path string) []string {
	var out []string
	switch {
	case py.IsDict(o):
		for _, k := range py.DictKeys(o) {
			v := py.Get(o, k)
			if v == nil {
				out = append(out, path+"."+k)
			}
			out = append(out, nulls(v, path+"."+k)...)
		}
	case py.IsList(o):
		for _, v := range py.List(o) {
			out = append(out, nulls(v, path)...)
		}
	}
	return out
}

// `{ type: string, description: A, B }` is a flow mapping, and the comma makes `B` a KEY with a null
// value. Helm applies it without complaint and the apiserver drops it; `kubectl apply` with strict field
// validation refuses the whole CRD.
func TestNoSchemaKeyParsesToNull(t *testing.T) {
	for _, crd := range []string{"proposal.crd.yaml", "reviewrun.crd.yaml"} {
		if n := nulls(testutil.YAML(t, "helm/nightly-review-crds/templates/"+crd), ""); len(n) != 0 {
			t.Error(crd, n)
		}
	}
}

func TestThePoliciesExemptExactlyTheServiceAccountTheCronjobRunsAs(t *testing.T) {
	tpl := testutil.Read(t, "helm/nightly-review/templates/decision-policy.yaml")
	cron := testutil.Read(t, "helm/nightly-review/templates/cronjob.yaml")
	if !strings.Contains(cron, `serviceAccountName: {{ include "nightly-review.fullname" . }}`) ||
		!strings.Contains(tpl, `$name := include "nightly-review.fullname" .`) ||
		!strings.Contains(tpl, `printf "system:serviceaccount:%s:%s" .Release.Namespace $name`) ||
		strings.Count(tpl, "request.userInfo.username != {{ $service | quote }}") != 2 {
		t.Fatal()
	}
}

func TestThePoliciesAreOnByDefaultAndDeclared(t *testing.T) {
	values := testutil.YAML(t, "helm/nightly-review/values.yaml")
	schema := testutil.JSON(t, "helm/nightly-review/values.schema.json")
	if testutil.Canon(py.Get(values, "decisionPolicy")) != `{"enabled": true}` ||
		py.GetPath(schema, "properties", "decisionPolicy", "properties", "enabled", "default") != true {
		t.Fatal(py.Get(values, "decisionPolicy"))
	}
}

func TestTheChartGrantsRunNowAndTheFailureReads(t *testing.T) {
	rbac := testutil.Read(t, "helm/nightly-review/templates/rbac.yaml")
	parts := strings.Split(rbac, "-run-now")
	runNow := parts[1]
	if !strings.Contains(runNow, `resources: ["cronjobs"]`) || !strings.Contains(runNow, "resourceNames:") || !strings.Contains(runNow, `verbs: ["get"]`) ||
		!strings.Contains(runNow, `verbs: ["create", "get", "list", "watch"]`) ||
		!strings.Contains(parts[len(parts)-1], "range .Values.portalAdminAccess.groups") {
		t.Fatal(runNow)
	}
	reads := strings.SplitN(rbac, "-failures-read", 2)[1]
	for _, gr := range [][2]string{{"observability.krateo.io", "incidents"}, {"core.krateo.io", "compositiondefinitions"}} {
		if !strings.Contains(reads, "apiGroups: [\""+gr[0]+"\"]\n    resources: [\""+gr[1]+"\"]\n    verbs: [\"list\"]") {
			t.Error(gr)
		}
	}
	if !strings.Contains(reads, "apiGroups: [\"composition.krateo.io\"]\n    resources: [\"*\"]\n    verbs: [\"list\"]") {
		t.Fatal(reads)
	}
	cron := testutil.Read(t, "helm/nightly-review/templates/cronjob.yaml")
	if !strings.Contains(cron, `dig "destinations" "blueprints" dict .Values.config`) || !strings.Contains(cron, "batch.kubernetes.io/job-name") ||
		!strings.Contains(cron, "name: JOB_DEADLINE_SECONDS") {
		t.Fatal(cron)
	}
}
