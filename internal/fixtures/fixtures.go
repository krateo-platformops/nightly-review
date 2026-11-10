// Package fixtures holds the objects the tests read, ported from the Python suite: the 2026-10-01
// credential outage the sync-stall check was built for (test_sync_stall.py), and the Incidents,
// CompositionDefinitions and Compositions of 057 on 2026-10-05 (test_failures.py).
package fixtures

import (
	"fmt"
	"strings"
	"time"

	"github.com/krateo-platformops/nightly-review/internal/kube"
	"github.com/krateo-platformops/nightly-review/internal/py"
)

// --- the sync-stall outage ------------------------------------------------------------------------

// SyncNow is the sync-stall fixtures' clock.
var SyncNow = time.Date(2026, 10, 1, 14, 0, 0, 0, time.UTC)

// SyncGroups is config.syncStall.groups for the outage.
func SyncGroups() *py.OMap {
	return py.O("github.krateo.io", py.O("component", "github-provider-kog", "kinds", []any{}),
		"git.krateo.io", py.O("component", "git-provider", "kinds", []any{}))
}

// SyncServed is what discovery answers for the two groups.
var SyncServed = map[string][]kube.Served{
	"github.krateo.io": {{Version: "v2022-11-28", Plural: "repositories", Kind: "Repository", Namespaced: true},
		{Version: "v2022-11-28", Plural: "pullrequests", Kind: "PullRequest", Namespaced: true},
		{Version: "v1alpha1", Plural: "repositoryconfigurations", Kind: "RepositoryConfiguration", Namespaced: true},
		{Version: "v1alpha1", Plural: "pullrequestconfigurations", Kind: "PullRequestConfiguration", Namespaced: true}},
	"git.krateo.io": {{Version: "v1alpha1", Plural: "repoes", Kind: "Repo", Namespaced: true},
		{Version: "v1alpha1", Plural: "localresources", Kind: "LocalResource", Namespaced: true}},
}

// Msg401 is GitHub's answer to the expired token, per repository.
func Msg401(n any) string {
	return fmt.Sprintf(`performing request: GET https://api.github.com/repos/krateo-blueprints/%v: 401 Unauthorized {"message":"Bad credentials"}`, n)
}

// Creds is the git-provider credential reference.
func Creds() map[string]any {
	return map[string]any{"key": "token", "name": "git-provider-credentials", "namespace": "krateo-system"}
}

// Cond is a (status, reason, message, minutes ago) condition.
type Cond struct {
	Status, Reason, Message string
	Ago                     float64
}

// Err is a ReconcileError condition.
func Err(msg string, ago float64) *Cond { return &Cond{"False", "ReconcileError", msg, ago} }

func ts(now time.Time, minutesAgo float64) string {
	return now.Add(-time.Duration(minutesAgo * float64(time.Minute))).Format("2006-01-02T15:04:05Z")
}

// Obj is one managed object with Synced/Ready conditions.
func Obj(name string, synced, ready *Cond, spec map[string]any, ns string) map[string]any {
	var conds []any
	for _, c := range []struct {
		typ string
		c   *Cond
	}{{"Synced", synced}, {"Ready", ready}} {
		if c.c != nil {
			conds = append(conds, map[string]any{"type": c.typ, "status": c.c.Status, "reason": c.c.Reason, "message": c.c.Message,
				"lastTransitionTime": ts(SyncNow, c.c.Ago)})
		}
	}
	if spec == nil {
		spec = map[string]any{}
	}
	if conds == nil {
		conds = []any{}
	}
	return map[string]any{"metadata": map[string]any{"name": name, "namespace": ns}, "spec": spec,
		"status": map[string]any{"conditions": conds}}
}

// Outage is 2026-10-01: every github.krateo.io and git.krateo.io object Synced=False with a 401.
func Outage(nRepos, nPRs, nRepoes, nLR int, ago float64) map[string][]any {
	kog := func() map[string]any {
		return map[string]any{"configurationRef": map[string]any{"name": "github-blueprints-config"}}
	}
	git := func() map[string]any {
		username := Creds()
		username["key"] = "username"
		return map[string]any{"toRepo": map[string]any{"url": "https://github.com/krateo-blueprints/x.git",
			"credentials": map[string]any{"secretRef": Creds(), "usernameRef": username}}}
	}
	out := map[string][]any{}
	for i := 0; i < nRepos; i++ {
		out["repositories"] = append(out["repositories"], Obj(fmt.Sprintf("repo-%d", i), Err(Msg401(i), ago),
			&Cond{"False", "Unavailable", "", ago}, kog(), "krateo-system"))
	}
	for i := 0; i < nPRs; i++ {
		out["pullrequests"] = append(out["pullrequests"], Obj(fmt.Sprintf("pr-%d", i), Err(Msg401(i), ago), nil, kog(), "krateo-system"))
	}
	for i := 0; i < nRepoes; i++ {
		out["repoes"] = append(out["repoes"], Obj(fmt.Sprintf("r-%d", i),
			Err("authentication required: Invalid username or token", ago), nil, git(), "krateo-system"))
	}
	for i := 0; i < nLR; i++ {
		out["localresources"] = append(out["localresources"], Obj(fmt.Sprintf("lr-%d", i),
			Err("authentication required: Invalid username or token", ago), nil, git(), "krateo-system"))
	}
	return out
}

// DefaultOutage is Outage(24, 24, 19, 3, 420).
func DefaultOutage() map[string][]any { return Outage(24, 24, 19, 3, 420) }

// SyncConfigs are the two Configurations the KOG objects reference.
func SyncConfigs() map[[2]string]map[string]any {
	cfg := func() map[string]any {
		return map[string]any{"spec": map[string]any{"authentication": map[string]any{"bearer": map[string]any{"tokenRef": Creds()}}}}
	}
	return map[[2]string]map[string]any{{"repositoryconfigurations", "github-blueprints-config"}: cfg(),
		{"pullrequestconfigurations", "github-blueprints-config"}: cfg()}
}

// --- the day's failures -----------------------------------------------------------------------------

// FailNow is the failures fixtures' clock.
var FailNow = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)

func fts(hoursAgo float64) string {
	return FailNow.Add(-time.Duration(hoursAgo * float64(time.Hour))).Format("2006-01-02T15:04:05Z")
}

// Incident builds one Incident as 057 recorded them.
type Incident struct {
	Name, State   string
	Opened, Fired float64
	Root, Apply   string
	Action        map[string]any
	Analyzed      []any
	Resolution    map[string]any
	Error, Alert  string
}

// Build renders the Incident object.
func (i Incident) Build() map[string]any {
	state := i.State
	if state == "" {
		state = "Open"
	}
	opened, fired := i.Opened, i.Fired
	alert := i.Alert
	if alert == "" {
		parts := strings.Split(i.Name, "-")
		alert = strings.Join(parts[:len(parts)-2], "-")
	}
	analyzed := append([]any{map[string]any{"gvr": "observability.krateo.io/v1alpha1/alerts", "name": alert,
		"namespace": "krateo-system", "whatWasRead": "spec.where"}}, i.Analyzed...)
	st := map[string]any{"state": state, "firings": int64(7), "lastFiredAt": fts(fired), "completedAt": fts(opened - 0.1),
		"analyzedResources": analyzed}
	if i.Root != "" {
		st["rootCause"] = map[string]any{"category": "image", "confidence": "0.95", "statement": i.Root}
	}
	if i.Apply != "" || i.Action != nil {
		action := i.Action
		if action == nil {
			action = map[string]any{}
		}
		st["howToFix"] = map[string]any{"apply": i.Apply, "applyAction": action}
	}
	if i.Resolution != nil {
		st["resolution"] = i.Resolution
	}
	if i.Error != "" {
		st["error"] = i.Error
	}
	return map[string]any{"apiVersion": "observability.krateo.io/v1alpha1", "kind": "Incident",
		"metadata": map[string]any{"name": i.Name, "namespace": "krateo-system", "creationTimestamp": fts(opened)},
		"spec": map[string]any{"alertRef": map[string]any{"name": alert, "namespace": "krateo-system"}, "trigger": "alert",
			"triggeredAt": fts(opened), "prompt": "The HyperDX alert ... has fired"},
		"status": st}
}

// Incidents are four Incidents: three in the window, one wholly before it.
func Incidents() []any {
	return []any{
		Incident{Name: "sre-image-pull-failure-20261004-101520", State: "Resolved", Opened: 22.7, Fired: 12.5,
			Root: "An ad-hoc Job named chq-disc-121224 in namespace krateo-system specified a non-existent " +
				"container image clickhouse/clickhouse-client:24.8",
			Apply: "#!/usr/bin/env bash\n# Delete stuck job chq-disc-121224 which references the non-existent " +
				"image.\nset -euo pipefail\nkubectl delete job -n krateo-system chq-disc-121224\n",
			Action: map[string]any{"apiVersion": "batch/v1", "resource": "jobs", "namespace": "krateo-system",
				"name": "chq-disc-121224", "verb": "delete"},
			Resolution: map[string]any{"by": "verify", "at": fts(11.3)}}.Build(),
		Incident{Name: "sre-probe-failing-20261003-105425", Opened: 46, Fired: 2.7,
			Root:  "Snowplow composition snowplow has no spec.startupProbe configured",
			Apply: "#!/usr/bin/env bash\n# Configure startupProbe on Snowplow composition.\n",
			Analyzed: []any{map[string]any{"gvr": "apps/v1/deployments", "name": "snowplow", "namespace": "krateo-system"},
				map[string]any{"gvr": "composition.krateo.io/v1-12-36/snowplows", "name": "snowplow", "namespace": "krateo-system"}}}.Build(),
		Incident{Name: "sre-node-not-ready-20261004-213642", Opened: 11.4, Fired: 11.2, Error: "The analysis returned no output."}.Build(),
		// Opened, fired and ended before the window: not tonight's.
		Incident{Name: "sre-probe-failing-20261001-080000", State: "Closed", Opened: 97, Fired: 90,
			Resolution: map[string]any{"by": "user", "at": fts(80)}}.Build(),
	}
}

func cd(name, url, version, kind string) map[string]any {
	return map[string]any{"metadata": map[string]any{"name": name, "namespace": "krateo-system"},
		"spec":   map[string]any{"chart": map[string]any{"url": url, "version": version}},
		"status": map[string]any{"kind": kind, "apiVersion": "composition.krateo.io/v" + strings.ReplaceAll(version, ".", "-")}}
}

// CDs are four CompositionDefinitions.
func CDs() []any {
	return []any{cd("github-provider-kog", "oci://ghcr.io/krateo-blueprints/charts/github-provider-kog", "0.3.2", "GithubProviderKog"),
		cd("tenant-db", "oci://ghcr.io/krateo-blueprints/charts/tenant-db", "1.4.0", "TenantDb"),
		cd("snowplow", "oci://ghcr.io/krateo-platformops/charts/snowplow", "1.12.36", "Snowplow"),
		cd("aws-rds-stack", "https://krateo-blueprints.github.io/charts/blueprints", "0.3.0", "AwsRdsStack")}
}

// CC is a composition condition (status, reason, hours ago, message).
type CC struct {
	Status, Reason string
	Ago            float64
	Message        string
}

// Comp builds a composition.
func Comp(kind, name string, ready, synced *CC, created float64, cdName, ns string) map[string]any {
	if ready == nil {
		ready = &CC{"True", "Available", 2, ""}
	}
	if synced == nil {
		synced = &CC{"True", "ReconcileSuccess", 0.01, ""}
	}
	if created == 0 {
		created = 24 * 10
	}
	if ns == "" {
		ns = "team-a"
	}
	conds := []any{}
	for _, c := range []struct {
		typ string
		c   *CC
	}{{"Ready", ready}, {"Synced", synced}} {
		conds = append(conds, map[string]any{"type": c.typ, "status": c.c.Status, "reason": c.c.Reason, "message": c.c.Message,
			"lastTransitionTime": fts(c.c.Ago)})
	}
	labels := map[string]any{}
	if cdName != "" {
		labels = map[string]any{"krateo.io/composition-definition-name": cdName, "krateo.io/composition-definition-namespace": "krateo-system"}
	}
	return map[string]any{"kind": kind, "metadata": map[string]any{"name": name, "namespace": ns, "creationTimestamp": fts(created),
		"labels": labels}, "status": map[string]any{"conditions": conds}}
}

// SchemaMsg is a chart refusing its values.
const SchemaMsg = "values don't meet the specifications of the schema(s) in the following chart(s): tenant-db: " +
	"- size: Does not match pattern '^[0-9]+Gi$'"

// Comps are the compositions by plural.
func Comps() map[string][]any {
	return map[string][]any{
		"tenantdbs": {
			Comp("TenantDb", "orders-db", &CC{"False", "Unavailable", 3, "Composition is not ready"},
				&CC{"False", "ReconcileError", 3, SchemaMsg}, 0, "tenant-db", ""),
			Comp("TenantDb", "billing-db", &CC{"True", "Available", 5, ""}, nil, 0, "tenant-db", ""), // recovered
			Comp("TenantDb", "fresh-db", &CC{"True", "Available", 1, ""}, nil, 2, "tenant-db", ""),   // just created
		},
		"githubproviderkogs": {Comp("GithubProviderKog", "github-provider-kog", &CC{"True", "Available", 40, ""}, nil, 0, "", "krateo-system")},
		"snowplows":          {Comp("Snowplow", "snowplow", &CC{"True", "Available", 2.8, ""}, nil, 0, "", "krateo-system")},
	}
}

// CompServed is what discovery answers for composition.krateo.io.
var CompServed = []kube.Served{{Version: "v1-4-0", Plural: "tenantdbs", Kind: "TenantDb", Namespaced: true},
	{Version: "v0-3-2", Plural: "githubproviderkogs", Kind: "GithubProviderKog", Namespaced: true},
	{Version: "v1-12-36", Plural: "snowplows", Kind: "Snowplow", Namespaced: true}}
