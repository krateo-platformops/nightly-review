package failures_test

// The day's real failures: Incidents and Compositions as evidence, blueprint destinations derived from
// CompositionDefinitions (tests/test_failures.py; the manual-run and chart cases are in packages review
// and chart). The fixtures are trimmed copies of real objects on krateo-057 on 2026-10-05.

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/krateo-platformops/nightly-review/internal/evidence"
	F "github.com/krateo-platformops/nightly-review/internal/failures"
	"github.com/krateo-platformops/nightly-review/internal/fake"
	FX "github.com/krateo-platformops/nightly-review/internal/fixtures"
	"github.com/krateo-platformops/nightly-review/internal/kube"
	"github.com/krateo-platformops/nightly-review/internal/prompt"
	"github.com/krateo-platformops/nightly-review/internal/targets"
)

var ctx = context.Background()
var window = prompt.Window{From: "2026-10-04T09:00:00+00:00", To: "2026-10-05T09:00:00+00:00"}

func api(comps map[string][]any, fail ...string) *fake.API {
	a := fake.NewAPI()
	a.Cluster = map[string][]any{"incidents": FX.Incidents(), "compositiondefinitions": FX.CDs()}
	if comps == nil {
		comps = FX.Comps()
	}
	for k, v := range comps {
		a.Cluster[k] = v
	}
	for _, f := range fail {
		a.Fail[f] = fmt.Errorf("403 forbidden: %s", f)
	}
	return a
}

func served(s []kube.Served) func(context.Context, string) ([]kube.Served, error) {
	return func(context.Context, string) ([]kube.Served, error) { return s, nil }
}

func noEvents(context.Context, prompt.Window) ([]*F.EventGroup, string, error) {
	return []*F.EventGroup{}, "warning events not read: CLICKHOUSE_URL is not configured", nil
}

// --- incidents --------------------------------------------------------------------------------------

func TestIncidentsInTheWindowEndedFirstWithCauseFixAndAffectedObject(t *testing.T) {
	body, st := F.Incidents(ctx, api(nil), window)
	if st["ok"] != true || st["returned"] != int64(4) || st["findings"] != int64(3) {
		t.Fatal(st)
	}
	lines := strings.Split(body, "\n")
	first := ""
	for _, ln := range lines {
		if strings.HasPrefix(ln, "- Incident ") {
			first = ln
			break
		}
	}
	if !strings.Contains(first, "sre-image-pull-failure-20261004-101520: Resolved (ended by its verify check") {
		t.Fatal(first)
	}
	for _, want := range []string{"affected (fix target): jobs.batch krateo-system/chq-disc-121224",
		"root cause [image, confidence 0.95]: An ad-hoc Job named chq-disc-121224",
		"remediation: Delete stuck job chq-disc-121224", "one API write: delete jobs krateo-system/chq-disc-121224",
		"affected (examined): deployments.apps krateo-system/snowplow; composition snowplows krateo-system/snowplow",
		"analysis failed: The analysis returned no output."} {
		if !strings.Contains(body, want) {
			t.Error(want)
		}
	}
	if strings.Contains(body, "20261001-080000") {
		t.Fatal("an incident wholly before the window is not tonight's")
	}
}

func TestIncidentsNotServedIsExplainedEmptinessAndA403IsDegradation(t *testing.T) {
	a := api(nil)
	a.Fail["incidents"] = &kube.APIError{Status: 404, Reason: "Not Found"}
	body, st := F.Incidents(ctx, a, window)
	if body != "" || st["ok"] != true || st["empty"] != true || st["note"] == "" {
		t.Fatal(st)
	}
	body, st = F.Incidents(ctx, api(nil, "incidents"), window)
	if body != "" || st["ok"] != false || !strings.Contains(st["error"].(string), "403") {
		t.Fatal(st)
	}
}

// --- compositions -----------------------------------------------------------------------------------

func compositions(a *fake.API, s []kube.Served, orgs []string, events F.ReadEvents) (string, map[string]any, []targets.NamedRepo) {
	if events == nil {
		events = noEvents
	}
	return F.Compositions(ctx, a, served(s), window, orgs, events)
}

func TestCompositionsFailingNowAndRecoveredInTheWindowWithTheirBlueprint(t *testing.T) {
	body, st, bps := compositions(api(nil), FX.CompServed, []string{"krateo-blueprints"}, nil)
	if st["ok"] != true || st["queried"] != int64(3) || st["returned"] != int64(5) || st["failing"] != int64(1) ||
		st["recovered"] != int64(2) || st["findings"] != int64(3) {
		t.Fatal(st)
	}
	for _, want := range []string{"1 composition(s) NOT healthy now:", "TenantDb team-a/orders-db: Ready=False/Unavailable since",
		"Synced=False/ReconcileError since", "Does not match pattern '^[0-9]+Gi$'",
		"blueprint tenant-db (CompositionDefinition krateo-system/tenant-db, chart " +
			"oci://ghcr.io/krateo-blueprints/charts/tenant-db @ 1.4.0; source repository krateo-blueprints/tenant-db)",
		"TenantDb team-a/billing-db: Ready=True/Available since", "Snowplow krateo-system/snowplow: Ready=True",
		"chart oci://ghcr.io/krateo-platformops/charts/snowplow @ 1.12.36)"} {
		if !strings.Contains(body, want) {
			t.Error(want)
		}
	}
	if strings.Contains(body, "fresh-db") || strings.Contains(strings.Split(body, "RECOVERED")[0], "github-provider-kog") {
		t.Fatal(body)
	}
	want := []targets.NamedRepo{{Name: "github-provider-kog", Repo: "krateo-blueprints/github-provider-kog"}, {Name: "tenant-db", Repo: "krateo-blueprints/tenant-db"}}
	if !reflect.DeepEqual(bps, want) {
		t.Fatal(bps)
	}
}

func TestASyncedRestampIsNotARecovery(t *testing.T) {
	comps := map[string][]any{"tenantdbs": {FX.Comp("TenantDb", "x", &FX.CC{Status: "True", Reason: "Available", Ago: 100, Message: ""}, nil, 0, "tenant-db", "")}}
	body, st, _ := compositions(api(comps), FX.CompServed[:1], nil, nil)
	if body != "" || st["empty"] != true || st["failing"] != int64(0) || st["recovered"] != int64(0) {
		t.Fatal(st)
	}
}

func TestCompositionsDegradePerKindAndWithoutDefinitions(t *testing.T) {
	body, st, bps := compositions(api(nil, "snowplows", "compositiondefinitions"), FX.CompServed, []string{"krateo-blueprints"}, nil)
	if st["ok"] != false || !strings.Contains(st["error"].(string), "snowplows") || !strings.Contains(st["error"].(string), "compositiondefinitions") ||
		!strings.Contains(body, "orders-db") || !strings.Contains(body, "no CompositionDefinition found") || len(bps) != 0 {
		t.Fatal(st, bps)
	}
}

func TestTheBlueprintRepositoryComesOnlyFromTheOCIConvention(t *testing.T) {
	for _, c := range []struct {
		url       any
		org, name string
		ok        bool
	}{{"oci://ghcr.io/krateo-blueprints/charts/github-provider-kog", "krateo-blueprints", "github-provider-kog", true},
		{"oci://ghcr.io/krateo-blueprints/charts/x/", "krateo-blueprints", "x", true},
		{"https://krateo-blueprints.github.io/charts/blueprints", "", "", false},
		{"oci://ghcr.io/krateo-blueprints/charts/../../evil", "", "", false},
		{"oci://example.com/krateo-blueprints/charts/x", "", "", false}, {"", "", "", false}, {nil, "", "", false}} {
		o, n, ok := F.BlueprintRepo(c.url)
		if o != c.org || n != c.name || ok != c.ok {
			t.Error(c.url, o, n, ok)
		}
	}
}

// --- warning events on compositions (ClickHouse k8s-events) ----------------------------------------

const refusedMsg = `reconciling helm chart: reconcile: kube update (self-heal apply): failed to create resource: ` +
	`Deployment.apps "web-api-deployment" is invalid: spec.template.spec.containers[0].resources.requests: ` +
	`Invalid value: "2": must be less than or equal to cpu limit of 500m`

func group(kind, ns, name, reason string, count int64, uid, msg string) *F.EventGroup {
	if msg == "" {
		msg = refusedMsg
	}
	return &F.EventGroup{Kind: kind, Namespace: ns, Name: name, UID: uid, Reason: reason, Count: count,
		FirstSeen: "2026-10-05 07:01:02", LastSeen: "2026-10-05 07:40:00", Message: msg}
}

func compsWithUID() map[string][]any {
	comps := FX.Comps()
	orders := comps["tenantdbs"][0].(map[string]any)
	orders["metadata"].(map[string]any)["uid"] = "u-orders"
	comps["tenantdbs"] = append(comps["tenantdbs"], FX.Comp("TenantDb", "web-api", &FX.CC{Status: "True", Reason: "Available", Ago: 100, Message: ""}, nil, 0, "tenant-db", ""))
	return comps
}

func events() []*F.EventGroup {
	return []*F.EventGroup{
		group("TenantDb", "team-a", "x-renamed", "CannotObserveExternalResource", 3, "u-orders", "values don't meet the specifications"),
		group("TenantDb", "team-a", "web-api", "CannotObserveExternalResource", 12, "", ""),
		group("TenantDb", "team-b", "deleted-db", "CannotDeleteExternalResource", 2, "", "waiting for 1 managed child(ren) to finalize"),
	}
}

func TestACompositionRefusedAndSyncedAgainIsListedAsRecoveredWithTheRefusal(t *testing.T) {
	body, st, _ := compositions(api(compsWithUID()), FX.CompServed, []string{"krateo-blueprints"},
		func(context.Context, prompt.Window) ([]*F.EventGroup, string, error) { return events(), "", nil })
	if st["ok"] != true || st["warningEvents"] != int64(17) {
		t.Fatal(st)
	}
	refused := strings.Split(strings.Split(body, "RECOVERED after being REFUSED")[1], "RECOVERED in the window")[0]
	for _, want := range []string{"TenantDb team-a/web-api: recovered (was refused: CannotObserveExternalResource)",
		"source repository krateo-blueprints/tenant-db",
		"warning event CannotObserveExternalResource x12, first 2026-10-05 07:01:02, last 2026-10-05 07:40:00: reconciling helm chart",
		"must be less than or equal to cpu limit"} {
		if !strings.Contains(refused, want) {
			t.Error(want)
		}
	}
	// Matched by uid even under another name, and shown under the failing composition, not as recovered.
	failing := strings.Split(strings.Split(body, "NOT healthy now:")[1], "RECOVERED")[0]
	if !strings.Contains(failing, "orders-db") || !strings.Contains(failing, "values don't meet the specifications") ||
		strings.Contains(refused, "orders-db") {
		t.Fatal(failing)
	}
	// A composition gone since its events is still named.
	if !strings.Contains(body, "NO LONGER EXIST") || !strings.Contains(body, "TenantDb team-b/deleted-db:") ||
		st["recovered"] != int64(3) || st["failing"] != int64(1) || st["findings"] != int64(5) {
		t.Fatal(st)
	}
}

func TestAClickhouseFailureDegradesTheSourceButTheConditionsStillAnswer(t *testing.T) {
	boom := func(context.Context, prompt.Window) ([]*F.EventGroup, string, error) {
		return nil, "", errors.New("Code: 516. Authentication failed")
	}
	body, st, _ := compositions(api(nil), FX.CompServed, nil, boom)
	if st["ok"] != false || !strings.Contains(st["error"].(string), "warning events (ClickHouse)") || !strings.Contains(body, "orders-db") {
		t.Fatal(st)
	}
}

func TestTheWarningEventQueryIsBoundedExcludesExpiriesAndParsesRows(t *testing.T) {
	savedURL, savedPost := evidence.ClickhouseURL, evidence.Post
	t.Cleanup(func() { evidence.ClickhouseURL, evidence.Post = savedURL, savedPost })
	evidence.ClickhouseURL = "http://clickhouse.invalid"
	var sql string
	var maxRows int
	evidence.Post = func(_ context.Context, body string, rows int) (string, error) {
		sql, maxRows = body, rows
		return strings.Join([]string{`{"kind":"TenantDb","namespace":"team-a","name":"web-api","uid":"u1","reason":"CannotObserveExternalResource",` +
			`"count":"4","firstSeen":"2026-10-05 07:01:02.123","lastSeen":"2026-10-05 07:40:00.9","message":"m"}`,
			`["not", "a", "row"]`, "garbage", `{"kind":"","name":"x"}`}, "\n"), nil
	}
	groups, note, err := F.WarningEvents(ctx, prompt.Window{From: "2026-10-04T09:00:00+00:00", To: "2026-10-05T09:00:00+00:00"})
	want := []*F.EventGroup{{Kind: "TenantDb", Namespace: "team-a", Name: "web-api", UID: "u1", Reason: "CannotObserveExternalResource",
		Count: 4, FirstSeen: "2026-10-05 07:01:02", LastSeen: "2026-10-05 07:40:00", Message: "m"}}
	if err != nil || note != "" || !reflect.DeepEqual(groups, want) {
		t.Fatal(groups, note, err)
	}
	for _, s := range []string{"BETWEEN '2026-10-04 09:00:00' AND '2026-10-05 09:00:00'", "JSONExtractString(Body, 'type') != 'DELETED'",
		"JSONExtractString(Body, 'object', 'type') = 'Warning'",
		"startsWith(JSONExtractString(Body, 'object', 'involvedObject', 'apiVersion'), 'composition.krateo.io/')"} {
		if !strings.Contains(sql, s) {
			t.Error(s)
		}
	}
	if strings.Contains(strings.ReplaceAll(sql, "FORMAT JSONEachRow", ""), "{") || maxRows != F.MaxEventGroups {
		t.Fatal("every placeholder substituted, and the row cap sent")
	}
}

func TestNoClickhouseConfiguredIsANoteNotAFailure(t *testing.T) {
	saved := evidence.ClickhouseURL
	evidence.ClickhouseURL = ""
	t.Cleanup(func() { evidence.ClickhouseURL = saved })
	groups, note, err := F.WarningEvents(ctx, window)
	if err != nil || len(groups) != 0 || note != "warning events not read: CLICKHOUSE_URL is not configured" {
		t.Fatal(groups, note, err)
	}
}
