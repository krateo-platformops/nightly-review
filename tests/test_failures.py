"""The day's real failures (failures.py): Incidents and Compositions as evidence, blueprint destinations
derived from CompositionDefinitions, the prompt order, and a manual run that cannot collide with the
scheduled one.

The fixtures are trimmed copies of real objects on krateo-057 on 2026-10-05 — the Incident field paths
(spec.alertRef/trigger/triggeredAt, status.rootCause, status.howToFix.apply/applyAction,
status.analyzedResources, status.resolution) and the composition labels
(krateo.io/composition-definition-name/-namespace) are the ones the apiserver returned there."""
import datetime as dt
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import failures as F
import main as M
import prompt
import targets

NOW = dt.datetime(2026, 10, 5, 9, 0, tzinfo=dt.timezone.utc)
WINDOW = {"from": (NOW - dt.timedelta(hours=24)).isoformat(), "to": NOW.isoformat()}


def _ts(hours_ago):
    return (NOW - dt.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _incident(name, state="Open", opened=2, fired=1, root=None, apply=None, action=None, analyzed=(),
              resolution=None, error=None, alert=None):
    alert = alert or name.rsplit("-", 2)[0]
    st = {"state": state, "firings": 7, "lastFiredAt": _ts(fired), "completedAt": _ts(opened - 0.1),
          "analyzedResources": [{"gvr": "observability.krateo.io/v1alpha1/alerts", "name": alert,
                                 "namespace": "krateo-system", "whatWasRead": "spec.where"}] + list(analyzed)}
    if root:
        st["rootCause"] = {"category": "image", "confidence": "0.95", "statement": root}
    if apply or action:
        st["howToFix"] = {"apply": apply or "", "applyAction": action or {}}
    if resolution:
        st["resolution"] = resolution
    if error:
        st["error"] = error
    return {"apiVersion": "observability.krateo.io/v1alpha1", "kind": "Incident",
            "metadata": {"name": name, "namespace": "krateo-system", "creationTimestamp": _ts(opened)},
            "spec": {"alertRef": {"name": alert, "namespace": "krateo-system"}, "trigger": "alert",
                     "triggeredAt": _ts(opened), "prompt": "The HyperDX alert ... has fired"},
            "status": st}


INCIDENTS = [
    _incident("sre-image-pull-failure-20261004-101520", state="Resolved", opened=22.7, fired=12.5,
              root="An ad-hoc Job named chq-disc-121224 in namespace krateo-system specified a non-existent "
                   "container image clickhouse/clickhouse-client:24.8",
              apply="#!/usr/bin/env bash\n# Delete stuck job chq-disc-121224 which references the non-existent "
                    "image.\nset -euo pipefail\nkubectl delete job -n krateo-system chq-disc-121224\n",
              action={"apiVersion": "batch/v1", "resource": "jobs", "namespace": "krateo-system",
                      "name": "chq-disc-121224", "verb": "delete"},
              resolution={"by": "verify", "at": _ts(11.3)}),
    _incident("sre-probe-failing-20261003-105425", opened=46, fired=2.7,
              root="Snowplow composition snowplow has no spec.startupProbe configured",
              apply="#!/usr/bin/env bash\n# Configure startupProbe on Snowplow composition.\n",
              analyzed=[{"gvr": "apps/v1/deployments", "name": "snowplow", "namespace": "krateo-system"},
                        {"gvr": "composition.krateo.io/v1-12-36/snowplows", "name": "snowplow",
                         "namespace": "krateo-system"}]),
    _incident("sre-node-not-ready-20261004-213642", opened=11.4, fired=11.2,
              error="The analysis returned no output."),
    # Opened, fired and ended before the window: not tonight's.
    _incident("sre-probe-failing-20261001-080000", state="Closed", opened=97, fired=90,
              resolution={"by": "user", "at": _ts(80)}),
]


def _cd(name, url, version, kind):
    return {"metadata": {"name": name, "namespace": "krateo-system"},
            "spec": {"chart": {"url": url, "version": version}},
            "status": {"kind": kind, "apiVersion": f"composition.krateo.io/v{version.replace('.', '-')}"}}


CDS = [_cd("github-provider-kog", "oci://ghcr.io/krateo-blueprints/charts/github-provider-kog", "0.3.2",
           "GithubProviderKog"),
       _cd("tenant-db", "oci://ghcr.io/krateo-blueprints/charts/tenant-db", "1.4.0", "TenantDb"),
       _cd("snowplow", "oci://ghcr.io/krateo-platformops/charts/snowplow", "1.12.36", "Snowplow"),
       _cd("aws-rds-stack", "https://krateo-blueprints.github.io/charts/blueprints", "0.3.0", "AwsRdsStack")]


def _comp(kind, name, ready=("True", "Available", 2), synced=("True", "ReconcileSuccess", 0.01),
          created=24 * 10, cd=None, ns="team-a"):
    conds = []
    for typ, (status, reason, ago, *msg) in (("Ready", ready), ("Synced", synced)):
        conds.append({"type": typ, "status": status, "reason": reason, "message": (msg or [""])[0],
                      "lastTransitionTime": _ts(ago)})
    labels = {"krateo.io/composition-definition-name": cd, "krateo.io/composition-definition-namespace":
              "krateo-system"} if cd else {}
    return {"kind": kind, "metadata": {"name": name, "namespace": ns, "creationTimestamp": _ts(created),
                                       "labels": labels},
            "status": {"conditions": conds}}


SCHEMA_MSG = ("values don't meet the specifications of the schema(s) in the following chart(s): tenant-db: "
              "- size: Does not match pattern '^[0-9]+Gi$'")
COMPS = {
    "tenantdbs": [
        _comp("TenantDb", "orders-db", ready=("False", "Unavailable", 3, "Composition is not ready"),
              synced=("False", "ReconcileError", 3, SCHEMA_MSG), cd="tenant-db"),
        _comp("TenantDb", "billing-db", ready=("True", "Available", 5), cd="tenant-db"),        # recovered
        _comp("TenantDb", "fresh-db", ready=("True", "Available", 1), created=2, cd="tenant-db"),  # just created
    ],
    "githubproviderkogs": [_comp("GithubProviderKog", "github-provider-kog", ready=("True", "Available", 40),
                                 ns="krateo-system")],                                         # healthy, old
    "snowplows": [_comp("Snowplow", "snowplow", ready=("True", "Available", 2.8), ns="krateo-system")],
}
SERVED = [("v1-4-0", "tenantdbs", "TenantDb", True), ("v0-3-2", "githubproviderkogs", "GithubProviderKog", True),
          ("v1-12-36", "snowplows", "Snowplow", True)]


class _Api:
    def __init__(self, incidents=INCIDENTS, cds=CDS, comps=COMPS, fail=()):
        self.incidents, self.cds, self.comps, self.fail = incidents, cds, comps, set(fail)
        self.reads = []

    def list_cluster_custom_object(self, group, version, plural, **kw):
        self.reads.append((group, plural))
        if plural in self.fail:
            raise RuntimeError(f"403 forbidden: {plural}")
        items = {"incidents": self.incidents, "compositiondefinitions": self.cds}.get(plural)
        return {"items": items if items is not None else self.comps.get(plural, []), "metadata": {}}


# --- incidents --------------------------------------------------------------------------------------

def test_incidents_in_the_window_ended_first_with_cause_fix_and_affected_object():
    body, st = F.incidents(_Api(), WINDOW)
    assert st["ok"] and st["returned"] == 4 and st["findings"] == 3
    lines = body.splitlines()
    # The ended one leads: a failure somebody had to fix.
    first = next(i for i, ln in enumerate(lines) if ln.startswith("- Incident "))
    assert "sre-image-pull-failure-20261004-101520: Resolved (ended by its verify check" in lines[first]
    assert "affected (fix target): jobs.batch krateo-system/chq-disc-121224" in body
    assert "root cause [image, confidence 0.95]: An ad-hoc Job named chq-disc-121224" in body
    assert "remediation: Delete stuck job chq-disc-121224" in body
    assert "one API write: delete jobs krateo-system/chq-disc-121224" in body
    # The owning composition, when an analysed resource is one; the Alert itself is never "affected".
    assert "affected (examined): deployments.apps krateo-system/snowplow; composition snowplows krateo-system/snowplow" in body
    assert "analysis failed: The analysis returned no output." in body
    assert "20261001-080000" not in body, "an incident wholly before the window is not tonight's"


def test_incidents_not_served_is_explained_emptiness_and_a_403_is_degradation():
    class NotFound(Exception):
        status = 404

    class NotServed(_Api):
        def list_cluster_custom_object(self, *a, **k):
            raise NotFound("the server could not find the requested resource")
    body, st = F.incidents(NotServed(), WINDOW)
    assert body is None and st["ok"] and st["empty"] and st["note"]
    body, st = F.incidents(_Api(fail={"incidents"}), WINDOW)
    assert body is None and st["ok"] is False and "403" in st["error"]


# --- compositions -----------------------------------------------------------------------------------

def test_compositions_failing_now_and_recovered_in_the_window_with_their_blueprint():
    body, st, bps = F.compositions(_Api(), lambda g: SERVED, WINDOW, orgs=["krateo-blueprints"])
    assert st["ok"] and st["queried"] == 3 and st["returned"] == 5
    assert st["failing"] == 1 and st["recovered"] == 2 and st["findings"] == 3
    assert "1 composition(s) NOT healthy now:" in body
    assert "TenantDb team-a/orders-db: Ready=False/Unavailable since" in body
    assert "Synced=False/ReconcileError since" in body and "Does not match pattern '^[0-9]+Gi$'" in body
    assert ("blueprint tenant-db (CompositionDefinition krateo-system/tenant-db, chart "
            "oci://ghcr.io/krateo-blueprints/charts/tenant-db @ 1.4.0; source repository krateo-blueprints/tenant-db)") in body
    assert "TenantDb team-a/billing-db: Ready=True/Available since" in body
    # Found by KIND when the labels are absent; a platform chart gets no derived repository.
    assert "Snowplow krateo-system/snowplow: Ready=True" in body
    assert "chart oci://ghcr.io/krateo-platformops/charts/snowplow @ 1.12.36)" in body
    assert "fresh-db" not in body, "created inside the window: its Ready stamp is its birth, not a recovery"
    assert "github-provider-kog" not in body.split("RECOVERED")[0], "healthy and old: not listed"
    assert bps == {"github-provider-kog": "krateo-blueprints/github-provider-kog",
                   "tenant-db": "krateo-blueprints/tenant-db"}, "allowed orgs, OCI charts only"


def test_a_synced_restamp_is_not_a_recovery():
    """On 057 every composition's Synced=True carried the same minute: it is re-stamped each reconcile."""
    comps = {"tenantdbs": [_comp("TenantDb", "x", ready=("True", "Available", 100), cd="tenant-db")]}
    body, st, _ = F.compositions(_Api(comps=comps), lambda g: SERVED[:1], WINDOW)
    assert body is None and st["empty"] and st["failing"] == 0 and st["recovered"] == 0


def test_compositions_degrade_per_kind_and_without_definitions():
    body, st, bps = F.compositions(_Api(fail={"snowplows", "compositiondefinitions"}), lambda g: SERVED, WINDOW,
                                   orgs=["krateo-blueprints"])
    assert st["ok"] is False and "snowplows" in st["error"] and "compositiondefinitions" in st["error"]
    assert "orders-db" in body and "no CompositionDefinition found" in body and bps == {}


@pytest.mark.parametrize("url,want", [
    ("oci://ghcr.io/krateo-blueprints/charts/github-provider-kog", ("krateo-blueprints", "github-provider-kog")),
    ("oci://ghcr.io/krateo-blueprints/charts/x/", ("krateo-blueprints", "x")),
    ("https://krateo-blueprints.github.io/charts/blueprints", None),
    ("oci://ghcr.io/krateo-blueprints/charts/../../evil", None),
    ("oci://example.com/krateo-blueprints/charts/x", None), ("", None), (None, None),
])
def test_the_blueprint_repository_comes_only_from_the_oci_convention(url, want):
    assert F.blueprint_repo(url) == want


# --- warning events on compositions (ClickHouse k8s-events) ----------------------------------------

REFUSED_MSG = ('reconciling helm chart: reconcile: kube update (self-heal apply): failed to create resource: '
               'Deployment.apps "web-api-deployment" is invalid: spec.template.spec.containers[0].resources.requests: '
               'Invalid value: "2": must be less than or equal to cpu limit of 500m')


def _group(kind, ns, name, reason, count=3, uid="", msg=REFUSED_MSG, first="2026-10-05 07:01:02", last="2026-10-05 07:40:00"):
    return {"kind": kind, "namespace": ns, "name": name, "uid": uid, "reason": reason, "count": count,
            "firstSeen": first, "lastSeen": last, "message": msg}


def _comps_with_uid():
    comps = {k: [dict(o) for o in v] for k, v in COMPS.items()}
    comps["tenantdbs"][0]["metadata"] = dict(comps["tenantdbs"][0]["metadata"], uid="u-orders")
    comps["tenantdbs"].append(_comp("TenantDb", "web-api", ready=("True", "Available", 100), cd="tenant-db"))
    return comps


EVENTS = [_group("TenantDb", "team-a", "x-renamed", "CannotObserveExternalResource", uid="u-orders",
                 msg="values don't meet the specifications"),                                  # matched by uid
          _group("TenantDb", "team-a", "web-api", "CannotObserveExternalResource", count=12),  # by name+ns+kind
          _group("TenantDb", "team-b", "deleted-db", "CannotDeleteExternalResource", count=2,
                 msg="waiting for 1 managed child(ren) to finalize")]


def test_a_composition_refused_and_synced_again_is_listed_as_recovered_with_the_refusal():
    """The case conditions cannot show: a chart the apiserver refused (cpu request over its limit) shows only
    Synced=False, and once a person fixes it the condition says nothing. The Warning events still do."""
    body, st, _ = F.compositions(_Api(comps=_comps_with_uid()), lambda g: SERVED, WINDOW,
                                 orgs=["krateo-blueprints"], read_events=lambda w: (EVENTS, None))
    assert st["ok"] and st["warningEvents"] == 17
    refused = body.split("RECOVERED after being REFUSED")[1].split("RECOVERED in the window")[0]
    assert "TenantDb team-a/web-api: recovered (was refused: CannotObserveExternalResource)" in refused
    assert "source repository krateo-blueprints/tenant-db" in refused
    assert ("warning event CannotObserveExternalResource x12, first 2026-10-05 07:01:02, last 2026-10-05 07:40:00: "
            "reconciling helm chart") in refused and "must be less than or equal to cpu limit" in refused
    # Matched by uid even under another name, and shown under the failing composition, not as recovered.
    failing = body.split("NOT healthy now:")[1].split("RECOVERED")[0]
    assert "orders-db" in failing and "values don't meet the specifications" in failing
    assert "orders-db" not in refused
    # A composition gone since its events is still named.
    assert "NO LONGER EXIST" in body and "TenantDb team-b/deleted-db:" in body
    assert st["recovered"] == 3 and st["failing"] == 1 and st["findings"] == 5


def test_a_clickhouse_failure_degrades_the_source_but_the_conditions_still_answer():
    def boom(window):
        raise RuntimeError("Code: 516. Authentication failed")
    body, st, _ = F.compositions(_Api(), lambda g: SERVED, WINDOW, read_events=boom)
    assert st["ok"] is False and "warning events (ClickHouse)" in st["error"]
    assert "orders-db" in body


def test_the_warning_event_query_is_bounded_excludes_expiries_and_parses_rows(monkeypatch):
    import evidence as E
    sent = {}

    def post(url, data=None, params=None, **k):
        sent.update(data=data, params=params)
        rows = ['{"kind":"TenantDb","namespace":"team-a","name":"web-api","uid":"u1","reason":"CannotObserveExternalResource",'
                '"count":"4","firstSeen":"2026-10-05 07:01:02.123","lastSeen":"2026-10-05 07:40:00.9","message":"m"}',
                '["not", "a", "row"]', "garbage", '{"kind":"","name":"x"}']
        return types.SimpleNamespace(raise_for_status=lambda: None, text="\n".join(rows))
    monkeypatch.setattr(E, "CLICKHOUSE_URL", "http://clickhouse.invalid")
    monkeypatch.setattr(E, "requests", types.SimpleNamespace(post=post))
    groups, note = F.warning_events(WINDOW)
    assert note is None and groups == [{"kind": "TenantDb", "namespace": "team-a", "name": "web-api", "uid": "u1",
                                        "reason": "CannotObserveExternalResource", "count": 4,
                                        "firstSeen": "2026-10-05 07:01:02", "lastSeen": "2026-10-05 07:40:00",
                                        "message": "m"}]
    sql = sent["data"]
    assert "BETWEEN '2026-10-04 09:00:00' AND '2026-10-05 09:00:00'" in sql, "the window, in the prunable format"
    assert "JSONExtractString(Body, 'type') != 'DELETED'" in sql, "an expiry is a copy, not an occurrence"
    assert "JSONExtractString(Body, 'object', 'type') = 'Warning'" in sql
    assert "startsWith(JSONExtractString(Body, 'object', 'involvedObject', 'apiVersion'), 'composition.krateo.io/')" in sql
    assert "{" not in sql.replace("FORMAT JSONEachRow", ""), "every placeholder substituted"
    assert sent["params"]["max_result_rows"] == F.MAX_EVENT_GROUPS


def test_no_clickhouse_configured_is_a_note_not_a_failure(monkeypatch):
    import evidence as E
    monkeypatch.setattr(E, "CLICKHOUSE_URL", "")
    assert F.warning_events(WINDOW) == ([], "warning events not read: CLICKHOUSE_URL is not configured")


# --- targets ----------------------------------------------------------------------------------------

def _prop(kind="Documentation", subject="tenant-db/size-pattern-rejected", path="docs/values-schema.json"):
    return {"kind": kind, "subject": subject, "target": {"repo": "x", "path": path}}


def test_a_blueprint_proposal_lands_in_its_derived_repository_under_the_allowed_orgs(monkeypatch):
    monkeypatch.setattr(targets, "BLUEPRINT_POLICY", {"orgs": ["krateo-blueprints"], "pathPrefix": "chart"})
    monkeypatch.setattr(targets, "BLUEPRINTS", {})
    monkeypatch.setattr(targets, "COMPONENTS", {"github-provider-kog": {"repo": "krateo-blueprints/github-provider-kog",
                                                                      "pathPrefix": "docs"}})
    got = targets.register_blueprints({"tenant-db": "krateo-blueprints/tenant-db",
                                       "github-provider-kog": "krateo-blueprints/github-provider-kog",
                                       "evil": "someone-else/repo", "bad": "krateo-blueprints/../x"})
    assert got == {"tenant-db": "krateo-blueprints/tenant-db",
                   "github-provider-kog": "krateo-blueprints/github-provider-kog"}
    p = _prop()
    assert "retargeted" in targets.aim(p) and p["target"] == {"repo": "krateo-blueprints/tenant-db",
                                                               "path": "chart/values-schema.json"}
    # The components map wins over a derived destination.
    p = _prop(subject="github-provider-kog/x")
    targets.aim(p)
    assert p["target"]["path"] == "docs/values-schema.json"
    # Never a Prompt; and an org outside the allow-list derives nothing.
    p = _prop(kind="Prompt")
    assert " cleared: " in targets.aim(p) and p["target"]["repo"] == ""
    p = _prop(subject="evil/x")
    assert " cleared: " in targets.aim(p)


def test_no_org_allowed_means_nothing_is_derived(monkeypatch):
    monkeypatch.setattr(targets, "BLUEPRINT_POLICY", {})
    monkeypatch.setattr(targets, "BLUEPRINTS", {})
    assert targets.register_blueprints({"tenant-db": "krateo-blueprints/tenant-db"}) == {}


# --- the prompt -------------------------------------------------------------------------------------

def test_the_days_failures_come_before_the_log_patterns_and_the_prompt_says_why():
    msg = prompt.build_user_message(WINDOW, {"clickhouse": "c", "agent-analysis": "a", "compositions": "k",
                                             "incidents": "i", "kubernetes": "x"})
    order = [msg.index(f'source="{n}"') for n in ("incidents", "compositions", "agent-analysis", "clickhouse",
                                                   "kubernetes")]
    assert order == sorted(order)
    assert "A FAILURE A PERSON OR AN INCIDENT HAD TO FIX IS THE STRONGEST EVIDENCE" in prompt.SYSTEM
    assert "namespace/name" in prompt.SYSTEM.split("STRONGEST EVIDENCE")[1][:600]


# --- a manual run beside the scheduled one ----------------------------------------------------------

class _RunApi:
    def __init__(self, runs=(), taken=()):
        self.runs, self.taken, self.creates, self.patches = list(runs), set(taken), [], []

    def list_namespaced_custom_object(self, group, version, ns, plural):
        return {"items": self.runs if plural == "reviewruns" else []}

    def create_namespaced_custom_object(self, group, version, ns, plural, body):
        if body["metadata"]["name"] in self.taken:
            raise M.client.ApiException(status=409, reason="AlreadyExists")
        self.taken.add(body["metadata"]["name"])
        self.creates.append(body)
        return body

    def patch_namespaced_custom_object_status(self, group, version, ns, plural, name, body):
        self.patches.append((name, body["status"]))


def test_a_manual_run_is_named_from_its_start_and_a_same_minute_clash_takes_the_seconds(monkeypatch):
    monkeypatch.setattr(M, "JOB_NAME", "nightly-review-manual-x7k2p")
    api = _RunApi(taken={"rr-20261005-1037"})
    start = dt.datetime(2026, 10, 5, 10, 37, 12, tzinfo=dt.timezone.utc)
    assert M._create_run(api, start, WINDOW) == "rr-20261005-103712"
    assert api.creates[0]["metadata"]["labels"] == {"review.krateo.io/job": "nightly-review-manual-x7k2p"}
    assert M._create_run(_RunApi(), start, WINDOW) == "rr-20261005-1037"


def test_a_run_started_while_another_is_running_records_itself_as_not_run(monkeypatch):
    running = {"metadata": {"name": "rr-20261005-0200"},
               "status": {"phase": "Running", "startedAt": (NOW - dt.timedelta(minutes=20)).isoformat()}}
    stale = {"metadata": {"name": "rr-20261001-0200"},
             "status": {"phase": "Running", "startedAt": (NOW - dt.timedelta(days=4)).isoformat()}}
    assert M._run_in_progress(_RunApi(runs=[stale]), NOW) is None, "killed past its handler: not in progress"
    api = _RunApi(runs=[running, stale])
    monkeypatch.setattr(M, "_now", lambda: NOW)
    monkeypatch.setattr(M.config, "load_incluster_config", lambda: None)
    monkeypatch.setattr(M.client, "CustomObjectsApi", lambda: api)
    monkeypatch.setattr(M.client, "CoreV1Api", lambda: None)
    asked = []
    monkeypatch.setattr(M.autopilot, "ask", lambda *a, **k: asked.append(a))
    assert M.main() == 0
    assert not asked, "nothing was reviewed"
    (name, status), = api.patches
    assert name == "rr-20261005-0900" and status["phase"] == "Failed"
    assert "rr-20261005-0200 was still running" in status["error"]


def test_the_chart_grants_run_now_and_the_failure_reads():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    rbac = (root / "helm/nightly-review/templates/rbac.yaml").read_text()
    run_now = rbac.split("-run-now")[1]
    assert 'resources: ["cronjobs"]' in run_now and "resourceNames:" in run_now and 'verbs: ["get"]' in run_now
    assert 'verbs: ["create", "get", "list", "watch"]' in run_now
    assert "range .Values.portalAdminAccess.groups" in rbac.split("-run-now")[-1]
    reads = rbac.split("-failures-read")[1]
    for group, res in (("observability.krateo.io", "incidents"), ("core.krateo.io", "compositiondefinitions")):
        assert f'apiGroups: ["{group}"]\n    resources: ["{res}"]\n    verbs: ["list"]' in reads
    assert 'apiGroups: ["composition.krateo.io"]\n    resources: ["*"]\n    verbs: ["list"]' in reads
    cron = (root / "helm/nightly-review/templates/cronjob.yaml").read_text()
    assert 'dig "destinations" "blueprints" dict .Values.config' in cron
    assert "batch.kubernetes.io/job-name" in cron and "name: JOB_DEADLINE_SECONDS" in cron
