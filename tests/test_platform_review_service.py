"""The Platform Review service contract: what a finding IS (its subject), which alert kind exists, whether
the target exists, and — the one that keeps regressing — whether everything the service writes survives
the apiserver's structural pruning.

Each block names the defect it pins. The last one is the reason this file exists: evidence.*.queries
was written by every run since 0.1.14 and pruned by every write, and nothing noticed for seven releases,
because a pruned field produces no error — only an absence."""
import os
import pathlib
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import yaml

import autopilot as A
import proposals as P
import publish
import targets

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _prop(kind="Alert", subject="snowplow/sar-unauthorized", content="a: 1\n", repo="org/repo",
          path="x.yaml", fmt="yaml"):
    p = {"kind": kind, "title": "t", "rationale": "r", "confidence": "low",
         "evidence": [{"source": "clickhouse", "summary": "s"}],
         "target": {"repo": repo, "path": path}, "change": {"format": fmt, "content": content}}
    if subject is not None:
        p["subject"] = subject
    return p


NOOP = lambda payload: None


# --- subject: normalised, never trusted as typed ------------------------------------------------

@pytest.mark.parametrize("raw,want", [
    ("snowplow/subjectaccessreview-unauthorized", "snowplow/subjectaccessreview-unauthorized"),
    ("Snowplow/SubjectAccessReview Unauthorized", "snowplow/subject-access-review-unauthorized"),
    ("installer-chart-inspector:RBAC generation HTTP 500", "installer-chart-inspector/rbac-generation-http-500"),
    ("rest-dynamic-controller/CannotObserveExternalResource",
     "rest-dynamic-controller/cannot-observe-external-resource"),
    ("  kagent / agent never used  ", "kagent/agent-never-used"),
    ("a/b/c", "a/b-c"),
])
def test_one_finding_typed_many_ways_normalises_to_one_subject(raw, want):
    """The model's casing and punctuation must not split one finding into two."""
    assert P.normalise_subject(raw) == want


def test_the_same_event_reason_meets_itself_in_camel_and_kebab():
    """Kubernetes spells reasons CamelCase; the model paraphrases them in kebab. They must meet."""
    assert (P.normalise_subject("x/CannotObserveExternalResource")
            == P.normalise_subject("x/cannot-observe-external-resource"))


@pytest.mark.parametrize("raw", [None, 7, "", "no-separator-at-all", "/signal-only", "component/", "!!/??"])
def test_an_unusable_subject_is_none_not_a_guess(raw):
    assert P.normalise_subject(raw) is None


def test_validate_batch_keeps_a_proposal_whose_subject_folds_to_nothing():
    """A finding is not lost to punctuation. It is kept, subject-less, and the run says so."""
    kept, notes = P.validate_batch({"proposals": [_prop(subject="nonsense")]}, NOOP)
    assert len(kept) == 1 and "subject" not in kept[0]
    assert any("no usable subject" in n for n in notes)


def test_the_subject_is_required_by_the_contract():
    import prompt
    assert "subject" in prompt.ITEM_SCHEMA["required"]
    assert "subject" in prompt.ITEM_SCHEMA["properties"]


def test_the_subject_does_not_change_the_fingerprint():
    """Exact repeats are still exact repeats however the model labels them tonight."""
    assert P.fingerprint(_prop(subject="a/b")) == P.fingerprint(_prop(subject="c/d"))


# --- supersession by subject --------------------------------------------------------------------

class _Api:
    """Enough of CustomObjectsApi to drive open_index / create / supersede, recording every write."""
    def __init__(self, proposals=(), alerts=(), agents=()):
        self.proposals = {p["metadata"]["name"]: p for p in proposals}
        self.alerts, self.agents = list(alerts), list(agents)
        self.status_writes, self.creates, self.spec_patches = [], [], []

    def list_namespaced_custom_object(self, group, version, ns, plural):
        if plural == "proposals":
            return {"items": list(self.proposals.values())}
        if plural == "alerts":
            return {"items": self.alerts}
        return {"items": []}

    def list_cluster_custom_object(self, group, version, plural):
        return {"items": self.agents}

    def create_namespaced_custom_object(self, group, version, ns, plural, body):
        self.creates.append((plural, body))
        if plural == "proposals":
            self.proposals[body["metadata"]["name"]] = body
        return body

    def patch_namespaced_custom_object(self, group, version, ns, plural, name, body):
        self.spec_patches.append((plural, name, body))

    def get_namespaced_custom_object(self, group, version, ns, plural, name):
        return self.proposals[name]

    def patch_namespaced_custom_object_status(self, group, version, ns, plural, name, body):
        self.status_writes.append((plural, name, body))
        if plural == "proposals" and name in self.proposals:
            self.proposals[name].setdefault("status", {}).update(body["status"])


def _stored(name, kind="Alert", subject=None, phase="Proposed", run="rr-old", repo="org/old", fp=None):
    spec = {"kind": kind, "target": {"repo": repo, "path": f"{name}.yaml"}, "fingerprint": fp or f"fp-{name}",
            "producedBy": {"runRef": run}}
    if subject:
        spec["subject"] = subject
    return {"metadata": {"name": name}, "spec": spec, "status": {"phase": phase}}


def test_a_new_proposal_supersedes_an_open_one_about_the_same_finding_in_another_repo():
    """THE CASE THAT MOTIVATED THE FIELD: one chart-inspector failure, a different repository every
    night. Target keys never matched; the subject does."""
    api = _Api([_stored("p-old", subject="snowplow/sar-unauthorized", repo="org/elsewhere")])
    by_fp, by_target, by_subject = publish.open_index(api, "rr-new")
    assert P.classify(_prop(), by_fp, by_target, by_subject) == ("supersede", ["p-old"])


def test_null_subjects_never_group_with_each_other():
    """Twenty legacy proposals carry no subject. If absent matched absent, the first new subject-less
    proposal of each kind would retire every one of them."""
    api = _Api([_stored("p-legacy-1"), _stored("p-legacy-2")])
    by_fp, by_target, by_subject = publish.open_index(api, "rr-new")
    assert by_subject == {}
    assert P.classify(_prop(subject=None), by_fp, by_target, by_subject) == ("new", None)
    assert P.subject_key(_prop(subject=None)) is None


def test_a_subject_match_needs_the_same_kind():
    """An Alert and the Documentation for the same failure are two halves of one answer."""
    api = _Api([_stored("p-doc", kind="Documentation", subject="snowplow/sar-unauthorized")])
    assert P.classify(_prop(), *publish.open_index(api, "rr-new")) == ("new", None)


@pytest.mark.parametrize("phase", ["PrOpen", "Superseded", "Merged", "Rejected", "Refused", "Failed"])
def test_only_a_proposed_one_is_superseded_by_subject(phase):
    """PrOpen has a person's pull request hanging off it; the rest are already decided."""
    api = _Api([_stored("p-old", subject="snowplow/sar-unauthorized", phase=phase)])
    assert publish.open_index(api, "rr-new")[2] == {}


def test_a_proposal_from_the_same_run_is_not_superseded_by_subject():
    api = _Api([_stored("p-sibling", subject="snowplow/sar-unauthorized", run="rr-new")])
    assert publish.open_index(api, "rr-new")[2] == {}


def test_an_exact_repeat_is_still_a_duplicate_not_a_supersession():
    prop = _prop()
    fp = P.fingerprint(prop)
    api = _Api([_stored("p-old", subject="snowplow/sar-unauthorized", fp=fp)])
    assert P.classify(prop, *publish.open_index(api, "rr-new")) == ("dedup", "p-old")


def test_supersession_writes_supersededby_and_a_terminal_phase():
    """supersededBy was declared from the first release and never written."""
    api = _Api([_stored("p-old", subject="s/x")])
    publish.mark_superseded(api, "p-old", by="p-new", reason="r")
    (_, name, body), = api.status_writes
    assert name == "p-old"
    assert body["status"]["phase"] == publish.PHASE_SUPERSEDED
    assert body["status"]["supersededBy"] == "p-new"


def test_a_superseded_prior_is_forgotten_so_it_is_not_counted_twice():
    api = _Api([_stored("p-old", subject="snowplow/sar-unauthorized")])
    by_fp, by_target, by_subject = publish.open_index(api, "rr-new")
    _, priors = P.classify(_prop(content="a: 1\n"), by_fp, by_target, by_subject)
    for n in priors:
        publish.forget(n, by_target, by_subject)
    assert P.classify(_prop(content="a: 2\n"), by_fp, by_target, by_subject) == ("new", None)


# --- the alert kind (#24) -----------------------------------------------------------------------

PROM = """apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata: {name: x}
spec: {groups: []}
"""
INVENTED = """apiVersion: monitoring.krateo.io/v1alpha1
kind: Alert
metadata: {name: x}
"""
REAL = """apiVersion: observability.krateo.io/v1alpha1
kind: Alert
metadata: {name: x, namespace: krateo-system}
spec: {interval: 15m, threshold: 1, thresholdType: above, where: "Body LIKE '%x%'"}
"""


@pytest.mark.parametrize("content", [PROM, INVENTED], ids=["PrometheusRule", "monitoring.krateo.io"])
def test_the_two_shapes_every_alert_proposal_on_057_took_are_refused(content):
    """Eleven PrometheusRules and two invented-group Alerts: thirteen of thirteen, none could fire."""
    kept, notes = P.validate_batch({"proposals": [_prop(content=content)]}, NOOP)
    assert kept == []
    assert any(n.startswith("DROPPED") and "observability.krateo.io/v1alpha1" in n for n in notes)


def test_the_real_alert_kind_passes():
    kept, notes = P.validate_batch({"proposals": [_prop(content=REAL)]}, NOOP)
    assert len(kept) == 1 and not any(n.startswith("DROPPED") for n in notes)


def test_an_alert_proposal_cannot_carry_some_other_object():
    other = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n"
    assert P.alert_kind_violation(_prop(content=other))


def test_a_widget_called_alert_is_fine_in_a_widget_proposal():
    """alerts.widgets.templates.krateo.io is a real portal widget; the Alert-only rule is for Alerts."""
    w = "apiVersion: widgets.templates.krateo.io/v1beta1\nkind: Alert\nmetadata: {name: x}\n"
    assert P.alert_kind_violation(_prop(kind="Widget", content=w)) is None


def test_a_prometheusrule_is_refused_whatever_kind_carries_it():
    assert P.alert_kind_violation(_prop(kind="Policy", content=PROM))


def test_a_diff_alert_naming_a_forbidden_kind_is_refused_by_text():
    diff = "+apiVersion: monitoring.coreos.com/v1\n+kind: PrometheusRule\n"
    assert P.alert_kind_violation(_prop(content=diff, fmt="diff"))


def test_documentation_may_mention_prometheusrule_in_prose():
    doc = "We do not use PrometheusRule here; see observability.krateo.io Alerts."
    assert P.alert_kind_violation(_prop(kind="Documentation", content=doc, fmt="markdown")) is None


def test_the_prompt_names_only_the_real_alert_kind_and_its_live_fields():
    import prompt
    assert "observability.krateo.io/v1alpha1" in prompt.SYSTEM
    for field in ("interval", "threshold", "thresholdType", "where", "displayName", "message"):
        assert field in prompt.ALERT_KIND
    assert "NEVER a PrometheusRule" in prompt.SYSTEM


# --- TargetResolved -----------------------------------------------------------------------------

def _head(code, calls=None):
    def head(url, **kw):
        if calls is not None:
            calls.append(url)
        return types.SimpleNamespace(status_code=code)
    return types.SimpleNamespace(head=head)


@pytest.mark.parametrize("code,status,reason", [
    (200, "True", "RepoFound"), (404, "False", "RepoNotFound"),
    (403, "Unknown", "CheckFailed"), (429, "Unknown", "CheckFailed"), (502, "Unknown", "CheckFailed"),
])
def test_the_condition_says_what_github_answered_and_no_more(monkeypatch, code, status, reason):
    """A rate limit says nothing about the repository and must not be recorded as if it did."""
    monkeypatch.setattr(targets, "requests", _head(code))
    c = targets.resolve("krateo-platformops/x")
    assert (c["type"], c["status"], c["reason"]) == ("TargetResolved", status, reason)


def test_a_404_admits_it_cannot_tell_private_from_missing(monkeypatch):
    monkeypatch.setattr(targets, "requests", _head(404))
    assert "private" in targets.resolve("o/r")["message"]


@pytest.mark.parametrize("repo", ["../../user", "o/r?x=1", "o/r#f", "o/r/extra", "o", "/r", "o/..", "o r/x"])
def test_a_model_chosen_repo_never_reaches_a_url_unless_it_is_owner_name(monkeypatch, repo):
    """target.repo is model output over an attacker-influenceable corpus, about to become a URL path."""
    calls = []
    monkeypatch.setattr(targets, "requests", _head(200, calls))
    c = targets.resolve(repo)
    assert calls == [] and (c["status"], c["reason"]) == ("False", "InvalidRepo")


def test_each_repository_is_asked_once_per_run(monkeypatch):
    calls, cache = [], {}
    monkeypatch.setattr(targets, "requests", _head(200, calls))
    for _ in range(5):
        targets.resolve("o/r", cache=cache)
    assert len(calls) == 1


def test_the_check_holds_no_credential():
    """The point of choosing anonymous: this service still holds no git credential."""
    src = (ROOT / "targets.py").read_text()
    for gone in ("Authorization", "GITHUB_TOKEN", "secret"):
        assert gone not in src.replace("Secret", "")


# --- status.model: measured or absent -----------------------------------------------------------

def test_token_usage_is_read_where_kagent_actually_puts_it():
    result = {"metadata": {"kagent_usage_metadata": {
        "promptTokenCount": 1200, "candidatesTokenCount": 300, "totalTokenCount": 1500}}}
    assert A.token_usage(result) == {"inputTokens": 1200, "outputTokens": 300, "totalTokens": 1500}


def test_no_usage_is_empty_not_zeros():
    """Zeros were the bug: they read as a measurement."""
    assert A.token_usage({"usage": {"inputTokens": 5}}) == {}
    assert A.token_usage({}) == {}


def test_ask_returns_the_usage_from_the_final_event(monkeypatch):
    lines = ['data: {"result": {"status": {"state": "working"}, "metadata": {"kagent_usage_metadata": '
             '{"promptTokenCount": 10, "candidatesTokenCount": 2, "totalTokenCount": 12}}}}',
             'data: {"result": {"status": {"state": "completed", "message": {"parts": '
             '[{"kind": "text", "text": "{\\"proposals\\": []}"}]}}}}']
    resp = types.SimpleNamespace(raise_for_status=lambda: None, close=lambda: None,
                                 iter_lines=lambda decode_unicode=False: iter(lines))
    monkeypatch.setattr(A, "requests", types.SimpleNamespace(post=lambda *a, **k: resp))
    _, _, usage = A.ask("sys", "msg", "rr-usage")
    assert usage == {"inputTokens": 10, "outputTokens": 2, "totalTokens": 12}


# --- EVERYTHING THE SERVICE WRITES IS DECLARED --------------------------------------------------
# Structural schemas PRUNE undeclared fields on write, silently. So this drives a whole run through
# main.main() against a fake apiserver — every evidence source on its richest path, truncation, a
# supersession, a publish — and walks every object and status it wrote against the CRDs in this repo.

def _crd_schema(name):
    doc = yaml.safe_load((ROOT / "helm/nightly-review-crds/templates" / name).read_text())
    return doc["spec"]["versions"][0]["schema"]["openAPIV3Schema"]


def _undeclared(value, schema, path=""):
    """Paths the apiserver would prune (undeclared) or reject (outside an enum)."""
    out = []
    if schema.get("x-kubernetes-preserve-unknown-fields"):
        return out
    if "enum" in schema and value is not None and value not in schema["enum"]:
        out.append(f"{path} = {value!r} not in enum")
    if isinstance(value, dict):
        props, extra = schema.get("properties"), schema.get("additionalProperties")
        for k, v in value.items():
            if props and k in props:
                out += _undeclared(v, props[k], f"{path}.{k}")
            elif isinstance(extra, dict):
                out += _undeclared(v, extra, f"{path}.{k}")
            else:
                out.append(f"{path}.{k}")
    elif isinstance(value, list) and "items" in schema:
        for i, v in enumerate(value):
            out += _undeclared(v, schema["items"], f"{path}[{i}]")
    return out


@pytest.fixture
def full_run(monkeypatch):
    """One run through main.main() on every rich path, returning the fake apiserver."""
    import datetime as dt
    import evidence as E
    import main as M

    old = _stored("p-old", subject="snowplow/sar-unauthorized", run="rr-older")
    api = _Api(proposals=[old, _stored("p-legacy")],
               alerts=[{"metadata": {"name": "a"}, "spec": {"displayName": "A", "threshold": 1}}],
               agents=[{"metadata": {"namespace": "krateo-system", "name": "never-used"}},
                       {"metadata": {"namespace": "krateo-system", "name": "busy"}}])
    monkeypatch.setattr(M.config, "load_incluster_config", lambda: None)
    monkeypatch.setattr(M.client, "CustomObjectsApi", lambda: api)
    monkeypatch.setattr(M, "DRY_RUN", False)

    # ClickHouse: a windowed query that answers, so stats carries `queries`; MAX_CHARS tiny so every
    # source is truncated and records truncated/truncatedAtChars/droppedChars.
    monkeypatch.setenv("CLICKHOUSE_QUERIES", '{"errors": "SELECT 1 WHERE t BETWEEN \'{from}\' AND \'{to}\'"}')
    monkeypatch.setattr(E, "CLICKHOUSE_URL", "http://clickhouse.invalid")
    monkeypatch.setattr(E, "MAX_CHARS", 10)
    ok = types.SimpleNamespace(raise_for_status=lambda: None, text='["svc", 5]\n["svc2", 3]\n')
    monkeypatch.setattr(E, "requests", types.SimpleNamespace(post=lambda *a, **k: ok))

    # kagent sessions through a fake pg8000, with one busy agent and one deployed-never-used.
    now = dt.datetime.now(dt.timezone.utc)
    rows = [("krateo_system__NS__busy", 40, 4, 3, now), ("krateo_system__NS__gone", 2, 0, 1,
                                                          now - dt.timedelta(days=30))]
    conn = types.SimpleNamespace(run=lambda *a, **k: rows, close=lambda: None)
    native = types.SimpleNamespace(Connection=lambda **k: conn)
    monkeypatch.setitem(sys.modules, "pg8000", types.SimpleNamespace(native=native))
    monkeypatch.setitem(sys.modules, "pg8000.native", native)
    monkeypatch.setattr(E, "KAGENT_DB_USER", "u")
    monkeypatch.setattr(E, "KAGENT_DB_PASSWORD", "p")

    payload = {"summary": "one real finding and one aimed at a missing repo",
               "proposals": [
                   dict(_prop(content=REAL, repo="krateo-platformops/snowplow"),
                        subject="Snowplow/SAR Unauthorized", confidence="high"),
                   dict(_prop(kind="Documentation", subject="kagent:agent never used", fmt="markdown",
                              content="# x", repo="krateo-platformops/does-not-exist"), confidence="low"),
               ]}
    monkeypatch.setattr(M.autopilot, "service_jwt", lambda: None)
    monkeypatch.setattr(M.autopilot, "ask", lambda *a, **k: (
        payload, "{}", A.token_usage({"metadata": {"kagent_usage_metadata": {
            "promptTokenCount": 9, "candidatesTokenCount": 3, "totalTokenCount": 12}}})))
    monkeypatch.setattr(M.publish, "publish_version", lambda: "v1-8-53")
    monkeypatch.setattr(targets, "requests", types.SimpleNamespace(head=lambda url, **k: types.SimpleNamespace(
        status_code=404 if "does-not-exist" in url else 200)))

    assert M.main() == 0
    return api


def test_every_reviewrun_status_the_service_writes_is_declared(full_run):
    schema = _crd_schema("reviewrun.crd.yaml")["properties"]["status"]
    writes = [b["status"] for plural, _, b in full_run.status_writes if plural == "reviewruns"]
    assert writes, "the run wrote no status at all"
    final = writes[-1]
    # The run exercised what it is meant to, or this test proves nothing.
    assert final["evidence"]["clickhouse"]["queries"], "queries were not written, so not tested"
    assert final["evidence"]["clickhouse"]["truncated"] is True
    assert final["summary"] and final["model"]["inputTokens"] == 9
    assert [s["name"] for s in final["steps"]] == ["gather", "ask", "validate", "publish", "record"]
    assert final["proposals"]["superseded"] == 1
    for st in writes:
        assert _undeclared(st, schema, "status") == []


def test_every_proposal_the_service_writes_is_declared(full_run):
    schema = _crd_schema("proposal.crd.yaml")["properties"]
    created = [b for plural, b in full_run.creates if plural == "proposals"]
    assert len(created) == 2
    for body in created:
        assert _undeclared(body["spec"], schema["spec"], "spec") == []
    statuses = [b["status"] for plural, _, b in full_run.status_writes if plural == "proposals"]
    assert any(s.get("supersededBy") for s in statuses)
    assert any(c["type"] == "TargetResolved" for s in statuses for c in s.get("conditions", []))
    for st in statuses:
        assert _undeclared(st, schema["status"], "status") == []


def test_the_legacy_subjectless_proposal_survives_a_run_untouched(full_run):
    assert "status" not in full_run.proposals["p-legacy"] or \
        full_run.proposals["p-legacy"]["status"]["phase"] == "Proposed"


def test_a_missing_repo_is_recorded_and_written_but_gets_no_claim(full_run):
    """TargetUnresolved is a normal state: the proposal exists; only the doomed claim is skipped."""
    by_name = {b["metadata"]["name"]: b for plural, b in full_run.creates if plural == "proposals"}
    doc = next(b for b in by_name.values() if b["spec"]["kind"] == "Documentation")
    st = full_run.proposals[doc["metadata"]["name"]]["status"]
    (cond,) = [c for c in st["conditions"] if c["type"] == "TargetResolved"]
    assert (cond["status"], cond["reason"]) == ("False", "RepoNotFound")
    claims = [b for plural, b in full_run.creates if plural == "builderpublishes"]
    assert [c["spec"]["target"]["repo"] for c in claims] == ["snowplow"]


def test_every_stats_key_evidence_assigns_by_subscript_is_declared():
    """A cheap static belt under the run above: a key added on a path the fake run does not reach is
    still caught if it is assigned the usual way."""
    import re
    declared = set(_crd_schema("reviewrun.crd.yaml")["properties"]["status"]["properties"]["evidence"]
                   ["additionalProperties"]["properties"])
    src = (ROOT / "evidence.py").read_text()
    written = set(re.findall(r'stats\["(\w+)"\]\s*(?:=|\+=)', src))
    assert written and written <= declared, written - declared
