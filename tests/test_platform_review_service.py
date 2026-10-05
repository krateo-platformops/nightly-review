"""The Platform Review service contract: what a finding IS (its subject), which alert kind exists, whether
the target exists, and — the one that keeps regressing — whether everything the service writes survives
the apiserver's structural pruning.

Each block names the defect it pins. The last one is the reason this file exists: evidence.*.queries
was written by every run since 0.1.14 and pruned by every write, and nothing noticed for seven releases,
because a pruned field produces no error — only an absence."""
import json
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
    def __init__(self, proposals=(), alerts=(), agents=(), flexes=(), cluster=None, configs=None):
        self.proposals = {p["metadata"]["name"]: p for p in proposals}
        self.alerts, self.agents, self.flexes = list(alerts), list(agents), list(flexes)
        # The sync-stall check's reads: plural -> items, and (plural, name) -> a Configuration.
        self.cluster, self.configs = cluster or {}, configs or {}
        self.status_writes, self.creates, self.spec_patches = [], [], []

    def list_namespaced_custom_object(self, group, version, ns, plural):
        if plural == "proposals":
            return {"items": list(self.proposals.values())}
        if plural == "alerts":
            return {"items": self.alerts}
        if plural == "flexes":
            return {"items": self.flexes}
        return {"items": []}

    def list_cluster_custom_object(self, group, version, plural, **kw):
        if plural == "agents":
            return {"items": self.agents}
        return {"items": self.cluster.get(plural, [])}

    def create_namespaced_custom_object(self, group, version, ns, plural, body):
        self.creates.append((plural, body))
        if plural == "proposals":
            self.proposals[body["metadata"]["name"]] = body
        return body

    def patch_namespaced_custom_object(self, group, version, ns, plural, name, body):
        self.spec_patches.append((plural, name, body))

    def get_namespaced_custom_object(self, group, version, ns, plural, name):
        if plural != "proposals":
            return self.configs[(plural, name)]
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


def test_a_proposal_with_an_open_pr_is_never_superseded_by_target_either():
    """The same file with a new body used to retire a PrOpen proposal from under its pull request. The
    target index is Proposed-only now, like the subject one: the newer body lands beside it as new."""
    stored = _stored("p-pr", phase="PrOpen", repo="org/old")
    api = _Api([stored])
    by_fp, by_target, by_subject = publish.open_index(api, "rr-new")
    assert by_target == {}
    same_file = _prop(subject=None)
    same_file["target"] = dict(stored["spec"]["target"])
    assert P.classify(same_file, by_fp, by_target, by_subject) == ("new", None)


def test_a_proposed_one_is_still_superseded_by_target():
    stored = _stored("p-old", repo="org/old")
    api = _Api([stored])
    same_file = _prop(subject=None)
    same_file["target"] = dict(stored["spec"]["target"])
    assert P.classify(same_file, *publish.open_index(api, "rr-new")) == ("supersede", ["p-old"])


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

def _head(code, calls=None, headers=None):
    def head(url, **kw):
        if calls is not None:
            calls.append(url)
        if headers is not None:
            headers.append(dict(kw.get("headers") or {}))
        return types.SimpleNamespace(status_code=code)
    return types.SimpleNamespace(head=head)


@pytest.fixture(autouse=True)
def _anonymous_by_default(monkeypatch):
    """No test inherits a token from the shell that runs it."""
    monkeypatch.delenv(targets.TOKEN_ENV, raising=False)


@pytest.mark.parametrize("code,status,reason", [
    (200, "True", "RepoFound"), (404, "False", "NotFoundOrPrivate"),
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


def test_the_anonymous_check_sends_no_credential(monkeypatch):
    """No token configured, no Authorization header — and a 404 stays honest about being anonymous."""
    sent = []
    monkeypatch.setattr(targets, "requests", _head(404, headers=sent))
    assert targets.resolve("krateo-agentiko/autopilot")["reason"] == "NotFoundOrPrivate"
    assert "Authorization" not in sent[0]


@pytest.mark.parametrize("code,status,reason", [
    (200, "True", "RepoFound"), (404, "False", "RepoNotFound"), (401, "Unknown", "CheckFailed"),
    (403, "Unknown", "CheckFailed"), (502, "Unknown", "CheckFailed"),
])
def test_with_a_token_404_is_definitive_and_401_is_about_the_credential(monkeypatch, code, status, reason):
    """rr-20260930-0200: both Prompt proposals aimed at private krateo-agentiko repositories that exist,
    and both read NotFoundOrPrivate. With the platform's token a 200 there is RepoFound; a 404 is
    RepoNotFound; a REJECTED token says nothing about the repository and must never read as not found."""
    sent = []
    monkeypatch.setenv(targets.TOKEN_ENV, "tok-under-test")
    monkeypatch.setattr(targets, "requests", _head(code, headers=sent))
    c = targets.resolve("krateo-agentiko/installer-agent")
    assert (c["status"], c["reason"]) == (status, reason)
    assert sent[0]["Authorization"] == "Bearer tok-under-test"
    assert "tok-under-test" not in str(c)
    if code == 401:
        assert "credential" in c["message"] and "rejected" in c["message"]


def test_a_blank_token_is_the_anonymous_check(monkeypatch):
    """optional: true with the key present but empty must not send `Bearer ` and call 404 definitive."""
    sent = []
    monkeypatch.setenv(targets.TOKEN_ENV, "  ")
    monkeypatch.setattr(targets, "requests", _head(404, headers=sent))
    assert targets.resolve("o/r")["reason"] == "NotFoundOrPrivate" and "Authorization" not in sent[0]


def test_the_rbac_still_grants_no_secret_read():
    """The token arrives by secretKeyRef, which the KUBELET resolves. The ServiceAccount must stay unable
    to read Secrets — that is the property the anonymous design protected, and it must survive this."""
    import re
    rbac = (ROOT / "helm/nightly-review/templates/rbac.yaml").read_text()
    granted = re.findall(r"^\s*resources:\s*\[(.*)\]", rbac, re.M)
    assert len(granted) > 5, "no rules found, so this test proves nothing"
    assert not any("secrets" in g.lower() for g in granted), granted
    cron = (ROOT / "helm/nightly-review/templates/cronjob.yaml").read_text()
    assert "name: TARGET_CHECK_TOKEN" in cron and "optional: true" in cron.split("TARGET_CHECK_TOKEN")[1][:300]


# --- config.targets: where a kind lands is configuration -------------------------------------------

OBS = {"Alert": {"repo": "krateo-platformops/observability", "pathPrefix": "charts/krateo-observability/templates"}}


def test_an_alert_goes_where_the_chart_says_whatever_the_model_chose():
    """rr-20260930-0200 aimed all three Alert proposals at `krateo-observability`: no owner, InvalidRepo."""
    p = _prop(repo="krateo-observability", path="alerts/snowplow-sar-unauthorized.yaml")
    note = targets.aim(p, OBS)
    assert p["target"] == {"repo": "krateo-platformops/observability",
                           "path": "charts/krateo-observability/templates/snowplow-sar-unauthorized.yaml"}
    assert "krateo-observability/alerts/snowplow-sar-unauthorized.yaml -> krateo-platformops/observability" in note
    assert "config.targets.Alert" in note


def test_the_destination_is_the_charts_values_and_absent_means_no_destination():
    """The values live in values.yaml ONLY. With no env (keys absent from the values) the code carries no
    destination of its own, so a proposal is not retargeted to a default — it gets NO repository."""
    values = yaml.safe_load((ROOT / "helm/nightly-review/values.yaml").read_text())
    assert values["config"]["targets"] == OBS
    assert values["config"]["targetCheck"]["tokenSecret"] == {"name": "gh-token", "key": "token"}
    assert values["config"]["destinations"]["components"]["snowplow"]["repo"] == "krateo-platformops/snowplow"
    assert targets.DESTINATIONS == {}, "the code must not carry its own default destination"
    assert targets.COMPONENTS == {}, "the code must not carry its own default destination"
    p = _prop(repo="krateo-observability", path="alerts/a.yaml")
    assert "cleared" in targets.aim(p)
    assert p["target"] == {"repo": "", "path": "a.yaml"}


def test_no_destination_is_hardcoded_in_the_code():
    """Diego: "this destinations must be in values, not hardcoded". No repository of the platform's orgs
    appears in the service's code outside comments and docstrings."""
    import ast
    import io
    import tokenize
    for name in ("targets.py", "main.py", "prompt.py", "analysis.py", "publish.py", "proposals.py",
                 "sync_health.py", "failures.py"):
        src = (ROOT / name).read_text()
        doc_lines = set()
        for node in ast.walk(ast.parse(src)):
            body = getattr(node, "body", None)
            if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                    and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                doc_lines.update(range(body[0].lineno, body[0].end_lineno + 1))
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.STRING and tok.start[0] not in doc_lines:
                assert not any(org + "/" in tok.string for org in
                               ("krateo-platformops", "krateo-agentiko", "krateo-blueprints")), (name, tok.string[:80])


# Keys this change added to values.schema.json. core-provider applies schema defaults straight into the
# live composition CR spec, so a `default` there is a silent live override, not documentation — the
# installer's check-fill-defaults.py exists because one (frontend agentgateway.enabled) broke Autopilot
# for every user. Its rule, mirrored: no `default` at ANY depth under these keys.
NEW_SCHEMA_KEYS = ("targets", "targetCheck", "destinations", "syncStall")


def _defaults(node, path):
    out = []
    if isinstance(node, dict):
        if "default" in node:
            out.append(path)
        for k, v in node.items():
            out += _defaults(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += _defaults(v, f"{path}[{i}]")
    return out


def test_no_new_schema_key_carries_a_default():
    import json as _json
    cfg = _json.loads((ROOT / "helm/nightly-review/values.schema.json").read_text())["properties"]["config"]["properties"]
    for key in NEW_SCHEMA_KEYS:
        assert key in cfg, f"config.{key} is not declared, so this test proves nothing"
        assert _defaults(cfg[key], f"config.{key}") == []


def test_the_chart_passes_the_components_map_and_survives_its_absence():
    """No schema default fills config.destinations, so the template digs for it; the env name is the one
    targets.py reads."""
    cron = (ROOT / "helm/nightly-review/templates/cronjob.yaml").read_text()
    assert "name: TARGET_COMPONENTS" in cron
    assert 'dig "destinations" "components" dict .Values.config' in cron.split("TARGET_COMPONENTS")[1][:200]
    assert 'os.environ.get("TARGET_COMPONENTS")' in (ROOT / "targets.py").read_text()


def test_the_chart_renders_the_anonymous_check_when_the_key_is_absent():
    """No schema default fills config.targetCheck, so the template must survive its absence."""
    cron = (ROOT / "helm/nightly-review/templates/cronjob.yaml").read_text()
    assert 'dig "targetCheck" "tokenSecret" dict .Values.config' in cron
    assert ".Values.config.targetCheck." not in cron


@pytest.mark.parametrize("path,want", [
    ("../../.github/workflows/x.yaml", "x.yaml"), ("a/b c;$(id).yaml", "b-c-id-.yaml"),
    ("", "snowplow-sar-unauthorized.yaml"), (None, "snowplow-sar-unauthorized.yaml"),
])
def test_the_model_keeps_only_a_safe_file_name(path, want):
    """The prefix is the chart's; the file name is model output and becomes a path in a pull request."""
    p = _prop(path=path)
    targets.aim(p, OBS)
    assert p["target"]["path"] == f"charts/krateo-observability/templates/{want}"


# --- config.destinations: where every other proposal lands is configuration too ----------------------

COMPS = {
    "snowplow": {"repo": "krateo-platformops/snowplow", "pathPrefix": "docs"},
    "kagent": {"repo": "krateo-agentiko/kagent", "pathPrefix": "docs"},
    "installer-agent": {"repo": "krateo-agentiko/installer-agent", "pathPrefix": "docs",
                        "prompt": {"repo": "krateo-agentiko/installer-agent",
                                   "path": "helm/installer-agent/files/prompts-eng.yaml"}},
}


def test_a_component_in_the_values_is_retargeted_keeping_the_models_file_name():
    p = _prop(kind="Documentation", subject="Snowplow/SAR Unauthorized", repo="krateo-platformops/snowplow-docs",
              path="guides/sar/why.md", fmt="markdown")
    note = targets.aim(p, OBS, COMPS)
    assert p["target"] == {"repo": "krateo-platformops/snowplow", "path": "docs/why.md"}
    assert note == ("Documentation proposal retargeted krateo-platformops/snowplow-docs/guides/sar/why.md -> "
                    "krateo-platformops/snowplow/docs/why.md (config.destinations.components.snowplow)")


def test_a_prompt_proposal_lands_at_the_prompt_path_exactly():
    """A prompt is ONE file: the model's file name is not kept, prompt.path is."""
    p = _prop(kind="Prompt", subject="installer-agent/repeated-get-resource-yaml",
              repo="krateo-agentiko/installer-agent", path="prompts/installer_agent.txt", fmt="diff")
    note = targets.aim(p, OBS, COMPS)
    assert p["target"] == {"repo": "krateo-agentiko/installer-agent",
                           "path": "helm/installer-agent/files/prompts-eng.yaml"}
    assert "(config.destinations.components.installer-agent.prompt)" in note


def test_a_prompt_proposal_about_a_component_without_a_prompt_has_no_destination():
    """The component's chart repository is not its prompt: no `prompt`, no destination for a Prompt."""
    p = _prop(kind="Prompt", subject="snowplow/x", repo="krateo-platformops/snowplow", fmt="diff")
    targets.aim(p, OBS, COMPS)
    assert p["target"]["repo"] == ""
    cond = targets.no_destination(p, OBS, COMPS)
    assert (cond["status"], cond["reason"]) == ("False", "NoDestination")
    assert "config.destinations.components.snowplow.prompt" in cond["message"]


def test_no_destination_clears_the_models_guess_and_says_which_component():
    """rr-20260930-0200 built krateo-platformops/<component> for components with no repository of that
    name. Keeping the guess is exactly what this replaces."""
    p = _prop(kind="Policy", subject="tk-swarm-ro/idle", repo="krateo-platformops/kagent",
              path="policies/tk-swarm-ro-idle.yaml")
    note = targets.aim(p, OBS, COMPS)
    assert p["target"] == {"repo": "", "path": "tk-swarm-ro-idle.yaml"}
    assert note == ("Policy proposal krateo-platformops/kagent/policies/tk-swarm-ro-idle.yaml cleared: "
                    "no destination configured for component tk-swarm-ro; add it to config.destinations")
    assert targets.no_destination(p, OBS, COMPS) == {
        "type": "TargetResolved", "status": "False", "reason": "NoDestination",
        "message": "no destination configured for component tk-swarm-ro; add it to config.destinations"}


def test_a_subject_that_cannot_be_normalised_has_no_destination():
    p = _prop(kind="Documentation", subject=None, repo="krateo-platformops/snowplow", fmt="markdown")
    targets.aim(p, OBS, COMPS)
    assert p["target"]["repo"] == ""
    assert "no subject component" in targets.no_destination(p, OBS, COMPS)["message"]


@pytest.mark.parametrize("kind,kinds,want", [
    # 1. A kind override wins over the component's entry: every Alert is an observability CR.
    ("Alert", OBS, ("krateo-platformops/observability", "config.targets.Alert")),
    # 2. With no override for the kind, the component's entry.
    ("Documentation", OBS, ("krateo-platformops/snowplow", "config.destinations.components.snowplow")),
    ("Alert", {}, ("krateo-platformops/snowplow", "config.destinations.components.snowplow")),
    # A kind override wins even over a component's prompt.
    ("Prompt", {"Prompt": {"repo": "o/prompts", "pathPrefix": "p"}}, ("o/prompts", "config.targets.Prompt")),
])
def test_precedence_is_kind_then_component_then_none(kind, kinds, want):
    p = _prop(kind=kind, subject="snowplow/sar-unauthorized", path="f.yaml")
    repo, _, source = targets.destination(p, kinds, dict(COMPS, snowplow=dict(COMPS["snowplow"], prompt={
        "repo": "krateo-agentiko/snowplow-agent", "path": "p.yaml"})))
    assert (repo, source) == want


@pytest.mark.parametrize("components", [None, {}])
def test_an_absent_map_gives_no_destination_but_the_kind_override_still_applies(components, monkeypatch):
    monkeypatch.setattr(targets, "COMPONENTS", {})
    doc = _prop(kind="Documentation", subject="snowplow/x", repo="krateo-platformops/snowplow", fmt="markdown")
    targets.aim(doc, OBS, components)
    assert doc["target"]["repo"] == ""
    alert = _prop(subject="snowplow/x")
    targets.aim(alert, OBS, components)
    assert alert["target"]["repo"] == "krateo-platformops/observability"


def test_configured_keys_meet_subjects_however_either_is_cased():
    p = _prop(kind="Documentation", subject="snowplow/x", fmt="markdown")
    targets.aim(p, {}, {"Snowplow": {"repo": "krateo-platformops/snowplow"}})
    assert p["target"]["repo"] == "krateo-platformops/snowplow"


def test_the_seeded_values_validate_against_the_schema():
    """What the installer applies: values.yaml through values.schema.json, the new map included."""
    import jsonschema
    schema = json.loads((ROOT / "helm/nightly-review/values.schema.json").read_text())
    values = yaml.safe_load((ROOT / "helm/nightly-review/values.yaml").read_text())
    jsonschema.validate(values, schema)
    bad = json.loads(json.dumps(values))
    bad["config"]["destinations"]["components"]["snowplow"]["repo"] = "krateo-platformops"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)


# rr-20260930-0200's proposals, as they are on 057 (kubectl get proposals, read-only, 2026-09-30).
RR_0200 = [
    ("Alert", "snowplow/subjectaccessreview-unauthorized", "krateo-observability",
     "alerts/snowplow-subjectaccessreview-unauthorized.yaml"),
    ("Alert", "github-provider-kog-pullrequest-controller/cannot-observe-external-resource", "krateo-observability",
     "alerts/kog-provider-cannot-observe-external-resource.yaml"),
    ("Prompt", "installer-agent/repeated-get-resource-yaml", "krateo-agentiko/installer-agent",
     "prompts/installer_agent.txt"),
    ("Alert", "installer-chart-inspector/rbac-generation-http-500", "krateo-observability",
     "alerts/chart-inspector-rbac-generation-failure.yaml"),
    ("Prompt", "autopilot/suggest-widget-kinds-to-specialist", "krateo-agentiko/autopilot", "prompts/autopilot.txt"),
]


def test_rr_20260930_0200_replayed_through_the_seeded_values():
    """The night that motivated this, through the chart's own values.yaml: the Alerts land in the
    observability chart, the Prompts in the agents' real prompt files — nothing the model built."""
    cfg = yaml.safe_load((ROOT / "helm/nightly-review/values.yaml").read_text())["config"]
    got = []
    for kind, subject, repo, path in RR_0200:
        p = _prop(kind=kind, subject=subject, repo=repo, path=path)
        targets.aim(p, cfg["targets"], cfg["destinations"]["components"])
        got.append((p["target"]["repo"], p["target"]["path"]))
    obs = "charts/krateo-observability/templates/"
    assert got == [
        ("krateo-platformops/observability", obs + "snowplow-subjectaccessreview-unauthorized.yaml"),
        ("krateo-platformops/observability", obs + "kog-provider-cannot-observe-external-resource.yaml"),
        ("krateo-agentiko/installer-agent", "helm/installer-agent/files/prompts-eng.yaml"),
        ("krateo-platformops/observability", obs + "chart-inspector-rbac-generation-failure.yaml"),
        ("krateo-agentiko/autopilot", "chart/files/prompts-eng.yaml"),
    ]


def test_every_agent_in_the_seeded_values_has_its_prompt():
    comps = yaml.safe_load((ROOT / "helm/nightly-review/values.yaml").read_text())["config"]["destinations"]["components"]
    for agent in ("autopilot", "frontend-agent", "core-provider-agent", "installer-agent", "incident-agent",
                  "clickstack-agent", "snowplow-agent", "authn-agent", "k8s-agent", "helm-agent"):
        assert comps[agent]["prompt"]["repo"].startswith("krateo-agentiko/") and comps[agent]["prompt"]["path"], agent


def test_an_already_correct_target_is_no_note():
    p = _prop(repo="krateo-platformops/observability", path="charts/krateo-observability/templates/x.yaml")
    assert targets.aim(p, OBS) is None


def test_the_prompt_says_the_destination_is_fixed():
    import prompt
    msg = prompt.build_user_message({"from": "a", "to": "b"}, {"x": "y"}, destinations=OBS)
    assert "FIXED DESTINATIONS" in msg and "krateo-platformops/observability" in msg
    assert "charts/krateo-observability/templates/" in msg


def test_the_prompt_says_destinations_are_configured_and_names_the_components():
    import prompt
    msg = prompt.build_user_message({"from": "a", "to": "b"}, {"x": "y"}, destinations=OBS, components=COMPS)
    header = msg.split("DATA REGION")[0]
    assert "CONFIGURED COMPONENTS" in header and "installer-agent, kagent, snowplow" in header
    assert "WHERE PROPOSALS LAND IS CONFIGURED" in prompt.SYSTEM
    assert "krateo-agentiko repositories" not in prompt.SYSTEM, "the prompt must not steer the model to an org"
    assert "CONFIGURED COMPONENTS" not in prompt.build_user_message({"from": "a", "to": "b"}, {"x": "y"})
    assert "FIXED DESTINATIONS" not in prompt.build_user_message({"from": "a", "to": "b"}, {"x": "y"})


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
    """Paths the apiserver would prune (undeclared) or reject (outside an enum, over a maxLength or a
    maxItems — a rejection fails the WHOLE status write, which is worse than a prune)."""
    out = []
    if schema.get("x-kubernetes-preserve-unknown-fields"):
        return out
    if "enum" in schema and value is not None and value not in schema["enum"]:
        out.append(f"{path} = {value!r} not in enum")
    if isinstance(value, str) and len(value) > schema.get("maxLength", len(value)):
        out.append(f"{path} longer than maxLength {schema['maxLength']}")
    if isinstance(value, list) and len(value) > schema.get("maxItems", len(value)):
        out.append(f"{path} has more than maxItems {schema['maxItems']}")
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
    return _drive(monkeypatch)


def _drive(monkeypatch, ask_fails=False, extra_props=()):
    import datetime as dt
    import evidence as E
    import main as M
    import sync_health as S

    import test_failures as TF
    import test_sync_stall as T

    import analysis as AN

    old = _stored("p-old", subject="snowplow/sar-unauthorized", run="rr-older")
    # `busy` carries a promptTemplate include and DECLARES its prompt's repository, so the analyse stage
    # resolves a ConfigMap and the retarget path runs.
    busy = {"metadata": {"namespace": "krateo-system", "name": "busy",
                         "annotations": {"krateo.io/prompt-repo": "krateo-agentiko/busy-agent"}},
            "spec": {"type": "Declarative", "declarative": {
                "systemMessage": '{{include "prompts/busy"}}\nBe brief.',
                "promptTemplate": {"dataSources": [{"alias": "prompts", "kind": "ConfigMap",
                                                    "name": "busy-prompts"}]}}}}
    api = _Api(proposals=[old, _stored("p-legacy")],
               alerts=[{"metadata": {"name": "a"}, "spec": {"displayName": "A", "threshold": 1}}],
               agents=[{"metadata": {"namespace": "krateo-system", "name": "never-used"}}, busy],
               flexes=[{"metadata": {"name": "page-dashboard",
                                     "annotations": {"krateo.io/nav-path": "/dashboard"}}},
                       {"metadata": {"name": "dashboard-row-1"}}],
               # 2026-10-01's outage, read by the sync-stall check through discovery: two findings.
               # ...and the day's failures: Incidents, CompositionDefinitions and a failing composition.
               cluster=dict(T._outage(ago=60 * 24 * 365), incidents=TF.INCIDENTS, compositiondefinitions=TF.CDS,
                            **TF.COMPS),
               configs={(c[0], c[1]): c[2] for c in T.CONFIGS})
    monkeypatch.setattr(S, "GROUPS", T.GROUPS)
    monkeypatch.setattr(S, "discoverer", lambda client: (
        lambda g: TF.SERVED if g == "composition.krateo.io" else T._discover(g)))
    monkeypatch.setattr(M.config, "load_incluster_config", lambda: None)
    monkeypatch.setattr(M.client, "CustomObjectsApi", lambda: api)
    cm = types.SimpleNamespace(data={"busy": "You are busy. Always cite the tool you used."},
                               metadata=types.SimpleNamespace(name="busy-prompts", annotations={}))
    monkeypatch.setattr(M.client, "CoreV1Api", lambda: types.SimpleNamespace(
        read_namespaced_config_map=lambda name, ns: cm))
    monkeypatch.setattr(M, "DRY_RUN", False)

    # ClickHouse: a windowed query that answers, so stats carries `queries`; MAX_CHARS tiny so every
    # source is truncated and records truncated/truncatedAtChars/droppedChars.
    monkeypatch.setenv("CLICKHOUSE_QUERIES", '{"errors": "SELECT 1 WHERE t BETWEEN \'{from}\' AND \'{to}\'"}')
    monkeypatch.setattr(E, "CLICKHOUSE_URL", "http://clickhouse.invalid")
    monkeypatch.setattr(E, "MAX_CHARS", 10)
    ok = types.SimpleNamespace(raise_for_status=lambda: None, text='["svc", 5]\n["svc2", 3]\n')
    monkeypatch.setattr(E, "requests", types.SimpleNamespace(post=lambda *a, **k: ok))

    # kagent sessions through a fake pg8000, with one busy agent and one deployed-never-used — and the
    # questions read on its richest path: a matched question, an unparseable row, more messages in the
    # session than the cap, so questions/shapes/droppedMessages are all written and all checked.
    now = dt.datetime.now(dt.timezone.utc)
    rows = [("krateo_system__NS__busy", 40, 4, 3, now), ("krateo_system__NS__gone", 2, 0, 1,
                                                          now - dt.timedelta(days=30))]
    q = '{"Author": "user", "Content": {"role": "user", "parts": [{"text": "why is my composition not ready?"}]}}'
    qrows = [("s1", "krateo_system__NS__busy", q, 9), ("s1", "krateo_system__NS__busy", "not json", 9)]

    # The analyse stage's two reads: busy has two conversations (one over the session cap), a tool result
    # over its cap, and an event too large to fetch — so every cut field is written and checked.
    monkeypatch.setattr(AN, "MAX_SESSIONS", 1)
    monkeypatch.setattr(AN, "MAX_TOOL_RESULT_CHARS", 50)
    busy_id = "krateo_system__NS__busy"
    acensus = [(busy_id, 2, 5, 1), ("krateo_system__NS__gone", 1, 1, 0)]
    arows = [(busy_id, 1, "agent", 5, 1, q, len(q)),
             (busy_id, 1, "agent", 5, 2, '{"Author": "busy", "Content": {"parts": [{"functionResponse": '
              '{"name": "k8s_get", "response": {"result": "' + "y" * 400 + '"}}}]}}', 500),
             (busy_id, 1, "agent", 5, 3, None, 999999),
             (busy_id, 1, "agent", 5, 4, '{"Author": "busy", "Content": {"parts": [{"text": "It is not ready '
              'because its child failed."}]}}', 90)]

    def run(sql, **k):
        if "AS delegated" in sql:
            return acensus
        if "dense_rank" in sql:
            return arows
        if "WITH q AS" in sql:
            return qrows
        if "AS user_authored" in sql:
            return [(20, 9, 2, 2)]
        return rows
    conn = types.SimpleNamespace(run=run, close=lambda: None)
    native = types.SimpleNamespace(Connection=lambda **k: conn)
    monkeypatch.setitem(sys.modules, "pg8000", types.SimpleNamespace(native=native))
    monkeypatch.setitem(sys.modules, "pg8000.native", native)
    monkeypatch.setattr(E, "KAGENT_DB_USER", "u")
    monkeypatch.setattr(E, "KAGENT_DB_PASSWORD", "p")

    assessment = {"summary": "busy mostly answers", "servedWell": "readiness questions",
                  "failurePatterns": [{"pattern": "skips the child", "category": "made-up-category",
                                       "conversations": [1, 77],
                                       "examples": [{"conversation": 1, "excerpt": "its child failed"},
                                                    {"conversation": 1, "excerpt": "an invented quote here"}]}],
                  "promptFindings": [{"finding": "no rule to name the failing child",
                                      "promptExcerpt": "Always cite the tool you used", "evidence": "c1",
                                      "suggestedChange": "add: name the failing child", "conversations": [1]}],
                  "recurringNeeds": [{"need": "why is my composition not ready", "conversations": [1]}]}
    payload = {"summary": "one real finding and one aimed at a missing repo",
               "proposals": [
                   dict(_prop(content=REAL, repo="krateo-platformops/snowplow"),
                        subject="Snowplow/SAR Unauthorized", confidence="high"),
                   dict(_prop(kind="Documentation", subject="kagent:agent never used", fmt="markdown",
                              content="# x", repo="krateo-platformops/does-not-exist"), confidence="low"),
                   dict(_prop(kind="Prompt", subject="busy/skips-the-child", fmt="diff", content="+ name it",
                              repo="krateo-platformops/guessed", path="prompts/busy.md"), confidence="medium"),
                   dict(_prop(kind="Widget", subject="portal/missing-page", content="kind: Page",
                              repo="krateo-platformops/portal-guess", path="pages/p.yaml"), confidence="low"),
               ] + list(extra_props)}
    asked = []
    monkeypatch.setattr(M.autopilot, "service_jwt", lambda: None)
    def ask(system, message, run_name, token=None, context=None, timeout=None):
        asked.append((context, message))
        if ask_fails and not context:
            raise TimeoutError("the reviewer did not answer")
        if context:                                    # an analyse call
            return assessment, "{}", {"inputTokens": 40, "outputTokens": 5, "totalTokens": 45}
        return payload, "{}", A.token_usage({"metadata": {"kagent_usage_metadata": {
            "promptTokenCount": 9, "candidatesTokenCount": 3, "totalTokenCount": 12}}})
    monkeypatch.setattr(M.autopilot, "ask", ask)
    monkeypatch.setattr(M.publish, "publish_version", lambda: "v1-8-53")
    # The chart's values.yaml destinations, as the CronJob would pass them. busy's prompt is configured in
    # a DIFFERENT repository from the one its Agent's annotation declares, so the run shows which one wins;
    # kagent points at a repository GitHub denies; `portal` is not configured at all.
    monkeypatch.setattr(targets, "DESTINATIONS", OBS)
    monkeypatch.setattr(targets, "COMPONENTS", {
        "busy": {"repo": "krateo-agentiko/busy-agent",
                 "prompt": {"repo": "krateo-agentiko/busy-prompts", "path": "helm/busy/files/prompts-eng.yaml"}},
        "kagent": {"repo": "krateo-platformops/does-not-exist", "pathPrefix": "docs"},
    })
    heads = []
    def head(url, **k):
        heads.append((url, dict(k.get("headers") or {})))
        return types.SimpleNamespace(status_code=404 if "does-not-exist" in url else 200)
    monkeypatch.setattr(targets, "requests", types.SimpleNamespace(head=head))

    assert M.main() == (1 if ask_fails else 0)
    api.asked, api.heads = asked, heads
    return api


def test_every_reviewrun_status_the_service_writes_is_declared(full_run):
    schema = _crd_schema("reviewrun.crd.yaml")["properties"]["status"]
    writes = [b["status"] for plural, _, b in full_run.status_writes if plural == "reviewruns"]
    assert writes, "the run wrote no status at all"
    final = writes[-1]
    # The run exercised what it is meant to, or this test proves nothing.
    assert final["evidence"]["clickhouse"]["queries"], "queries were not written, so not tested"
    assert final["evidence"]["clickhouse"]["truncated"] is True
    ks = final["evidence"]["kagent-sessions"]
    assert ks["questions"] == 1 and ks["shapes"]["unparseable"] == 1 and ks["droppedMessages"] > 0, ks
    assert final["evidence"]["kubernetes"]["returned"] == 2, "an Alert and one page root"
    assert final["evidence"]["incidents"]["ok"] and final["evidence"]["incidents"]["returned"] == 4
    comps = final["evidence"]["compositions"]
    assert comps["ok"] and comps["failing"] == 1, comps
    (main_message,) = [m for ctx, m in full_run.asked if not ctx]
    assert main_message.index('source="compositions"') < main_message.index('source="clickhouse"')
    assert final["summary"] and final["model"]["inputTokens"] == 9
    assert [s["name"] for s in final["steps"]] == ["gather", "analyse", "ask", "validate", "publish", "record"]
    aa = final["evidence"]["agent-analysis"]
    (busy,) = aa["agents"]
    assert aa["ok"] and aa["returned"] == 1 and aa["skipped"][0]["reason"] == "not deployed"
    assert busy["droppedChars"] > 999999 and busy["droppedSessions"] == 1 and busy["tokens"]["totalTokens"] == 45
    assert busy["promptRepo"] == "krateo-agentiko/busy-agent" and busy["unverifiedExamples"] == 1
    (a,) = final["agentAnalysis"]["assessments"]
    assert a["failurePatterns"][0]["category"] == "other" and a["failurePatterns"][0]["count"] == 1
    assert a["promptFindings"][0]["promptExcerpt"] and a["recurringNeeds"]
    assert final["usage"]["total"] == {"calls": 2, "reportedCalls": 2, "inputTokens": 49,
                                       "outputTokens": 8, "totalTokens": 57}
    assert ks["questionsFolded"] == 1
    assert final["proposals"]["superseded"] == 1
    for st in writes:
        assert _undeclared(st, schema, "status") == []


def test_every_proposal_the_service_writes_is_declared(full_run):
    schema = _crd_schema("proposal.crd.yaml")["properties"]
    created = [b for plural, b in full_run.creates if plural == "proposals"]
    assert len(created) == 6, "four from the model, two from the sync-stall check"
    assert sorted(b["spec"]["producedBy"]["agent"] for b in created) == ["krateo-autopilot"] * 4 + [
        "nightly-review/sync-stall"] * 2
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
    assert (cond["status"], cond["reason"]) == ("False", "NotFoundOrPrivate")
    claims = [b for plural, b in full_run.creates if plural == "builderpublishes"]
    assert [c["spec"]["target"]["repo"] for c in claims] == ["observability", "busy-prompts"]


def test_a_prompt_proposal_goes_where_the_values_say_not_where_the_agent_declares(full_run):
    """The model guessed krateo-platformops/guessed and the Agent's annotation says busy-agent: the values
    say busy-prompts, at one exact file, and only the values count."""
    (prompt,) = [b for plural, b in full_run.creates if plural == "proposals" and b["spec"]["kind"] == "Prompt"]
    assert prompt["spec"]["target"] == {"repo": "krateo-agentiko/busy-prompts",
                                        "path": "helm/busy/files/prompts-eng.yaml"}


def test_a_proposal_with_no_destination_is_written_without_a_repo_and_never_published(full_run):
    by_name = {b["metadata"]["name"]: b for plural, b in full_run.creates if plural == "proposals"}
    (widget,) = [b for b in by_name.values() if b["spec"]["kind"] == "Widget"]
    assert widget["spec"]["target"] == {"repo": "", "path": "p.yaml"}
    assert widget["spec"]["fingerprint"] == P.fingerprint(widget["spec"])
    st = full_run.proposals[widget["metadata"]["name"]]["status"]
    (cond,) = [c for c in st["conditions"] if c["type"] == "TargetResolved"]
    assert (cond["status"], cond["reason"], cond["message"]) == (
        "False", "NoDestination", "no destination configured for component portal; add it to config.destinations")
    assert not any("portal-guess" in c["spec"]["target"]["repo"] or not c["spec"]["target"]["repo"]
                   for plural, c in full_run.creates if plural == "builderpublishes")
    assert all(url.rstrip("/").split("/repos/")[1].count("/") == 1 for url, _ in full_run.heads), \
        "an empty repository must never reach the existence check"
    final = [b["status"] for plural, _, b in full_run.status_writes if plural == "reviewruns"][-1]
    (notes,) = [c for c in final["conditions"] if c["type"] == "ValidationNotes"]
    assert "Widget proposal krateo-platformops/portal-guess/pages/p.yaml cleared: no destination configured " \
           "for component portal" in notes["message"]


def test_the_main_review_gets_the_assessment_and_not_the_transcript(full_run):
    """The whole point of the stage: conversations are read in their own calls, and only the bounded
    assessment reaches the main corpus — while the questions it covered are not quoted there twice."""
    analyse_msgs = [m for ctx, m in full_run.asked if ctx]
    (main_msg,) = [m for ctx, m in full_run.asked if not ctx]
    assert len(analyse_msgs) == 1 and "It is not ready because its child failed." in analyse_msgs[0]
    assert "yyyyyyyyyy" in analyse_msgs[0], "the analysis saw the tool result"
    assert 'source="agent-analysis"' in main_msg and "FAILURE [other] in 1 conversation(s)" in main_msg
    assert "because its child failed" not in main_msg.replace('"its child failed"', ""), \
        "only the verified excerpt may appear, never the reply"
    assert "yyyyyyyyyy" not in main_msg, "a tool result reached the main review"
    assert "use the spelling listed: busy, kagent" in main_msg.split("DATA REGION")[0], \
        "the configured components must reach the model"


def test_every_stats_key_evidence_assigns_by_subscript_is_declared():
    """A cheap static belt under the run above: a key added on a path the fake run does not reach is
    still caught if it is assigned the usual way."""
    import re
    declared = set(_crd_schema("reviewrun.crd.yaml")["properties"]["status"]["properties"]["evidence"]
                   ["additionalProperties"]["properties"])
    src = (ROOT / "evidence.py").read_text()
    written = set(re.findall(r'stats\["(\w+)"\]\s*(?:=|\+=)', src))
    assert written and written <= declared, written - declared


def test_a_retargeted_proposal_is_named_by_its_new_target(full_run):
    """The model aimed the Alert at krateo-platformops/snowplow; config.targets sent it to observability.
    The fingerprint must be recomputed over the target it HAS, or tomorrow's identical proposal would
    neither dedup against it nor find it by name (#34 retargeted without recomputing)."""
    created = [b for plural, b in full_run.creates if plural == "proposals"]
    for body in created:
        assert body["spec"]["fingerprint"] == P.fingerprint(body["spec"]), body["spec"]["kind"]
        assert body["metadata"]["name"] == publish.proposal_name(body["spec"])
    (alert,) = [b for b in created if b["spec"]["kind"] == "Alert"]
    assert alert["spec"]["target"] == {"repo": "krateo-platformops/observability",
                                       "path": "charts/krateo-observability/templates/x.yaml"}
    final = [b["status"] for plural, _, b in full_run.status_writes if plural == "reviewruns"][-1]
    (notes,) = [c for c in final["conditions"] if c["type"] == "ValidationNotes"]
    assert "Alert proposal retargeted krateo-platformops/snowplow/x.yaml -> krateo-platformops/observability/" \
           "charts/krateo-observability/templates/x.yaml (config.targets.Alert)" in notes["message"]


def test_the_run_states_its_coverage_in_the_summary_and_to_the_model(full_run):
    """The fake run cuts every source (MAX_CHARS 10) and one of busy's two conversations: the summary
    must open with the service's sentence, and the main model must have been told the same thing."""
    final = [b["status"] for plural, _, b in full_run.status_writes if plural == "reviewruns"][-1]
    cov = final["coverage"]
    assert cov["complete"] is False
    assert (cov["conversationsRead"], cov["conversationsTotal"]) == (1, 2)
    assert 0 < cov["charsRead"] < cov["charsTotal"] and cov["charsTotalIsLowerBound"] is True
    assert {c["source"] for c in cov["sourcesCut"]} >= {"clickhouse", "kagent-sessions"}
    assert final["summary"].startswith(cov["sentence"] + " one real finding")
    assert "Based on 1 of 2 agent conversations" in cov["sentence"]
    (main_msg,) = [m for ctx, m in full_run.asked if not ctx]
    assert cov["sentence"] in main_msg.split("DATA REGION")[0], "the sentence must be outside the data region"
    assert "busy: 1 conversation(s) of 2 in the window analysed" in main_msg


FAKE_TOKEN = "tok-nightly-FAKE-0c9d2b7e"   # deliberately NOT secret-shaped: redact() must not be what hides it


def test_the_check_token_reaches_nothing_but_the_check(monkeypatch, capsys):
    """THE TOKEN'S WHOLE REACH. A full main.main() with TARGET_CHECK_TOKEN set: the token must be on the
    existence check's HEAD — or this proves nothing — and in NOTHING else: not a ReviewRun status, not a
    Proposal, not a BuilderPublish, not a message to any model, not a log line. The fake token is not
    shaped like any credential redact() knows, so a leak cannot be hidden by the redaction pass."""
    monkeypatch.setenv(targets.TOKEN_ENV, FAKE_TOKEN)
    api = _drive(monkeypatch)
    assert api.heads and all(h.get("Authorization") == f"Bearer {FAKE_TOKEN}" for _, h in api.heads)
    written = json.dumps({"creates": api.creates, "status": api.status_writes, "patches": api.spec_patches,
                          "stored": api.proposals}, default=str)
    asked = json.dumps(api.asked)
    logs = capsys.readouterr()
    assert FAKE_TOKEN not in written
    assert FAKE_TOKEN not in asked
    assert FAKE_TOKEN not in logs.out + logs.err
    # Mutation guard on the guard: the serialisations above did capture the run.
    assert "krateo-platformops/observability" in written and "agent-analysis" in asked


# --- the sync-stall check inside a whole run -------------------------------------------------------

def test_the_sync_stall_findings_are_recorded_and_told_to_the_model(full_run):
    final = [b["status"] for plural, _, b in full_run.status_writes if plural == "reviewruns"][-1]
    sh = final["evidence"]["sync-health"]
    assert sh["ok"] and sh["stalled"] == 70 and sh["findings"] == 2 and sh["thresholdMinutes"] == 15
    (main_msg,) = [m for ctx, m in full_run.asked if not ctx]
    assert 'source="sync-health"' in main_msg and "subject git-provider/credential-rejected" in main_msg
    subjects = {b["spec"].get("subject") for plural, b in full_run.creates if plural == "proposals"}
    assert {"git-provider/credential-rejected", "github-provider-kog/credential-rejected"} <= subjects


def test_the_sync_stall_findings_are_written_even_when_the_model_does_not_answer(monkeypatch):
    """A backstop that died with the model would not be one: the outage night is exactly the night the
    rest of the run may fail too."""
    api = _drive(monkeypatch, ask_fails=True)
    final = [b["status"] for plural, _, b in api.status_writes if plural == "reviewruns"][-1]
    assert final["phase"] == "Failed" and final["proposals"]["created"] == 2
    record = next(s for s in final["steps"] if s["name"] == "record")
    assert record["phase"] == "Succeeded" and "sync-stall findings only" in record["message"]
    created = [b for plural, b in api.creates if plural == "proposals"]
    assert {b["spec"]["producedBy"]["agent"] for b in created} == {"nightly-review/sync-stall"}
    assert not [b for plural, b in api.creates if plural == "builderpublishes"], "never published from here"
    schema = _crd_schema("reviewrun.crd.yaml")["properties"]["status"]
    for plural, _, b in api.status_writes:
        if plural == "reviewruns":
            assert _undeclared(b["status"], schema, "status") == []


def test_the_chart_grants_the_sync_check_read_only_on_its_groups_and_never_the_core_group():
    import re
    rbac = (ROOT / "helm/nightly-review/templates/rbac.yaml").read_text()
    block = rbac.split("-sync-read")[1].split("---")[0]
    assert re.search(r'verbs: \["get", "list"\]', block) and "create" not in block and "patch" not in block
    assert 'fail (printf "config.syncStall.groups' in rbac, "a group without a dot (the core group) must fail"
    cron = (ROOT / "helm/nightly-review/templates/cronjob.yaml").read_text()
    assert 'dig "syncStall" dict .Values.config' in cron and "name: SYNC_STALL_GROUPS" in cron
    assert 'os.environ.get("SYNC_STALL_GROUPS")' in (ROOT / "sync_health.py").read_text()


def test_a_model_proposal_about_a_service_subject_is_dropped(monkeypatch):
    """Review of #40, finding 7: the model re-proposing a counted finding would supersede it with a judged
    copy, or sit beside it as a duplicate."""
    dup = dict(_prop(kind="Documentation", subject="Git-Provider/credential rejected", fmt="markdown",
                     content="# token expired", repo="x/y"), confidence="medium")
    api = _drive(monkeypatch, extra_props=[dup])
    created = [b for plural, b in api.creates if plural == "proposals"]
    assert len(created) == 6, "the four model proposals and the two service ones; not the duplicate"
    (svc,) = [b for b in created if b["spec"].get("subject") == "git-provider/credential-rejected"]
    assert svc["spec"]["producedBy"]["agent"] == "nightly-review/sync-stall"
    final = [b["status"] for plural, _, b in api.status_writes if plural == "reviewruns"][-1]
    (notes,) = [c for c in final["conditions"] if c["type"] == "ValidationNotes"]
    assert ("DROPPED model Documentation proposal about git-provider/credential-rejected: the sync-stall "
            "check already proposed that subject this run") in notes["message"]
