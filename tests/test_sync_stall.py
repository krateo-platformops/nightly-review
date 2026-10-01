"""The sync-stall check (sync_health.py): which conditions count, how they group, what reaches a Proposal,
and that a Secret is named and never read.

The fixtures are shaped like 2026-10-01 on 057: the GitHub token in krateo-system/git-provider-credentials
expired, and every github.krateo.io Repository/PullRequest and git.krateo.io Repo/LocalResource went
Synced=False with a 401 for hours while nothing reported it."""
import datetime as dt
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jsonschema
import pytest

import main as M
import prompt
import proposals as P
import sync_health as S
import targets

NOW = dt.datetime(2026, 10, 1, 14, 0, tzinfo=dt.timezone.utc)
GROUPS = {"github.krateo.io": {"component": "github-provider-kog", "kinds": []},
          "git.krateo.io": {"component": "git-provider", "kinds": []}}
SERVED = {
    "github.krateo.io": [("v2022-11-28", "repositories", "Repository", True),
                         ("v2022-11-28", "pullrequests", "PullRequest", True),
                         ("v1alpha1", "repositoryconfigurations", "RepositoryConfiguration", True),
                         ("v1alpha1", "pullrequestconfigurations", "PullRequestConfiguration", True)],
    "git.krateo.io": [("v1alpha1", "repoes", "Repo", True), ("v1alpha1", "localresources", "LocalResource", True)],
}
MSG_401 = ('performing request: GET https://api.github.com/repos/krateo-blueprints/{n}: 401 Unauthorized '
           '{{"message":"Bad credentials"}}')
CREDS = {"key": "token", "name": "git-provider-credentials", "namespace": "krateo-system"}


def _ts(minutes_ago):
    return (NOW - dt.timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _obj(name, synced=None, ready=None, spec=None, ns="krateo-system"):
    conds = []
    for typ, c in (("Synced", synced), ("Ready", ready)):
        if c:
            status, reason, msg, ago = c
            conds.append({"type": typ, "status": status, "reason": reason, "message": msg,
                          "lastTransitionTime": _ts(ago)})
    return {"metadata": {"name": name, "namespace": ns}, "spec": spec or {}, "status": {"conditions": conds}}


def _err(msg, ago=300):
    return ("False", "ReconcileError", msg, ago)


class _Api:
    """list_cluster_custom_object and get_namespaced_custom_object, recording every read."""
    def __init__(self, lists, configs=(), fail=()):
        self.lists, self.configs, self.fail = lists, {(c[0], c[1]): c[2] for c in configs}, set(fail)
        self.reads = []

    def list_cluster_custom_object(self, group, version, plural, **kw):
        self.reads.append(("list", group, version, plural))
        if plural in self.fail:
            raise RuntimeError(f"403 forbidden: {plural}")
        return {"items": self.lists.get(plural, []), "metadata": {}}

    def get_namespaced_custom_object(self, group, version, ns, plural, name):
        self.reads.append(("get", group, version, plural, name))
        return self.configs[(plural, name)]


def _discover(group):
    return SERVED[group]


def _outage(n_repos=24, n_prs=24, n_repoes=19, n_lr=3, ago=420):
    kog = {"configurationRef": {"name": "github-blueprints-config"}}
    git = {"toRepo": {"url": "https://github.com/krateo-blueprints/x.git",
                      "credentials": {"secretRef": CREDS, "usernameRef": dict(CREDS, key="username")}}}
    return {
        "repositories": [_obj(f"repo-{i}", _err(MSG_401.format(n=i), ago), ("False", "Unavailable", "", ago), kog)
                         for i in range(n_repos)],
        "pullrequests": [_obj(f"pr-{i}", _err(MSG_401.format(n=i), ago), spec=kog) for i in range(n_prs)],
        "repoes": [_obj(f"r-{i}", _err("authentication required: Invalid username or token", ago), spec=git)
                   for i in range(n_repoes)],
        "localresources": [_obj(f"lr-{i}", _err("authentication required: Invalid username or token", ago),
                                spec=git) for i in range(n_lr)],
    }


CONFIGS = [("repositoryconfigurations", "github-blueprints-config",
            {"spec": {"authentication": {"bearer": {"tokenRef": CREDS}}}}),
           ("pullrequestconfigurations", "github-blueprints-config",
            {"spec": {"authentication": {"bearer": {"tokenRef": CREDS}}}})]


def _run(lists, configs=CONFIGS, **kw):
    api = _Api(lists, configs, **kw.pop("api_kw", {}))
    body, stats, props = S.gather(api, _discover, now=NOW, groups=kw.pop("groups", GROUPS),
                                  threshold_minutes=kw.pop("threshold", 15))
    return api, body, stats, props


# --- which conditions count ---------------------------------------------------------------------

def test_sustained_failures_are_grouped_by_component_and_pattern():
    """2026-10-01 in one run: 48 github.krateo.io objects and 22 git.krateo.io objects, all 401 — two
    findings, one per provider component, each saying the credential was rejected and counting it."""
    _, body, stats, props = _run(_outage())
    assert stats["ok"] and stats["stalled"] == 70 and stats["findings"] == 2 and stats["freshFailures"] == 0
    by = {p["subject"]: p for p in props}
    assert set(by) == {"github-provider-kog/credential-rejected", "git-provider/credential-rejected"}
    kog = by["github-provider-kog/credential-rejected"]
    assert kog["evidence"][0]["observedCount"] == 48
    assert "Repository x24" in kog["title"] and "PullRequest x24" in kog["title"]
    assert "credential rejected" in kog["title"]
    assert by["git-provider/credential-rejected"]["evidence"][0]["observedCount"] == 22
    assert "48x credential rejected" in body and "22x credential rejected" in body


def test_a_fresh_failure_under_the_threshold_is_counted_not_reported():
    _, body, stats, props = _run({"repositories": [_obj("a", _err(MSG_401.format(n=1), ago=5))]})
    assert props == [] and stats["stalled"] == 0 and stats["freshFailures"] == 1
    assert "failing for less than 15m" in body and "Repository.github.krateo.io x1" in body


def test_ready_stale_but_synced_true_is_never_reported():
    """Synced is the reconcile's verdict. A Ready that is old, or even False for a reconcile error, does not
    outvote a Synced=True from the latest reconcile."""
    lists = {"repoes": [
        _obj("old-ready", ("True", "ReconcileSuccess", "", 5), ("True", "Available", "", 60 * 24 * 14)),
        _obj("contradictory", ("True", "ReconcileSuccess", "", 5), _err("401 Unauthorized", 600)),
    ]}
    _, body, stats, props = _run(lists)
    assert props == [] and stats["stalled"] == 0 and stats["freshFailures"] == 0 and body is None
    assert stats["returned"] == 2, "the objects were read, or this proves nothing"


def test_ready_false_counts_only_for_a_reconcile_error_and_only_without_a_synced_verdict():
    lists = {"repoes": [_obj("no-synced-err", ready=_err("401 Unauthorized", 600)),
                        _obj("creating", ready=("False", "Creating", "", 600)),
                        _obj("deleting", ready=("False", "Deleting", "", 600))]}
    _, _, stats, props = _run(lists)
    assert stats["stalled"] == 1 and [p["subject"] for p in props] == ["git-provider/credential-rejected"]


def test_a_paused_reconcile_is_intent_not_a_stall():
    _, _, stats, props = _run({"repoes": [_obj("p", ("False", "ReconcilePaused", "", 600))]})
    assert props == [] and stats["stalled"] == 0


def test_a_condition_without_a_transition_time_is_not_called_sustained():
    obj = _obj("x", _err("401 Unauthorized"))
    del obj["status"]["conditions"][0]["lastTransitionTime"]
    _, _, stats, props = _run({"repoes": [obj]})
    assert props == [] and stats["freshFailures"] == 1


# --- patterns -----------------------------------------------------------------------------------

@pytest.mark.parametrize("msg,signal", [
    ("GET https://api.github.com/repos/o/r: 401 Unauthorized", "credential-rejected"),
    ("authentication required: Invalid username or token", "credential-rejected"),
    ("401 Unauthorized: repository not found", "credential-rejected"),       # the 401 is the cause
    ("403 Forbidden: Resource not accessible by personal access token", "permission-denied"),
    ("repository not found", "remote-not-found"),
    ("GET .../repos/o/r: 404 Not Found", "remote-not-found"),
    ("API rate limit exceeded for user", "rate-limited"),
    ('Get "https://github.com/o/r.git/info/refs?service=git-upload-pack": context deadline exceeded',
     "remote-unreachable"),
    ("422 Unprocessable Entity: No commits between main and b", "remote-rejected-request"),
])
def test_a_message_is_read_for_what_went_wrong(msg, signal):
    assert S.classify("ReconcileError", msg)[0] == signal


def test_an_unknown_message_is_named_by_its_first_clause_without_its_particulars():
    """The two spellings of one failure must meet: paths, quoted names and numbers are the object's, not
    the failure's."""
    a = S.classify("ReconcileError", "failed to download file: creating destination file: open "
                                     "/tmp/rest-dynamic-controller/pullrequest.yaml: no such file")
    b = S.classify("ReconcileError", "failed to download file: open /tmp/x/repository.yaml: 2 errors")
    assert a[0] == b[0] == "failed-to-download-file"


# --- secrets are named, never read --------------------------------------------------------------

def test_the_secret_is_named_from_spec_refs_and_configurations_and_never_read():
    api, body, _, props = _run(_outage())
    for p in props:
        assert "krateo-system/git-provider-credentials" in p["change"]["content"]
        assert "krateo-system/git-provider-credentials" in p["rationale"]
    assert "RepositoryConfiguration krateo-system/github-blueprints-config" in \
        next(p for p in props if p["subject"].startswith("github"))["change"]["content"]
    # One read per Configuration per run, and only of the provider's own kinds — never a Secret.
    gets = [r for r in api.reads if r[0] == "get"]
    assert sorted(r[3] for r in gets) == ["pullrequestconfigurations", "repositoryconfigurations"]
    assert not any("secret" in r[3] for r in api.reads)


def test_secret_refs_takes_names_only_and_ignores_refs_that_are_not_secret_keys():
    spec = {"configurationRef": {"name": "cfg"}, "a": {"tokenRef": {"name": "t", "key": "token"}},
            "list": [{"passwordRef": {"name": "p", "namespace": "other", "key": "pw"}}]}
    assert S.secret_refs(spec, "ns") == {"ns/t", "other/p"}


# --- redaction ----------------------------------------------------------------------------------

def test_a_credential_quoted_in_a_controller_message_is_redacted_everywhere():
    """Controller messages quote what the remote said, and a misconfigured client can echo its own
    Authorization header. Nothing secret-shaped may reach the Proposal or the corpus."""
    leak = "ghp_" + "A" * 36
    msg = f"401 Unauthorized: request with Authorization: Bearer {leak} token={'z' * 20} rejected"
    _, body, _, props = _run({"repoes": [_obj("x", _err(msg, 600))]})
    kept, notes = M._service_findings(props)
    blob = json.dumps(kept) + body
    assert leak not in blob and "z" * 20 not in blob
    assert "<REDACTED" in blob


# --- the contract, the subject and the fingerprint ------------------------------------------------

def test_every_finding_passes_the_models_own_contract_and_lands_where_the_values_say(monkeypatch):
    monkeypatch.setattr(targets, "COMPONENTS", {"git-provider": {"repo": "o/git-provider", "pathPrefix": "docs"}})
    _, _, _, props = _run(_outage())
    for p in props:
        jsonschema.validate(p, prompt.ITEM_SCHEMA)
    kept, _ = M._service_findings(props)
    by = {p["subject"]: p for p in kept}
    assert by["git-provider/credential-rejected"]["target"] == {
        "repo": "o/git-provider", "path": "docs/git-provider-credential-rejected.md"}
    assert by["github-provider-kog/credential-rejected"]["target"]["repo"] == "", "not configured: no repo"
    for p in kept:
        assert p["fingerprint"] == P.fingerprint(p)


def test_the_same_outage_on_the_next_night_is_the_same_fingerprint():
    """Nothing in the body moves by itself: an outage still going the next night deduplicates instead of
    piling up a second proposal."""
    a = S.gather(_Api(_outage(), CONFIGS), _discover, now=NOW, groups=GROUPS, threshold_minutes=15)[2]
    b = S.gather(_Api(_outage(), CONFIGS), _discover, now=NOW + dt.timedelta(hours=24), groups=GROUPS,
                 threshold_minutes=15)[2]
    assert [P.fingerprint(p) for p in a] == [P.fingerprint(p) for p in b]


def test_a_changed_outage_is_a_new_body_under_the_same_subject():
    a = S.gather(_Api(_outage(), CONFIGS), _discover, now=NOW, groups=GROUPS, threshold_minutes=15)[2]
    b = S.gather(_Api(_outage(n_repos=30), CONFIGS), _discover, now=NOW, groups=GROUPS, threshold_minutes=15)[2]
    sa, sb = {p["subject"]: p for p in a}, {p["subject"]: p for p in b}
    k = "github-provider-kog/credential-rejected"
    assert P.fingerprint(sa[k]) != P.fingerprint(sb[k])


# --- discovery, configuration and failure ---------------------------------------------------------

def test_kinds_come_from_discovery_and_the_values_may_narrow_them():
    api, _, stats, _ = _run(_outage(), groups={"git.krateo.io": {"component": "git-provider", "kinds": ["Repo"]}})
    assert [r[3] for r in api.reads if r[0] == "list"] == ["repoes"]
    api, _, stats, _ = _run(_outage(), groups={"git.krateo.io": {"component": "git-provider", "kinds": []}})
    assert [r[3] for r in api.reads if r[0] == "list"] == ["repoes", "localresources"]


def test_no_group_is_hardcoded_and_an_empty_map_says_it_checked_nothing():
    assert S.GROUPS == {}, "which groups are checked is the chart's values, never the code's"
    _, body, stats, props = _run(_outage(), groups={})
    assert body is None and props == [] and stats["empty"] and "config.syncStall.groups is empty" in stats["note"]
    _, _, stats, _ = _run(_outage(), groups={"git.krateo.io": None})
    assert stats["empty"], "a group dropped with null is not checked"


def test_a_kind_that_cannot_be_read_degrades_the_source_and_the_rest_still_report():
    _, _, stats, props = _run(_outage(), api_kw={"fail": ["pullrequests"]})
    assert stats["ok"] is False and "pullrequests.github.krateo.io" in stats["error"]
    assert {p["subject"] for p in props} == {"github-provider-kog/credential-rejected",
                                             "git-provider/credential-rejected"}


def test_a_failed_discovery_degrades_the_source():
    def broken(group):
        raise RuntimeError("discovery down")
    body, stats, props = S.gather(_Api({}), broken, now=NOW, groups=GROUPS, threshold_minutes=15)
    assert stats["ok"] is False and "discovery of" in stats["error"] and props == []


def test_the_discoverer_takes_every_version_preferred_first_and_skips_subresources():
    docs = {
        "/apis/github.krateo.io": {"preferredVersion": {"version": "v2022-11-28"},
                                   "versions": [{"version": "v2022-11-28"}, {"version": "v1alpha1"}]},
        "/apis/github.krateo.io/v2022-11-28": {"resources": [
            {"name": "repositories", "kind": "Repository", "namespaced": True, "verbs": ["get", "list"]},
            {"name": "repositories/status", "kind": "Repository", "verbs": ["get"]}]},
        "/apis/github.krateo.io/v1alpha1": {"resources": [
            {"name": "repositoryconfigurations", "kind": "RepositoryConfiguration", "namespaced": True,
             "verbs": ["list"]},
            {"name": "repositories", "kind": "Repository", "verbs": ["list"]}]},
    }
    client = type("C", (), {"call_api": lambda self, path, *a, **k: docs[path]})()
    assert S.discoverer(client)("github.krateo.io") == [
        ("v2022-11-28", "repositories", "Repository", True),
        ("v1alpha1", "repositoryconfigurations", "RepositoryConfiguration", True)]


def test_the_findings_are_capped_and_the_cap_is_recorded(monkeypatch):
    monkeypatch.setattr(S, "MAX_FINDINGS", 1)
    _, body, stats, props = _run(_outage())
    assert len(props) == 1 and stats["findings"] == 1 and "not proposed" in stats["note"]
    assert "not proposed (over the per-run cap)" in body
