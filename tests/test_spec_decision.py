"""spec.decision: a person's answer, written where the portal can reach it, and respected before it is
mirrored.

The portal cannot write the status subresource — snowplow's /call builds only the main-resource path —
so a decision arrives in the spec and this service copies it to status on its next run. Between those
two moments the status is stale by design, and every test here pins one way that staleness used to be
acted on: a rejected suggestion superseded by the next night's rewording, or rewritten back to Proposed
because the same fingerprint came round again and the object is named after it."""
import os
import pathlib
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import yaml

import proposals as P
import publish
from test_platform_review_service import _Api, _prop, _stored, _undeclared

ROOT = pathlib.Path(__file__).resolve().parent.parent


class _LabelApi(_Api):
    """_Api, but a main-resource patch lands on the stored object, so a second pass sees the label."""
    def patch_namespaced_custom_object(self, group, version, ns, plural, name, body):
        super().patch_namespaced_custom_object(group, version, ns, plural, name, body)
        labels = (body.get("metadata") or {}).get("labels")
        if plural == "proposals" and labels:
            self.proposals[name].setdefault("metadata", {}).setdefault("labels", {}).update(labels)


def _decided(name, phase="Rejected", status_phase="Proposed", **decision):
    p = _stored(name, subject="snowplow/sar-unauthorized", phase=status_phase)
    p["spec"]["decision"] = {"phase": phase, **decision}
    return p


def _proposal_schema():
    doc = yaml.safe_load((ROOT / "helm/nightly-review-crds/templates/proposal.crd.yaml").read_text())
    return doc["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]


# --- the spec is authoritative until the mirror catches up ---------------------------------------

def test_the_decision_wins_over_a_status_that_has_not_caught_up():
    assert publish.effective_phase(_decided("p", "Rejected", "Proposed")) == "Rejected"


def test_a_merged_pr_is_later_than_the_decision_that_opened_it():
    """Merged is where a PrOpen decision leads; reading the decision there would undo the outcome."""
    assert publish.effective_phase(_decided("p", "PrOpen", "Merged", claim="c")) == "Merged"


def test_without_a_decision_status_is_the_phase():
    assert publish.effective_phase(_stored("p", phase="Superseded")) == "Superseded"


@pytest.mark.parametrize("bad", [{"phase": "Merged"}, {"phase": None}, "Rejected", {}])
def test_a_decision_this_service_cannot_read_is_ignored_not_guessed(bad):
    p = _stored("p")
    p["spec"]["decision"] = bad
    assert publish.decision(p) is None
    assert publish.effective_phase(p) == "Proposed"


@pytest.mark.parametrize("phase", ["Rejected", "PrOpen"])
def test_a_decided_proposal_is_in_none_of_the_open_indexes(phase):
    """Rejected in the spec, still Proposed on status: the index used to read status and treat it as
    open — supersedable by subject and by target, and a dedup target by fingerprint."""
    api = _Api([_decided("p-dec", phase, claim="c")])
    decided = {}
    by_fp, by_target, by_subject = publish.open_index(api, "rr-new", decided=decided)
    assert (by_fp, by_target, by_subject) == ({}, {}, {})
    assert decided == {"fp-p-dec": "p-dec"}


def test_a_rewording_of_a_rejected_finding_is_new_not_a_supersession():
    """The same subject, a different body: before, tonight's version retired the one a person had just
    rejected, and the rejection went with it."""
    api = _Api([_decided("p-dec")])
    decided = {}
    idx = publish.open_index(api, "rr-new", decided=decided)
    assert P.classify(_prop(content="b: 2\n"), *idx, decided=decided) == ("new", None)


def test_an_exact_repeat_of_a_rejected_proposal_is_decided_not_rewritten():
    """The object is named by fingerprint. Writing it again would PATCH the spec and set status back to
    Proposed — the rejection undone by the suggestion it rejected."""
    prop = _prop()
    fp = P.fingerprint(prop)
    api = _Api([_decided("p-dec") | {"spec": _decided("p-dec")["spec"] | {"fingerprint": fp}}])
    decided = {}
    idx = publish.open_index(api, "rr-new", decided=decided)
    assert P.classify(prop, *idx, decided=decided) == ("decided", "p-dec")


@pytest.mark.parametrize("phase", ["Rejected", "Merged"])
def test_a_person_decided_status_without_a_spec_decision_is_respected_too(phase):
    """Written by hand, or by a portal from before this field existed."""
    prop = _prop()
    api = _Api([_stored("p-old", phase=phase, fp=P.fingerprint(prop))])
    decided = {}
    idx = publish.open_index(api, "rr-new", decided=decided)
    assert P.classify(prop, *idx, decided=decided) == ("decided", "p-old")


def test_the_services_own_terminal_phases_can_still_reopen():
    """Superseded and Failed are this service's bookkeeping; the same finding returning re-proposes it,
    exactly as before."""
    prop = _prop()
    api = _Api([_stored("p-sup", phase="Superseded", fp=P.fingerprint(prop))])
    decided = {}
    idx = publish.open_index(api, "rr-new", decided=decided)
    assert decided == {}
    assert P.classify(prop, *idx, decided=decided) == ("new", None)


def test_callers_that_pass_no_decided_index_keep_working():
    api = _Api([_decided("p-dec")])
    assert publish.open_index(api, "rr-new") == ({}, {}, {})


# --- the mirror --------------------------------------------------------------------------------

def test_the_mirror_copies_the_decision_onto_status():
    api = _LabelApi([_decided("p-dec", reason="not our problem", decidedBy="admin",
                              decidedAt="2026-09-29T10:00:00Z")])
    assert publish.mirror_decisions(api) == 1
    (plural, name, body), = api.status_writes
    assert (plural, name) == ("proposals", "p-dec")
    assert body["status"] == {"phase": "Rejected", "reason": "not our problem", "decidedBy": "admin",
                              "decidedAt": "2026-09-29T10:00:00Z"}


def test_the_mirror_is_idempotent():
    api = _LabelApi([_decided("p-dec", "PrOpen", claim="bp-1", decidedBy="admin",
                              decidedAt="2026-09-29T10:00:00Z")])
    assert publish.mirror_decisions(api) == 1
    writes = len(api.status_writes) + len(api.spec_patches)
    assert publish.mirror_decisions(api) == 0
    assert len(api.status_writes) + len(api.spec_patches) == writes


def test_the_claim_lands_on_the_label_the_service_already_uses():
    api = _LabelApi([_decided("p-dec", "PrOpen", claim="bp-1")])
    publish.mirror_decisions(api)
    (_, name, body), = api.spec_patches
    assert body == {"metadata": {"labels": {publish.CLAIM_LABEL: "bp-1"}}}, "only the label, never the spec"


def test_a_field_the_decision_lacks_is_not_cleared_from_status():
    p = _decided("p-dec")
    p["status"]["decidedAt"] = "2026-09-01T00:00:00Z"
    api = _LabelApi([p])
    publish.mirror_decisions(api)
    assert api.proposals["p-dec"]["status"]["decidedAt"] == "2026-09-01T00:00:00Z"


def test_the_mirror_does_not_pull_a_merged_proposal_back_to_propen():
    api = _LabelApi([_decided("p-dec", "PrOpen", "Merged", claim="bp-1")])
    publish.mirror_decisions(api)
    assert api.status_writes == []


def test_what_the_mirror_writes_is_declared():
    schema = _proposal_schema()["status"]
    api = _LabelApi([_decided("p-a", reason="r", decidedBy="u", decidedAt="2026-09-29T10:00:00Z"),
                     _decided("p-b", "PrOpen", claim="bp", decidedBy="u")])
    publish.mirror_decisions(api)
    assert len(api.status_writes) == 2
    for _, _, body in api.status_writes:
        assert _undeclared(body["status"], schema, "status") == []


# --- the contract with the CRD ------------------------------------------------------------------

def test_the_decision_phases_are_the_crds():
    decl = _proposal_schema()["spec"]["properties"]["decision"]
    assert set(decl["properties"]["phase"]["enum"]) == publish.DECISION_PHASES
    assert set(decl["properties"]) >= {"phase", "reason", "decidedBy", "decidedAt", "claim"}


@pytest.mark.parametrize("crd", ["proposal.crd.yaml", "reviewrun.crd.yaml"])
def test_no_schema_key_parses_to_null(crd):
    """`{ type: string, description: A, B }` is a flow mapping, and the comma makes `B` a KEY with a null
    value. Helm applies it without complaint and the apiserver drops it; `kubectl apply` with strict field
    validation refuses the whole CRD — which is how producedBy.runRef's description was found, while
    dry-running the decision field against 057."""
    def nulls(o, path=""):
        if isinstance(o, dict):
            return [f"{path}.{k}" for k, v in o.items() if v is None] + \
                   [n for k, v in o.items() for n in nulls(v, f"{path}.{k}")]
        if isinstance(o, list):
            return [n for v in o for n in nulls(v, path)]
        return []
    assert nulls(yaml.safe_load((ROOT / "helm/nightly-review-crds/templates" / crd).read_text())) == []


def test_every_mirrored_phase_is_a_status_phase():
    status_enum = set(_proposal_schema()["status"]["properties"]["phase"]["enum"])
    assert publish.DECISION_PHASES <= status_enum
    assert publish.DECISION_PHASES <= publish.WRITTEN_PHASES


# --- the run --------------------------------------------------------------------------------------

def test_a_run_mirrors_first_and_leaves_a_rejected_repeat_alone(monkeypatch):
    """End to end through main.main(): the night's only proposal is exactly one a person rejected
    yesterday. Nothing is created, nothing is superseded, the rejection reaches status, and the
    object's spec is never re-asserted."""
    import main as M

    prop = dict(_prop(repo="krateo-platformops/snowplow"), confidence="high")
    fp = P.fingerprint(prop)
    rejected = _decided("p-dec", reason="no", decidedBy="admin", decidedAt="2026-09-28T10:00:00Z")
    rejected["spec"]["fingerprint"] = fp
    api = _LabelApi([rejected])
    monkeypatch.setattr(M.config, "load_incluster_config", lambda: None)
    monkeypatch.setattr(M.client, "CustomObjectsApi", lambda: api)
    monkeypatch.setattr(M, "DRY_RUN", True)
    ok = ("evidence", {"ok": True, "queried": 1, "returned": 1})
    for src in ("clickhouse", "kagent_sessions", "kubernetes"):
        monkeypatch.setattr(M.evidence, src, lambda *a, **k: ok)
    monkeypatch.setattr(M.autopilot, "service_jwt", lambda: None)
    monkeypatch.setattr(M.autopilot, "ask", lambda *a, **k: ({"summary": "s", "proposals": [prop]}, "{}", {}))
    monkeypatch.setattr(M.targets, "resolve", lambda *a, **k: {"type": "TargetResolved", "status": "True",
                                                                "reason": "RepoFound"})

    assert M.main() == 0
    assert [b for plural, b in api.creates if plural == "proposals"] == []
    assert api.proposals["p-dec"]["status"]["phase"] == "Rejected"
    assert not [n for plural, n, _ in api.spec_patches if plural == "proposals" and n == "p-dec"]
    final = [b["status"] for plural, _, b in api.status_writes if plural == "reviewruns"][-1]
    assert final["proposals"]["created"] == 0 and final["proposals"]["deduplicated"] == 0
    (validate,) = [s for s in final["steps"] if s["name"] == "validate"]
    assert "1 already decided" in validate["message"]


# --- the policies ----------------------------------------------------------------------------------

def test_the_policies_exempt_exactly_the_service_account_the_cronjob_runs_as():
    """The exemption is by username. If it named a different ServiceAccount than the one the run uses,
    every re-assertion of a spec on a fingerprint collision would be refused — or, the other way round,
    someone else's would be let through."""
    tpl = (ROOT / "helm/nightly-review/templates/decision-policy.yaml").read_text()
    cron = (ROOT / "helm/nightly-review/templates/cronjob.yaml").read_text()
    assert 'serviceAccountName: {{ include "nightly-review.fullname" . }}' in cron
    assert '$name := include "nightly-review.fullname" .' in tpl
    assert 'printf "system:serviceaccount:%s:%s" .Release.Namespace $name' in tpl
    assert tpl.count("request.userInfo.username != {{ $service | quote }}") == 2


def test_the_policies_are_on_by_default_and_declared():
    import json
    values = yaml.safe_load((ROOT / "helm/nightly-review/values.yaml").read_text())
    schema = json.loads((ROOT / "helm/nightly-review/values.schema.json").read_text())
    assert values["decisionPolicy"] == {"enabled": True}
    assert schema["properties"]["decisionPolicy"]["properties"]["enabled"]["default"] is True
