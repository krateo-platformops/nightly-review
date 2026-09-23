"""The trust boundary, asserted by exercising it.

Everything here is a control that stands between attacker-influenceable text and a pull request. A
control nobody runs is a comment — frontend#334 is the record of what that costs: 1891 tests sat in
the repo while three regressions shipped on one code path, because CI never executed them.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import proposals as P


def _p(**over):
    base = {
        "kind": "Alert", "title": "t", "rationale": "r", "confidence": "medium",
        "evidence": [{"source": "clickhouse", "summary": "s", "observedCount": 9},
                     {"source": "clickhouse", "summary": "s2", "observedCount": 4}],
        "target": {"repo": "org/allowed", "path": "p.yaml"},
        "change": {"format": "yaml", "content": "a: 1"},
    }
    base.update(over)
    return base


ALLOW = {"Alert": {"org/allowed"}, "Documentation": {"org/docs"}}
NOOP = lambda payload: None


# --- the control that matters most -------------------------------------------------------------
def test_a_proposal_aimed_outside_the_allowlist_is_refused_not_redirected():
    """target.repo is model-chosen from a corpus containing user chat text. One sentence in a
    conversation must not be able to aim this service's write credential."""
    kept, notes = P.validate_batch(
        {"proposals": [_p(target={"repo": "attacker/exfil", "path": ".github/workflows/x.yml"})]},
        ALLOW, NOOP)
    assert kept == []
    assert any("REFUSED" in n and "attacker/exfil" in n for n in notes)


def test_the_refusal_names_injection_so_it_is_never_quiet():
    _, notes = P.validate_batch({"proposals": [_p(target={"repo": "attacker/exfil"})]}, ALLOW, NOOP)
    assert any("injected" in n.lower() for n in notes)


def test_a_permitted_repo_for_the_WRONG_kind_is_still_refused():
    """org/docs is allowlisted, but only for Documentation. Per-kind, not a global set."""
    kept, _ = P.validate_batch({"proposals": [_p(target={"repo": "org/docs"})]}, ALLOW, NOOP)
    assert kept == []


# --- redaction ---------------------------------------------------------------------------------
@pytest.mark.parametrize("secret,marker", [
    ("eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaaaaaaaaaaaa.bbb", "<REDACTED-JWT>"),
    ("AKIAIOSFODNN7EXAMPLE", "<REDACTED-AWS-KEY-ID>"),
    ("ghp_abcdefghijklmnopqrstuvwxyz0123", "<REDACTED-GITHUB-PAT>"),
    ("Bearer abcdefghijklmnopqrstuvwxyz", "Bearer <REDACTED>"),
])
def test_secrets_are_scrubbed_wherever_they_appear(secret, marker):
    """Not only in change.content: the model writes rationale and summary too, so assuming a
    credential could only land in the obvious field assumes away the thing being guarded."""
    out = P.redact({"rationale": secret, "nested": [{"summary": secret}]})
    assert marker in out["rationale"] and secret not in out["rationale"]
    assert marker in out["nested"][0]["summary"]


def test_redaction_reaches_every_field_of_a_real_proposal():
    kept, notes = P.validate_batch(
        {"proposals": [_p(rationale="token eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaaaaaaaaaaaa.ccc")]},
        ALLOW, NOOP)
    assert "eyJ" not in json.dumps(kept)
    assert any("redacted" in n for n in notes)


# --- confidence --------------------------------------------------------------------------------
def test_high_confidence_from_a_single_observation_is_capped():
    """alert-troubleshooter#30 encoded as code: confidence describes the evidence, not enthusiasm."""
    kept, notes = P.validate_batch(
        {"proposals": [_p(confidence="high",
                          evidence=[{"source": "kagent-sessions", "summary": "once", "observedCount": 1}])]},
        ALLOW, NOOP)
    assert kept[0]["confidence"] == "medium"
    assert any("capped to medium" in n for n in notes)


def test_high_confidence_with_real_support_survives():
    kept, _ = P.validate_batch({"proposals": [_p(confidence="high")]}, ALLOW, NOOP)
    assert kept[0]["confidence"] == "high"


# --- fingerprint -------------------------------------------------------------------------------
def test_rewording_the_rationale_does_not_change_the_fingerprint():
    """Otherwise night two re-proposes night one under a new identity and dedup silently stops."""
    a = P.fingerprint(_p(rationale="because X"))
    b = P.fingerprint(_p(rationale="a completely different explanation"))
    assert a == b


def test_trailing_whitespace_and_blank_lines_do_not_change_it():
    a = P.fingerprint(_p(change={"format": "yaml", "content": "a: 1\nb: 2"}))
    b = P.fingerprint(_p(change={"format": "yaml", "content": "a: 1  \n\n\nb: 2   "}))
    assert a == b


def test_a_different_target_IS_a_different_proposal():
    a = P.fingerprint(_p())
    b = P.fingerprint(_p(target={"repo": "org/allowed", "path": "other.yaml"}))
    assert a != b


# --- batch semantics ---------------------------------------------------------------------------
def test_an_empty_proposal_list_is_valid_and_not_an_error():
    """Most nights a healthy platform deserves no changes. A loop that must produce something will."""
    kept, notes = P.validate_batch({"proposals": []}, ALLOW, NOOP)
    assert kept == [] and notes == []


def test_a_non_object_response_is_refused_whole():
    with pytest.raises(P.Refused):
        P.validate_batch(["not", "an", "object"], ALLOW, NOOP)


def test_one_bad_proposal_does_not_discard_the_good_ones():
    kept, notes = P.validate_batch(
        {"proposals": [_p(), _p(target={"repo": "attacker/x"}), _p()]}, ALLOW, NOOP)
    assert len(kept) == 2 and any("REFUSED" in n for n in notes)


# ---------------------------------------------------------------------------------------------
# The allowlist is a BOUNDARY, not a routing table: a kind may permit several repos and the agent
# chooses among them. These protect the two properties that makes safe — that the older list shape
# keeps working, and that describing the options to the model never widens what is accepted.
# ---------------------------------------------------------------------------------------------
def test_list_shape_still_loads():
    """An existing config written as a list must not break when the shape gained descriptions."""
    al = P.load_allowlist('{"Documentation": ["org/a", "org/b"]}')
    assert al == {"Documentation": {"org/a": "", "org/b": ""}}


def test_mapping_shape_carries_purpose():
    al = P.load_allowlist('{"Alert": {"org/a": "the reconcile engine"}}')
    assert al["Alert"]["org/a"] == "the reconcile engine"


def test_several_repos_are_all_permitted():
    """The point of the change: one kind, more than one legitimate home."""
    al = P.load_allowlist('{"Documentation": {"org/a": "x", "org/b": "y"}}')
    for repo in ("org/a", "org/b"):
        kept, notes = P.validate_batch(
            {"proposals": [_p(kind="Documentation", target={"repo": repo, "path": "d.md"})]}, al, NOOP)
        assert len(kept) == 1 and not [n for n in notes if "REFUSED" in n]


def test_describing_targets_does_not_permit_them():
    """describe_targets is prose for the model. Acceptance is still decided by validate_batch, so a
    repo that appears in the description but not the allowlist must still be refused."""
    al = P.load_allowlist('{"Documentation": {"org/a": "x"}}')
    assert "org/a" in P.describe_targets(al)
    kept, notes = P.validate_batch(
        {"proposals": [_p(kind="Documentation", target={"repo": "org/elsewhere", "path": "d.md"})]}, al, NOOP)
    assert kept == [] and any("REFUSED" in n for n in notes)


def test_empty_allowlist_tells_the_model_to_propose_nothing():
    """Deny-all must be legible to the agent, or it spends a night producing refusals."""
    text = P.describe_targets({})
    assert "refused" in text.lower() and "propose nothing else" in text.lower()


def test_kind_with_no_repos_is_marked_do_not_propose():
    text = P.describe_targets({"Alert": {}})
    assert "do not propose this kind" in text


def test_a_kind_with_no_allowlist_entry_refuses_everything():
    """DENY BY DEFAULT, and this is the property worth guarding hardest.

    Found by mutation: making an unconfigured kind fall back to "whatever repo the model named"
    passed the entire suite. An operator who configures Documentation and forgets Policy must get a
    refusal for Policy, not an open door — the failure is silent, aimed by untrusted text, and
    indistinguishable from working."""
    al = P.load_allowlist('{"Documentation": {"org/docs": "x"}}')
    kept, notes = P.validate_batch(
        {"proposals": [_p(kind="Policy", target={"repo": "anything/at-all", "path": "p.yaml"})]},
        al, NOOP)
    assert kept == [] and any("REFUSED" in n for n in notes)


def test_a_kind_present_but_empty_refuses_everything():
    """An explicitly emptied kind is a deliberate deny, and must behave like one."""
    al = P.load_allowlist('{"Policy": []}')
    kept, notes = P.validate_batch(
        {"proposals": [_p(kind="Policy", target={"repo": "anything/at-all", "path": "p.yaml"})]},
        al, NOOP)
    assert kept == [] and any("REFUSED" in n for n in notes)


def test_an_entirely_empty_allowlist_refuses_everything():
    kept, notes = P.validate_batch({"proposals": [_p()]}, P.load_allowlist("{}"), NOOP)
    assert kept == [] and any("REFUSED" in n for n in notes)
