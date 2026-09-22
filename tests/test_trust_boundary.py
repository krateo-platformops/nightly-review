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
